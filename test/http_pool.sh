#!/usr/bin/env bash
# Exercise the HTTP worker-pool path. Cases:
#   concurrency  - a long call in session A must not block session B
#   exhaustion   - a third open fails when two workers are leased
#   crash        - a child exit is contained and the session can re-open
#   disconnect   - dropped client SSE streams release leased workers
#   manager-disconnect - dropped standalone SSE closes pooled rmcp session without opening IDA
#   second-open-failure - failed second open keeps the existing session lease/IDB
set -euo pipefail

CASE="${POOL_TEST_CASE:-${1:-concurrency}}"
PORT="${PORT:-8765}"
BIN="${MCP_HTTP_BIN:-./target/release/ida-mcp}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
ALLOW_ORIGIN="${MCP_HTTP_ALLOW_ORIGIN:-http://localhost,http://127.0.0.1}"
BIND_HOST="${MCP_HTTP_BIND_HOST:-127.0.0.1}"
CONNECT_HOST="${MCP_HTTP_CONNECT_HOST:-127.0.0.1}"
IDB_PATH="${IDB_PATH:-fixtures/mini}"
MAX_WORKERS="${MAX_WORKERS:-2}"
OP_TIMEOUT="${WORKER_OP_TIMEOUT:-20}"
DISCONNECT_GRACE="${WORKER_DISCONNECT_GRACE:-1}"

for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "$cmd is required" >&2
    exit 1
  fi
done

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
server_log="$tmpdir/server.log"
headers_file="$tmpdir/headers.log"
body_file="$tmpdir/body.log"

cleanup() {
  if [[ -n "${slow_pid:-}" ]]; then
    kill "$slow_pid" >/dev/null 2>&1 || true
    wait "$slow_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${sse_a_pid:-}" ]]; then
    kill "$sse_a_pid" >/dev/null 2>&1 || true
    wait "$sse_a_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${sse_b_pid:-}" ]]; then
    kill "$sse_b_pid" >/dev/null 2>&1 || true
    wait "$sse_b_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

case "$IDB_PATH" in
*.i64) fixture_ext=".i64" ;;
*.idb) fixture_ext=".idb" ;;
*) fixture_ext="" ;;
esac

fixture_a="$tmpdir/mini-a${fixture_ext}"
fixture_b="$tmpdir/mini-b${fixture_ext}"
fixture_c="$tmpdir/mini-c${fixture_ext}"
if [[ "$CASE" != "manager-disconnect" ]]; then
  cp "$IDB_PATH" "$fixture_a"
  cp "$IDB_PATH" "$fixture_b"
  cp "$IDB_PATH" "$fixture_c"
fi

curl_headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: $ORIGIN"
)
url="http://$CONNECT_HOST:$PORT/"

"$BIN" serve-http \
  --bind "$BIND_HOST:$PORT" \
  --allow-origin "$ALLOW_ORIGIN" \
  --max-workers "$MAX_WORKERS" \
  --worker-idle-timeout-secs 60 \
  --worker-op-timeout-secs "$OP_TIMEOUT" \
  --worker-disconnect-grace-secs "$DISCONNECT_GRACE" \
  >"$server_log" 2>&1 &
server_pid=$!

extract_json() {
  awk '/^\{/{print; exit} /^data: \{/{sub(/^data: /,""); print; exit}'
}

init_session() {
  local payload
  payload="$(jq -cn '{jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2024-11-05",clientInfo:{name:"pool-test",version:"0.1"},capabilities:{}}}')"
  for _ in {1..300}; do
    if curl -sS -D "$headers_file" -o "$body_file" \
      "${curl_headers[@]}" \
      -d "$payload" \
      "$url" >/dev/null 2>&1; then
      local sid
      sid="$(awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' "$headers_file" | tr -d '\r')"
      if [[ -n "$sid" ]]; then
        curl -sS "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
          -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
          "$url" >/dev/null
        printf '%s' "$sid"
        return 0
      fi
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  echo "failed to obtain Mcp-Session-Id" >&2
  cat "$server_log" >&2 || true
  exit 1
}

call_rpc() {
  local sid="$1" rid="$2" method="$3" params="$4" max_time="${5:-0}"
  local payload
  payload="$(jq -cn --argjson id "$rid" --arg method "$method" --argjson params "$params" \
    '{jsonrpc:"2.0",id:$id,method:$method,params:$params}')"
  local curl_args=(-sS)
  if [[ "$max_time" != "0" ]]; then
    curl_args+=(--max-time "$max_time")
  fi
  curl "${curl_args[@]}" "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
    -d "$payload" \
    "$url" | extract_json
}

tool_call() {
  local sid="$1" rid="$2" tool="$3" args="$4" max_time="${5:-0}"
  local params
  params="$(jq -cn --arg name "$tool" --argjson arguments "$args" \
    '{name:$name,arguments:$arguments}')"
  call_rpc "$sid" "$rid" "tools/call" "$params" "$max_time"
}

tool_text() {
  jq -r '.result.content[0].text // empty'
}

assert_tool_ok() {
  local resp="$1" context="$2"
  local is_error
  is_error="$(printf '%s' "$resp" | jq -r '.result.isError // false')"
  if [[ "$is_error" == "true" || -z "$resp" ]]; then
    echo "$context failed" >&2
    printf '%s\n' "$resp" | jq . >&2 || printf '%s\n' "$resp" >&2
    cat "$server_log" >&2 || true
    exit 1
  fi
}

assert_tool_error_contains() {
  local resp="$1" needle="$2" context="$3"
  local is_error text
  is_error="$(printf '%s' "$resp" | jq -r '.result.isError // false')"
  text="$(printf '%s' "$resp" | tool_text)"
  if [[ "$is_error" != "true" || "$text" != *"$needle"* ]]; then
    echo "$context did not return expected error containing '$needle'" >&2
    printf '%s\n' "$resp" | jq . >&2 || printf '%s\n' "$resp" >&2
    cat "$server_log" >&2 || true
    exit 1
  fi
}

wait_for_log() {
  local needle="$1" timeout_secs="$2"
  local deadline=$((SECONDS + timeout_secs))
  while ((SECONDS <= deadline)); do
    if grep -Fq "$needle" "$server_log"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

open_fixture() {
  local sid="$1" rid="$2" path="$3"
  local args resp
  args="$(jq -cn --arg path "$path" '{path:$path}')"
  resp="$(tool_call "$sid" "$rid" open_idb "$args" 45)"
  assert_tool_ok "$resp" "open_idb $path"
  printf '%s' "$resp" | tool_text | jq -e '.function_count' >/dev/null || {
    echo "open_idb response missing function_count for $path" >&2
    printf '%s\n' "$resp" | jq . >&2
    exit 1
  }
}

close_session() {
  local sid="$1" rid="$2"
  tool_call "$sid" "$rid" close_idb '{}' 10 >/dev/null || true
}

start_standalone_stream() {
  local sid="$1" name="$2"
  curl -sS -N "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
    "$url" >"$tmpdir/$name-sse.log" 2>&1 &
  local pid=$!
  sleep 0.5
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "standalone SSE stream for $name exited unexpectedly" >&2
    cat "$tmpdir/$name-sse.log" >&2 || true
    cat "$server_log" >&2 || true
    exit 1
  fi
  printf '%s' "$pid"
}

session_a="$(init_session)"
session_b="$(init_session)"
session_c="$(init_session)"

case "$CASE" in
concurrency)
  open_fixture "$session_a" 10 "$fixture_a"
  open_fixture "$session_b" 20 "$fixture_b"

  slow_args="$(jq -cn --arg code 'import time; time.sleep(8); print("slow done")' \
    '{code:$code,timeout_secs:15}')"
  slow_resp_file="$tmpdir/slow-response.json"
  tool_call "$session_a" 30 run_script "$slow_args" 20 >"$slow_resp_file" &
  slow_pid=$!
  sleep 1

  status_resp="$(tool_call "$session_b" 31 analysis_status '{}' 4)"
  assert_tool_ok "$status_resp" "analysis_status while session A is busy"
  if ! kill -0 "$slow_pid" 2>/dev/null; then
    echo "slow run_script finished before concurrency check completed" >&2
    cat "$slow_resp_file" >&2 || true
    exit 1
  fi

  wait "$slow_pid"
  unset slow_pid
  slow_resp="$(cat "$slow_resp_file")"
  assert_tool_ok "$slow_resp" "slow run_script"
  printf '%s' "$slow_resp" | tool_text | grep -q 'slow done' || {
    echo "slow run_script output missing marker" >&2
    printf '%s\n' "$slow_resp" | jq . >&2
    exit 1
  }
  close_session "$session_a" 90
  close_session "$session_b" 91
  echo "HTTP pool concurrency test passed"
  ;;

exhaustion)
  open_fixture "$session_a" 10 "$fixture_a"
  open_fixture "$session_b" 20 "$fixture_b"
  third_args="$(jq -cn --arg path "$fixture_c" '{path:$path}')"
  third_resp="$(tool_call "$session_c" 30 open_idb "$third_args" 15)"
  assert_tool_error_contains "$third_resp" "Worker pool exhausted" "third pooled open"
  close_session "$session_a" 90
  close_session "$session_b" 91
  echo "HTTP pool exhaustion test passed"
  ;;

second-open-failure)
  open_fixture "$session_a" 10 "$fixture_a"
  second_args="$(jq -cn --arg path "$fixture_b" '{path:$path}')"
  second_resp="$(tool_call "$session_a" 20 open_idb "$second_args" 15)"
  assert_tool_error_contains "$second_resp" "A database is already open" "second pooled open"

  meta_resp="$(tool_call "$session_a" 30 idb_meta '{}' 10)"
  assert_tool_ok "$meta_resp" "idb_meta after failed second open"
  printf '%s' "$meta_resp" | tool_text | jq -e '(.path // .input_file_path // "") | contains("mini-a")' >/dev/null || {
    echo "failed second open did not preserve the original database" >&2
    printf '%s\n' "$meta_resp" | jq . >&2
    cat "$server_log" >&2 || true
    exit 1
  }

  close_session "$session_a" 90
  echo "HTTP pool second-open failure test passed"
  ;;

crash)
  open_fixture "$session_a" 10 "$fixture_a"
  open_fixture "$session_b" 20 "$fixture_b"
  crash_args="$(jq -cn --arg code 'import os; os._exit(139)' '{code:$code,timeout_secs:10}')"
  crash_resp="$(tool_call "$session_a" 30 run_script "$crash_args" 15)"
  assert_tool_error_contains "$crash_resp" "Worker" "crashing child call"

  status_resp="$(tool_call "$session_b" 31 analysis_status '{}' 10)"
  assert_tool_ok "$status_resp" "analysis_status in unaffected session"

  open_fixture "$session_a" 40 "$fixture_c"
  close_session "$session_a" 90
  close_session "$session_b" 91
  echo "HTTP pool crash-containment test passed"
  ;;

disconnect)
  open_fixture "$session_a" 10 "$fixture_a"
  open_fixture "$session_b" 20 "$fixture_b"

  sse_a_pid="$(start_standalone_stream "$session_a" session-a)"
  sse_b_pid="$(start_standalone_stream "$session_b" session-b)"
  kill "$sse_a_pid" "$sse_b_pid" >/dev/null 2>&1 || true
  wait "$sse_a_pid" "$sse_b_pid" >/dev/null 2>&1 || true
  sleep "$((DISCONNECT_GRACE + 2))"

  open_fixture "$session_c" 30 "$fixture_c"
  close_session "$session_c" 91
  echo "HTTP pool disconnect cleanup test passed"
  ;;

manager-disconnect)
  sse_a_pid="$(start_standalone_stream "$session_a" session-a)"
  kill "$sse_a_pid" >/dev/null 2>&1 || true
  wait "$sse_a_pid" >/dev/null 2>&1 || true
  unset sse_a_pid

  if ! wait_for_log "Using disconnect-aware pooled HTTP session manager" 5; then
    echo "pooled HTTP path did not install the disconnect-aware session manager" >&2
    cat "$server_log" >&2 || true
    exit 1
  fi
  if ! wait_for_log "closing pooled HTTP session after client stream disconnect" "$((DISCONNECT_GRACE + 5))"; then
    echo "pooled session manager did not close abandoned standalone SSE stream" >&2
    cat "$server_log" >&2 || true
    exit 1
  fi
  echo "HTTP pool manager disconnect wiring test passed"
  ;;

*)
  echo "unknown POOL_TEST_CASE: $CASE" >&2
  exit 2
  ;;
esac
