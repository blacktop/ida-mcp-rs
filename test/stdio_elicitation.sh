#!/usr/bin/env bash
set -euo pipefail

BIN="${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-mcp}}"
THRESHOLD_BYTES=$((50 * 1024 * 1024))
THRESHOLD_MIB=$((THRESHOLD_BYTES / 1024 / 1024))
EXPECTED_THRESHOLD_MSG="threshold ${THRESHOLD_MIB} MiB"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for elicitation test (brew install jq)" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

if [[ ! -x fixtures/mini ]]; then
  echo "missing fixture binary: fixtures/mini" >&2
  exit 1
fi

server_pid=""
tmpdir=""
current_large=""

cleanup_case() {
  exec 3>&- || true
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    sleep 0.5
    if kill -0 "$server_pid" >/dev/null 2>&1; then
      kill -9 "$server_pid" >/dev/null 2>&1 || true
    fi
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
  if [[ -n "${tmpdir:-}" ]]; then
    rm -rf "$tmpdir"
    tmpdir=""
  fi
  if [[ -n "${current_large:-}" ]]; then
    rm -f "$current_large" \
      "$current_large.i64" "$current_large.idb" "$current_large.imcp" \
      "$current_large.i64.imcp" "$current_large.idb.imcp" \
      "$current_large.til" "$current_large.nam"
    current_large=""
  fi
}

trap cleanup_case EXIT INT TERM

make_large_fixture() {
  local path="$1"
  rm -f "$path" "$path.i64" "$path.idb" "$path.imcp" "$path.i64.imcp" "$path.idb.imcp"
  cp fixtures/mini "$path"
  dd if=/dev/zero of="$path" bs=1 count=1 seek="$THRESHOLD_BYTES" conv=notrunc >/dev/null 2>&1
}

send() {
  echo "$1" >&3
}

json_line_matching() {
  local filter="$1"
  local timeout="${2:-60}"
  local elapsed=0
  while [[ "$elapsed" -lt "$timeout" ]]; do
    while IFS= read -r line; do
      if [[ "$line" != *'"jsonrpc"'* ]]; then
        continue
      fi
      if echo "$line" | jq -e "$filter" >/dev/null 2>&1; then
        echo "$line"
        return 0
      fi
    done <"$log"
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "server process died while waiting for: $filter" >&2
      cat "$log" >&2
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "timeout waiting for: $filter" >&2
  cat "$log" >&2
  return 1
}

wait_response() {
  local id="$1"
  local timeout="${2:-60}"
  json_line_matching ".id == $id and (has(\"result\") or has(\"error\"))" "$timeout"
}

wait_elicitation() {
  local timeout="${1:-60}"
  json_line_matching '.method == "elicitation/create"' "$timeout"
}

content_text() {
  jq -r '.result.content[0].text // empty'
}

assert_background_response() {
  local response="$1"
  local label="$2"
  local text
  text="$(echo "$response" | content_text)"
  if ! echo "$text" | jq -e \
    '.analysis_background == true
     and (.analysis_task_id | type == "string")
     and (.analysis_task_id | startswith("analyze-"))
     and (.analysis_task_status == "started" or .analysis_task_status == "already_running")
     and (.analysis_background_reason | contains("background task"))' >/dev/null; then
    echo "❌ $label open_idb response did not report background analysis" >&2
    echo "$response" | jq . >&2 || echo "$response" >&2
    echo "$text" >&2
    return 1
  fi
  echo "$text" | jq -r '.analysis_task_id'
}

assert_task_status() {
  local response="$1"
  local expected_task="$2"
  local label="$3"
  local text
  text="$(echo "$response" | content_text)"
  if ! echo "$text" | jq -e --arg task "$expected_task" \
    '.task_id == $task and (.status == "running" or .status == "completed")' >/dev/null; then
    echo "❌ $label task_status did not report running/completed task $expected_task" >&2
    echo "$response" | jq . >&2 || echo "$response" >&2
    echo "$text" >&2
    return 1
  fi
}

start_server() {
  tmpdir="$(mktemp -d)"
  fifo_in="$tmpdir/in.fifo"
  log="$tmpdir/server.log"
  mkfifo "$fifo_in"
  RUST_LOG="${RUST_LOG:-ida_mcp=trace}" "$BIN" <"$fifo_in" >"$log" 2>&1 &
  server_pid=$!
  exec 3>"$fifo_in"
}

run_case() {
  local label="$1"
  local capabilities_json="$2"
  local answer_elicitation="$3"
  local open_timeout_secs="${4:-600}"
  current_large="fixtures/mini-${label}"
  make_large_fixture "$current_large"
  start_server

  echo "── $label ──"
  send "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"clientInfo\":{\"name\":\"${label}\",\"version\":\"0.1\"},\"capabilities\":${capabilities_json}}}"
  wait_response 1 20 >/dev/null
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

  send "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"${current_large}\",\"auto_analyse\":true,\"timeout_secs\":${open_timeout_secs}}}}"

  if [[ "$answer_elicitation" == "yes" ]]; then
    local elicit_line elicit_id
    elicit_line="$(wait_elicitation 60)"
    if ! echo "$elicit_line" | jq -e --arg threshold_msg "$EXPECTED_THRESHOLD_MSG" \
      '.params.requestedSchema.properties.background.type == "boolean"
       and (.params.message | contains($threshold_msg))' >/dev/null; then
      echo "❌ elicitation request did not contain expected yes/no schema" >&2
      echo "$elicit_line" | jq . >&2 || echo "$elicit_line" >&2
      return 1
    fi
    elicit_id="$(echo "$elicit_line" | jq -c '.id')"
    send "{\"jsonrpc\":\"2.0\",\"id\":${elicit_id},\"result\":{\"action\":\"accept\",\"content\":{\"background\":true}}}"
  elif [[ "$answer_elicitation" == "timeout" ]]; then
    wait_elicitation 60 >/dev/null
  fi

  local open_resp task_id status_resp
  open_resp="$(wait_response 2 180)"
  task_id="$(assert_background_response "$open_resp" "$label")"
  echo "   background task: $task_id"

  send "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"task_status\",\"arguments\":{\"task_id\":\"${task_id}\"}}}"
  status_resp="$(wait_response 3 30)"
  assert_task_status "$status_resp" "$task_id" "$label"

  cleanup_case
}

run_case "no-elicitation" '{}' "no"
run_case "elicitation-accept" '{"elicitation":{"form":{}}}' "yes"
run_case "elicitation-timeout" '{"elicitation":{"form":{}}}' "timeout" 10

echo "✅ Elicitation auto-background test passed"
