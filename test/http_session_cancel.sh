#!/usr/bin/env bash
# End-to-end oracle for legacy session-owned background-task cancellation on
# single-worker HTTP: a background analyze_funcs task spawned by a legacy
# session must remain private from a second legacy session and then terminate
# through cancellation after its owner is DELETEd, instead of surviving as an
# orphan that holds the shared IDA worker.
#
# Determinism: the single IDA worker serializes ops. A slow foreground open_idb
# of a 50 MiB fixture is fired first (async), the background AnalyzeFuncs op
# queues behind it, and the session is DELETEd while the open is still active
# (observed via recent_operations, not a sleep). The worker's pre-dequeue and
# post-auto_wait cancel checks then fail the task regardless of IDA timing.
set -euo pipefail

PORT="${PORT:-8794}"
BIN="${MCP_HTTP_BIN:-./target/release/ida-mcp}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
ALLOW_ORIGIN="${MCP_HTTP_ALLOW_ORIGIN:-http://localhost,http://127.0.0.1}"
BIND_HOST="${MCP_HTTP_BIND_HOST:-127.0.0.1}"
CONNECT_HOST="${MCP_HTTP_CONNECT_HOST:-127.0.0.1}"
THRESHOLD_BYTES=$((50 * 1024 * 1024))
MODERN_META='{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"session-cancel-test","version":"0.1"},"io.modelcontextprotocol/clientCapabilities":{}}'

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

if [[ ! -x fixtures/mini ]]; then
  echo "missing fixture binary: fixtures/mini" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
server_log="$tmpdir/server.log"
large_fixture="fixtures/mini-session-cancel"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
  rm -f "$large_fixture" \
    "$large_fixture.i64" "$large_fixture.idb" "$large_fixture.imcp" \
    "$large_fixture.i64.imcp" "$large_fixture.idb.imcp" \
    "$large_fixture.til" "$large_fixture.nam"
}
trap cleanup EXIT INT TERM

rm -f "$large_fixture" "$large_fixture.i64" "$large_fixture.idb"
cp fixtures/mini "$large_fixture"
dd if=/dev/zero of="$large_fixture" bs=1 count=1 seek="$THRESHOLD_BYTES" conv=notrunc >/dev/null 2>&1

curl_headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: $ORIGIN"
)

url="http://$CONNECT_HOST:$PORT/"

RUST_LOG="${RUST_LOG:-info},ida_mcp=info" "$BIN" serve-http \
  --bind "$BIND_HOST:$PORT" \
  --allow-origin "$ALLOW_ORIGIN" \
  >"$server_log" 2>&1 &
server_pid=$!

fail() {
  echo "❌ $1" >&2
  shift
  for extra in "$@"; do
    echo "$extra" >&2
  done
  echo "── server log ──" >&2
  cat "$server_log" >&2
  exit 1
}

wait_for_owned_listener() {
  local expected="MCP HTTP server listening on http://$BIND_HOST:$PORT"
  for _ in {1..600}; do
    if grep -Fq "$expected" "$server_log"; then
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  fail "spawned server did not prove ownership of $BIND_HOST:$PORT"
}

# Do not probe the port until this child has logged a successful bind. A curl
# alone could reach an unrelated listener when the randomized port collides.
wait_for_owned_listener

extract_response_json() {
  # Accept plain JSON and SSE framing (strip the `data: ` prefix); pick the
  # response frame, not the first data event.
  sed -e 's/^data: //' | jq -cR 'fromjson? | select(has("result") or has("error"))' | tail -1
}

# init_session prints the Mcp-Session-Id of a fresh legacy client to stdout.
init_session() {
  local headers="$tmpdir/init.h.$$"
  local payload='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"session-cancel","version":"0.1"},"capabilities":{}}}'
  for _ in {1..300}; do
    if curl -sS -D "$headers" -o /dev/null "${curl_headers[@]}" -d "$payload" "$url" 2>/dev/null; then
      local sid
      sid="$(awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' "$headers" | tr -d '\r')"
      if [[ -n "$sid" ]]; then
        curl -sS "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
          -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
          "$url" >/dev/null
        rm -f "$headers"
        printf '%s' "$sid"
        return 0
      fi
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  rm -f "$headers"
  fail "failed to obtain Mcp-Session-Id"
}

# session_tool_text <session-id> <id> <tool> <args-json> -> tool text payload
session_tool_text() {
  local sid="$1" rid="$2" tool="$3" args="$4"
  curl -sS "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${rid},\"method\":\"tools/call\",\"params\":{\"name\":\"${tool}\",\"arguments\":${args}}}" \
    "$url" | extract_response_json | jq -r '.result.content[0].text // empty'
}

# modern_tool_text <id> <tool> <args-json> -> tool text payload (sessionless)
modern_tool_text() {
  local rid="$1" tool="$2" args="$3"
  curl -sS "${curl_headers[@]}" \
    -H "MCP-Protocol-Version: 2026-07-28" \
    -H "Mcp-Method: tools/call" -H "Mcp-Name: ${tool}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${rid},\"method\":\"tools/call\",\"params\":{\"_meta\":${MODERN_META},\"name\":\"${tool}\",\"arguments\":${args}}}" \
    "$url" | extract_response_json | jq -r '.result.content[0].text // empty'
}

session_a="$(init_session)"
echo "   session A: $session_a"

# --- Phase 1: occupy the worker with a slow foreground open (async) ---
curl -sS "${curl_headers[@]}" -H "Mcp-Session-Id: $session_a" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"$large_fixture\",\"auto_analyse\":false,\"timeout_secs\":600}}}" \
  "$url" >"$tmpdir/open.out" 2>/dev/null &
open_curl_pid=$!

open_active=""
for _ in {1..300}; do
  ops="$(modern_tool_text 20 recent_operations '{}')"
  if [[ -n "$ops" ]] && echo "$ops" | jq -e \
    '.active_operation.tool == "open_idb"' >/dev/null 2>&1; then
    open_active=1
    break
  fi
  sleep 0.1
done
[[ -n "$open_active" ]] || fail "open_idb never became the active operation" "$ops"
echo "   open_idb active on the worker"

# --- Phase 2: queue a background analysis behind it, owned by session A ---
analyze_text="$(session_tool_text "$session_a" 11 analyze_funcs '{"background":true}')"
task_id="$(echo "$analyze_text" | jq -r '.task_id // empty')"
[[ -n "$task_id" ]] || fail "analyze_funcs did not return a task_id" "$analyze_text"
echo "   background task: $task_id"

status_text="$(session_tool_text "$session_a" 12 task_status "{\"task_id\":\"$task_id\"}")"
echo "$status_text" | jq -e '.status == "running"' >/dev/null ||
  fail "task not running before session close" "$status_text"

# --- Phase 3: session B cannot reuse, observe, or learn session A's task ---
session_b="$(init_session)"
echo "   session B: $session_b"

other_analyze_text="$(session_tool_text "$session_b" 30 analyze_funcs '{"background":true}')"
echo "$other_analyze_text" | grep -qi 'task handle stays with the response' ||
  fail "session B was not rejected from session A's deduplicated work" "$other_analyze_text"
if echo "$other_analyze_text" | grep -Fq "$task_id"; then
  fail "session B learned session A's task_id through deduplication" "$other_analyze_text"
fi

other_status_text="$(session_tool_text "$session_b" 31 task_status "{\"task_id\":\"$task_id\"}")"
echo "$other_status_text" | grep -q 'Unknown task_id' ||
  fail "session B could poll session A's task" "$other_status_text"
echo "   session B cannot reuse or poll session A's task"

# --- Phase 4: close session A while its task is queued/running ---
curl -sS -X DELETE "${curl_headers[@]}" -H "Mcp-Session-Id: $session_a" "$url" >/dev/null
echo "   session A deleted"

# --- Phase 5: server records cancellation of the now-private task ---
# Task IDs are bearer capabilities and are deliberately never written to the
# server log, so these oracles match on the log message alone; this test runs
# exactly one background analysis, so the messages are unambiguous.
cancel_log=""
for _ in {1..360}; do
  cancel_log="$(grep -F 'Background auto-analysis cancelled after work settled' "$server_log" | tail -1 || true)"
  if [[ -n "$cancel_log" ]]; then
    break
  fi
  sleep 0.5
done

[[ -n "$cancel_log" ]] ||
  fail "server did not record cancellation after session close"
if grep -Fq 'Background auto-analysis completed' "$server_log"; then
  fail "task completed despite session close (cancel-on-disconnect regressed)"
fi
if grep -F "$task_id" "$server_log" >/dev/null; then
  fail "task bearer ID leaked into the server log"
fi

echo "   task $task_id terminated through owner cancellation"
wait "$open_curl_pid" 2>/dev/null || true
echo "✅ HTTP session cancel test passed"
