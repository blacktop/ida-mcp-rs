#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8768}"
BIN="${MCP_HTTP_BIN:-./target/release/ida-mcp}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
IDB_PATH="${IDB_PATH:-fixtures/mini}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
headers_file="$tmpdir/headers.log"
body_file="$tmpdir/body.log"
server_log="$tmpdir/server.log"
open_resp_file="$tmpdir/open-response.log"

cleanup() {
  if [[ -n "${open_pid:-}" ]]; then
    wait "$open_pid" 2>/dev/null || true
  fi
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

"$BIN" serve-http --bind "127.0.0.1:$PORT" --allow-origin "http://localhost,http://127.0.0.1" >"$server_log" 2>&1 &
server_pid=$!

init_payload='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"observability-test","version":"0.1"},"capabilities":{}}}'

session_id=""
for _ in {1..100}; do
  if curl -sS -D "$headers_file" -o "$body_file" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Origin: $ORIGIN" \
    -d "$init_payload" \
    "http://127.0.0.1:$PORT/" >/dev/null 2>/dev/null; then
    session_id="$(awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' "$headers_file" | tr -d '\r')"
    if [[ -n "$session_id" ]]; then
      break
    fi
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ -z "$session_id" ]]; then
  echo "failed to obtain Mcp-Session-Id" >&2
  [[ -s "$server_log" ]] && cat "$server_log" >&2
  exit 1
fi

call_tool() {
  local request_id="$1"
  local tool_name="$2"
  local arguments_json="$3"
  local extra_params="${4:-}"
  curl -sS \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Origin: $ORIGIN" \
    -H "Mcp-Session-Id: $session_id" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${request_id},\"method\":\"tools/call\",\"params\":{${extra_params}\"name\":\"${tool_name}\",\"arguments\":${arguments_json}}}" \
    "http://127.0.0.1:$PORT/"
}

curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  "http://127.0.0.1:$PORT/" >/dev/null

curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"_meta\":{\"progressToken\":\"obs-open\"},\"name\":\"open_idb\",\"arguments\":{\"path\":\"$IDB_PATH\",\"timeout_secs\":600}}}" \
  "http://127.0.0.1:$PORT/" >"$open_resp_file" &
open_pid=$!

recent_resp=""
for _ in {1..20}; do
  recent_resp="$(call_tool 3 recent_operations '{"limit":5}')"
  if echo "$recent_resp" | grep -q 'open_idb'; then
    break
  fi
  sleep 1
done

echo "$recent_resp" | grep -q 'open_idb' || {
  echo "recent_operations did not report open_idb in either active_operation or recent_events" >&2
  echo "$recent_resp" >&2
  [[ -s "$server_log" ]] && cat "$server_log" >&2
  exit 1
}

echo "$recent_resp" | grep -Eq 'queued|initializing|opening|analyzing|completed' || {
  echo "recent_operations did not include the open_idb phase trail" >&2
  echo "$recent_resp" >&2
  [[ -s "$server_log" ]] && cat "$server_log" >&2
  exit 1
}

wait "$open_pid"

if ! grep -q 'function_count' "$open_resp_file"; then
  echo "observability open_idb call did not complete successfully" >&2
  cat "$open_resp_file" >&2
  [[ -s "$server_log" ]] && cat "$server_log" >&2
  exit 1
fi

close_token="$(sed -n 's/.*\\\"close_token\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\\\"]*\\)\\\".*/\\1/p' "$open_resp_file")"
if [[ -n "$close_token" ]]; then
  close_args="{\"close_token\":\"$close_token\"}"
else
  close_args="{}"
fi

call_tool 4 close_idb "$close_args" >/dev/null

echo "HTTP observability integration test passed"
