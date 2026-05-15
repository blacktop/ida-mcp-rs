#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8766}"
BIN="${MCP_HTTP_BIN:-./target/release/ida-mcp}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
IDB_PATH="${IDB_PATH:-fixtures/mini}"
BOOTSTRAP_I64="${BOOTSTRAP_I64:-${IDB_PATH}.i64}"

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

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

"$BIN" serve-http --bind "127.0.0.1:$PORT" --allow-origin "http://localhost,http://127.0.0.1" >"$server_log" 2>&1 &
server_pid=$!

init_payload='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"bootstrap","version":"0.1"},"capabilities":{}}}'

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
  if [[ -s "$server_log" ]]; then
    echo "server output:" >&2
    cat "$server_log" >&2
  fi
  exit 1
fi

curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  "http://127.0.0.1:$PORT/" >/dev/null

open_resp=$(curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"$IDB_PATH\",\"timeout_secs\":600}}}" \
  "http://127.0.0.1:$PORT/")

echo "$open_resp" | grep -q "function_count" || {
  echo "bootstrap open_idb failed" >&2
  echo "$open_resp" >&2
  if [[ -s "$server_log" ]]; then
    echo "server output:" >&2
    cat "$server_log" >&2
  fi
  exit 1
}

close_token="$(echo "$open_resp" | sed -n 's/.*\\\"close_token\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\\\"]*\\)\\\".*/\\1/p')"
if [[ -n "$close_token" ]]; then
  close_args="{\"close_token\":\"$close_token\"}"
else
  close_args="{}"
fi

curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":$close_args}}" \
  "http://127.0.0.1:$PORT/" >/dev/null

if [[ ! -f "$BOOTSTRAP_I64" ]]; then
  echo "bootstrap did not create $BOOTSTRAP_I64" >&2
  if [[ -s "$server_log" ]]; then
    echo "server output:" >&2
    cat "$server_log" >&2
  fi
  exit 1
fi

echo "HTTP bootstrap test passed"
