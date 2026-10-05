#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8765}"
BIN="${MCP_HTTP_BIN:-./target/release/ida-mcp}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
ALLOW_ORIGIN="${MCP_HTTP_ALLOW_ORIGIN:-http://localhost,http://127.0.0.1}"
BIND_HOST="${MCP_HTTP_BIND_HOST:-127.0.0.1}"
CONNECT_HOST="${MCP_HTTP_CONNECT_HOST:-127.0.0.1}"
HOST_HEADER="${MCP_HTTP_HOST_HEADER:-}"
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

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

server_args=(serve-http --bind "$BIND_HOST:$PORT" --allow-origin "$ALLOW_ORIGIN")
if [[ -n "${MCP_HTTP_ALLOW_HOST+x}" ]]; then
  server_args+=(--allow-host "$MCP_HTTP_ALLOW_HOST")
fi

curl_headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: $ORIGIN"
)
if [[ -n "$HOST_HEADER" ]]; then
  curl_headers+=(-H "Host: $HOST_HEADER")
fi

url="http://$CONNECT_HOST:$PORT/"

"$BIN" "${server_args[@]}" >"$server_log" 2>&1 &
server_pid=$!

proto_version="${MCP_PROTOCOL_VERSION:-2024-11-05}"
echo "   protocolVersion=${proto_version}"
init_payload=$(printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"%s","clientInfo":{"name":"test","version":"0.1"},"capabilities":{}}}' "$proto_version")

session_id=""
for _ in {1..100}; do
  if curl -sS -D "$headers_file" -o "$body_file" \
    "${curl_headers[@]}" \
    -d "$init_payload" \
    "$url" >/dev/null 2>/dev/null; then
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

# Send notifications/initialized
curl -sS \
  "${curl_headers[@]}" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  "$url" >/dev/null

# tools/list should include core tools and analysis tools
list_resp=$(curl -sS \
  "${curl_headers[@]}" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  "$url")

echo "$list_resp" | grep -q '"open_idb"' || {
  echo "tools/list missing open_idb" >&2
  exit 1
}

echo "$list_resp" | grep -q '"xrefs_to"' || {
  echo "tools/list missing xrefs_to" >&2
  exit 1
}

echo "$list_resp" | grep -q '"recent_operations"' || {
  echo "tools/list missing recent_operations" >&2
  exit 1
}

# Open mini fixture and verify functions list
open_resp=$(curl -sS \
  "${curl_headers[@]}" \
  -H "Mcp-Session-Id: $session_id" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"$IDB_PATH\"}}}" \
  "$url")

echo "$open_resp" | grep -q "function_count" || {
  echo "open_idb failed" >&2
  echo "$open_resp" >&2
  exit 1
}

func_resp=$(curl -sS \
  "${curl_headers[@]}" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":10,"filter":"interesting_function"}}}' \
  "$url")

echo "$func_resp" | grep -q "interesting_function" || {
  echo "list_functions missing interesting_function" >&2
  echo "$func_resp" >&2
  exit 1
}

close_token="$(echo "$open_resp" | sed -n 's/.*\\\"close_token\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\\\"]*\\)\\\".*/\\1/p')"
if [[ -n "$close_token" ]]; then
  close_args="{\"close_token\":\"$close_token\"}"
else
  close_args="{}"
fi

curl -sS \
  "${curl_headers[@]}" \
  -H "Mcp-Session-Id: $session_id" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"close_idb\",\"arguments\":$close_args}}" \
  "$url" >/dev/null

echo "HTTP integration test passed"
