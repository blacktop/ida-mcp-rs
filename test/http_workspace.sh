#!/usr/bin/env bash
# Prove database-ID routing survives sessionless MCP 2026 HTTP handlers.
set -euo pipefail

BIN="${MCP_HTTP_BIN:-${SERVER_BIN:-../target/debug/ida-mcp}}"
FIXTURE="${WORKSPACE_FIXTURE:-fixtures/mini.i64}"
PORT="${PORT:-9878}"
URL="http://127.0.0.1:$PORT/"
META='{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"ida-mcp-workspace-http-test","version":"0.1"},"io.modelcontextprotocol/clientCapabilities":{}}'

[[ -x "$BIN" ]] || { echo "missing server binary: $BIN" >&2; exit 1; }
[[ -f "$FIXTURE" ]] || { echo "missing workspace fixture: $FIXTURE" >&2; exit 1; }
for command in curl jq; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 1; }
done

tmpdir="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -9 "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

cp "$FIXTURE" "$tmpdir/http.i64"
RUST_LOG="${RUST_LOG:-ida_mcp=info}" "$BIN" --workspace serve-http \
  --stateless --json-response --bind "127.0.0.1:$PORT" \
  >"$tmpdir/server.out" 2>"$tmpdir/server.err" &
server_pid=$!

headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: http://localhost"
  -H "MCP-Protocol-Version: 2026-07-28"
)

request() {
  local method="$1" name="$2" body="$3"
  local extra=(-H "Mcp-Method: $method")
  if [[ -n "$name" ]]; then
    extra+=(-H "Mcp-Name: $name")
  fi
  curl -sS "${headers[@]}" "${extra[@]}" -d "$body" "$URL"
}

discover="$(jq -cn --argjson meta "$META" \
  '{jsonrpc:"2.0",id:1,method:"server/discover",params:{_meta:$meta}}')"
ready=""
for _ in {1..600}; do
  if grep -Fq "MCP workspace HTTP server listening" "$tmpdir/server.err"; then
    ready="$(request server/discover "" "$discover" 2>/dev/null || true)"
    [[ -n "$ready" ]] && break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "workspace HTTP server exited during startup" >&2
    cat "$tmpdir/server.err" >&2
    exit 1
  fi
  sleep 0.1
done
jq -e '.result.resultType == "complete"
  and (.result.supportedVersions | index("2026-07-28") != null)' \
  >/dev/null <<<"$ready"

list="$(jq -cn --argjson meta "$META" \
  '{jsonrpc:"2.0",id:2,method:"tools/list",params:{_meta:$meta}}')"
list_response="$(request tools/list "" "$list")"
jq -e 'any(.result.tools[]; .name == "list_functions"
  and (.inputSchema.required | index("database_id") != null))' \
  >/dev/null <<<"$list_response"

open="$(jq -cn --argjson meta "$META" --arg path "$tmpdir/http.i64" \
  '{jsonrpc:"2.0",id:3,method:"tools/call",params:{_meta:$meta,name:"open_idb",arguments:{path:$path}}}')"
open_response="$(request tools/call open_idb "$open")"
jq -e '.result.resultType == "complete" and .result.isError == false' \
  >/dev/null <<<"$open_response"
database_id="$(jq -r '.result.content[0].text | fromjson | .database_id // empty' \
  <<<"$open_response")"
[[ -n "$database_id" ]] || { echo "workspace HTTP open returned no database_id" >&2; exit 1; }

list_funcs="$(jq -cn --argjson meta "$META" --arg id "$database_id" \
  '{jsonrpc:"2.0",id:4,method:"tools/call",params:{_meta:$meta,name:"list_functions",arguments:{database_id:$id,limit:1}}}')"
list_funcs_response="$(request tools/call list_functions "$list_funcs")"
jq -e '.result.resultType == "complete" and .result.isError == false
  and ((.result.content[0].text | fromjson | .functions) | length == 1)' \
  >/dev/null <<<"$list_funcs_response"

missing="$(jq -cn --argjson meta "$META" \
  '{jsonrpc:"2.0",id:5,method:"tools/call",params:{_meta:$meta,name:"list_functions",arguments:{limit:1}}}')"
missing_response="$(request tools/call list_functions "$missing")"
jq -e '.error.code == -32602 and (.error.message | contains("requires database_id"))' \
  >/dev/null <<<"$missing_response"

close="$(jq -cn --argjson meta "$META" --arg id "$database_id" \
  '{jsonrpc:"2.0",id:6,method:"tools/call",params:{_meta:$meta,name:"close_idb",arguments:{database_id:$id}}}')"
close_response="$(request tools/call close_idb "$close")"
jq -e '.result.resultType == "complete" and .result.isError == false' \
  >/dev/null <<<"$close_response"

stale="$(jq -cn --argjson meta "$META" --arg id "$database_id" \
  '{jsonrpc:"2.0",id:7,method:"tools/call",params:{_meta:$meta,name:"list_functions",arguments:{database_id:$id,limit:1}}}')"
stale_response="$(request tools/call list_functions "$stale")"
jq -e '.error.code == -32602 and (.error.message | contains("unknown or expired"))' \
  >/dev/null <<<"$stale_response"

echo "   stateless MCP 2026 reused one explicit database handle across requests"
echo "workspace HTTP integration passed"
