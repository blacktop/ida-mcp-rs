#!/usr/bin/env bash
set -euo pipefail

BIN="${MCP_BIN:-${SERVER_BIN:-../target/debug/ida-mcp}}"
PORT="${PORT:-9876}"
META='{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"ida-mcp-modern-test","version":"0.1"},"io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}},"extensions":{"io.modelcontextprotocol/tasks":{}}}}'
LEGACY_META='{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientInfo":{"name":"ida-mcp-legacy-owner-test","version":"0.1"},"io.modelcontextprotocol/clientCapabilities":{}}'

for command in curl jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required for modern protocol test" >&2
    exit 1
  fi
done

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
server_pid=""

cleanup_server() {
  if [[ -z "${server_pid:-}" ]]; then
    return
  fi

  kill "$server_pid" >/dev/null 2>&1 || true
  for _ in {1..10}; do
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "$server_pid" >/dev/null 2>&1; then
    kill -9 "$server_pid" >/dev/null 2>&1 || true
  fi
  wait "$server_pid" >/dev/null 2>&1 || true
  server_pid=""
}

cleanup() {
  cleanup_server
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

assert_json() {
  local label="$1"
  local payload="$2"
  local filter="$3"
  if ! echo "$payload" | jq -e "$filter" >/dev/null; then
    echo "❌ $label" >&2
    echo "$payload" | jq . >&2 2>/dev/null || echo "$payload" >&2
    return 1
  fi
}

wait_json_line() {
  local log="$1"
  local id="$2"
  local elapsed=0
  # 60s budget: startup covers process spawn + IDA library load + license
  # preflight, which can exceed 10s on cold or loaded machines.
  while [[ "$elapsed" -lt 600 ]]; do
    local line
    # jq -R + fromjson? skips non-JSON lines (e.g. tracing output merged into
    # the log) instead of aborting the whole stream on the first parse error.
    line="$(grep '"jsonrpc"' "$log" | jq -cR "fromjson? | select(.id == $id and (has(\"result\") or has(\"error\")))" 2>/dev/null | tail -1 || true)"
    if [[ -n "$line" ]]; then
      echo "$line"
      return 0
    fi
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
      echo "server exited while waiting for response id $id" >&2
      cat "$log" >&2
      cat "$log.err" >&2 2>/dev/null || true
      return 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done
  echo "timed out waiting for response id $id" >&2
  cat "$log" >&2
  cat "$log.err" >&2 2>/dev/null || true
  return 1
}

run_stdio_modern() {
  local fifo="$tmpdir/stdio.fifo"
  local log="$tmpdir/stdio.log"
  mkfifo "$fifo"
  # JSON-RPC stdout and tracing stderr must not share a file offset: a trace
  # line flushed mid-response tears the response line in the log for good.
  RUST_LOG="${RUST_LOG:-ida_mcp=info}" "$BIN" <"$fifo" >"$log" 2>"$log.err" &
  server_pid=$!
  exec 3>"$fifo"

  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":$META}}" >&3
  local discover
  discover="$(wait_json_line "$log" 1)"
  assert_json "stdio discover must advertise 2026 and the tasks extension" "$discover" \
    '.result.resultType == "complete"
     and (.result.supportedVersions | index("2026-07-28") != null)
     and (.result.capabilities.extensions["io.modelcontextprotocol/tasks"] == {})'

  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{\"_meta\":$META}}" >&3
  local tools
  tools="$(wait_json_line "$log" 2)"
  assert_json "stdio tools/list must include open_dsc without execution metadata" "$tools" \
    '.result.resultType == "complete"
     and any(.result.tools[]; .name == "open_dsc")
     and all(.result.tools[]; has("execution") | not)'

  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"_meta\":$META,\"name\":\"tool_catalog\",\"arguments\":{\"query\":\"database lifecycle\",\"limit\":1}}}" >&3
  local call
  call="$(wait_json_line "$log" 3)"
  assert_json "stdio modern tools/call must complete" "$call" \
    '.result.resultType == "complete"
     and .result.isError == false
     and (.result.content[0].text | contains("tools"))'

  printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}' >&3
  local malformed
  malformed="$(wait_json_line "$log" 4)"
  assert_json "incomplete request _meta must be rejected with -32602" "$malformed" \
    '.error.code == -32602
     and (.error.message | contains("request _meta is missing or has malformed required fields"))'

  exec 3>&-
  cleanup_server
  echo "   stdio discover/list/call and strict request metadata passed"
}

run_stdio_legacy_owner() {
  local fifo="$tmpdir/legacy-stdio.fifo"
  local log="$tmpdir/legacy-stdio.log"
  mkfifo "$fifo"
  RUST_LOG="${RUST_LOG:-ida_mcp=info}" "$BIN" <"$fifo" >"$log" 2>"$log.err" &
  server_pid=$!
  exec 3>"$fifo"

  printf '%s\n' '{"jsonrpc":"2.0","id":30,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"ida-mcp-legacy-owner-test","version":"0.1"},"capabilities":{}}}' >&3
  local initialize
  initialize="$(wait_json_line "$log" 30)"
  assert_json "legacy stdio initialize must negotiate 2025-11-25" "$initialize" \
    '.result.protocolVersion == "2025-11-25"'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' >&3

  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":31,\"method\":\"tools/call\",\"params\":{\"_meta\":$LEGACY_META,\"name\":\"analyze_funcs\",\"arguments\":{\"background\":true}}}" >&3
  local analyze
  analyze="$(wait_json_line "$log" 31)"
  assert_json "full-metadata legacy stdio request must start a background task" "$analyze" \
    '.result.isError == false and (.result.content[0].text | fromjson | .task_id | length > 0)'
  local task_id
  task_id="$(echo "$analyze" | jq -r '.result.content[0].text | fromjson | .task_id')"

  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":32,\"method\":\"tools/call\",\"params\":{\"name\":\"task_status\",\"arguments\":{\"task_id\":\"$task_id\"}}}" >&3
  local status
  status="$(wait_json_line "$log" 32)"
  assert_json "metadata-free request on the same stdio connection must retain task ownership" "$status" \
    ".result.isError == false and (.result.content[0].text | fromjson | .task_id == \"$task_id\")"

  exec 3>&-
  cleanup_server
  echo "   legacy stdio task ownership stayed connection-scoped across metadata changes"
}

http_headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: http://localhost"
)

wait_http() {
  local url="$1"
  local body="$2"
  local version="$3"
  local method="$4"
  local startup_pattern="$5"
  local headers=("${http_headers[@]}" -H "MCP-Protocol-Version: $version" -H "Mcp-Method: $method")
  local elapsed=0
  # 60s budget: see wait_json_line.
  while [[ "$elapsed" -lt 600 ]]; do
    if grep -Fq "$startup_pattern" "$tmpdir/http-server.log"; then
      break
    fi
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
      echo "HTTP server exited before proving listener ownership" >&2
      cat "$tmpdir/http-server.log" >&2
      return 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done
  if ! grep -Fq "$startup_pattern" "$tmpdir/http-server.log"; then
    echo "spawned HTTP server did not prove listener ownership" >&2
    cat "$tmpdir/http-server.log" >&2
    return 1
  fi

  elapsed=0
  while [[ "$elapsed" -lt 600 ]]; do
    if curl -sS "${headers[@]}" -d "$body" "$url" >"$tmpdir/http-ready.out" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
      echo "owned HTTP server exited before becoming ready" >&2
      cat "$tmpdir/http-server.log" >&2
      return 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done
  echo "owned HTTP server did not become ready" >&2
  cat "$tmpdir/http-server.log" >&2
  return 1
}

extract_http_json() {
  local file="$1"
  local event
  # Pick the response frame (has result/error), not merely the first SSE data
  # event — notifications or keep-alives may precede it on the stream.
  event="$(sed -n 's/^data: //p' "$file" \
    | jq -cR 'fromjson? | select(has("result") or has("error"))' 2>/dev/null \
    | tail -1 || true)"
  if [[ -n "$event" ]]; then
    printf '%s\n' "$event"
  else
    cat "$file"
  fi
}

run_http_modern() {
  local url="http://127.0.0.1:$PORT/"
  local log="$tmpdir/http-server.log"
  local discover="{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"server/discover\",\"params\":{\"_meta\":$META}}"
  RUST_LOG="${RUST_LOG:-info},ida_mcp=info" "$BIN" serve-http --bind "127.0.0.1:$PORT" \
    --allow-origin "http://localhost,http://127.0.0.1" >"$log" 2>&1 &
  server_pid=$!
  wait_http "$url" "$discover" "2026-07-28" "server/discover" \
    "MCP HTTP server listening on http://127.0.0.1:$PORT"

  local discover_response
  discover_response="$(extract_http_json "$tmpdir/http-ready.out")"
  assert_json "HTTP discover must advertise 2026" "$discover_response" \
    '.result.resultType == "complete"
     and (.result.supportedVersions | index("2026-07-28") != null)'

  local list="{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/list\",\"params\":{\"_meta\":$META}}"
  curl -sS -D "$tmpdir/http-headers.out" "${http_headers[@]}" \
    -H "MCP-Protocol-Version: 2026-07-28" -H "Mcp-Method: tools/list" \
    -d "$list" "$url" >"$tmpdir/http-list.out"
  assert_json "sessionless HTTP tools/list must complete" \
    "$(extract_http_json "$tmpdir/http-list.out")" \
    '.result.resultType == "complete" and any(.result.tools[]; .name == "open_idb")'
  if grep -qi '^Mcp-Session-Id:' "$tmpdir/http-headers.out"; then
    echo "modern HTTP response unexpectedly created a legacy session" >&2
    exit 1
  fi

  local call="{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{\"_meta\":$META,\"name\":\"tool_catalog\",\"arguments\":{\"limit\":1}}}"
  curl -sS "${http_headers[@]}" -H "MCP-Protocol-Version: 2026-07-28" \
    -H "Mcp-Method: tools/call" -H "Mcp-Name: tool_catalog" \
    -d "$call" "$url" >"$tmpdir/http-call.out"
  assert_json "sessionless HTTP tools/call must complete" \
    "$(extract_http_json "$tmpdir/http-call.out")" \
    '.result.resultType == "complete" and .result.isError == false'

  cleanup_server
  echo "   default single-worker HTTP stayed sessionless for discover/list/call"
}

run_pooled_boundary() {
  local pooled_port=$((PORT + 1))
  local url="http://127.0.0.1:$pooled_port/"
  local log="$tmpdir/http-server.log"
  local legacy_meta='{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientInfo":{"name":"ida-mcp-modern-test","version":"0.1"},"io.modelcontextprotocol/clientCapabilities":{}}'
  local discover="{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"server/discover\",\"params\":{\"_meta\":$legacy_meta}}"
  RUST_LOG="${RUST_LOG:-info},ida_mcp=info" "$BIN" serve-http --bind "127.0.0.1:$pooled_port" --max-workers 2 \
    --allow-origin "http://localhost,http://127.0.0.1" >"$log" 2>&1 &
  server_pid=$!
  wait_http "$url" "$discover" "2025-11-25" "server/discover" \
    "MCP pooled HTTP server listening on http://127.0.0.1:$pooled_port"

  local discover_response
  discover_response="$(extract_http_json "$tmpdir/http-ready.out")"
  assert_json "pooled discover must advertise legacy versions only" "$discover_response" \
    '(.result.supportedVersions | index("2025-11-25") != null)
     and (.result.supportedVersions | index("2026-07-28") == null)'

  local list="{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"tools/list\",\"params\":{\"_meta\":$META}}"
  local status
  status="$(curl -sS -o "$tmpdir/pooled-reject.out" -w '%{http_code}' \
    "${http_headers[@]}" -H "MCP-Protocol-Version: 2026-07-28" \
    -H "Mcp-Method: tools/list" -d "$list" "$url")"
  if [[ "$status" != "400" ]]; then
    echo "pooled HTTP accepted MCP 2026 request (status $status)" >&2
    cat "$tmpdir/pooled-reject.out" >&2
    exit 1
  fi
  assert_json "pooled 2026 rejection must use -32022" \
    "$(cat "$tmpdir/pooled-reject.out")" \
    '.error.code == -32022'

  # A legacy protocol version with the full 2026 inline-metadata key set is
  # routed sessionless by rmcp, which would mint a fresh worker lease per
  # request. The server must reject the tool call instead of leasing.
  local inline_call="{\"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"tools/call\",\"params\":{\"_meta\":$legacy_meta,\"name\":\"tool_catalog\",\"arguments\":{\"limit\":1}}}"
  curl -sS "${http_headers[@]}" -H "MCP-Protocol-Version: 2025-11-25" \
    -H "Mcp-Method: tools/call" -H "Mcp-Name: tool_catalog" \
    -d "$inline_call" "$url" >"$tmpdir/pooled-inline.out"
  assert_json "pooled sessionless legacy-version tool call must be rejected" \
    "$(extract_http_json "$tmpdir/pooled-inline.out")" \
    '.error.code == -32602
     and (.error.message | contains("legacy initialize lifecycle"))'

  cleanup_server
  echo "   pooled HTTP advertised legacy-only and rejected sessionless requests"
}

echo "🧪 Running MCP 2026 lifecycle test..."
run_stdio_modern
run_stdio_legacy_owner
run_http_modern
run_pooled_boundary
echo "✅ MCP 2026 lifecycle test passed"
