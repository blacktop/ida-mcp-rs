#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8767}"
BIN="${MCP_HTTP_BIN:-./target/release/ida-mcp}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
IDB_PATH="${IDB_PATH:-fixtures/mini.i64}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
# Work on a private copy: the script edits, saves, and rebases the database,
# and a graceful shutdown would persist a half-finished run into the fixture.
cp "$IDB_PATH" "$tmpdir/$(basename "$IDB_PATH")"
IDB_PATH="$tmpdir/$(basename "$IDB_PATH")"
headers_file="$tmpdir/headers.log"
body_file="$tmpdir/body.log"
server_log="$tmpdir/server.log"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    # Let the server close and pack its database before its directory goes;
    # a graceful shutdown is bounded, so reap with a kill if it overruns.
    kill "$server_pid" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.5
    done
    kill -9 "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

"$BIN" serve-http --bind "127.0.0.1:$PORT" --allow-origin "http://localhost,http://127.0.0.1" >"$server_log" 2>&1 &
server_pid=$!

init_payload='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"script-test","version":"0.1"},"capabilities":{}}}'

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
  curl -sS \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Origin: $ORIGIN" \
    -H "Mcp-Session-Id: $session_id" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${request_id},\"method\":\"tools/call\",\"params\":{\"name\":\"${tool_name}\",\"arguments\":${arguments_json}}}" \
    "http://127.0.0.1:$PORT/"
}

curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  "http://127.0.0.1:$PORT/" >/dev/null

open_resp="$(call_tool 2 open_idb "{\"path\":\"$IDB_PATH\"}")"
echo "$open_resp" | grep -q "function_count" || {
  echo "open_idb failed" >&2
  echo "$open_resp" >&2
  [[ -s "$server_log" ]] && cat "$server_log" >&2
  exit 1
}

inline_resp="$(call_tool 3 run_script "{\"code\":\"import ida_funcs\\nprint(f'inline_simple_ok function_count={ida_funcs.get_func_qty()}')\"}")"
echo "$inline_resp" | grep -q "inline_simple_ok function_count=" || {
  echo "inline script output missing" >&2
  echo "$inline_resp" >&2
  exit 1
}

file_resp="$(call_tool 4 run_script "{\"file\":\"fixtures/test_analysis.py\"}")"
echo "$file_resp" | grep -q "total_functions=" || {
  echo "file-based script output missing" >&2
  echo "$file_resp" >&2
  exit 1
}

complex_resp="$(call_tool 5 run_script "{\"code\":\"import idautils\\nimport ida_funcs\\n\\ndef _func_info(ea):\\n    f = ida_funcs.get_func(ea)\\n    if not f:\\n        return None\\n    return (ida_funcs.get_func_name(ea), f.size(), ea)\\n\\ninfos = [_func_info(ea) for ea in idautils.Functions()]\\ninfos = [x for x in infos if x is not None]\\ninfos.sort(key=lambda t: t[1], reverse=True)\\nprint(f'complex_ok total={len(infos)} top={infos[:3]}')\"}")"
echo "$complex_resp" | grep -q "complex_ok total=" || {
  echo "complex inline script output missing" >&2
  echo "$complex_resp" >&2
  exit 1
}

syntax_resp="$(call_tool 6 run_script "{\"code\":\"def broken(:\\n    return 1\"}")"
echo "$syntax_resp" | grep -q '"isError":true' || {
  echo "syntax error response was not marked as MCP error" >&2
  echo "$syntax_resp" >&2
  exit 1
}
echo "$syntax_resp" | grep -q 'SyntaxError' || {
  echo "syntax error details missing" >&2
  echo "$syntax_resp" >&2
  exit 1
}
echo "$syntax_resp" | grep -q 'IDAPython script execution failed' || {
  echo "script failure summary missing" >&2
  echo "$syntax_resp" >&2
  exit 1
}

define_resp="$(call_tool 8 run_script "{\"code\":\"import ida_funcs\\npersisted_count = ida_funcs.get_func_qty()\"}")"
echo "$define_resp" | grep -q 'success\\": true' || {
  echo "script defining a global failed" >&2
  echo "$define_resp" >&2
  exit 1
}

result_resp="$(call_tool 9 run_script "{\"code\":\"{'count': persisted_count, 'kind': 'trailing'}\"}")"
echo "$result_resp" | grep -q 'kind\\": \\"trailing' || {
  echo "trailing expression was not returned as result, or globals did not persist" >&2
  echo "$result_resp" >&2
  exit 1
}

none_resp="$(call_tool 10 run_script "{\"code\":\"print('no_result_ok')\"}")"
if echo "$none_resp" | grep -q '\\"result\\"'; then
  echo "a None trailing expression must not produce a result field" >&2
  echo "$none_resp" >&2
  exit 1
fi

big_resp="$(call_tool 13 run_script "{\"code\":\"{'payload': 'x' * (1024 * 1024)}\"}")"
echo "$big_resp" | grep -q '"isError":true' || {
  echo "an oversized result must fail instead of being truncated" >&2
  echo "$big_resp" | cut -c1-400 >&2
  exit 1
}
echo "$big_resp" | grep -q 'over the 1 MiB limit' || {
  echo "oversized result error does not explain the limit" >&2
  echo "$big_resp" | cut -c1-400 >&2
  exit 1
}

nan_resp="$(call_tool 14 run_script "{\"code\":\"{'value': float('nan')}\"}")"
echo "$nan_resp" | grep -q 'result_is_repr\\": true' || {
  echo "a non-finite result must be flagged as a repr() fallback" >&2
  echo "$nan_resp" >&2
  exit 1
}

for big in "2**64 + 1" "-(2**63) - 1" "10**400" "[1, {'nested': 2**70}]"; do
  big_int_resp="$(call_tool 16 run_script "{\"code\":\"$big\"}")"
  echo "$big_int_resp" | grep -q 'result_is_repr\\": true' || {
    echo "integer outside the 64-bit range must use the repr() fallback: $big" >&2
    echo "$big_int_resp" >&2
    exit 1
  }
done
exact_resp="$(call_tool 17 run_script "{\"code\":\"[2**63, -(2**63), 2**64 - 1]\"}")"
echo "$exact_resp" | grep -q '9223372036854775808' || {
  echo "64-bit integers must round-trip exactly" >&2
  echo "$exact_resp" >&2
  exit 1
}
if echo "$exact_resp" | grep -q 'result_is_repr'; then
  echo "64-bit integers must not use the repr() fallback" >&2
  echo "$exact_resp" >&2
  exit 1
fi

plain_resp="$(call_tool 15 run_script "{\"code\":\"[1, 2, 3]\"}")"
if echo "$plain_resp" | grep -q 'result_is_repr'; then
  echo "a JSON-serializable result must not be flagged as repr()" >&2
  echo "$plain_resp" >&2
  exit 1
fi

# Responses may be SSE-framed; take the JSON payload line.
tool_text() { sed -n 's/^data: //p; /^{/p' | head -1 | jq -r '.result.content[0].text'; }
reported_base="$(call_tool 18 idb_meta "{}" | tool_text | jq -r '.image_base')"
ida_base="$(call_tool 19 run_script "{\"code\":\"import ida_nalt\\nhex(ida_nalt.get_imagebase())\"}" | tool_text | jq -r '.result')"
[[ -n "$reported_base" && "$reported_base" == "$ida_base" ]] || {
  echo "idb_meta.image_base ($reported_base) does not match ida_nalt.get_imagebase() ($ida_base)" >&2
  exit 1
}
rebased="$(call_tool 20 run_script "{\"code\":\"import ida_segment, ida_nalt\\nida_segment.rebase_program(0x10000, ida_segment.MSF_FIXONCE)\\nhex(ida_nalt.get_imagebase())\"}" | tool_text | jq -r '.result')"
after_rebase="$(call_tool 21 idb_meta "{}" | tool_text | jq -r '.image_base')"
[[ "$rebased" != "$ida_base" && "$after_rebase" == "$rebased" ]] || {
  echo "idb_meta.image_base did not follow the rebase: before=$ida_base ida=$rebased reported=$after_rebase" >&2
  exit 1
}
call_tool 22 run_script "{\"code\":\"import ida_segment\\nida_segment.rebase_program(-0x10000, ida_segment.MSF_FIXONCE)\"}" >/dev/null

save_resp="$(call_tool 11 save_idb "{}")"
echo "$save_resp" | grep -q 'saved\\": true' || {
  echo "save_idb failed" >&2
  echo "$save_resp" >&2
  exit 1
}

after_save_resp="$(call_tool 12 run_script "{\"code\":\"persisted_count\"}")"
echo "$after_save_resp" | grep -q '\\"result\\"' || {
  echo "database was not usable after save_idb" >&2
  echo "$after_save_resp" >&2
  exit 1
}

close_token="$(echo "$open_resp" | sed -n 's/.*\\\"close_token\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\\\"]*\\)\\\".*/\\1/p')"
if [[ -n "$close_token" ]]; then
  close_args="{\"close_token\":\"$close_token\"}"
else
  close_args="{}"
fi

call_tool 7 close_idb "$close_args" >/dev/null

echo "HTTP script integration test passed"
