#!/usr/bin/env bash
# Exercise explicit multi-database routing through one headless stdio server.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-${SERVER_BIN:-../target/debug/ida-mcp}}"
FIXTURE="${WORKSPACE_FIXTURE:-fixtures/mini.i64}"
RAW_FIXTURE="${WORKSPACE_RAW_FIXTURE:-${FIXTURE%.i64}}"

[[ -x "$BIN" ]] || { echo "missing server binary: $BIN" >&2; exit 1; }
[[ -f "$FIXTURE" ]] || { echo "missing workspace fixture: $FIXTURE" >&2; exit 1; }
[[ -f "$RAW_FIXTURE" ]] || { echo "missing workspace raw fixture: $RAW_FIXTURE" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required for workspace test" >&2; exit 1; }

tmpdir="$(mktemp -d)"
fifo="$tmpdir/in.fifo"
stdout_log="$tmpdir/server.out"
stderr_log="$tmpdir/server.err"
server_pid=""

cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "${server_pid:-}" ]]; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.2
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      kill "$server_pid" 2>/dev/null || true
      sleep 0.2
    fi
    if kill -0 "$server_pid" 2>/dev/null; then
      kill -9 "$server_pid" 2>/dev/null || true
    fi
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

cp "$FIXTURE" "$tmpdir/first.i64"
cp "$FIXTURE" "$tmpdir/second.i64"
mkfifo "$fifo"
RUST_LOG="${RUST_LOG:-ida_mcp=info}" "$BIN" --workspace --workspace-max-workers 2 \
  <"$fifo" >"$stdout_log" 2>"$stderr_log" &
server_pid=$!
exec 3>"$fifo"

send() { printf '%s\n' "$1" >&3; }

wait_response() {
  local id="$1" timeout="${2:-90}" elapsed=0 line
  local count_file="$tmpdir/response-$id.count" consumed=0 wanted
  if [[ -f "$count_file" ]]; then
    read -r consumed <"$count_file" || consumed=0
  fi
  wanted=$((consumed + 1))
  while (( elapsed < timeout * 10 )); do
    # JSON-RPC permits sequential ID reuse. Consume the next matching
    # response instead of returning a stale match from the append-only log.
    line="$(jq -cR "fromjson? | select(.id == $id and (has(\"result\") or has(\"error\")))" \
      "$stdout_log" 2>/dev/null | sed -n "${wanted}p" || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$wanted" >"$count_file"
      printf '%s\n' "$line"
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "workspace server exited while waiting for response id=$id" >&2
      cat "$stdout_log" >&2
      cat "$stderr_log" >&2
      return 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done
  echo "timed out waiting for workspace response id=$id" >&2
  cat "$stdout_log" >&2
  cat "$stderr_log" >&2
  return 1
}

assert_ok() {
  local label="$1" response="$2"
  if ! jq -e '.result.isError == false and (has("error") | not)' \
      >/dev/null 2>&1 <<<"$response"; then
    echo "FAIL: $label" >&2
    jq . <<<"$response" >&2 || printf '%s\n' "$response" >&2
    exit 1
  fi
}

result_text() {
  jq -r '.result.content[0].text // empty'
}

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"workspace-test","version":"0.1"},"capabilities":{}}}'
initialize="$(wait_response 1 30)"
jq -e '.result.protocolVersion == "2025-11-25"' >/dev/null <<<"$initialize"
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
tools="$(wait_response 2 30)"
jq -e '
  any(.result.tools[]; .name == "open_idb"
    and (.inputSchema.properties.database_id? == null))
  and any(.result.tools[]; .name == "list_functions"
    and (.inputSchema.required | index("database_id") != null)
    and .inputSchema.properties.database_id.format == "uuid")
' >/dev/null <<<"$tools"
echo "   workspace schemas distinguish allocation from database-scoped calls"

send '{"jsonrpc":"2.0","id":24,"method":"tools/call","params":{"name":"tool_help","arguments":{"name":"disasm"}}}'
help_response="$(wait_response 24 30)"
assert_ok "workspace tool_help example" "$help_response"
jq -e '
  .result.content[0].text | fromjson
  | (.parameters.required | index("database_id") != null)
    and ((.example | fromjson).database_id == "00000000-0000-0000-0000-000000000000")
' >/dev/null <<<"$help_response"
echo "   workspace help examples include the required database handle"

send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":1}}}'
missing_id="$(wait_response 3 30)"
jq -e '.error.code == -32602 and (.error.message | contains("requires database_id"))' \
  >/dev/null <<<"$missing_id"

open_first="$(jq -cn --arg path "$tmpdir/first.i64" \
  '{jsonrpc:"2.0",id:4,method:"tools/call",params:{name:"open_idb",arguments:{path:$path}}}')"
send "$open_first"
first_response="$(wait_response 4 120)"
assert_ok "open first database" "$first_response"
first_text="$(result_text <<<"$first_response")"
first_id="$(jq -r '.database_id // empty' <<<"$first_text")"
jq -e '.close_token? == null and (.close_hint | contains("workspace mode"))' \
  >/dev/null <<<"$first_text"

open_second="$(jq -cn --arg path "$tmpdir/second.i64" \
  '{jsonrpc:"2.0",id:5,method:"tools/call",params:{name:"open_idb",arguments:{path:$path}}}')"
send "$open_second"
second_response="$(wait_response 5 120)"
assert_ok "open second database" "$second_response"
second_id="$(result_text <<<"$second_response" | jq -r '.database_id // empty')"

[[ -n "$first_id" && -n "$second_id" && "$first_id" != "$second_id" ]] || {
  echo "FAIL: workspace opens did not return distinct database IDs" >&2
  exit 1
}
echo "   two databases opened with distinct UUID handles"

rename_first="$(jq -cn --arg id "$first_id" \
  '{jsonrpc:"2.0",id:6,method:"tools/call",params:{name:"rename",arguments:{database_id:$id,current_name:"interesting_function",name:"workspace_first_canary",flags:0}}}')"
send "$rename_first"
assert_ok "rename in first database" "$(wait_response 6 30)"

resolve_first="$(jq -cn --arg id "$first_id" \
  '{jsonrpc:"2.0",id:7,method:"tools/call",params:{name:"resolve_function",arguments:{database_id:$id,name:"workspace_first_canary"}}}')"
send "$resolve_first"
first_resolve_response="$(wait_response 7 30)"
assert_ok "resolve canary in first database" "$first_resolve_response"
first_address="$(result_text <<<"$first_resolve_response" | jq -r '.address')"

resolve_second="$(jq -cn --arg id "$second_id" \
  '{jsonrpc:"2.0",id:8,method:"tools/call",params:{name:"resolve_function",arguments:{database_id:$id,name:"interesting_function"}}}')"
send "$resolve_second"
second_resolve_response="$(wait_response 8 30)"
assert_ok "resolve original in second database" "$second_resolve_response"
jq -e '.name == "interesting_function"' >/dev/null \
  <<<"$(result_text <<<"$second_resolve_response")"
echo "   mutation stayed isolated to its selected database"

range_end="$(printf '0x%x' "$((first_address + 64))")"
render_request="$(jq -cn --arg id "$first_id" --arg start "$first_address" --arg end "$range_end" \
  '{jsonrpc:"2.0",id:20,method:"tools/call",params:{name:"render_range",arguments:{database_id:$id,start:$start,end:$end,max_lines:1}}}')"
send "$render_request"
render_response="$(wait_response 20 30)"
assert_ok "render bounded IDA range" "$render_response"
jq -e '
  .line_count == 1 and .truncated == true
  and (.next_address | type == "string")
  and (.lines | length == 1)
  and (.text | length > 0)
' >/dev/null <<<"$(result_text <<<"$render_response")"
echo "   IDA-style range rendering returned a truthful continuation"

render_full_request="$(jq -cn --arg id "$first_id" --arg start "$first_address" --arg end "$range_end" \
  '{jsonrpc:"2.0",id:24,method:"tools/call",params:{name:"render_range",arguments:{database_id:$id,start:$start,end:$end,max_lines:4096}}}')"
send "$render_full_request"
render_full_response="$(wait_response 24 30)"
assert_ok "render complete IDA range" "$render_full_response"
jq -e --arg end "$range_end" '
  .truncated == false
  and .next_address == null
  and .rendered_until == $end
' >/dev/null <<<"$(result_text <<<"$render_full_response")"
echo "   complete IDA-style range reports the requested half-open end"

callgraph_request="$(jq -cn --arg id "$first_id" --arg root "$first_address" \
  '{jsonrpc:"2.0",id:21,method:"tools/call",params:{name:"callgraph",arguments:{database_id:$id,roots:$root,direction:"both",max_depth:2,max_nodes:32}}}')"
send "$callgraph_request"
callgraph_response="$(wait_response 21 30)"
assert_ok "bidirectional callgraph" "$callgraph_response"
jq -e '
  .direction == "both"
  and .truncated == false
  and (.nodes | length >= 2)
  and (.edges | length >= 1)
  and all(.edges[]; (.from | startswith("0x")) and (.to | startswith("0x")))
' >/dev/null <<<"$(result_text <<<"$callgraph_response")"
echo "   caller/callee traversal returned normalized caller-to-callee edges"

capped_callgraph_request="$(jq -cn --arg id "$first_id" --arg root "$first_address" \
  '{jsonrpc:"2.0",id:25,method:"tools/call",params:{name:"callgraph",arguments:{database_id:$id,roots:$root,direction:"both",max_depth:2,max_nodes:1}}}')"
send "$capped_callgraph_request"
capped_callgraph_response="$(wait_response 25 30)"
assert_ok "capped bidirectional callgraph" "$capped_callgraph_response"
jq -e '
  .truncated == true
  and (.nodes | length == 1)
  and (.edges | length == 0)
' >/dev/null <<<"$(result_text <<<"$capped_callgraph_response")"
echo "   capped callgraph reports truncation instead of looking complete"

patch_request="$(jq -cn --arg id "$first_id" --arg address "$first_address" \
  '{jsonrpc:"2.0",id:22,method:"tools/call",params:{name:"patch",arguments:{database_id:$id,address:$address,bytes:"de ad"}}}')"
send "$patch_request"
assert_ok "patch two contiguous bytes" "$(wait_response 22 30)"

patch_end="$(printf '0x%x' "$((first_address + 2))")"
patches_request="$(jq -cn --arg id "$first_id" --arg start "$first_address" --arg end "$patch_end" \
  '{jsonrpc:"2.0",id:23,method:"tools/call",params:{name:"list_patches",arguments:{database_id:$id,start:$start,end:$end,offset:0,limit:1}}}')"
send "$patches_request"
patches_response="$(wait_response 23 30)"
assert_ok "list coalesced patches" "$patches_response"
jq -e '
  .total == 1
  and (.ranges | length == 1)
  and .ranges[0].length == 2
  and .ranges[0].patched_hex == "de ad"
  and .next_offset == null
' >/dev/null <<<"$(result_text <<<"$patches_response")"
echo "   contiguous native patch records coalesced and paginated"

runtime_with_id="$(jq -cn --arg id "$first_id" \
  '{jsonrpc:"2.0",id:9,method:"tools/call",params:{name:"tool_catalog",arguments:{database_id:$id,query:"disassembly"}}}')"
send "$runtime_with_id"
jq -e '.error.code == -32602 and (.error.message | contains("runtime-scoped"))' \
  >/dev/null <<<"$(wait_response 9 30)"

# Handle discovery: both open databases must be re-addressable from
# list_databases alone, which is how an agent recovers after a lost response.
send '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"list_databases","arguments":{}}}'
list_databases_response="$(wait_response 20 30)"
assert_ok "list workspace databases" "$list_databases_response"
list_databases_text="$(result_text <<<"$list_databases_response")"
jq -e --arg first "$first_id" --arg second "$second_id" '
  .count >= 2
  and ([.databases[].database_id] | index($first) != null and index($second) != null)
  and (.databases[] | select(.database_id == $first) | .state == "open" and (.path | length) > 0)
' >/dev/null <<<"$list_databases_text" || {
  echo "FAIL: list_databases did not report both open handles with paths" >&2
  printf '%s\n' "$list_databases_text" >&2
  exit 1
}
echo "   list_databases re-addressed both open handles"

close_first="$(jq -cn --arg id "$first_id" \
  '{jsonrpc:"2.0",id:10,method:"tools/call",params:{name:"close_idb",arguments:{database_id:$id}}}')"
send "$close_first"
assert_ok "close first database" "$(wait_response 10 30)"

stale_first="$(jq -cn --arg id "$first_id" \
  '{jsonrpc:"2.0",id:11,method:"tools/call",params:{name:"list_functions",arguments:{database_id:$id,limit:1}}}')"
send "$stale_first"
jq -e '.error.code == -32602 and (.error.message | contains("unknown or expired"))' \
  >/dev/null <<<"$(wait_response 11 30)"

# A closed handle disappears from discovery too.
send '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"list_databases","arguments":{}}}'
after_close_text="$(result_text <<<"$(wait_response 21 30)")"
jq -e --arg first "$first_id" --arg second "$second_id" '
  ([.databases[].database_id] | index($first) == null and index($second) != null)
' >/dev/null <<<"$after_close_text" || {
  echo "FAIL: list_databases still reports the closed handle" >&2
  printf '%s\n' "$after_close_text" >&2
  exit 1
}

list_second="$(jq -cn --arg id "$second_id" \
  '{jsonrpc:"2.0",id:12,method:"tools/call",params:{name:"list_functions",arguments:{database_id:$id,limit:1}}}')"
send "$list_second"
assert_ok "second database survives first close" "$(wait_response 12 30)"

close_second="$(jq -cn --arg id "$second_id" \
  '{jsonrpc:"2.0",id:13,method:"tools/call",params:{name:"close_idb",arguments:{database_id:$id}}}')"
send "$close_second"
assert_ok "close second database" "$(wait_response 13 30)"

echo "   close invalidated only the selected handle"

# The fixture's sibling mini.i64 deliberately exists. With an explicit output,
# the parent and pooled child must both precheck that requested output rather
# than falsely rejecting the open because the unrelated sibling exists.
raw_output="$tmpdir/explicit-raw-output.i64"
raw_open="$(jq -cn --arg path "$RAW_FIXTURE" --arg output "$raw_output" \
  '{jsonrpc:"2.0",id:14,method:"tools/call",params:{name:"open_idb",arguments:{path:$path,idb_out:$output,processor:"arm:ARMv8-A",auto_analyse:false}}}')"
send "$raw_open"
raw_response="$(wait_response 14 120)"
assert_ok "workspace raw open with explicit output" "$raw_response"
raw_text="$(result_text <<<"$raw_response")"
raw_id="$(jq -r '.database_id // empty' <<<"$raw_text")"
jq -e --arg output "$raw_output" '.path == $output' >/dev/null <<<"$raw_text"
[[ -n "$raw_id" ]] || { echo "raw workspace open did not return a database_id" >&2; exit 1; }

close_raw="$(jq -cn --arg id "$raw_id" \
  '{jsonrpc:"2.0",id:15,method:"tools/call",params:{name:"close_idb",arguments:{database_id:$id}}}')"
send "$close_raw"
assert_ok "close raw workspace database" "$(wait_response 15 30)"
[[ -f "$raw_output" ]] || { echo "explicit raw output was not materialized" >&2; exit 1; }
echo "   pooled raw-target precheck honored the explicit output path"

echo "workspace stdio integration passed"
