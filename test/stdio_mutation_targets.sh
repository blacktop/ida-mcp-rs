#!/usr/bin/env bash
# Mutating tools take an exact target: one address, or one name that matches
# a symbol literally and case-sensitively. A near miss is refused with
# suggestions and changes nothing; results report the resolved target. The
# workspace case checks that the target record survives the pooled child's
# typed stack result.
# The jq filters passed to check() use $vars bound by jq --arg, not shell expansion.
# shellcheck disable=SC2016
set -euo pipefail

BIN="${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-mcp}}"
NOP="1f 20 03 d5"

command -v jq >/dev/null 2>&1 || {
  echo "jq is required for the mutation target test (brew install jq)" >&2
  exit 1
}
[[ -x "$BIN" ]] || {
  echo "missing server binary: $BIN" >&2
  exit 1
}

server_pid=""
tmpdir=""

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
}

trap cleanup_case EXIT INT TERM

send() {
  echo "$1" >&3
}

dump_server_logs() {
  echo "── server stdout ──" >&2
  cat "$log" >&2 || true
  echo "── server stderr ──" >&2
  tail -40 "$errlog" >&2 || true
}

wait_response() {
  local id="$1" timeout="${2:-60}" elapsed=0 line
  while [[ "$elapsed" -lt "$timeout" ]]; do
    line="$(jq -cR "fromjson? | select(.id == $id and (has(\"result\") or has(\"error\")))" \
      "$log" 2>/dev/null | head -1 || true)"
    if [[ -n "$line" ]]; then
      echo "$line"
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "server exited while waiting for response $id" >&2
      dump_server_logs
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "timeout waiting for response $id" >&2
  dump_server_logs
  return 1
}

start_server() {
  tmpdir="$(mktemp -d)"
  fifo_in="$tmpdir/in.fifo"
  log="$tmpdir/server.log"
  errlog="$tmpdir/server.err.log"
  mkfifo "$fifo_in"
  : >"$log"
  echo 10 >"$tmpdir/next-id"
  RUST_LOG="${RUST_LOG:-ida_mcp=trace}" "$BIN" "$@" <"$fifo_in" >"$log" 2>"$errlog" &
  server_pid=$!
  exec 3>"$fifo_in"
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"mutation-targets","version":"0.1"},"capabilities":{}}}'
  wait_response 1 30 >/dev/null
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
}

# call <tool> <arguments-json>: print the response line. Callers run it in
# command substitutions, so the request id counter lives in a file.
call() {
  local id
  id=$(($(cat "$tmpdir/next-id") + 1))
  echo "$id" >"$tmpdir/next-id"
  send "$(jq -nc --argjson id "$id" --arg name "$1" --argjson args "$2" \
    '{jsonrpc:"2.0", id:$id, method:"tools/call", params:{name:$name, arguments:$args}}')"
  wait_response "$id" 300
}

tool_text() {
  jq -r '.result.content[0].text // empty'
}

# ok <label> <tool> <arguments-json>: print the result text or fail.
ok() {
  local response
  response="$(call "$2" "$3")"
  if ! jq -e '.result.isError != true and (has("error") | not)' >/dev/null <<<"$response"; then
    echo "❌ $1: unexpected error" >&2
    jq . <<<"$response" >&2 || echo "$response" >&2
    exit 1
  fi
  tool_text <<<"$response"
}

# refused <label> <needle> <tool> <arguments-json>
refused() {
  local response
  response="$(call "$3" "$4")"
  if ! jq -e --arg needle "$2" \
    '.result.isError == true and (.result.content[0].text | contains($needle))' \
    >/dev/null <<<"$response"; then
    echo "❌ $1: expected a tool error containing: $2" >&2
    jq . <<<"$response" >&2 || echo "$response" >&2
    exit 1
  fi
}

check() {
  local label="$1" filter="$2" json="$3"
  shift 3
  if ! jq -e "$@" "$filter" >/dev/null <<<"$json"; then
    echo "❌ $label: $filter" >&2
    jq . <<<"$json" >&2 || echo "$json" >&2
    exit 1
  fi
}

hex_add() {
  printf '0x%x' $(($1 + $2))
}

bytes_at() {
  ok "read $1" get_bytes "$(jq -nc --arg a "$1" '{address:$a, size:16}')" | jq -r '.bytes'
}

# Exact function names differ by format (Mach-O "_main", ELF "main"), so
# discover them; tests must never rely on the loose matching they replace.
function_named() {
  jq -r --arg pattern "$2" '[.functions[] | select(.name | test($pattern))][0] // empty' <<<"$1"
}

case_local() {
  start_server
  echo "── single worker: exact targets on a raw open ──"
  # No sibling dSYM, so the loader's symbol names stay as-is.
  cp fixtures/mini "$tmpdir/mini"
  mkdir "$tmpdir/out"
  local database="$tmpdir/out/mini.i64"
  ok "open" open_idb "$(jq -nc --arg p "$tmpdir/mini" --arg o "$database" \
    '{path:$p, idb_out:$o, auto_analyse:true, timeout_secs:300}')" >/dev/null

  local functions main helper main_name main_addr helper_name helper_addr query
  functions="$(ok "list functions" list_functions '{"limit":1000}')"
  main="$(function_named "$functions" '^_?main$')"
  helper="$(function_named "$functions" '^_?interesting_function$')"
  [[ -n "$main" && -n "$helper" ]] || {
    echo "❌ fixture functions not found" >&2
    exit 1
  }
  main_name="$(jq -r .name <<<"$main")"
  main_addr="$(jq -r .address <<<"$main")"
  helper_name="$(jq -r .name <<<"$helper")"
  helper_addr="$(jq -r .address <<<"$helper")"
  if [[ "$main_name" == "_main" ]]; then query="main"; else query="_main"; fi

  # The rejected query must name nothing: no function and no global.
  check "no function is named $query" '[.functions[] | select(.name == $q)] | length == 0' \
    "$functions" --arg q "$query"
  check "no global is named $query" '[.globals[] | select(.name == $q)] | length == 0' \
    "$(ok "list globals" list_globals "$(jq -nc --arg q "$query" '{query:$q, limit:1000}')")" \
    --arg q "$query"
  echo "   \"$query\" names nothing; $main_name is at $main_addr"

  local renamed
  renamed="$(ok "rename by exact name" rename "$(jq -nc --arg n "$helper_name" \
    '{current_name:$n, name:"domain_check"}')")"
  check "rename reports its target" '
    .name == "domain_check" and .target.selector == "name" and .target.symbol == $old
    and .target.base == $addr and .target.address == $addr and .target.database == $db' \
    "$renamed" --arg old "$helper_name" --arg addr "$helper_addr" --arg db "$database"
  echo "   exact rename: $helper_name -> domain_check at $helper_addr"

  local main_bytes helper_bytes
  main_bytes="$(bytes_at "$main_addr")"
  helper_bytes="$(bytes_at "$helper_addr")"

  local error
  error="$(call patch "$(jq -nc --arg q "$query" --arg b "$NOP" '{target_name:$q, bytes:$b}')" |
    jq -r 'select(.result.isError == true) | .result.content[0].text')"
  [[ "$error" == *"no symbol is named exactly \"$query\""* ]] || {
    echo "❌ near-miss patch was not refused: $error" >&2
    exit 1
  }
  [[ "$error" == *"\"$main_name\" at $main_addr"* ]] || {
    echo "❌ suggestions omit $main_name at $main_addr: $error" >&2
    exit 1
  }
  if [[ "$query" == "main" && "$error" != *"\"domain_check\" at $helper_addr"* ]]; then
    echo "❌ suggestions omit the substring candidate domain_check: $error" >&2
    exit 1
  fi
  refused "both selectors" "not both" patch "$(jq -nc --arg a "$main_addr" --arg n "$main_name" \
    --arg b "$NOP" '{address:$a, target_name:$n, bytes:$b}')"
  refused "several addresses" "exactly one address" patch "$(jq -nc --arg a "$main_addr" \
    --arg h "$helper_addr" --arg b "$NOP" '{address:[$a, $h], bytes:$b}')"
  [[ "$(bytes_at "$main_addr")" == "$main_bytes" && "$(bytes_at "$helper_addr")" == "$helper_bytes" ]] || {
    echo "❌ a refused patch changed bytes" >&2
    exit 1
  }
  echo "   refused: near miss, both selectors, several addresses; bytes unchanged"

  local patched
  patched="$(ok "patch by address" patch "$(jq -nc --arg a "$helper_addr" --arg b "$NOP" \
    '{address:$a, bytes:$b}')")"
  check "address patch reports the listed name" '
    .target.selector == "address" and .target.symbol == "domain_check" and .target.base == $addr
    and .target.requested_address == $addr and .target.address == $addr' "$patched" --arg addr "$helper_addr"
  [[ "$(bytes_at "$helper_addr")" == 1f2003d5* && "$(bytes_at "$main_addr")" == "$main_bytes" ]] || {
    echo "❌ address patch did not change exactly its target" >&2
    exit 1
  }
  echo "   address patch changed only $helper_addr"

  local inner commented
  inner="$(hex_add "$helper_addr" 4)"
  commented="$(ok "comment an unnamed address" set_comments "$(jq -nc --arg a "$inner" \
    '{address:$a, comment:"inside"}')")"
  check "unnamed address has a null symbol" '.target.symbol == null and .target.base == $a' \
    "$commented" --arg a "$inner"
  commented="$(ok "comment name+offset" set_comments "$(jq -nc --arg n "$main_name" \
    '{target_name:$n, offset:8, comment:"main+8"}')")"
  check "offset moves the address, not the base" '
    .target.symbol == $n and .target.base == $base and .target.requested_address == $at
    and .target.address == $at and .address == $at' \
    "$commented" --arg n "$main_name" --arg base "$main_addr" --arg at "$(hex_add "$main_addr" 8)"
  echo "   unnamed address reports null; offset kept separate from base"

  local stack
  stack="$(ok "declare stack variable" declare_stack "$(jq -nc --arg n "$main_name" \
    '{target_name:$n, offset:-8, var_name:"probe", decl:"int probe;"}')")"
  check "stack offset is not a target offset" '
    .target.symbol == $n and .target.base == $addr and .target.address == $addr
    and .function == $addr' "$stack" --arg n "$main_name" --arg addr "$main_addr"
  refused "stack near miss" "no symbol is named exactly \"$query\"" delete_stack \
    "$(jq -nc --arg q "$query" '{target_name:$q, var_name:"probe"}')"
  echo "   stack tools resolve the function exactly"
  cleanup_case
}

case_workspace() {
  start_server --workspace --workspace-max-workers 2
  echo "── workspace: target survives the pooled child's typed stack result ──"
  cp fixtures/mini.i64 "$tmpdir/ws.i64"
  local opened id functions main main_name main_addr query stack
  opened="$(ok "workspace open" open_idb "$(jq -nc --arg p "$tmpdir/ws.i64" '{path:$p}')")"
  id="$(jq -r '.database_id' <<<"$opened")"
  functions="$(ok "workspace list" list_functions "$(jq -nc --arg id "$id" \
    '{database_id:$id, limit:1000}')")"
  main="$(function_named "$functions" '^_?main$')"
  main_name="$(jq -r .name <<<"$main")"
  main_addr="$(jq -r .address <<<"$main")"
  if [[ "$main_name" == "_main" ]]; then query="main"; else query="_main"; fi

  stack="$(ok "workspace declare_stack" declare_stack "$(jq -nc --arg id "$id" --arg n "$main_name" \
    '{database_id:$id, target_name:$n, offset:-8, var_name:"probe", decl:"int probe;"}')")"
  check "pooled stack result keeps its target" '
    .target.selector == "name" and .target.symbol == $n and .target.base == $addr
    and (.target.database | endswith("ws.i64"))' "$stack" --arg n "$main_name" --arg addr "$main_addr"
  refused "workspace near miss" "no symbol is named exactly \"$query\"" patch \
    "$(jq -nc --arg id "$id" --arg q "$query" --arg b "$NOP" '{database_id:$id, target_name:$q, bytes:$b}')"
  ok "workspace close" close_idb "$(jq -nc --arg id "$id" '{database_id:$id}')" >/dev/null
  echo "   pooled declare_stack reports its target; near miss refused through the child"
  cleanup_case
}

case_local
case_workspace

echo "✅ Mutation target test passed"
