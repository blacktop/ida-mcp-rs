#!/usr/bin/env bash
# Verify open_idb behavior for raw inputs when a generated .i64 already exists.
#
# Nine phases, with all fixtures isolated in one temporary directory. The
# first three establish the core rebuild contract:
#   1. Open raw, rename interesting_function -> $CANARY, close -> creates .i64
#      with the rename packed into it.
#   2. Re-open the SAME raw path with no rebuild flag. The handler must reuse
#      the existing .i64 (proven by the "Reusing SHA-256-verified IDA database for raw
#      input" log line) and the renamed function must still resolve.
#   3. Re-open raw with rebuild=true. The handler must overwrite the .i64
#      (proven by the "Rebuilding raw input and overwriting provenance-matched" log line),
#      the canary must be gone, and the original symbol name must reappear.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-mcp}}"
CANARY="rebuild_canary_renamed"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for rebuild-idb test (brew install jq)" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

if [[ ! -x fixtures/mini ]]; then
  echo "missing fixture binary: fixtures/mini (run 'just fixture' first)" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
raw="$tmpdir/mini"
idb="$tmpdir/mini.i64"
cp fixtures/mini "$raw"

server_pid=""
log=""
fifo_in=""

cleanup() {
  exec 3>&- || true
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    sleep 0.3
    kill -9 "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
  chmod -R u+w "$tmpdir" 2>/dev/null || true
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

start_server() {
  log="$tmpdir/server.log"
  fifo_in="$tmpdir/in.fifo"
  rm -f "$log" "$fifo_in"
  mkfifo "$fifo_in"
  RUST_LOG="${RUST_LOG:-ida_mcp=trace}" "$BIN" <"$fifo_in" >"$log" 2>&1 &
  server_pid=$!
  exec 3>"$fifo_in"
}

stop_server() {
  exec 3>&- || true
  if [[ -n "${server_pid:-}" ]]; then
    # Give the server up to ~3s to flush any pending writes after the
    # close_idb response is observed (drop returns before stdout is flushed
    # on some platforms).
    for _ in 1 2 3 4 5 6; do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.5
    done
    kill "$server_pid" >/dev/null 2>&1 || true
    sleep 0.3
    kill -9 "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
}

send() { echo "$1" >&3; }

wait_response() {
  local id="$1"
  local timeout="${2:-60}"
  local elapsed=0
  while [[ "$elapsed" -lt "$timeout" ]]; do
    local line
    line="$(grep -m1 "\"id\":${id}[,}]" "$log" 2>/dev/null | grep '"jsonrpc"' || true)"
    if [[ -n "$line" ]]; then
      echo "$line"
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "server died waiting for id=$id" >&2
      cat "$log" >&2
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "timeout waiting for id=$id" >&2
  cat "$log" >&2
  return 1
}

init() {
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"rebuild-idb","version":"0.1"},"capabilities":{}}}'
  wait_response 1 20 >/dev/null
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
}

assert_ok() {
  local label="$1" resp="$2"
  if echo "$resp" | jq -e '.result.isError == true' >/dev/null 2>&1; then
    echo "❌ $label returned isError=true" >&2
    echo "$resp" | jq . >&2
    exit 1
  fi
  if echo "$resp" | jq -e 'has("error")' >/dev/null 2>&1; then
    echo "❌ $label returned JSON-RPC error" >&2
    echo "$resp" | jq . >&2
    exit 1
  fi
}

assert_err() {
  local label="$1" resp="$2"
  if ! echo "$resp" | jq -e '.result.isError == true' >/dev/null 2>&1; then
    echo "❌ $label was expected to fail but succeeded" >&2
    echo "$resp" | jq . >&2
    exit 1
  fi
}

assert_log_contains() {
  local needle="$1"
  if ! grep -qF "$needle" "$log"; then
    echo "❌ expected server log to contain: $needle" >&2
    grep -E "Opening|Reusing|Rebuilding" "$log" >&2 || true
    exit 1
  fi
}

assert_log_absent() {
  local needle="$1"
  if grep -qF "$needle" "$log"; then
    echo "❌ server log unexpectedly contains: $needle" >&2
    grep -E "Opening|Reusing|Rebuilding" "$log" >&2 || true
    exit 1
  fi
}

echo "🧪 Running open_idb rebuild semantics test..."

echo "── Phase 1: open raw, rename, close (seeds .i64 with rename) ──"
start_server
init
# auto_analyse=true ensures interesting_function is registered in the IDA
# function database; without it the symbol is recognized but
# resolve_function (which iterates registered funcs) can't see it on reopen.
send "$(jq -cn --arg p "$raw" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,auto_analyse:true,timeout_secs:120}}}')"
assert_ok "Phase 1 open_idb" "$(wait_response 2 180)"
assert_log_absent "Reusing SHA-256-verified IDA database for raw input"
assert_log_absent "Rebuilding raw input and overwriting provenance-matched IDA database"

send "$(jq -cn --arg name "$CANARY" \
  '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"rename",arguments:{current_name:"interesting_function",name:$name,flags:0}}}')"
assert_ok "Phase 1 rename" "$(wait_response 3 30)"

send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 4 30 >/dev/null
stop_server

if [[ ! -f "$idb" ]]; then
  echo "❌ expected $idb to exist after Phase 1 close" >&2
  exit 1
fi
echo "   ✓ packed $idb with canary rename"

echo "── Phase 2: re-open raw, default rebuild=false → reuse existing .i64 ──"
start_server
init
send "$(jq -cn --arg p "$raw" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
assert_ok "Phase 2 open_idb" "$(wait_response 2 30)"
assert_log_contains "Reusing SHA-256-verified IDA database for raw input"
assert_log_absent "Rebuilding raw input and overwriting provenance-matched IDA database"
echo "   ✓ reuse path taken (log line present)"

send "$(jq -cn --arg name "$CANARY" \
  '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"resolve_function",arguments:{name:$name}}}')"
canary_resp="$(wait_response 3 15)"
assert_ok "Phase 2 resolve canary" "$canary_resp"
if ! echo "$canary_resp" | jq -e --arg name "$CANARY" \
  '.result.content[0].text | fromjson | .name == $name' >/dev/null; then
  echo "❌ Phase 2 resolve_function returned unexpected payload for $CANARY" >&2
  echo "$canary_resp" | jq . >&2
  exit 1
fi
echo "   ✓ $CANARY resolved (rename survived reuse)"

send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server

echo "── Phase 3: re-open raw with rebuild=true → overwrite .i64 ──"
start_server
init
send "$(jq -cn --arg p "$raw" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,rebuild:true,auto_analyse:true,timeout_secs:120}}}')"
assert_ok "Phase 3 open_idb" "$(wait_response 2 180)"
assert_log_contains "Rebuilding raw input and overwriting provenance-matched IDA database"
assert_log_absent "Reusing SHA-256-verified IDA database for raw input"
echo "   ✓ rebuild path taken (log line present)"

send "$(jq -cn --arg name "$CANARY" \
  '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"resolve_function",arguments:{name:$name}}}')"
assert_err "Phase 3 canary lookup" "$(wait_response 3 15)"
echo "   ✓ $CANARY no longer resolves (rebuilt from scratch)"

send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"resolve_function","arguments":{"name":"interesting_function"}}}'
orig_resp="$(wait_response 4 15)"
assert_ok "Phase 3 original lookup" "$orig_resp"
echo "   ✓ interesting_function resolves again"

conflicting_output="$tmpdir/conflicting-output.i64"
send "$(jq -cn --arg p "$raw" --arg out "$conflicting_output" \
  '{jsonrpc:"2.0",id:5,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out}}}')"
conflicting_response="$(wait_response 5 15)"
assert_err "Phase 3 explicit output retry against default open" "$conflicting_response"
echo "$conflicting_response" | jq -e '
  .result.content[0].text | contains("A database is already open")
' >/dev/null || {
  echo "❌ explicit output retry failed for the wrong reason" >&2
  echo "$conflicting_response" | jq . >&2
  exit 1
}
[[ ! -e "$conflicting_output" ]] || {
  echo "❌ explicit output retry silently created the wrong database" >&2
  exit 1
}
echo "   ✓ explicit output retry did not adopt the default open database"

send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server

echo "── Phase 4: explicit idb_out works beside a read-only input directory ──"
readonly_dir="$tmpdir/readonly-input"
database_dir="$tmpdir/databases"
explicit_raw="$readonly_dir/mini"
explicit_idb="$database_dir/explicit.i64"
mkdir -p "$readonly_dir" "$database_dir"
cp fixtures/mini "$explicit_raw"
chmod 0555 "$readonly_dir"

start_server
init
send "$(jq -cn --arg p "$explicit_raw" --arg out "$explicit_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out}}}')"
assert_ok "Phase 4 explicit idb_out open" "$(wait_response 2 120)"
send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server
[[ -f "$explicit_idb" ]] || { echo "❌ explicit idb_out was not created" >&2; exit 1; }
[[ ! -f "$explicit_raw.i64" ]] || { echo "❌ IDB leaked beside read-only input" >&2; exit 1; }
echo "   ✓ explicit output created without a sibling IDB"

echo "── Phase 5: explicit idb_out reuse requires the recorded input hash ──"
start_server
init
send "$(jq -cn --arg p "$explicit_raw" --arg out "$explicit_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out}}}')"
assert_ok "Phase 5 hash-verified explicit reuse" "$(wait_response 2 30)"
assert_log_contains "Reusing SHA-256-verified IDA database for raw input"

send "$(jq -cn --arg p "$explicit_raw" --arg out "$explicit_idb" \
  '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out}}}')"
assert_ok "Phase 5 idempotent explicit retry while open" "$(wait_response 3 30)"

# Idempotency is content identity, not merely output-path identity. Mutate the
# raw input while its explicit output is still open, then retry the exact same
# request. The server must refuse to return stale analysis from the open IDB.
printf '\0' >>"$explicit_raw"
send "$(jq -cn --arg p "$explicit_raw" --arg out "$explicit_idb" \
  '{jsonrpc:"2.0",id:4,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out}}}')"
stale_open_response="$(wait_response 4 30)"
assert_err "Phase 5 changed input against already-open output" "$stale_open_response"
echo "$stale_open_response" | jq -e '
  .result.content[0].text | contains("A database is already open")
' >/dev/null || {
  echo "❌ already-open stale input was rejected for the wrong reason" >&2
  echo "$stale_open_response" | jq . >&2
  exit 1
}
send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server
echo "   ✓ matching input reused explicit output; changed bytes were refused while open"

echo "── Phase 6: changed input cannot blindly adopt explicit idb_out after close ──"
start_server
init
send "$(jq -cn --arg p "$explicit_raw" --arg out "$explicit_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out}}}')"
assert_err "Phase 6 mismatched explicit reuse" "$(wait_response 2 30)"
stop_server
echo "   ✓ mismatched hash was rejected"

echo "── Phase 7: rebuild may replace an output recorded for the same input path ──"
start_server
init
send "$(jq -cn --arg p "$explicit_raw" --arg out "$explicit_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out,rebuild:true}}}')"
assert_ok "Phase 7 provenance-matched rebuild" "$(wait_response 2 120)"
assert_log_contains "Rebuilding raw input and overwriting provenance-matched IDA database"
send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server
echo "   ✓ recorded input path allowed explicit rebuild"

echo "── Phase 8: typed raw target survives close and verified reuse ──"
typed_raw="$tmpdir/aarch64.bin"
typed_idb="$tmpdir/aarch64.i64"
# AArch64 NOP; RET. This is deliberately headerless so IDA cannot infer the
# processor, application bitness, load address, or entry point from a format.
printf '\x1f\x20\x03\xd5\xc0\x03\x5f\xd6' >"$typed_raw"

start_server
init
send "$(jq -cn --arg p "$typed_raw" --arg out "$typed_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out,processor:"arm:ARMv8-A",bitness:64,base_address:"0x1000",entry_point:"0x1000",auto_analyse:true,timeout_secs:120}}}')"
typed_open_resp="$(wait_response 2 180)"
assert_ok "Phase 8 typed raw open" "$typed_open_resp"
if ! echo "$typed_open_resp" | jq -e \
  '.result.content[0].text | fromjson | .bits == 64 and (.processor | test("arm"; "i"))' >/dev/null; then
  echo "❌ typed raw open did not report a 64-bit ARM database" >&2
  echo "$typed_open_resp" | jq . >&2
  exit 1
fi

send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"segments","arguments":{}}}'
segments_resp="$(wait_response 3 30)"
assert_ok "Phase 8 segments" "$segments_resp"
if ! echo "$segments_resp" | jq -e \
  '.result.content[0].text | fromjson | any(.[]; .start == "0x1000" and .bitness == 2)' >/dev/null; then
  echo "❌ typed raw segment did not retain base 0x1000 and IDA 64-bit segment mode 2" >&2
  echo "$segments_resp" | jq . >&2
  exit 1
fi

send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"entrypoints","arguments":{}}}'
entrypoints_resp="$(wait_response 4 30)"
assert_ok "Phase 8 entrypoints" "$entrypoints_resp"
if ! echo "$entrypoints_resp" | jq -e \
  '.result.content[0].text | fromjson | index("0x1000") != null' >/dev/null; then
  echo "❌ typed raw entry point 0x1000 was not recorded" >&2
  echo "$entrypoints_resp" | jq . >&2
  exit 1
fi

send "$(jq -cn --arg p "$typed_raw" --arg out "$typed_idb" \
  '{jsonrpc:"2.0",id:5,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out,processor:"arm:ARMv8-A",bitness:64,base_address:"0x2000",entry_point:"0x2000"}}}')"
assert_err "Phase 8 raw target retry while open" "$(wait_response 5 30)"

send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server
[[ -f "$typed_idb" ]] || { echo "❌ typed raw IDB was not created" >&2; exit 1; }

start_server
init
send "$(jq -cn --arg p "$typed_raw" --arg out "$typed_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out}}}')"
typed_reuse_resp="$(wait_response 2 30)"
assert_ok "Phase 8 typed raw reuse" "$typed_reuse_resp"
assert_log_contains "Reusing SHA-256-verified IDA database for raw input"
if ! echo "$typed_reuse_resp" | jq -e \
  '.result.content[0].text | fromjson | .bits == 64 and (.processor | test("arm"; "i"))' >/dev/null; then
  echo "❌ verified reuse lost typed raw processor or bitness" >&2
  echo "$typed_reuse_resp" | jq . >&2
  exit 1
fi
send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server
echo "   ✓ processor, bitness, base, and entry point survived verified reuse"

echo "── Phase 8b: Thumb-tagged ARM entry points retain code address and T-state ──"
thumb_raw="$tmpdir/thumb.bin"
thumb_idb="$tmpdir/thumb.i64"
dd if=/dev/zero of="$thumb_raw" bs=1 count=256 >/dev/null 2>&1
# Thumb NOP; BX LR at offset 0x100.
printf '\x00\xbf\x70\x47' >>"$thumb_raw"

start_server
init
send "$(jq -cn --arg p "$thumb_raw" --arg out "$thumb_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out,processor:"arm:ARMv7-M",bitness:32,base_address:"0x08000000",entry_point:"0x08000101",auto_analyse:true,timeout_secs:120}}}')"
assert_ok "Phase 8b Thumb raw open" "$(wait_response 2 180)"
send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server
[[ -f "$thumb_idb" ]] || { echo "❌ Thumb raw IDB was not created" >&2; exit 1; }

start_server
init
send "$(jq -cn --arg p "$thumb_raw" --arg out "$thumb_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out}}}')"
assert_ok "Phase 8b Thumb raw reuse" "$(wait_response 2 30)"
assert_log_contains "Reusing SHA-256-verified IDA database for raw input"

send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"entrypoints","arguments":{}}}'
thumb_entrypoints="$(wait_response 3 30)"
assert_ok "Phase 8b Thumb entry point" "$thumb_entrypoints"
echo "$thumb_entrypoints" | jq -e '
  .result.content[0].text | fromjson
  | index("0x8000100") != null and index("0x8000101") == null
' >/dev/null || {
  echo "❌ Thumb-tagged entry point was not normalized to its code address" >&2
  echo "$thumb_entrypoints" | jq . >&2
  exit 1
}

send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"disasm","arguments":{"address":"0x08000100","count":2}}}'
thumb_disasm="$(wait_response 4 30)"
assert_ok "Phase 8b Thumb disassembly" "$thumb_disasm"
echo "$thumb_disasm" | jq -e '
  .result.content[0].text | test("0x8000100.*NOP"; "is")
' >/dev/null || {
  echo "❌ Thumb state was not active at the normalized entry point" >&2
  echo "$thumb_disasm" | jq . >&2
  exit 1
}
send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server
echo "   ✓ odd Thumb pointer and Thumb decoding survived verified reuse"

echo "── Phase 9: failed rebuild removes partial output and permits recovery ──"
start_server
init
send "$(jq -cn --arg p "$typed_raw" --arg out "$typed_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out,rebuild:true,processor:"arm:ARMv8-A",bitness:64,base_address:"0x1000",entry_point:"0x2000",auto_analyse:true,timeout_secs:120}}}')"
assert_err "Phase 9 invalid typed rebuild" "$(wait_response 2 180)"
stop_server

typed_base="${typed_idb%.*}"
for artifact in "$typed_idb" "$typed_base.id0" "$typed_base.id1" \
  "$typed_base.id2" "$typed_base.nam" "$typed_base.til"; do
  if [[ -e "$artifact" ]]; then
    echo "❌ failed rebuild left reusable database artifact: $artifact" >&2
    exit 1
  fi
done
echo "   ✓ invalid entry point failed closed without reusable artifacts"

start_server
init
send "$(jq -cn --arg p "$typed_raw" --arg out "$typed_idb" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,idb_out:$out,processor:"arm:ARMv8-A",bitness:64,base_address:"0x1000",entry_point:"0x1000",auto_analyse:true,timeout_secs:120}}}')"
assert_ok "Phase 9 recovery open" "$(wait_response 2 180)"
send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server
[[ -f "$typed_idb" ]] || { echo "❌ recovery did not recreate typed raw IDB" >&2; exit 1; }
echo "   ✓ a valid retry recreated and packed the database"

chmod 0755 "$readonly_dir"
echo "✅ rebuild/idb_out provenance test passed"
