#!/usr/bin/env bash
# A shutdown signal must save the open database and exit promptly even when
# the client never closes stdin (an MCP client that hangs up its children).
# Covers the default stdio server and the --workspace router, for SIGTERM
# and SIGHUP, and checks that an unsaved rename survived the shutdown.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-../target/debug/ida-mcp}"
IDB_PATH="${IDB_PATH:-fixtures/mini.i64}"
RAW_PATH="${RAW_PATH:-fixtures/mini}"
EXIT_BUDGET_SECS="${EXIT_BUDGET_SECS:-8}"

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing server binary: $BIN" >&2; exit 1; }
[[ -f "$IDB_PATH" ]] || { echo "missing fixture: $IDB_PATH" >&2; exit 1; }

work="$(mktemp -d)"
pid=
cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "$pid" ]]; then kill -9 "$pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

send() { echo "$1" >&3; }

wait_response() {
  local target_id="$1" log="$2" timeout="${3:-30}" elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    local line
    line=$(grep -m1 "\"id\":${target_id}[,}]" "$log" 2>/dev/null | grep '"jsonrpc"' || true)
    [[ -n "$line" ]] && { echo "$line"; return 0; }
    sleep 1; elapsed=$((elapsed + 1))
  done
  echo "timeout waiting for id=$target_id" >&2
  cat "$log" >&2
  return 1
}

# run_case <label> <signal> [server flags...]
run_case() {
  local label="$1" sig="$2"; shift 2
  local dir="$work/$label" fifo log db
  mkdir -p "$dir"
  fifo="$dir/stdin.fifo"; log="$dir/out.log"; db="$dir/mini.i64"
  cp "$IDB_PATH" "$db"
  mkfifo "$fifo"
  RUST_LOG=ida_mcp=info "$BIN" "$@" < "$fifo" > "$log" 2>&1 &
  pid=$!
  exec 3>"$fifo"

  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"shutdown-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 "$log" 10 >/dev/null
  send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
  local open_resp db_id rename
  open_resp="$(wait_response 2 "$log" 120)"
  echo "$open_resp" | jq -e '.result.isError != true' >/dev/null || { echo "FAIL[$label]: open failed" >&2; echo "$open_resp" >&2; exit 1; }
  db_id="$(echo "$open_resp" | jq -r '.result.content[0].text' | jq -r '.database_id // empty')"
  if [[ -n "$db_id" ]]; then
    rename="$(jq -cn --arg id "$db_id" '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"rename",arguments:{database_id:$id,current_name:"interesting_function",name:"survived_shutdown",flags:0}}}')"
  else
    rename='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rename","arguments":{"current_name":"interesting_function","name":"survived_shutdown","flags":0}}}'
  fi
  send "$rename"
  wait_response 3 "$log" 30 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL[$label]: rename failed" >&2; exit 1; }

  # The signal arrives while stdin stays open on fd 3.
  kill "-$sig" "$pid"
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    sleep 1; waited=$((waited + 1))
    if [[ $waited -ge $EXIT_BUDGET_SECS ]]; then
      echo "FAIL[$label]: still running ${waited}s after $sig with stdin open" >&2
      cat "$log" >&2
      exit 1
    fi
  done
  exec 3>&-
  pid=
  # Strip ANSI color codes before matching the structured log field.
  sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -q "Shutdown signal received.*signal=\"SIG$sig\"" || {
    echo "FAIL[$label]: log does not name $sig" >&2; cat "$log" >&2; exit 1; }
  for leftover in "$dir"/mini.id0 "$dir"/mini.id1 "$dir"/mini.nam "$dir"/mini.til; do
    [[ ! -e "$leftover" ]] || { echo "FAIL[$label]: database left unpacked: $leftover" >&2; exit 1; }
  done

  # The rename must be on disk: reopen the saved database with a fresh server.
  local check_fifo="$dir/check.fifo" check_log="$dir/check.log"
  mkfifo "$check_fifo"
  RUST_LOG=ida_mcp=info "$BIN" < "$check_fifo" > "$check_log" 2>&1 &
  pid=$!
  exec 3>"$check_fifo"
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"shutdown-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 "$check_log" 10 >/dev/null
  send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
  wait_response 2 "$check_log" 120 >/dev/null
  send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"resolve_function","arguments":{"name":"survived_shutdown"}}}'
  wait_response 3 "$check_log" 30 | jq -e '.result.isError != true' >/dev/null || {
    echo "FAIL[$label]: rename did not survive $sig" >&2; cat "$check_log" >&2; exit 1; }
  send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
  wait_response 4 "$check_log" 30 >/dev/null
  exec 3>&-
  wait "$pid" 2>/dev/null || true
  pid=
  echo "   ✓ $label: $sig saved the rename and exited within ${waited}s with stdin open"
}

# A closebase hook reproduces an IDA close that never finishes. The default
# watchdog must not extend the 120-second shutdown budget; shorter operation
# watchdogs can still end the close earlier.
run_hung_close_case() {
  local sig="$1" max_wait="$2" dir="$work/hung-close-$1" fifo log db code child_pid response waited
  shift 2
  mkdir -p "$dir"
  fifo="$dir/stdin.fifo"; log="$dir/out.log"; db="$dir/mini.i64"
  cp "$IDB_PATH" "$db"
  mkfifo "$fifo"
  RUST_LOG=ida_mcp=info "$BIN" "$@" < "$fifo" > "$log" 2>&1 &
  pid=$!
  exec 3>"$fifo"
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"shutdown-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 "$log" 10 >/dev/null
  send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
  wait_response 2 "$log" 120 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL[hung-close-$sig]: open failed" >&2; exit 1; }
  code="$(cat <<'PY'
import ida_idp, ida_loader, os, time
_shutdown_marker = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) + '.close-entered'
class _ShutdownHang(ida_idp.IDB_Hooks):
    def closebase(self):
        with open(_shutdown_marker, 'w') as marker:
            marker.write('entered')
        time.sleep(600)
_shutdown_hang = _ShutdownHang()
if not _shutdown_hang.hook():
    raise RuntimeError('could not install closebase hook')
os.getpid()
PY
)"
  send "$(jq -cn --arg code "$code" '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"run_script",arguments:{code:$code}}}')"
  response="$(wait_response 3 "$log" 30)"
  echo "$response" | jq -e '.result.isError != true' >/dev/null || { echo "FAIL[hung-close-$sig]: hook failed" >&2; echo "$response" >&2; exit 1; }
  child_pid="$(echo "$response" | jq -r '.result.content[0].text' | jq -r '.result')"
  [[ "$child_pid" =~ ^[0-9]+$ ]] || { echo "FAIL[hung-close-$sig]: missing child PID" >&2; exit 1; }

  if [[ "$sig" == EOF ]]; then exec 3>&-; else kill "-$sig" "$pid"; fi
  waited=0
  while kill -0 "$pid" 2>/dev/null; do
    sleep 1; waited=$((waited + 1))
    if [[ $waited -ge $max_wait ]]; then
      echo "FAIL[hung-close-$sig]: server still running after ${waited}s" >&2
      cat "$log" >&2
      exit 1
    fi
  done
  wait "$pid" || { echo "FAIL[hung-close-$sig]: server exited unsuccessfully" >&2; exit 1; }
  pid=
  exec 3>&-
  [[ -f "$db.close-entered" ]] || { echo "FAIL[hung-close-$sig]: closebase was never entered" >&2; cat "$log" >&2; exit 1; }
  grep -Eq 'IDA database close (timed out|failed) during shutdown' "$log" || { echo "FAIL[hung-close-$sig]: shutdown deadline did not fire" >&2; cat "$log" >&2; exit 1; }
  for _ in {1..5}; do
    kill -0 "$child_pid" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$child_pid" 2>/dev/null; then echo "FAIL[hung-close-$sig]: child $child_pid survived shutdown" >&2; exit 1; fi
  echo "   ✓ hung-close-$sig: entered closebase, retired child, exited within ${waited}s"
}

# A SIGKILL cannot be handled, so finished auto-analysis must already be on
# disk: reopening the unpacked database after the kill shows every function.
run_kill_case() {
  local dir="$work/kill" fifo log raw
  mkdir -p "$dir"
  fifo="$dir/stdin.fifo"; log="$dir/out.log"; raw="$dir/mini"
  cp "$RAW_PATH" "$raw"
  mkfifo "$fifo"
  RUST_LOG=ida_mcp=info "$BIN" < "$fifo" > "$log" 2>&1 &
  pid=$!
  exec 3>"$fifo"
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"shutdown-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 "$log" 10 >/dev/null
  send "$(jq -cn --arg p "$raw" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,auto_analyse:true}}}')"
  local open_resp analyzed
  open_resp="$(wait_response 2 "$log" 120)"
  analyzed="$(echo "$open_resp" | jq -r '.result.content[0].text' | jq -r '.function_count')"
  [[ "$analyzed" =~ ^[0-9]+$ && "$analyzed" -gt 0 ]] || { echo "FAIL[kill]: open reported no functions" >&2; echo "$open_resp" >&2; exit 1; }
  kill -9 "$pid"
  wait "$pid" 2>/dev/null || true
  exec 3>&-
  pid=
  # The flush writes the packed .i64; the kill leaves the working files beside it.
  [[ -e "$raw.id0" ]] || { echo "FAIL[kill]: expected the killed server's working files" >&2; ls "$dir" >&2; exit 1; }
  [[ -e "$raw.i64" ]] || { echo "FAIL[kill]: analysis was not flushed to $raw.i64" >&2; ls "$dir" >&2; exit 1; }

  local check_fifo="$dir/check.fifo" check_log="$dir/check.log" recovered
  mkfifo "$check_fifo"
  RUST_LOG=ida_mcp=info "$BIN" < "$check_fifo" > "$check_log" 2>&1 &
  pid=$!
  exec 3>"$check_fifo"
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"shutdown-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 "$check_log" 10 >/dev/null
  send "$(jq -cn --arg p "$raw.i64" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p,force:true}}}')"
  recovered="$(wait_response 2 "$check_log" 120 | jq -r '.result.content[0].text' | jq -r '.function_count')"
  send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
  wait_response 3 "$check_log" 30 >/dev/null
  exec 3>&-
  wait "$pid" 2>/dev/null || true
  pid=
  [[ "$recovered" == "$analyzed" ]] || { echo "FAIL[kill]: recovered $recovered functions, analysis had $analyzed" >&2; exit 1; }
  echo "   ✓ kill: analysis of $analyzed functions survived SIGKILL on disk"
}

run_case stdio-term TERM
run_case stdio-hup HUP
run_case workspace-term TERM --workspace
run_case workspace-hup HUP --workspace
run_hung_close_case TERM 140
run_hung_close_case HUP 35 --workspace-worker-op-timeout-secs 2
run_hung_close_case EOF 35 --workspace-worker-op-timeout-secs 2
run_kill_case

echo "✅ shutdown-signal test passed"
