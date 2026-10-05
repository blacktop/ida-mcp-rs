#!/usr/bin/env bash
# A call stuck inside IDA on the default stdio server must not wedge the
# server: the call returns a timeout within its bound, the child that ran it
# is gone, the database is no longer bound, the next open gets a fresh child,
# and edits saved before the hang are intact. Also: a parent killed with
# SIGKILL while its child is stuck must not leave that child running.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-../target/debug/ida-mcp}"
IDB_PATH="${IDB_PATH:-fixtures/mini.i64}"

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing server binary: $BIN" >&2; exit 1; }
[[ -f "$IDB_PATH" ]] || { echo "missing fixture: $IDB_PATH" >&2; exit 1; }

work="$(mktemp -d)"
pid=
cleanup() {
  exec 3>&- 2>/dev/null || true
  exec 4>&- 2>/dev/null || true
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

text() { jq -r '.result.content[0].text // empty'; }

# Piped match checks must consume all input: grep -q can give the producer
# SIGPIPE after a match, turning success into a failure under pipefail.

child_pids() {
  # Every child the router reported spawning, in order.
  sed 's/\x1b\[[0-9;]*m//g' "$1" | sed -n 's/.*spawned IDA child worker.*pid=Some(\([0-9]*\)).*/\1/p'
}

start() {
  local dir="$1"
  mkdir -p "$dir"
  mkfifo "$dir/stdin.fifo"
  RUST_LOG=ida_mcp=info "$BIN" serve < "$dir/stdin.fifo" > "$dir/out.log" 2>&1 &
  pid=$!
  exec 3>"$dir/stdin.fifo"
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"stuck-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 "$dir/out.log" 10 >/dev/null
}

# ---------------------------------------------------------------------------
echo "── stuck call on the default stdio server ──"
dir="$work/stuck"; db="$dir/mini.i64"
start "$dir"
cp "$IDB_PATH" "$db"
send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 2 "$dir/out.log" 120 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: open failed" >&2; exit 1; }
first_child="$(child_pids "$dir/out.log" | head -1)"
[[ -n "$first_child" ]] || { echo "FAIL: router did not report a child pid" >&2; cat "$dir/out.log" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rename","arguments":{"current_name":"interesting_function","name":"saved_before_hang","flags":0}}}'
wait_response 3 "$dir/out.log" 30 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: rename failed" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"save_idb","arguments":{}}}'
wait_response 4 "$dir/out.log" 60 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: save failed" >&2; exit 1; }

# A Python call that never returns while the IDA thread waits on it. The
# per-call bound is 5s; the router adds its own grace before killing.
started=$(date +%s)
send '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import time\ntime.sleep(600)","timeout_secs":5}}}'
# The router's own operation record must show the script executing while
# the child is stuck (phases do not cross the transport, so the router
# reports what it knows).
sleep 2
send '{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"recent_operations","arguments":{}}}'
wait_response 50 "$dir/out.log" 10 | text | grep '"executing"' >/dev/null || { echo "FAIL: recent_operations does not show the stuck script as executing" >&2; exit 1; }
stuck_resp="$(wait_response 5 "$dir/out.log" 60)" || { echo "FAIL: the stuck call never returned" >&2; exit 1; }
elapsed=$(( $(date +%s) - started ))
echo "$stuck_resp" | jq -e '.result.isError == true' >/dev/null || { echo "FAIL: stuck call did not return an error" >&2; echo "$stuck_resp" >&2; exit 1; }
# The typed retirement error, not the generic script timeout: it tells the
# agent the database is gone and to reopen.
stuck_text="$(echo "$stuck_resp" | text)"
if ! { grep -q 'killed worker' <<<"$stuck_text" && grep -q 'open_idb again' <<<"$stuck_text"; }; then
  echo "FAIL: stuck call error does not report the retirement and recovery" >&2; echo "$stuck_resp" >&2; exit 1
fi
[[ $elapsed -le 30 ]] || { echo "FAIL: stuck call took ${elapsed}s to return" >&2; exit 1; }
echo "   ✓ stuck call returned a timeout after ${elapsed}s"

for _ in $(seq 1 10); do kill -0 "$first_child" 2>/dev/null || break; sleep 1; done
if kill -0 "$first_child" 2>/dev/null; then echo "FAIL: stuck child $first_child is still running" >&2; exit 1; fi
echo "   ✓ child $first_child is gone"

send '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"idb_meta","arguments":{}}}'
wait_response 6 "$dir/out.log" 30 | text | grep 'No database is currently open' >/dev/null || { echo "FAIL: a database was still bound after the stuck child was killed" >&2; exit 1; }
echo "   ✓ no database bound after retirement"

send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:7,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 7 "$dir/out.log" 120 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: reopen failed" >&2; cat "$dir/out.log" >&2; exit 1; }
second_child="$(child_pids "$dir/out.log" | tail -1)"
[[ -n "$second_child" && "$second_child" != "$first_child" ]] || { echo "FAIL: reopen did not use a fresh child (first=$first_child last=$second_child)" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"resolve_function","arguments":{"name":"saved_before_hang"}}}'
wait_response 8 "$dir/out.log" 30 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: the edit saved before the hang is missing" >&2; exit 1; }
echo "   ✓ reopened on child $second_child with the saved rename intact"
# Calls queued behind a healthy, finite one have started nothing: their
# own deadline or cancellation ends only the wait, and afterwards the same
# worker, database, and Python state are still there.
send '{"jsonrpc":"2.0","id":60,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import time\nqueued_marker = 7\ntime.sleep(25)\nqueued_marker","timeout_secs":60}}}'
sleep 1
busy_child="$(child_pids "$dir/out.log" | tail -1)"
started=$(date +%s)
send '{"jsonrpc":"2.0","id":61,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":1,"timeout_secs":1}}}'
queued_resp="$(wait_response 61 "$dir/out.log" 40)" || { echo "FAIL: the queued call never returned" >&2; exit 1; }
elapsed=$(( $(date +%s) - started ))
echo "$queued_resp" | text | grep 'waiting for the IDA worker' >/dev/null || { echo "FAIL: queued call did not report a queue timeout" >&2; echo "$queued_resp" >&2; exit 1; }
[[ $elapsed -le 20 ]] || { echo "FAIL: queued call took ${elapsed}s" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":63,"method":"tools/call","params":{"name":"recent_operations","arguments":{}}}'
wait_response 63 "$dir/out.log" 10 | text | grep '"queued"' >/dev/null || { echo "FAIL: the queued call was not recorded as queued" >&2; exit 1; }
# Cancelling a queued read and a queued open likewise end only the wait.
send '{"jsonrpc":"2.0","id":65,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":1,"timeout_secs":30}}}'
send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:66,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
sleep 1
send '{"jsonrpc":"2.0","id":64,"method":"tools/call","params":{"name":"recent_operations","arguments":{}}}'
wait_response 64 "$dir/out.log" 10 | text | jq -e '.active_operation.tool == "open_idb" and .active_operation.status == "queued"' >/dev/null || { echo "FAIL: the cancellation target did not enter the worker queue" >&2; exit 1; }
# Neither request may have finished (for example, with Busy) before we
# cancel it. The healthy script still owns the only worker's call lock.
if grep -E '"id":(65|66)[,}]' "$dir/out.log" | grep '"jsonrpc"' >/dev/null; then
  echo "FAIL: a cancellation target finished before it could be cancelled" >&2
  exit 1
fi
send '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":65,"reason":"test"}}'
send '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":66,"reason":"test"}}'
# The finite call completes normally despite everything queued behind it.
finished="$(wait_response 60 "$dir/out.log" 60)" || { echo "FAIL: the finite call behind the queue never returned" >&2; exit 1; }
echo "$finished" | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: queued deadlines or cancellations broke the running call" >&2; echo "$finished" >&2; exit 1; }
kill -0 "$busy_child" 2>/dev/null || { echo "FAIL: queued failures retired the healthy worker $busy_child" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":67,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"queued_marker + 1","timeout_secs":10}}}'
state_resp="$(wait_response 67 "$dir/out.log" 30)"
[[ "$(echo "$state_resp" | text | jq -r '.result')" == "8" ]] || { echo "FAIL: Python state did not survive queued failures" >&2; echo "$state_resp" >&2; exit 1; }
[[ "$(child_pids "$dir/out.log" | tail -1)" == "$busy_child" ]] || { echo "FAIL: a new child was spawned after queued failures" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":68,"method":"tools/call","params":{"name":"idb_meta","arguments":{}}}'
wait_response 68 "$dir/out.log" 30 | text | jq -e '.function_count' >/dev/null || { echo "FAIL: the database was unreachable after queued failures" >&2; exit 1; }
echo "   ✓ queued timeout and cancellations left the worker $busy_child, its database, and its state intact"

# Exercise admission independently so its flood cannot mask cancellation.
send '{"jsonrpc":"2.0","id":80,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import time\ntime.sleep(15)\nqueued_marker","timeout_secs":45}}}'
sleep 1
for i in $(seq 100 175); do
  send "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/call\",\"params\":{\"name\":\"list_functions\",\"arguments\":{\"limit\":1,\"timeout_secs\":120}}}"
done
busy_seen=
for _ in $(seq 1 10); do
  if grep -q 'Server is busy' "$dir/out.log"; then busy_seen=1; break; fi
  sleep 1
done
[[ -n "$busy_seen" ]] || { echo "FAIL: pipelined calls past the admission bound were not rejected as busy" >&2; exit 1; }
wait_response 80 "$dir/out.log" 60 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: admission flood broke the running call" >&2; exit 1; }
for i in $(seq 100 175); do wait_response "$i" "$dir/out.log" 30 >/dev/null; done
[[ "$(child_pids "$dir/out.log" | tail -1)" == "$busy_child" ]] || { echo "FAIL: admission flood retired the healthy worker" >&2; exit 1; }
echo "   ✓ calls past the admission bound were rejected as busy"

# A read tool stuck inside IDA (an output hook that never returns) must be
# bounded by the supervisor too, and the retirement must be the call's
# top-level error even though search normally folds per-item failures.
send '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import ida_idp, time\nclass Stuck(ida_idp.IDP_Hooks):\n    def ev_out_insn(self, ctx):\n        time.sleep(600)\n        return 0\nstuck_hook = Stuck()\nstuck_hook.hook()"}}}'
wait_response 10 "$dir/out.log" 30 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: could not install the stuck output hook" >&2; exit 1; }
stuck_child="$(child_pids "$dir/out.log" | tail -1)"
started=$(date +%s)
send '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"search","arguments":{"targets":["ret"],"kind":"text","limit":5,"timeout_secs":2}}}'
read_resp="$(wait_response 11 "$dir/out.log" 60)" || { echo "FAIL: the stuck read tool never returned" >&2; exit 1; }
elapsed=$(( $(date +%s) - started ))
echo "$read_resp" | jq -e '.result.isError == true' >/dev/null || { echo "FAIL: stuck read tool did not return a top-level error" >&2; echo "$read_resp" >&2; exit 1; }
echo "$read_resp" | text | grep 'killed worker' >/dev/null || { echo "FAIL: stuck read tool error does not report the retirement" >&2; echo "$read_resp" >&2; exit 1; }
[[ $elapsed -le 30 ]] || { echo "FAIL: stuck read tool took ${elapsed}s to return" >&2; exit 1; }
for _ in $(seq 1 10); do kill -0 "$stuck_child" 2>/dev/null || break; sleep 1; done
if kill -0 "$stuck_child" 2>/dev/null; then echo "FAIL: child $stuck_child stuck in a read tool is still running" >&2; exit 1; fi
echo "   ✓ stuck read tool returned the retirement error after ${elapsed}s and child $stuck_child is gone"
send '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"list_functions","arguments":{"limit":1,"timeout_secs":5}}}'
wait_response 12 "$dir/out.log" 30 | text | grep 'No database is currently open' >/dev/null || { echo "FAIL: a later read tool did not report the database as closed" >&2; exit 1; }
echo "   ✓ later calls answer immediately with no database open"

# A worker that dies mid-call is a fatal, top-level error even from a batch
# tool, never a successful envelope with the loss buried in results[].
send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:70,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 70 "$dir/out.log" 120 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: reopen before the crash case failed" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import ida_idp, os\nclass Die(ida_idp.IDP_Hooks):\n    def ev_out_insn(self, ctx):\n        os._exit(3)\ndie_hook = Die()\ndie_hook.hook()"}}}'
wait_response 71 "$dir/out.log" 30 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: could not install the exiting output hook" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"search","arguments":{"targets":["ret"],"kind":"text","limit":5,"timeout_secs":10}}}'
dead_resp="$(wait_response 72 "$dir/out.log" 40)" || { echo "FAIL: search on a dying worker never returned" >&2; exit 1; }
echo "$dead_resp" | jq -e '.result.isError == true' >/dev/null || { echo "FAIL: a worker dying inside search returned success" >&2; echo "$dead_resp" >&2; exit 1; }
echo "$dead_resp" | text | grep 'crashed or disconnected' >/dev/null || { echo "FAIL: worker loss inside search was not reported as such" >&2; echo "$dead_resp" >&2; exit 1; }
echo "   ✓ worker death inside a batch tool is the call's error"
exec 3>&-
wait "$pid" 2>/dev/null || true
pid=

# ---------------------------------------------------------------------------
echo "── parent killed with SIGKILL while its child is stuck ──"
dir="$work/orphan"; db="$dir/mini.i64"
start "$dir"
cp "$IDB_PATH" "$db"
send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 2 "$dir/out.log" 120 >/dev/null
child="$(child_pids "$dir/out.log" | head -1)"
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import time\ntime.sleep(600)","timeout_secs":300}}}'
sleep 2
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
pid=
exec 3>&-
# The child's parent-side pipes are gone; it must notice and exit on its own,
# within its bounded worker shutdown, even though its IDA thread is stuck.
waited=0
while kill -0 "$child" 2>/dev/null; do
  sleep 1; waited=$((waited + 1))
  if [[ $waited -ge 45 ]]; then echo "FAIL: orphaned stuck child $child still running after ${waited}s" >&2; exit 1; fi
done
echo "   ✓ orphaned stuck child $child exited within ${waited}s"

# ---------------------------------------------------------------------------
echo "── target-scoped logging reaches the user through the child ──"
dir="$work/logging"; db="$dir/mini.i64"
mkdir -p "$dir"
mkfifo "$dir/stdin.fifo"
RUST_LOG=ida_mcp::ida::loop_impl=info "$BIN" serve < "$dir/stdin.fifo" > "$dir/out.log" 2>&1 &
pid=$!
exec 3>"$dir/stdin.fifo"
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"stuck-test","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
wait_response 1 "$dir/out.log" 10 >/dev/null
cp "$IDB_PATH" "$db"
send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 2 "$dir/out.log" 120 >/dev/null
sed 's/\x1b\[[0-9;]*m//g' "$dir/out.log" | grep 'ida_mcp::ida::loop_impl.*Database opened' >/dev/null || {
  echo "FAIL: a target-scoped RUST_LOG did not show the child's loop_impl log" >&2; exit 1; }
exec 3>&-
wait "$pid" 2>/dev/null || true
pid=
echo "   ✓ RUST_LOG=ida_mcp::ida::loop_impl=info shows the child's database-open line"

# ---------------------------------------------------------------------------
echo "── an unread stderr pipe cannot stop the supervisor watchdog ──"
dir="$work/stderr"; db="$dir/mini.i64"
mkdir -p "$dir"
mkfifo "$dir/stdin.fifo" "$dir/stderr.fifo"
# Keep a reader present without consuming bytes. Native writes fill this pipe.
exec 4<>"$dir/stderr.fifo"
RUST_LOG=ida_mcp=info "$BIN" serve < "$dir/stdin.fifo" > "$dir/out.log" 2> "$dir/stderr.fifo" &
pid=$!
exec 3>"$dir/stdin.fifo"
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"stderr-test","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
wait_response 1 "$dir/out.log" 10 >/dev/null
cp "$IDB_PATH" "$db"
send "$(jq -cn --arg p "$db" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$p}}}')"
wait_response 2 "$dir/out.log" 120 | jq -e '.result.isError != true' >/dev/null || { echo "FAIL: stderr probe could not open its fixture" >&2; exit 1; }
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import os\nfor _ in range(256):\n    os.write(2, b\"F\" * 4095 + b\"\\n\")\n42","timeout_secs":2}}}'
stderr_resp="$(wait_response 3 "$dir/out.log" 30)" || { echo "FAIL: unread stderr stopped the watchdog" >&2; exit 1; }
echo "$stderr_resp" | jq -e '.result.isError == true' >/dev/null || { echo "FAIL: native stderr did not fill the pipe" >&2; exit 1; }
echo "$stderr_resp" | text | grep 'killed worker' >/dev/null || { echo "FAIL: stderr probe did not report retirement" >&2; exit 1; }
exec 4>&-
exec 3>&-
for _ in $(seq 1 15); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
if kill -0 "$pid" 2>/dev/null; then echo "FAIL: stderr logger blocked server shutdown" >&2; exit 1; fi
wait "$pid" 2>/dev/null || true
pid=
echo "   ✓ the watchdog retired the child with stderr still unread"

echo "✅ stuck-call test passed"
