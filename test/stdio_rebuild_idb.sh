#!/usr/bin/env bash
# Verify open_idb behavior for raw inputs when a generated .i64 already exists.
#
# Three phases, one tmpdir-isolated fixture per run:
#   1. Open raw, rename interesting_function -> $CANARY, close -> creates .i64
#      with the rename packed into it.
#   2. Re-open the SAME raw path with no rebuild flag. The handler must reuse
#      the existing .i64 (proven by the "Reusing existing IDA database for raw
#      input" log line) and the renamed function must still resolve.
#   3. Re-open raw with rebuild=true. The handler must overwrite the .i64
#      (proven by the "Rebuilding raw input and overwriting" log line),
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
assert_log_absent "Reusing existing IDA database for raw input"
assert_log_absent "Rebuilding raw input and overwriting"

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
assert_log_contains "Reusing existing IDA database for raw input"
assert_log_absent "Rebuilding raw input and overwriting"
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
assert_log_contains "Rebuilding raw input and overwriting"
assert_log_absent "Reusing existing IDA database for raw input"
echo "   ✓ rebuild path taken (log line present)"

send "$(jq -cn --arg name "$CANARY" \
  '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"resolve_function",arguments:{name:$name}}}')"
assert_err "Phase 3 canary lookup" "$(wait_response 3 15)"
echo "   ✓ $CANARY no longer resolves (rebuilt from scratch)"

send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"resolve_function","arguments":{"name":"interesting_function"}}}'
orig_resp="$(wait_response 4 15)"
assert_ok "Phase 3 original lookup" "$orig_resp"
echo "   ✓ interesting_function resolves again"

send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 30 >/dev/null
stop_server

echo "✅ rebuild-idb test passed"
