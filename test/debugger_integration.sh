#!/usr/bin/env bash
# Verify debugger capability gating and the non-invasive status surface.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-${SERVER_BIN:-../target/debug/ida-mcp}}"
[[ -x "$BIN" ]] || { echo "missing server binary: $BIN" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required for debugger test" >&2; exit 1; }

tmpdir="$(mktemp -d)"
server_pid=""
last_response=""

cleanup_server() {
  { exec 3>&-; } 2>/dev/null || true
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    server_pid=""
  fi
}

cleanup() {
  cleanup_server
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

wait_response() {
  local log="$1" id="$2" elapsed=0 line
  while (( elapsed < 300 )); do
    line="$(jq -cR "fromjson? | select(.id == $id and (has(\"result\") or has(\"error\")))" \
      "$log" 2>/dev/null | tail -1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
      echo "debugger test server exited while waiting for response id=$id" >&2
      cat "$log" >&2
      cat "$log.err" >&2 2>/dev/null || true
      return 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done
  echo "timed out waiting for debugger response id=$id" >&2
  return 1
}

start_server() {
  local name="$1"
  shift
  local fifo="$tmpdir/$name.fifo" log="$tmpdir/$name.out"
  mkfifo "$fifo"
  RUST_LOG="${RUST_LOG:-ida_mcp=info}" "$BIN" "$@" \
    <"$fifo" >"$log" 2>"$log.err" &
  server_pid=$!
  exec 3>"$fifo"
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"debugger-gate-test","version":"0.1"},"capabilities":{}}}' >&3
  wait_response "$log" 1 >/dev/null
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' >&3
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' >&3
  last_response="$(wait_response "$log" 2)"
}

start_server default
default_tools="$last_response"
jq -e 'all(.result.tools[]; (.name | startswith("debug_")) | not)' \
  >/dev/null <<<"$default_tools"
cleanup_server
echo "   default tools/list contains no debugger surface"

start_server enabled --enable-debugger
enabled_tools="$last_response"
if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  jq -e '
    any(.result.tools[]; .name == "debug_status")
    and any(.result.tools[]; .name == "debug_launch")
    and any(.result.tools[]; .name == "debug_modules")
    and all(.result.tools[]; .name != "debug_open_module")
  ' >/dev/null <<<"$enabled_tools"
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"debug_status","arguments":{}}}' >&3
  status="$(wait_response "$tmpdir/enabled.out" 3)"
  jq -e '
    .result.isError == false
    and (.result.content[0].text | fromjson
      | (.status == "ready" or .status == "user_action_required" or .status == "unavailable")
      and .platform == "macos"
      and .transport == "signed_loopback_helper"
      and .backend_selection == "opened_database_target"
      and (.backends | index("arm_mac") != null)
      and (.backends | index("mac") != null))
  ' >/dev/null <<<"$status"
  echo "   macOS opt-in status reports signed-helper readiness without opening IDA"
else
  jq -e 'all(.result.tools[]; (.name | startswith("debug_")) | not)' \
    >/dev/null <<<"$enabled_tools"
  echo "   unsupported platform keeps debugger tools unadvertised"
fi
cleanup_server

if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  start_server workspace --workspace --enable-debugger
  workspace_tools="$last_response"
  jq -e '
    any(.result.tools[];
      .name == "debug_open_module"
      and (.inputSchema.required | index("database_id") != null)
      and (.inputSchema.required | index("module") != null)
      and (.inputSchema.required | index("idb_out") != null))
  ' >/dev/null <<<"$workspace_tools"
  cleanup_server
  echo "   workspace opt-in advertises debug_open_module with required source and output"
fi

echo "debugger capability integration passed"
