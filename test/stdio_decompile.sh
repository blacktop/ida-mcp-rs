#!/usr/bin/env bash
# Regression test for the IDA 9.4 final Hex-Rays API magic. The SDK's
# init_hexrays_plugin() is inline, so a stale binding can open an IDB but
# report that the installed decompiler is unavailable.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-mcp}}"
IDB_PATH="${IDB_PATH:-fixtures/mini.i64}"

[[ -x "$BIN" ]] || { echo "missing server binary: $BIN" >&2; exit 1; }
[[ -f "$IDB_PATH" ]] || { echo "missing IDB fixture: $IDB_PATH" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

tmpdir="$(mktemp -d)"
fifo_in="$tmpdir/in.fifo"
log="$tmpdir/server.log"
server_pid=""

cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

is_windows() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
    *) return 1 ;;
  esac
}

response_from_log() {
  grep -m1 "\"id\":$1[,}]" "$log" 2>/dev/null | grep '"jsonrpc"' || true
}

content_text() {
  jq -r '.result.content[0].text // empty'
}

if is_windows; then
  # MSYS FIFOs do not reliably expose native Windows process responses until
  # EOF. Use a regular pipe and the stable main address in the checked-in IDB.
  main_address="0x1000004f0"
  {
    printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"decompile-regression","version":"0.1"},"capabilities":{}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
      "$(printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"open_idb\",\"arguments\":{\"path\":\"%s\"}}}' "$IDB_PATH")" \
      '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_funcs","arguments":{"background":false,"timeout_secs":60}}}' \
      '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"resolve_function","arguments":{"name":"main"}}}' \
      "$(printf '{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"decompile\",\"arguments\":{\"address\":\"%s\"}}}' "$main_address")" \
      '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
    sleep 30
  } | RUST_LOG="${RUST_LOG:-ida_mcp=trace}" "$BIN" >"$log" 2>&1 || true

  open_response=$(response_from_log 2)
  analysis_response=$(response_from_log 3)
  resolved_address=$(response_from_log 4 | content_text | jq -r '.address // empty')
  decompile_response=$(response_from_log 5)

  if [[ -z "$open_response" || -z "$analysis_response" || -z "$decompile_response" ]]; then
    echo "missing Windows decompile regression response" >&2
    cat "$log" >&2
    exit 1
  fi
  if ! echo "$open_response" | jq -e '.result.isError == false' >/dev/null; then
    echo "open_idb failed" >&2
    echo "$open_response" | jq . >&2
    exit 1
  fi
  if ! echo "$analysis_response" | jq -e '.result.isError == false' >/dev/null; then
    echo "analyze_funcs failed" >&2
    echo "$analysis_response" | jq . >&2
    exit 1
  fi
  if [[ "$resolved_address" != "$main_address" ]]; then
    echo "resolve_function returned $resolved_address, expected $main_address" >&2
    exit 1
  fi
  if ! echo "$decompile_response" | jq -e '.result.isError == false' >/dev/null; then
    echo "decompile failed for main at $main_address" >&2
    echo "$decompile_response" | jq . >&2
    exit 1
  fi

  pseudocode=$(echo "$decompile_response" | content_text)
  if [[ -z "$pseudocode" ]]; then
    echo "decompile returned empty pseudocode for main at $main_address" >&2
    exit 1
  fi

  echo "Decompiled main at $main_address"
  exit 0
fi

mkfifo "$fifo_in"
RUST_LOG="${RUST_LOG:-ida_mcp=trace}" "$BIN" <"$fifo_in" >"$log" 2>&1 &
server_pid=$!
exec 3>"$fifo_in"

send() {
  echo "$1" >&3
}

wait_response() {
  local target_id="$1"
  local timeout="${2:-60}"
  local elapsed=0

  while [[ "$elapsed" -lt "$timeout" ]]; do
    local line
    line=$(response_from_log "$target_id")
    if [[ -n "$line" ]]; then
      echo "$line"
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "server exited while waiting for response $target_id" >&2
      cat "$log" >&2
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "timed out waiting for response $target_id" >&2
  cat "$log" >&2
  return 1
}

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"decompile-regression","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
wait_response 1 10 >/dev/null

open_request=$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_idb","arguments":{"path":"%s"}}}' "$IDB_PATH")
send "$open_request"
open_response=$(wait_response 2 60)
if ! echo "$open_response" | jq -e '.result.isError == false' >/dev/null; then
  echo "open_idb failed" >&2
  echo "$open_response" | jq . >&2
  exit 1
fi

send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_funcs","arguments":{"background":false,"timeout_secs":60}}}'
analysis_response=$(wait_response 3 90)
if ! echo "$analysis_response" | jq -e '.result.isError == false' >/dev/null; then
  echo "analyze_funcs failed" >&2
  echo "$analysis_response" | jq . >&2
  exit 1
fi

send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"resolve_function","arguments":{"name":"main"}}}'
address=$(wait_response 4 30 | content_text | jq -r '.address // empty')
if [[ -z "$address" || "$address" == "null" ]]; then
  echo "resolve_function did not return main's address" >&2
  exit 1
fi

decompile_request=$(printf '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"decompile","arguments":{"address":"%s"}}}' "$address")
send "$decompile_request"
decompile_response=$(wait_response 5 60)
if ! echo "$decompile_response" | jq -e '.result.isError == false' >/dev/null; then
  echo "decompile failed for main at $address" >&2
  echo "$decompile_response" | jq . >&2
  exit 1
fi

pseudocode=$(echo "$decompile_response" | content_text)
if [[ -z "$pseudocode" ]]; then
  echo "decompile returned empty pseudocode for main at $address" >&2
  exit 1
fi

send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 10 >/dev/null

echo "Decompiled main at $address"
