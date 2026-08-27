#!/usr/bin/env bash
# Exercise the real macOS signed-helper launch path against the harmless fixture.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  echo "debugger live integration skipped: macOS arm64 gate only"
  exit 0
fi

BIN="${MCP_STDIO_BIN:-${SERVER_BIN:-../target/debug/ida-mcp}}"
FIXTURE="${DEBUGGER_FIXTURE:-fixtures/mini}"
FIXTURE_IDB="${DEBUGGER_FIXTURE_IDB:-fixtures/mini.i64}"
REQUIRE_READY="${DEBUGGER_REQUIRE_READY:-0}"
[[ -x "$BIN" ]] || { echo "missing server binary: $BIN" >&2; exit 1; }
[[ -x "$FIXTURE" ]] || { echo "missing executable fixture: $FIXTURE" >&2; exit 1; }
[[ -f "$FIXTURE_IDB" ]] || { echo "missing IDB fixture: $FIXTURE_IDB" >&2; exit 1; }
[[ "$REQUIRE_READY" == "0" || "$REQUIRE_READY" == "1" ]] || {
  echo "DEBUGGER_REQUIRE_READY must be 0 or 1" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || { echo "jq is required for debugger live test" >&2; exit 1; }

tmpdir="$(mktemp -d)"
fifo="$tmpdir/in.fifo"
stdout_log="$tmpdir/server.out"
stderr_log="$tmpdir/server.err"
server_pid=""
debuggee_pid=""
source_closed=0

cleanup() {
  { exec 3>&-; } 2>/dev/null || true
  if [[ -n "${debuggee_pid:-}" ]]; then
    kill -KILL "$debuggee_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

cp "$FIXTURE_IDB" "$tmpdir/debugger.i64"
fixture_path="$(cd "$(dirname "$FIXTURE")" && pwd -P)/$(basename "$FIXTURE")"
cp "$FIXTURE" "$tmpdir/external-debuggee"
chmod 0755 "$tmpdir/external-debuggee"
external_fixture_path="$(cd "$tmpdir" && pwd -P)/external-debuggee"
mkfifo "$fifo"
RUST_LOG="${RUST_LOG:-ida_mcp=info}" "$BIN" --workspace --workspace-max-workers 2 \
  --enable-debugger \
  <"$fifo" >"$stdout_log" 2>"$stderr_log" &
server_pid=$!
exec 3>"$fifo"

send() { printf '%s\n' "$1" >&3; }

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

find_debuggee_pid() {
  ps -axo pid=,command= 2>/dev/null \
    | awk -v target="$external_fixture_path" '$2 == target { print $1; exit }'
}

wait_response() {
  local id="$1" timeout="${2:-90}" elapsed=0 line
  while (( elapsed < timeout * 10 )); do
    line="$(jq -cR "fromjson? | select(.id == $id and (has(\"result\") or has(\"error\")))" \
      "$stdout_log" 2>/dev/null | tail -1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
    if ! kill -0 "$server_pid" >/dev/null 2>&1; then
      echo "debugger server exited while waiting for response id=$id" >&2
      cat "$stdout_log" >&2
      cat "$stderr_log" >&2
      return 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
  done
  echo "timed out waiting for debugger response id=$id" >&2
  cat "$stderr_log" >&2
  return 1
}

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"debugger-live-test","version":"0.1"},"capabilities":{}}}'
wait_response 1 30 >/dev/null
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

open_request="$(jq -cn --arg path "$tmpdir/debugger.i64" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$path}}}')"
send "$open_request"
open_response="$(wait_response 2 120)"
assert_ok "open debugger database" "$open_response"
source_id="$(result_text <<<"$open_response" | jq -r '.database_id // empty')"
[[ -n "$source_id" ]] || { echo "open_idb did not return a database_id" >&2; exit 1; }

stop_without_session_request="$(jq -cn --arg id "$source_id" \
  '{jsonrpc:"2.0",id:14,method:"tools/call",params:{name:"debug_stop",arguments:{database_id:$id,timeout_secs:5}}}')"
send "$stop_without_session_request"
stop_without_session_response="$(wait_response 14 15)"
jq -e '
  .result.isError == true
  and (.result.content[0].text | contains("no active debugger session"))
' >/dev/null <<<"$stop_without_session_response" || {
  echo "debug_stop without a session did not fail before backend setup" >&2
  jq . <<<"$stop_without_session_response" >&2
  exit 1
}

modules_without_session_request="$(jq -cn --arg id "$source_id" \
  '{jsonrpc:"2.0",id:15,method:"tools/call",params:{name:"debug_modules",arguments:{database_id:$id}}}')"
send "$modules_without_session_request"
modules_without_session_response="$(wait_response 15 15)"
jq -e '
  .result.isError == true
  and (.result.content[0].text | contains("no active debugger session"))
' >/dev/null <<<"$modules_without_session_response" || {
  echo "debug_modules without a session did not fail before backend setup" >&2
  jq . <<<"$modules_without_session_response" >&2
  exit 1
}

launch_request="$(jq -cn --arg id "$source_id" --arg path "$fixture_path" \
  '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"debug_launch",arguments:{database_id:$id,path:$path,timeout_secs:10}}}')"
send "$launch_request"
launch_response="$(wait_response 3 30)"
assert_ok "launch debug target" "$launch_response"
launch_status="$(result_text <<<"$launch_response" | jq -r '.status')"
ready=0

case "$launch_status" in
  ready)
    ready=1
    modules_request="$(jq -cn --arg id "$source_id" \
      '{jsonrpc:"2.0",id:4,method:"tools/call",params:{name:"debug_modules",arguments:{database_id:$id}}}')"
    send "$modules_request"
    modules_response="$(wait_response 4 30)"
    assert_ok "enumerate runtime modules" "$modules_response"
    modules_text="$(result_text <<<"$modules_response")"
    jq -e --arg path "$fixture_path" \
      '.module_count > 0 and any(.modules[]; .path == $path)' \
      >/dev/null <<<"$modules_text" || {
      echo "FAIL: runtime modules did not include the launched fixture" >&2
      printf '%s\n' "$modules_text" >&2
      exit 1
    }

    module_output="$tmpdir/runtime-module.i64"
    open_module_request="$(jq -cn \
      --arg id "$source_id" --arg module "$fixture_path" --arg output "$module_output" \
      '{jsonrpc:"2.0",id:5,method:"tools/call",params:{name:"debug_open_module",arguments:{database_id:$id,module:$module,idb_out:$output,timeout_secs:120}}}')"
    send "$open_module_request"
    open_module_response="$(wait_response 5 180)"
    assert_ok "open runtime module database" "$open_module_response"
    module_text="$(result_text <<<"$open_module_response")"
    module_id="$(jq -r '.database_id // empty' <<<"$module_text")"
    [[ -n "$module_id" && "$module_id" != "$source_id" ]] || {
      echo "debug_open_module did not allocate a distinct database_id" >&2
      exit 1
    }
    jq -e --arg source "$source_id" --arg module "$fixture_path" '
      .status == "ready"
      and .source_database_id == $source
      and .module.path == $module
      and (.preferred_base_value | type == "number")
      and (.runtime_slide.signed | type == "string")
    ' >/dev/null <<<"$module_text" || {
      echo "FAIL: debug_open_module result shape mismatch" >&2
      printf '%s\n' "$module_text" >&2
      exit 1
    }
    resolve_request="$(jq -cn --arg id "$module_id" \
      '{jsonrpc:"2.0",id:6,method:"tools/call",params:{name:"resolve_function",arguments:{database_id:$id,name:"interesting_function"}}}')"
    send "$resolve_request"
    resolve_response="$(wait_response 6 30)"
    assert_ok "resolve symbol in runtime module database" "$resolve_response"
    resolve_text="$(result_text <<<"$resolve_response")"
    jq -e '.name == "interesting_function" and (.address | startswith("0x"))' \
      >/dev/null <<<"$resolve_text" || {
      echo "FAIL: interesting_function did not resolve in the module database" >&2
      printf '%s\n' "$resolve_text" >&2
      exit 1
    }

    modules_after_request="$(jq -cn --arg id "$source_id" \
      '{jsonrpc:"2.0",id:7,method:"tools/call",params:{name:"debug_modules",arguments:{database_id:$id}}}')"
    send "$modules_after_request"
    modules_after_response="$(wait_response 7 30)"
    assert_ok "source debugger survives module open" "$modules_after_response"

    stop_request="$(jq -cn --arg id "$source_id" \
      '{jsonrpc:"2.0",id:8,method:"tools/call",params:{name:"debug_stop",arguments:{database_id:$id,action:"auto",timeout_secs:10}}}')"
    send "$stop_request"
    stop_response="$(wait_response 8 30)"
    assert_ok "ownership-aware debugger stop" "$stop_response"
    stop_text="$(result_text <<<"$stop_response")"
    jq -e '.status == "ready" and .action == "terminate" and .process_state == "no_process"' \
      >/dev/null <<<"$stop_text" || {
      echo "FAIL: ownership-aware stop result shape mismatch" >&2
      printf '%s\n' "$stop_text" >&2
      exit 1
    }

    missing_attach_request="$(jq -cn --arg id "$source_id" \
      '{jsonrpc:"2.0",id:11,method:"tools/call",params:{name:"debug_attach",arguments:{database_id:$id,pid:2000000000,timeout_secs:5}}}')"
    send "$missing_attach_request"
    missing_attach_response="$(wait_response 11 15)"
    if ! jq -e '
      .result.isError == true
      and (.result.content[0].text | contains("user_action_required") | not)
    ' >/dev/null <<<"$missing_attach_response"; then
      echo "a nonexistent target was not reported as a debugger error" >&2
      jq . <<<"$missing_attach_response" >&2
      exit 1
    fi
    echo "   nonexistent attach target was not misreported as an authorization prompt"

    close_module_request="$(jq -cn --arg id "$module_id" \
      '{jsonrpc:"2.0",id:9,method:"tools/call",params:{name:"close_idb",arguments:{database_id:$id}}}')"
    send "$close_module_request"
    assert_ok "close runtime module database" "$(wait_response 9 30)"
    [[ -f "$module_output" ]] || {
      echo "closing the runtime module database did not materialize the requested IDB output" >&2
      exit 1
    }

    external_launch_request="$(jq -cn --arg id "$source_id" --arg path "$external_fixture_path" \
      '{jsonrpc:"2.0",id:12,method:"tools/call",params:{name:"debug_launch",arguments:{database_id:$id,path:$path,timeout_secs:10}}}')"
    send "$external_launch_request"
    external_launch_response="$(wait_response 12 30)"
    assert_ok "launch target for external-exit recovery" "$external_launch_response"
    external_launch_text="$(result_text <<<"$external_launch_response")"
    jq -e '.status == "ready"' >/dev/null <<<"$external_launch_text" || {
      echo "FAIL: external-exit recovery launch did not reach ready" \
        "(a second Take Control prompt for the copied debuggee may need approval)" >&2
      printf '%s\n' "$external_launch_text" >&2
      exit 1
    }

    for _ in 1 2 3 4 5 6 7 8 9 10; do
      debuggee_pid="$(find_debuggee_pid || true)"
      [[ -n "$debuggee_pid" ]] && break
      sleep 0.1
    done
    [[ -n "$debuggee_pid" ]] || {
      echo "could not identify the uniquely-copied debuggee process" >&2
      exit 1
    }
    kill -KILL "$debuggee_pid"
    sleep 1

    stop_source_after_kill="$(jq -cn --arg id "$source_id" \
      '{jsonrpc:"2.0",id:13,method:"tools/call",params:{name:"debug_stop",arguments:{database_id:$id,action:"auto",timeout_secs:10}}}')"
    send "$stop_source_after_kill"
    stop_after_kill_response="$(wait_response 13 30)"
    assert_ok "stop debugger after external target exit" "$stop_after_kill_response"
    stop_after_kill_text="$(result_text <<<"$stop_after_kill_response")"
    # Whether IDA has already processed the external exit when stop() polls is
    # a race: the NoProcess short-circuit reports already_stopped=true, while a
    # terminate that drains the pending exit event omits it. Both are correct
    # recoveries; the contract is that stop succeeds and ends with no process.
    jq -e '
      .status == "ready"
      and .action == "terminate"
      and .process_state == "no_process"
    ' >/dev/null <<<"$stop_after_kill_text" || {
      echo "FAIL: stop after external exit did not end ready/no_process" >&2
      printf '%s\n' "$stop_after_kill_text" >&2
      exit 1
    }

    close_source_after_kill="$(jq -cn --arg id "$source_id" \
      '{jsonrpc:"2.0",id:16,method:"tools/call",params:{name:"close_idb",arguments:{database_id:$id}}}')"
    send "$close_source_after_kill"
    assert_ok "close debugger database after external target exit" "$(wait_response 16 30)"
    source_closed=1
    debuggee_pid=""
    echo "   debugger launch, module-to-IDB open, terminal stop, and external-exit stop/close recovery passed"
    ;;
  user_action_required)
    launch_text="$(result_text <<<"$launch_response")"
    jq -e '.message | contains("Take Control")' >/dev/null <<<"$launch_text" || {
      echo "FAIL: user_action_required response did not mention Take Control" >&2
      printf '%s\n' "$launch_text" >&2
      exit 1
    }
    launch_error="$(jq -r '.error // "unknown error"' <<<"$launch_text")"
    echo "   signed helper reached macOS authorization gate and returned user_action_required: $launch_error"
    ;;
  *)
    echo "unexpected debugger launch status: $launch_status" >&2
    jq . <<<"$launch_response" >&2
    exit 1
    ;;
esac

if [[ "$source_closed" == "0" ]]; then
  close_source_request="$(jq -cn --arg id "$source_id" \
    '{jsonrpc:"2.0",id:10,method:"tools/call",params:{name:"close_idb",arguments:{database_id:$id}}}')"
  send "$close_source_request"
  assert_ok "close debugger database" "$(wait_response 10 30)"
fi
if [[ "$REQUIRE_READY" == "1" && "$ready" != "1" ]]; then
  echo "debugger live integration requires an authorized ready lifecycle" >&2
  exit 1
fi
echo "debugger live integration passed"
