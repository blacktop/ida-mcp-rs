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
server2_pid=""
debuggee_pid=""
debuggee2_pid=""
helper2_pid=""
source_closed=0

cleanup() {
  { exec 3>&-; } 2>/dev/null || true
  { exec 4>&-; } 2>/dev/null || true
  # Orphaned helpers hold inherited fifo write fds; they must die before the
  # servers can see stdin EOF and finish their runtime shutdown.
  for victim in "${debuggee_pid:-}" "${debuggee2_pid:-}" "${helper2_pid:-}"; do
    [[ -n "$victim" ]] && kill -KILL "$victim" >/dev/null 2>&1 || true
  done
  for srv in "${server_pid:-}" "${server2_pid:-}"; do
    [[ -n "$srv" ]] || continue
    kill "$srv" >/dev/null 2>&1 || true
    for _ in $(seq 1 50); do
      kill -0 "$srv" >/dev/null 2>&1 || break
      sleep 0.1
    done
    # A leaked pipe fd anywhere in the process tree can pin the server's
    # stdin read past its graceful shutdown; never hang the harness on it.
    kill -KILL "$srv" >/dev/null 2>&1 || true
    wait "$srv" >/dev/null 2>&1 || true
  done
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
    second_start_request="$(jq -cn --arg id "$source_id" \
      '{jsonrpc:"2.0",id:17,method:"tools/call",params:{name:"debug_attach",arguments:{database_id:$id,pid:2000000000,timeout_secs:5}}}')"
    send "$second_start_request"
    second_start_response="$(wait_response 17 15)"
    jq -e '
      .result.isError == true
      and (.result.content[0].text | contains("debugger session is already active"))
    ' >/dev/null <<<"$second_start_response" || {
      echo "FAIL: a second debugger start was not rejected before changing ownership" >&2
      jq . <<<"$second_start_response" >&2
      exit 1
    }

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
    module_segments_request="$(jq -cn --arg id "$module_id" \
      '{jsonrpc:"2.0",id:20,method:"tools/call",params:{name:"segments",arguments:{database_id:$id}}}')"
    send "$module_segments_request"
    module_segments_response="$(wait_response 20 30)"
    assert_ok "inspect runtime module segments" "$module_segments_response"
    module_segments_text="$(result_text <<<"$module_segments_response")"
    # IDA 9.4 omits this fixture's Mach-O __PAGEZERO from the IDB segment
    # list. The exact PAGEZERO exclusion is pinned by the Rust unit test;
    # live coverage verifies that the reported base names a loaded segment
    # instead of an unmapped/zero address.
    jq -e \
      --arg preferred "$(jq -r '.preferred_base' <<<"$module_text")" \
      --argjson preferred_value "$(jq '.preferred_base_value' <<<"$module_text")" '
      $preferred_value > 0
      and any(.[];
        .start == $preferred
        and (.name | ascii_upcase) != "__PAGEZERO"
        and (.permissions | test("[^-]"))
      )
    ' >/dev/null <<<"$module_segments_text" || {
      echo "FAIL: runtime preferred base is not a loaded Mach-O segment" >&2
      printf '%s\n' "$module_text" >&2
      printf '%s\n' "$module_segments_text" >&2
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

    close_module_request="$(jq -cn --arg id "$module_id" \
      '{jsonrpc:"2.0",id:9,method:"tools/call",params:{name:"close_idb",arguments:{database_id:$id}}}')"
    send "$close_module_request"
    assert_ok "close runtime module database" "$(wait_response 9 30)"
    [[ -f "$module_output" ]] || {
      echo "closing the runtime module database did not materialize the requested IDB output" >&2
      exit 1
    }

    modules_after_request="$(jq -cn --arg id "$source_id" \
      '{jsonrpc:"2.0",id:7,method:"tools/call",params:{name:"debug_modules",arguments:{database_id:$id}}}')"
    send "$modules_after_request"
    modules_after_response="$(wait_response 7 30)"
    assert_ok "source debugger survives module open" "$modules_after_response"

    # Select a module that the debugger reports but the filesystem does not:
    # on modern macOS this is the public shape of a dyld-cache-backed system
    # library. debug_open_module must resolve it without an extracted dylib or
    # an idat subprocess.
    cache_module=""
    while IFS= read -r candidate; do
      if [[ "$candidate" == /* && ! -f "$candidate" ]]; then
        cache_module="$candidate"
        break
      fi
    done < <(jq -r '.modules[].path // empty' <<<"$modules_text")
    [[ -n "$cache_module" ]] || {
      echo "FAIL: debugger reported no cache-backed runtime module for DSC coverage" >&2
      printf '%s\n' "$modules_text" >&2
      exit 1
    }

    cache_module_output="$tmpdir/runtime-cache-module.i64"
    cache_open_request="$(jq -cn \
      --arg id "$source_id" --arg module "$cache_module" --arg output "$cache_module_output" \
      '{jsonrpc:"2.0",id:18,method:"tools/call",params:{name:"debug_open_module",arguments:{database_id:$id,module:$module,idb_out:$output,timeout_secs:600}}}')"
    send "$cache_open_request"
    cache_open_response="$(wait_response 18 660)"
    assert_ok "open cache-backed runtime module database" "$cache_open_response"
    cache_module_text="$(result_text <<<"$cache_open_response")"
    cache_module_id="$(jq -r '.database_id // empty' <<<"$cache_module_text")"
    jq -e --arg source "$source_id" --arg module "$cache_module" '
      .status == "ready"
      and .source_database_id == $source
      and .module.path == $module
      and .module_source == "dyld_shared_cache"
      and (.dsc_image.name | type == "string")
      and .preferred_base_value == .dsc_image.address_value
      and (.runtime_slide.signed | type == "string")
    ' >/dev/null <<<"$cache_module_text" || {
      echo "FAIL: cache-backed debug_open_module result shape mismatch" >&2
      printf '%s\n' "$cache_module_text" >&2
      exit 1
    }
    cache_close_request="$(jq -cn --arg id "$cache_module_id" \
      '{jsonrpc:"2.0",id:19,method:"tools/call",params:{name:"close_idb",arguments:{database_id:$id}}}')"
    send "$cache_close_request"
    assert_ok "close cache-backed runtime module database" "$(wait_response 19 60)"
    [[ -f "$cache_module_output" ]] || {
      echo "cache-backed runtime module did not materialize the requested IDB output" >&2
      exit 1
    }

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

    # Worker-loss reaping uses a second server with healthy idle eviction
    # disabled. This proves transport maintenance is independent of TTL and
    # covers terminal worker loss only. A target killed outside ida-mcp is a
    # documented limitation, not an oracle: IDA's process state is a cached
    # getter, so nothing can observe that exit until a call drains the
    # pending debug event.
    cp "$FIXTURE" "$tmpdir/external-debuggee-2"
    chmod 0755 "$tmpdir/external-debuggee-2"
    external2_path="$(cd "$tmpdir" && pwd -P)/external-debuggee-2"
    fifo2="$tmpdir/in2.fifo"
    stdout2_log="$tmpdir/server2.out"
    stderr2_log="$tmpdir/server2.err"
    mkfifo "$fifo2"
    RUST_LOG="${RUST_LOG:-ida_mcp=info}" "$BIN" --workspace --workspace-max-workers 2 \
      --enable-debugger --workspace-idle-timeout-secs 0 \
      <"$fifo2" >"$stdout2_log" 2>"$stderr2_log" &
    server2_pid=$!
    exec 4>"$fifo2"
    send2() { printf '%s\n' "$1" >&4; }
    wait_response2() {
      local id="$1" timeout="${2:-30}" elapsed=0 line
      while ((elapsed < timeout * 10)); do
        line="$(jq -cR "fromjson? | select(.id == $id and (has(\"result\") or has(\"error\")))" \
          "$stdout2_log" 2>/dev/null | tail -1 || true)"
        if [[ -n "$line" ]]; then
          printf '%s\n' "$line"
          return 0
        fi
        if ! kill -0 "$server2_pid" >/dev/null 2>&1; then
          echo "reaper-test server exited while waiting for response id=$id" >&2
          cat "$stderr2_log" >&2
          return 1
        fi
        sleep 0.1
        elapsed=$((elapsed + 1))
      done
      echo "timed out waiting for reaper-test response id=$id" >&2
      cat "$stderr2_log" >&2
      return 1
    }

    send2 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"debugger-reap-test","version":"0.1"},"capabilities":{}}}'
    wait_response2 1 30 >/dev/null
    send2 '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

    # Open a fresh lease on the same server, then kill the pooled worker
    # itself (not the debuggee) with no further calls on its database. This
    # preserves the separate terminal-transport-loss oracle.
    cp "$FIXTURE_IDB" "$tmpdir/debugger3.i64"
    open3_request="$(jq -cn --arg path "$tmpdir/debugger3.i64" \
      '{jsonrpc:"2.0",id:5,method:"tools/call",params:{name:"open_idb",arguments:{path:$path}}}')"
    send2 "$open3_request"
    open3_response="$(wait_response2 5 120)"
    assert_ok "open worker-loss reaper database" "$open3_response"
    worker_reap_id="$(result_text <<<"$open3_response" | jq -r '.database_id // empty')"
    [[ -n "$worker_reap_id" ]] || {
      echo "worker-loss reaper open returned no database_id" >&2
      exit 1
    }
    launch3_request="$(jq -cn --arg id "$worker_reap_id" --arg path "$external2_path" \
      '{jsonrpc:"2.0",id:6,method:"tools/call",params:{name:"debug_launch",arguments:{database_id:$id,path:$path,timeout_secs:10}}}')"
    send2 "$launch3_request"
    launch3_response="$(wait_response2 6 30)"
    assert_ok "launch target for out-of-band worker death" "$launch3_response"
    jq -e '.status == "ready"' >/dev/null \
      <<<"$(result_text <<<"$launch3_response")" || {
      echo "FAIL: worker-loss launch did not reach ready" >&2
      result_text <<<"$launch3_response" >&2
      exit 1
    }

    # Capture the whole helper chain BEFORE killing the worker: SIGKILLing it
    # orphans its mac_server helper (and the suspended debuggee), and the
    # orphaned helper holds inherited fifo write fds that would otherwise
    # keep both servers' stdin open forever.
    for _ in $(seq 1 20); do
      debuggee2_pid="$(ps -axo pid=,command= 2>/dev/null \
        | awk -v target="$external2_path" '$2 == target { print $1; exit }' || true)"
      [[ -n "$debuggee2_pid" ]] && break
      sleep 0.1
    done
    [[ -n "$debuggee2_pid" ]] || {
      echo "could not identify the worker-loss debuggee" >&2
      exit 1
    }
    worker2_pid="$(ps -axo pid=,ppid=,command= 2>/dev/null \
      | awk -v ppid="$server2_pid" '$2 == ppid && /worker/ { print $1; exit }' || true)"
    [[ -n "$worker2_pid" ]] || {
      echo "could not identify the pooled worker child of the reaper-test server" >&2
      exit 1
    }
    helper2_pid="$(ps -axo pid=,ppid=,command= 2>/dev/null \
      | awk -v ppid="$worker2_pid" '$2 == ppid && /mac_server/ { print $1; exit }' || true)"
    kill -KILL "$worker2_pid"

    reap_seen=0
    for _ in $(seq 1 200); do
      if grep -q "workspace worker exited out of band" "$stderr2_log" 2>/dev/null \
        && grep -q "removing terminal workspace database" "$stderr2_log" 2>/dev/null; then
        reap_seen=1
        break
      fi
      sleep 0.1
    done
    [[ "$reap_seen" == "1" ]] || {
      echo "FAIL: reaper did not clear the debug-pinned lease after out-of-band worker death" >&2
      tail -40 "$stderr2_log" >&2
      exit 1
    }

    # Characterize (do not assert) what survives an out-of-band worker kill:
    # SIGKILL bypasses DebuggerRuntime::drop, so the helper is reparented
    # rather than terminated and can keep the target alive. Either outcome is
    # reported for the record. The matching server contract — that a retired
    # debug-pinned worker reports a lost session and never claims the debuggee
    # ended — is asserted deterministically by the unit test
    # `retiring_a_debugger_worker_reports_session_loss_truthfully`.
    helper_alive=0
    debuggee_alive=0
    [[ -n "${helper2_pid:-}" ]] && kill -0 "$helper2_pid" >/dev/null 2>&1 && helper_alive=1
    [[ -n "${debuggee2_pid:-}" ]] && kill -0 "$debuggee2_pid" >/dev/null 2>&1 && debuggee_alive=1
    if [[ "$helper_alive" == "1" || "$debuggee_alive" == "1" ]]; then
      echo "   worker SIGKILL orphans its debug helper (helper_alive=$helper_alive," \
        "debuggee_alive=$debuggee_alive) — ida-mcp must not claim the debuggee ended"
    else
      echo "   worker SIGKILL also ended the debug helper and target"
    fi

    # Retire the orphaned helper chain now that the oracle has its evidence;
    # their inherited fifo fds must not outlive this section.
    for orphan in "${helper2_pid:-}" "${debuggee2_pid:-}"; do
      [[ -n "$orphan" ]] && kill -KILL "$orphan" >/dev/null 2>&1 || true
    done
    debuggee2_pid=""
    helper2_pid=""

    status2_request="$(jq -cn --arg id "$worker_reap_id" \
      '{jsonrpc:"2.0",id:7,method:"tools/call",params:{name:"debug_modules",arguments:{database_id:$id}}}')"
    send2 "$status2_request"
    status2_response="$(wait_response2 7 15)"
    jq -e '
      .error.code == -32602 and (.error.message | contains("unknown or expired"))
    ' >/dev/null <<<"$status2_response" || {
      echo "FAIL: reaped database id was not invalidated" >&2
      jq . <<<"$status2_response" >&2
      exit 1
    }
    echo "   out-of-band worker death cleared the debug pin and reaped the database"
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
