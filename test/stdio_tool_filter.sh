#!/usr/bin/env bash
# Server-side tool filtering (Phase 2a):
#   1. tools/list reflects --toolsets/--tools/--exclude-tools at the protocol level
#   2. calling a filter-disabled tool returns an "invalid_params"-flavored error
#   3. tool_catalog reports filtering_active when the filter narrows the set
#   4. tool_help for a filter-disabled tool returns the disabled-tool message
#   5. env vars mirror flags
#   6. flags override env vars
#
# No IDA database required — exercises the dispatch surface only.
set -euo pipefail

BIN="${MCP_STDIO_BIN:-../target/debug/ida-mcp}"

[[ -x "$BIN" ]] || { echo "missing $BIN" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

work="$(mktemp -d)"
fifo="$work/in.fifo"
log="$work/server.log"

cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "${pid:-}" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

start_server() {
  # Args are extra flags passed to `$BIN serve`. Caller sets any env vars
  # inline before the function call (bash inherits them into the spawned
  # process automatically).
  cleanup_stale_pid
  pid=
  rm -f "$fifo"
  mkfifo "$fifo"
  : > "$log"
  "$BIN" serve "$@" < "$fifo" > "$log" 2>&1 &
  pid=$!
  exec 3>"$fifo"
}

cleanup_stale_pid() {
  if [[ -n "${pid:-}" ]]; then
    exec 3>&- 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    pid=
  fi
}

send() { echo "$1" >&3; }

wait_response() {
  local target_id="$1" timeout="${2:-15}" elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    local line
    line=$(grep -m1 "\"id\":${target_id}[,}]" "$log" 2>/dev/null | grep '"jsonrpc"' || true)
    [[ -n "$line" ]] && { echo "$line"; return 0; }
    sleep 1; elapsed=$((elapsed + 1))
  done
  echo "timeout id=$target_id" >&2
  echo "--- server log ---" >&2; cat "$log" >&2
  return 1
}

text() { jq -r '.result.content[0].text // empty'; }

initialize() {
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"filter-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 10 >/dev/null
}

# --- Phase A: --toolsets=core --exclude-tools=run_script via flags ---
# (run_script is in the `scripting` category, so --toolsets=core already
# omits it; --exclude-tools is redundant here but exercises the deny-list path.)
echo "── Phase A: flag-based filter (toolsets=core, exclude=run_script) ──"
start_server --toolsets=core --exclude-tools=run_script
initialize

send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)

echo "$names" | grep -q '^open_idb$' || { echo "FAIL: open_idb (core) missing"; exit 1; }
echo "$names" | grep -q '^tool_catalog$' || { echo "FAIL: tool_catalog (core) missing"; exit 1; }
if echo "$names" | grep -q '^run_script$'; then
  echo "FAIL: run_script should be filtered out" >&2; exit 1
fi
if echo "$names" | grep -q '^decompile$'; then
  echo "FAIL: decompile (decompile category) leaked into core-only" >&2; exit 1
fi
echo "   ✓ tools/list narrowed to core minus run_script"

# Calling a filter-disabled tool must return a JSON-RPC error ("invalid_params"
# message field), not a regular CallToolResult.
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"print(1)"}}}'
deny_resp=$(wait_response 3 10)
err_msg=$(echo "$deny_resp" | jq -r '.error.message // empty')
[[ -n "$err_msg" ]] || { echo "FAIL: expected JSON-RPC error for disabled tool, got $deny_resp" >&2; exit 1; }
echo "$err_msg" | grep -qi "disabled by current filter" || {
  echo "FAIL: error message should mention 'disabled by current filter'; got: $err_msg" >&2
  exit 1
}
echo "   ✓ run_script returned disabled-tool error"

# tool_catalog must report filtering_active and an enabled count.
send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"tool_catalog","arguments":{}}}'
cat_text=$(wait_response 4 10 | text)
echo "$cat_text" | jq -e '.filtering_active == true' >/dev/null || {
  echo "FAIL: tool_catalog should set filtering_active=true; got: $cat_text" >&2
  exit 1
}
echo "$cat_text" | jq -e '.enabled_tool_count and (.enabled_tool_count|tonumber > 0)' >/dev/null || {
  echo "FAIL: tool_catalog should include enabled_tool_count; got: $cat_text" >&2
  exit 1
}
echo "   ✓ tool_catalog reports filtering_active + enabled_tool_count"

# tool_help for a filtered-out tool must return the disabled message,
# not its schema.
send '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"tool_help","arguments":{"name":"run_script"}}}'
help_text=$(wait_response 5 10 | text)
echo "$help_text" | jq -e '.filtering_active == true and (.error | test("disabled by current filter"))' >/dev/null || {
  echo "FAIL: tool_help should report disabled-by-filter for run_script; got: $help_text" >&2
  exit 1
}
echo "   ✓ tool_help refuses to leak schema for filtered-out tool"

# --- Phase B: env-var mirror (no flags, only IDA_MCP_*) ---
echo "── Phase B: env-var mirror (IDA_MCP_TOOLSETS=core, IDA_MCP_EXCLUDE_TOOLS=run_script) ──"
IDA_MCP_TOOLSETS=core IDA_MCP_EXCLUDE_TOOLS=run_script start_server
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^open_idb$' || { echo "FAIL: env-var open_idb missing"; exit 1; }
if echo "$names" | grep -q '^run_script$'; then
  echo "FAIL: env-var IDA_MCP_EXCLUDE_TOOLS should drop run_script" >&2; exit 1
fi
echo "   ✓ env vars mirror flags"

# --- Phase B2: env-var mirror also applies to the default stdio command ---
# Most installed-client configs run `ida-mcp` directly, relying on the default
# stdio server path instead of spelling out `ida-mcp serve`.
echo "── Phase B2: env-var mirror on default command (no explicit serve) ──"
cleanup_stale_pid
pid=
rm -f "$fifo"
mkfifo "$fifo"
: > "$log"
IDA_MCP_TOOLSETS=decompile "$BIN" < "$fifo" > "$log" 2>&1 &
pid=$!
exec 3>"$fifo"
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^decompile$' || { echo "FAIL: default-command env should expose decompile"; exit 1; }
echo "$names" | grep -q '^pseudocode_at$' || { echo "FAIL: default-command env should expose pseudocode_at"; exit 1; }
if echo "$names" | grep -q '^open_idb$'; then
  echo "FAIL: default-command IDA_MCP_TOOLSETS=decompile should not expose open_idb" >&2
  exit 1
fi
echo "   ✓ env vars apply when running ida-mcp without explicit serve"

# --- Phase C: flags override env vars ---
# Env says 'core' (12 tools); flag forces 'decompile' (smaller set).
# The decompile category should win and core tools should NOT appear.
echo "── Phase C: --toolsets=decompile flag overrides IDA_MCP_TOOLSETS=core ──"
IDA_MCP_TOOLSETS=core start_server --toolsets=decompile
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^decompile$' || { echo "FAIL: decompile category should be active"; exit 1; }
if echo "$names" | grep -q '^open_idb$'; then
  echo "FAIL: --toolsets=decompile flag should override IDA_MCP_TOOLSETS=core; open_idb leaked" >&2
  exit 1
fi
echo "   ✓ flags override env vars"

# --- Phase D: startup must reject unknown toolset ---
echo "── Phase D: startup rejects unknown toolset name ──"
if "$BIN" serve --toolsets=not_a_real_category < /dev/null > "$work/bad.log" 2>&1; then
  echo "FAIL: startup should reject unknown toolset" >&2
  cat "$work/bad.log" >&2
  exit 1
fi
grep -q "unknown toolset category" "$work/bad.log" || {
  echo "FAIL: error should mention 'unknown toolset category'; got: $(cat "$work/bad.log")" >&2
  exit 1
}
echo "   ✓ unknown toolset rejected at startup"

echo "✅ stdio tool-filter test passed"
