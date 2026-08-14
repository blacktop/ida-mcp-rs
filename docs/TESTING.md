# Testing

## Run tests

```bash
just test         # Stdio JSONL integration test
just test-http    # HTTP/SSE integration test
just test-modern  # MCP 2026 discover/stateless lifecycle test
just test-script  # IDAPython script execution test
just test-elicitation # open_idb auto-background elicitation test
just test-session-cancel # legacy-session cancel-on-disconnect test
just test-http-startup # HTTP bind-failure exit status (no IDA license needed)
just test-dsc /path/to/dyld_shared_cache_arm64e  # DSC loading test
just cargo-test   # Unit tests (no IDA required)
```

All integration tests require IDA Pro with a valid license. Run `just build` first.

## What's tested

**Stdio test** (`just test`)
- MCP protocol handshake
- Tool discovery (`tool_catalog`, `tool_help`)
- Database operations (`open_idb`, `close_idb`, `idb_meta`, `analysis_status`)
- Analysis tools (`list_functions`, `resolve_function`, `disasm_by_name`, `find_insns`, `find_insn_operands`)
- Editing tools (`set_comments`, `rename`, `patch`, `patch_asm`)
- Types/stack tools (`declare_type`, `apply_types`, `infer_types`, `stack_frame`, `declare_stack`, `delete_stack`)
- Metadata tools (`segments`, `strings`, `imports`, `exports`, `structs`, `xrefs_to_field`, `search_structs`)

**HTTP test** (`just test-http`)
- Streamable HTTP transport with SSE
- `tools/list` returns the full tool list
- Database operations work over HTTP (`open_idb`, `list_functions`, `close_idb` with close_token)

**MCP 2026 test** (`just test-modern`)
- Exercises `server/discover`, `tools/list`, and `tools/call` over stdio
- Rejects MCP 2026 requests with incomplete required request metadata
- Exercises the same lifecycle over sessionless single-worker HTTP and verifies
  that no legacy session ID is created
- Verifies a legacy stdio task remains visible on the same connection when one
  request carries full routing metadata and the next omits it
- Verifies pooled HTTP advertises versions only through `2025-11-25`, rejects
  a `2026-07-28` request, and rejects sessionless inline-metadata tool calls
  that declare a legacy version

**Script test** (`just test-script`)
- Opens a binary, then runs inline Python via `run_script`
- Verifies stdout/stderr capture
- Verifies Python error reporting (division by zero)
- Verifies file-based script execution (`.py` file path)

**Elicitation test** (`just test-elicitation`)
- Creates a sparse Mach-O fixture just over 50 MiB
- Verifies `open_idb(auto_analyse=true)` silently routes analysis to a background task when the client has no elicitation capability
- Verifies an elicitation-capable client receives `elicitation/create`, accepts it, and gets `analysis_background=true` plus a pollable `analysis_task_id`
- Verifies MCP `2026-07-28` returns `input_required`, accepts the echoed
  integrity-protected `requestState` plus `inputResponses`, and completes the
  retried tool call

**Startup-failure test** (`just test-http-startup`)
- Squats a port with a pooled parent (binds in ms, takes no IDA license), then
  starts each HTTP topology against it
- Asserts single-worker HTTP exits nonzero, does not wedge (watchdog SIGKILL
  would show as 137), and releases its IDA worker loop
- Asserts pooled HTTP exits nonzero and never logs a clean stop it didn't achieve
- Needs no IDA license, database, or fixture

**Session-cancel test** (`just test-session-cancel`)
- Single-worker HTTP: a legacy session starts a slow foreground `open_idb`
  (observed via `recent_operations`), queues a background `analyze_funcs`
  behind it, then DELETEs the session
- Verifies a second legacy session cannot reuse the deduplicated task ID or
  poll the first session's task
- Verifies the server records owner cancellation only after the background
  operation settles and never records successful completion for that task

**DSC test** (`just test-dsc <path>`)
- Requires a real `dyld_shared_cache_arm64e` file
- Tests the native IDA 9.4 `dscu` path and legacy generated-`.i64` fallback where available
- Polls `task_status` until completion
- Verifies the database is usable after loading (`list_functions`)

**Unit tests** (`just cargo-test`)
- `src/dsc.rs` — file type strings, idat args, script generation, Python string escaping
- `src/server/task.rs` — task registry lifecycle, owner-scoped access and
  deduplication, bounded admission, cancellation, and ISO timestamps

## Test fixture

Tests use `test/fixtures/mini.c`, a minimal C program compiled into a Mach-O binary.
The tests open the raw binary via `open_idb` (IDA auto-analyzes and writes an .i64 alongside).
