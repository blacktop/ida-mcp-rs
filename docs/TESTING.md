# Testing

## Run tests

```bash
just test         # Stdio JSONL integration test
just test-http    # HTTP/SSE integration test
just test-script  # IDAPython script execution test
just test-dsc /path/to/dyld_shared_cache_arm64e  # DSC loading test
just cargo-test   # Unit tests (no IDA required)
```

All integration tests require IDA Pro with a valid license. Run `cargo build` first.

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

**Script test** (`just test-script`)
- Opens a binary, then runs inline Python via `run_script`
- Verifies stdout/stderr capture
- Verifies Python error reporting (division by zero)
- Verifies file-based script execution (`.py` file path)

**DSC test** (`just test-dsc <path>`)
- Requires a real `dyld_shared_cache_arm64e` file
- Tests both sync (pre-existing `.i64`) and async (background `idat`) paths
- Polls `task_status` until completion
- Verifies the database is usable after loading (`list_functions`)

**Unit tests** (`just cargo-test`)
- `src/dsc.rs` — file type strings, idat args, script generation, Python string escaping
- `src/server/task.rs` — task registry lifecycle, deduplication, cancellation, ISO timestamps

## Test fixture

Tests use `test/fixtures/mini.c`, a minimal C program compiled into a Mach-O binary.
The tests open the raw binary via `open_idb` (IDA auto-analyzes and writes an .i64 alongside).
