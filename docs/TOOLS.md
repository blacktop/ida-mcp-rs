# Tools

> Auto-generated from `src/tool_registry.rs`. Do not edit by hand.
> Regenerate with: `cargo run --bin gen_tools_doc -- docs/TOOLS.md`.

## Discovery Workflow

- `tools/list` returns the full tool set (currently 68 tools)
- `tool_catalog(query=...)` searches all tools by intent
- `tool_help(name=...)` returns full documentation and schema
- Call `close_idb` when done to release locks; in multi-client servers coordinate before closing (HTTP/SSE requires close_token from open_idb)

Note: `open_idb` accepts .i64/.idb or raw binaries (Mach-O/ELF/PE). Raw binaries are
auto-analyzed and saved as a .i64 alongside the input. If a sibling .dSYM
exists and no .i64 is present, its DWARF debug info is loaded automatically.

## Core (`core`)

Database open/close and discovery tools

| Tool | Description |
|------|-------------|
| `analysis_status` | Report auto-analysis status |
| `close_idb` | Close the current database (release locks) |
| `idb_meta` | Get database metadata and summary |
| `load_debug_info` | Load external debug info (e.g., dSYM/DWARF) |
| `open_dsc` | Open a dyld_shared_cache and load a single module |
| `open_idb` | Open an IDA database or raw binary |
| `task_status` | Check status of a background task (e.g. DSC loading) |
| `tool_catalog` | Discover available tools by query or category |
| `tool_help` | Get full documentation for a tool |

## Functions (`functions`)

List, search, and resolve functions

| Tool | Description |
|------|-------------|
| `analyze_funcs` | Run auto-analysis and wait for completion |
| `function_at` | Find the function containing an address |
| `list_funcs` | Alias of list_functions |
| `list_functions` | List functions with pagination and filtering |
| `lookup_funcs` | Batch lookup multiple functions by name |
| `resolve_function` | Find function address by name |

## Disassembly (`disassembly`)

Disassemble code at addresses

| Tool | Description |
|------|-------------|
| `disasm` | Disassemble instructions at an address |
| `disasm_by_name` | Disassemble a function by name |
| `disasm_function_at` | Disassemble the function containing an address |

## Decompile (`decompile`)

Decompile functions to pseudocode (requires Hex-Rays)

| Tool | Description |
|------|-------------|
| `decompile` | Decompile function to C pseudocode |
| `pseudocode_at` | Get pseudocode for specific address/range |

## Xrefs (`xrefs`)

Cross-reference analysis (xrefs to/from)

| Tool | Description |
|------|-------------|
| `xref_matrix` | Build xref matrix between addresses |
| `xrefs_from` | Find all references FROM an address |
| `xrefs_to` | Find all references TO an address |
| `xrefs_to_field` | Xrefs to a struct field |
| `xrefs_to_string` | Find xrefs to strings matching a query |

## Control Flow (`control_flow`)

Basic blocks, call graphs, control flow

| Tool | Description |
|------|-------------|
| `basic_blocks` | Get basic blocks of a function |
| `callees` | Find all functions called by a function |
| `callers` | Find all callers of a function |
| `callgraph` | Build call graph from a function |
| `find_paths` | Find control-flow paths between two addresses |

## Memory (`memory`)

Read bytes, strings, and data

| Tool | Description |
|------|-------------|
| `get_bytes` | Read raw bytes from an address |
| `get_global_value` | Read global value by name or address |
| `get_string` | Read string at an address |
| `get_u16` | Read 16-bit value |
| `get_u32` | Read 32-bit value |
| `get_u64` | Read 64-bit value |
| `get_u8` | Read 8-bit value |
| `int_convert` | Convert integers between bases |

## Search (`search`)

Search for bytes, strings, patterns

| Tool | Description |
|------|-------------|
| `analyze_strings` | Analyze strings with filtering |
| `find_bytes` | Search for byte pattern |
| `find_insn_operands` | Find instructions by operand substring |
| `find_insns` | Find instruction sequences by mnemonic |
| `find_string` | Find strings matching a query |
| `search` | Search for text or immediate values |
| `strings` | List all strings in the database |

## Metadata (`metadata`)

Database info, segments, imports, exports

| Tool | Description |
|------|-------------|
| `addr_info` | Resolve address to segment/function/symbol |
| `entrypoints` | List entry points |
| `export_funcs` | Export functions (JSON) |
| `exports` | List exported functions |
| `imports` | List imported functions |
| `list_globals` | List global variables |
| `segments` | List all segments |

## Types (`types`)

Types, structs, and stack variable info

| Tool | Description |
|------|-------------|
| `apply_types` | Apply a type to an address or stack variable |
| `declare_stack` | Declare a stack variable |
| `declare_type` | Declare a type in the local type library |
| `delete_stack` | Delete a stack variable |
| `infer_types` | Infer/guess type at an address |
| `local_types` | List local types |
| `read_struct` | Read a struct instance at an address |
| `search_structs` | Search structs by name |
| `stack_frame` | Get stack frame info |
| `struct_info` | Get struct info by name or ordinal |
| `structs` | List structs with pagination |

## Editing (`editing`)

Patching, renaming, and comment editing

| Tool | Description |
|------|-------------|
| `patch` | Patch bytes at an address |
| `patch_asm` | Patch instructions with assembly text |
| `rename` | Rename symbols |
| `set_comments` | Set comments at an address |

## Scripting (`scripting`)

Execute Python scripts via IDAPython

| Tool | Description |
|------|-------------|
| `run_script` | Execute Python code via IDAPython |

## Notes

- Many tools accept a single value or array (e.g., `"0x1000"` or `["0x1000", "0x2000"]`)
- String inputs may be comma-separated: `"0x1000, 0x2000"`
- Addresses accept hex (`0x1000`) or decimal (`4096`)
- Raw binaries are auto-analyzed on first open; `.i64` is saved alongside the input
