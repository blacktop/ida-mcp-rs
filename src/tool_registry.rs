//! Tool registry for dynamic tool discovery.
//!
//! All tools are exposed in tools/list by default to support MCP clients that only
//! register tools at connection time. `tool_catalog` is still recommended for discovery.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// State boundary a tool operates against.
///
/// Runtime tools can execute without an open database. Database tools are
/// routed to the worker that owns the selected IDB (the implicit worker in the
/// default UX, or an explicit workspace database in workspace mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolScope {
    Runtime,
    Database,
}

/// Opt-in capabilities required before a tool may be advertised or called.
///
/// The fields are independent so future tools can require combinations such as
/// workspace + debugger. Existing tools use [`Self::BASELINE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRequirements {
    pub workspace: bool,
    pub debugger: bool,
    pub experimental: bool,
}

impl ToolRequirements {
    pub const BASELINE: Self = Self {
        workspace: false,
        debugger: false,
        experimental: false,
    };

    pub const DEBUGGER: Self = Self {
        workspace: false,
        debugger: true,
        experimental: false,
    };
}

/// Tool category for grouping related tools
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// Core database operations (always available)
    Core,
    /// Function navigation and discovery
    Functions,
    /// Disassembly tools
    Disassembly,
    /// Decompilation tools (requires Hex-Rays)
    Decompile,
    /// Cross-reference analysis
    Xrefs,
    /// Control flow and call graph analysis
    ControlFlow,
    /// Memory and data reading
    Memory,
    /// Search and pattern matching
    Search,
    /// Metadata and structure info
    Metadata,
    /// Type/struct/stack information and type application
    Types,
    /// Editing and patching operations
    Editing,
    /// Debugger operations
    Debug,
    /// UI/cursor helpers
    Ui,
    /// Scripting/eval helpers
    Scripting,
}

impl ToolCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Functions => "functions",
            Self::Disassembly => "disassembly",
            Self::Decompile => "decompile",
            Self::Xrefs => "xrefs",
            Self::ControlFlow => "control_flow",
            Self::Memory => "memory",
            Self::Search => "search",
            Self::Metadata => "metadata",
            Self::Types => "types",
            Self::Editing => "editing",
            Self::Debug => "debug",
            Self::Ui => "ui",
            Self::Scripting => "scripting",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Core => "Database open/close and discovery tools",
            Self::Functions => "List, search, and resolve functions",
            Self::Disassembly => "Disassemble code at addresses",
            Self::Decompile => "Decompile functions to pseudocode (requires Hex-Rays)",
            Self::Xrefs => "Cross-reference analysis (xrefs to/from)",
            Self::ControlFlow => "Basic blocks, call graphs, control flow",
            Self::Memory => "Read bytes, strings, and data",
            Self::Search => "Search for bytes, strings, patterns",
            Self::Metadata => "Database info, segments, imports, exports",
            Self::Types => "Types, structs, and stack variable info",
            Self::Editing => "Patching, renaming, and comment editing",
            Self::Debug => "Opt-in headless debugger lifecycle and runtime modules",
            Self::Ui => "UI/cursor helpers (headless unsupported)",
            Self::Scripting => "Execute Python scripts via IDAPython",
        }
    }

    pub fn all() -> &'static [ToolCategory] {
        &[
            Self::Core,
            Self::Functions,
            Self::Disassembly,
            Self::Decompile,
            Self::Xrefs,
            Self::ControlFlow,
            Self::Memory,
            Self::Search,
            Self::Metadata,
            Self::Types,
            Self::Editing,
            Self::Debug,
            Self::Ui,
            Self::Scripting,
        ]
    }
}

impl FromStr for ToolCategory {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let normalized = input.trim().to_lowercase().replace(['-', ' '], "_");
        match normalized.as_str() {
            "core" => Ok(Self::Core),
            "functions" | "function" => Ok(Self::Functions),
            "disassembly" | "disasm" => Ok(Self::Disassembly),
            "decompile" | "decompiler" => Ok(Self::Decompile),
            "xrefs" | "xref" | "references" => Ok(Self::Xrefs),
            "control_flow" | "controlflow" | "cfg" => Ok(Self::ControlFlow),
            "memory" | "data" => Ok(Self::Memory),
            "search" => Ok(Self::Search),
            "metadata" | "meta" | "info" => Ok(Self::Metadata),
            "types" | "type" | "structs" => Ok(Self::Types),
            "editing" | "edit" => Ok(Self::Editing),
            "debug" | "debugger" => Ok(Self::Debug),
            "ui" => Ok(Self::Ui),
            "scripting" | "script" | "eval" => Ok(Self::Scripting),
            _ => Err(()),
        }
    }
}

/// Metadata for a single tool
#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: &'static str,
    pub category: ToolCategory,
    /// Worker/state boundary used for routing and availability checks.
    pub scope: ToolScope,
    /// Opt-in server capabilities required to expose this tool.
    pub requirements: ToolRequirements,
    /// Short description (1 line, <100 chars) - used in tool_catalog results
    pub short_desc: &'static str,
    /// Full description with usage details - used in tool_help
    pub full_desc: &'static str,
    /// Example invocation (JSON)
    pub example: &'static str,
    /// Whether this tool is in the default (core) set
    pub default: bool,
    /// Keywords for semantic search
    pub keywords: &'static [&'static str],
}

/// Whether a tool allocates a new workspace database rather than addressing
/// an existing one.
///
/// Workspace routing (which leases a fresh `database_id`) and schema
/// augmentation (which advertises that allocation instead of requiring a
/// `database_id` argument) must agree exactly. Keeping the answer here, beside
/// the rest of each tool's contract, stops those two call sites from drifting
/// apart as tools are added.
pub fn allocates_database(name: &str) -> bool {
    matches!(name, "open_idb" | "open_dsc")
}

/// Static registry of all tools
pub static TOOL_REGISTRY: &[ToolInfo] = &[
    // === CORE (always available) ===
    ToolInfo {
        name: "open_idb",
        category: ToolCategory::Core,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Open an IDA database or raw binary",
        full_desc: "Open an IDA Pro database file or a raw binary for analysis. \
                    Supports .i64 (64-bit) and .idb (32-bit) databases, as well as raw binaries \
                    like Mach-O/ELF/PE. Raw binaries default to a .i64 alongside the input; set \
                    idb_out to save in another existing, writable directory. Existing output databases \
                    are reused only when IDA's recorded input SHA-256 matches the current raw input. \
                    Set rebuild=true when the input changed or stale analysis should be overwritten; \
                    overwrite is allowed only when the existing database's hash or recorded input path \
                    proves that it belongs to this input. \
                    Auto-analysis does NOT run by default — open returns quickly with the database \
                    loaded. Check analysis_status in the response: if auto_is_ok is false and you \
                    need xrefs/decompile, call analyze_funcs(background=true) and poll task_status. \
                    list_functions, disasm, strings, get_bytes work immediately without full analysis. \
                    Set auto_analyse=true for small binaries to wait for analysis inline (risks timeout on large files). \
                    If opening a raw binary with no existing .i64 and a sibling .dSYM is present, \
                    its DWARF debug info is loaded automatically. \
                    Set load_debug_info=true to force loading external debug info after open \
                    (optionally specify debug_info_path). \
                    The database must be opened before using any other analysis tools. \
                    Call close_idb when finished to release database locks; in multi-client servers, coordinate before closing. \
                    In HTTP/SSE mode, keep the close_token returned by open_idb for sessionless MCP 2026 or cross-session close requests; the owning legacy session can close directly. \
                    Supports timeout_secs (default 300s, max 600s). Phase transitions are observable via recent_operations. \
                    Returns metadata about the binary: file type, processor, bitness, function count, analysis_status.",
        example: r#"{"path": "/path/to/binary", "auto_analyse": false}"#,
        default: true,
        keywords: &[
            "open", "load", "database", "binary", "idb", "i64", "macho", "elf", "pe",
        ],
    },
    ToolInfo {
        name: "open_dsc",
        category: ToolCategory::Core,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Open a dyld_shared_cache and load one module; use dsc_add_dylib/dsc_add_region for more",
        full_desc: "Open an Apple dyld_shared_cache file and extract a single dylib for analysis. \
                    A previously generated .i64 for the same DSC is reopened directly, preserving prior analysis. \
                    Otherwise IDA 9.4 opens the DSC header directly and loads images through IDA's native dscu service; \
                    older IDA builds keep the legacy idat background flow when a generated .i64 is needed. \
                    Use this instead of open_idb when working with dyld_shared_cache files. \
                    Optionally load additional frameworks to resolve cross-module references. \
                    To load more code modules after the initial open, call dsc_add_dylib. \
                    To load additional data/GOT/stub regions by address, call dsc_add_region.",
        example: r#"{"path": "/path/to/dyld_shared_cache_arm64e", "arch": "arm64e", "module": "/usr/lib/libobjc.A.dylib", "frameworks": ["/System/Library/Frameworks/Foundation.framework/Foundation"]}"#,
        default: false,
        keywords: &[
            "open", "dsc", "dyld", "shared", "cache", "dylib", "module", "region", "apple",
            "macos", "ios",
        ],
    },
    ToolInfo {
        name: "dsc_add_dylib",
        category: ToolCategory::Core,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Load an additional dylib into an open DSC database",
        full_desc: "Incrementally load a single dylib into a database previously opened via open_dsc. \
                    Uses IDA's native dscu service to add the module. \
                    Skips full auto-analysis to keep the operation fast. \
                    Call once per module; then check analysis_status. \
                    If auto_is_ok is false, run analyze_funcs before relying on xrefs/decompile. \
                    Requires: database opened via open_dsc.",
        example: r#"{"module": "/System/Library/Frameworks/Foundation.framework/Foundation", "timeout_secs": 300}"#,
        default: false,
        keywords: &[
            "dsc",
            "dyld",
            "dylib",
            "module",
            "load",
            "add",
            "framework",
            "cache",
        ],
    },
    ToolInfo {
        name: "dsc_add_region",
        category: ToolCategory::Core,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Load a DSC memory region by address (data/GOT/stubs)",
        full_desc: "Incrementally load a specific region from the currently open DSC database by address. \
                    Accepts exactly one address per call. \
                    Uses IDA's native dscu service for on-demand data/GOT/stub loading. \
                    This does not force full auto-analysis; check analysis_status and run analyze_funcs \
                    when deeper cross-reference/decompile fidelity is required after loading. \
                    Requires: database opened via open_dsc.",
        example: r#"{"address": "0x180116000", "timeout_secs": 300}"#,
        default: false,
        keywords: &[
            "dsc", "dyld", "region", "memory", "address", "got", "stubs", "data", "load",
        ],
    },
    ToolInfo {
        name: "load_debug_info",
        category: ToolCategory::Core,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Load external debug info (e.g., dSYM/DWARF)",
        full_desc: "Load external debug info (e.g., DWARF from a dSYM) into the current database. \
                    If path is omitted, attempts to locate a sibling .dSYM for the currently-open database. \
                    Returns whether the load succeeded.",
        example: r#"{"path": "/path/to/binary.dSYM/Contents/Resources/DWARF/binary"}"#,
        default: false,
        keywords: &["debug", "dwarf", "dsym", "symbols", "load"],
    },
    ToolInfo {
        name: "analysis_status",
        category: ToolCategory::Core,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Report auto-analysis status",
        full_desc: "Report auto-analysis status (auto_is_ok, auto_state) so clients can \
                    determine whether analysis-dependent tools like xrefs or decompile are fully ready.",
        example: r#"{}"#,
        default: true,
        keywords: &["analysis", "autoanalysis", "status", "xrefs", "decompile"],
    },
    ToolInfo {
        name: "close_idb",
        category: ToolCategory::Core,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Close the current database (release locks)",
        full_desc: "Close the currently open IDA database, releasing resources. \
                    Call this when done with analysis or before opening a different database. \
                    In multi-client servers, coordinate before closing to avoid interrupting others. \
                    In HTTP/SSE mode, provide the close_token returned by open_idb unless the request is in the owning legacy session.",
        example: r#"{"close_token": "token-from-open-idb"}"#,
        default: true,
        keywords: &["close", "unload", "database"],
    },
    ToolInfo {
        name: "tool_catalog",
        category: ToolCategory::Core,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Discover available tools by query or category",
        full_desc: "Search for relevant tools based on what you're trying to accomplish. \
                    Returns tool names with short descriptions and relevance reasons. \
                    Use this to find the right tool before calling tool_help for full details.",
        example: r#"{"query": "find all callers of a function"}"#,
        default: true,
        keywords: &["discover", "find", "search", "tools", "help", "catalog"],
    },
    ToolInfo {
        name: "tool_help",
        category: ToolCategory::Core,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Get full documentation for a tool",
        full_desc: "Returns complete documentation for a specific tool including: \
                    full description, parameter schema, and example invocation. \
                    Use tool_catalog first to find the tool name.",
        example: r#"{"name": "list_functions"}"#,
        default: true,
        keywords: &["help", "docs", "documentation", "schema", "usage"],
    },
    ToolInfo {
        name: "recent_operations",
        category: ToolCategory::Core,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Inspect recent foreground operation history",
        full_desc: "Return the currently active foreground operation (if any) and a capped trail of recent \
                    phase transitions recorded for open_idb, run_script, and analyze_funcs. \
                    Use this after timeouts, cancellations, or failures to inspect the last known phase.",
        example: r#"{"limit": 10}"#,
        default: false,
        keywords: &[
            "recent",
            "operations",
            "history",
            "progress",
            "timeout",
            "cancel",
            "observability",
        ],
    },
    ToolInfo {
        name: "task_status",
        category: ToolCategory::Core,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Check status of a background task (e.g. DSC loading)",
        full_desc: "Check the status of a background task started by open_dsc. \
                    Returns 'running' (with progress message), 'completed' (with db_info — \
                    database is already open and ready for analysis), or 'failed' (with error). \
                    Use the task_id returned by open_dsc when a new .i64 must be created.",
        example: r#"{"task_id": "dsc-abc123"}"#,
        default: true,
        keywords: &["task", "status", "poll", "background", "dsc", "progress"],
    },
    ToolInfo {
        name: "idb_meta",
        category: ToolCategory::Core,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Get database metadata and summary",
        full_desc: "Returns metadata about the currently open database: \
                    file type, processor architecture, bitness, entry points, \
                    segment count, function count, and other summary info.",
        example: r#"{}"#,
        default: true,
        keywords: &["info", "metadata", "summary", "database", "binary"],
    },
    // === FUNCTIONS ===
    ToolInfo {
        name: "list_functions",
        category: ToolCategory::Functions,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List functions with pagination and filtering",
        full_desc: "List all functions in the database with optional name filtering. \
                    Supports pagination via offset/limit. Returns function address, name, and size. \
                    Use filter parameter to search by substring in function name.",
        example: r#"{"offset": 0, "limit": 100, "filter": "init"}"#,
        default: false,
        keywords: &[
            "functions",
            "list",
            "enumerate",
            "find",
            "filter",
            "subroutines",
        ],
    },
    ToolInfo {
        name: "list_funcs",
        category: ToolCategory::Functions,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Alias of list_functions",
        full_desc: "Alias of list_functions. Lists all functions in the database with pagination \
                    and optional name filtering.",
        example: r#"{"offset": 0, "limit": 100, "filter": "init"}"#,
        default: false,
        keywords: &["functions", "list", "alias"],
    },
    ToolInfo {
        name: "resolve_function",
        category: ToolCategory::Functions,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find function address by name",
        full_desc: "Resolve a function name to its address. Supports exact names and demangled names. \
                    Returns the function's address, full name, and size if found.",
        example: r#"{"name": "main"}"#,
        default: false,
        keywords: &["resolve", "find", "lookup", "function", "name", "address"],
    },
    ToolInfo {
        name: "function_at",
        category: ToolCategory::Functions,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find the function containing an address",
        full_desc: "Return the function that contains the given address, including start/end and size. \
                    Useful for mapping PC/LR to a function.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["function", "address", "pc", "lr", "containing"],
    },
    ToolInfo {
        name: "lookup_funcs",
        category: ToolCategory::Functions,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Batch lookup multiple functions by name",
        full_desc: "Look up multiple function names at once. Returns address and size for each found function. \
                    More efficient than multiple resolve_function calls.",
        example: r#"{"names": ["main", "printf", "malloc"]}"#,
        default: false,
        keywords: &["lookup", "batch", "multiple", "functions", "names"],
    },
    ToolInfo {
        name: "analyze_funcs",
        category: ToolCategory::Functions,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Run auto-analysis (foreground or background task)",
        full_desc: "Run IDA auto-analysis. Set background=true for large binaries (kernelcache, \
                    DSC modules) — returns a task_id immediately, poll task_status for progress. \
                    The IDA worker thread blocks on auto_wait() either way, but in background mode \
                    the MCP request returns instead of timing out, and task_status reads the \
                    registry without going through the worker. Foreground mode (default) waits \
                    for completion, records phase transitions in recent_operations, and respects timeout_secs.",
        example: r#"{"background": true}"#,
        default: false,
        keywords: &[
            "analyze",
            "functions",
            "analysis",
            "auto",
            "background",
            "task",
        ],
    },
    // === DISASSEMBLY ===
    ToolInfo {
        name: "disasm",
        category: ToolCategory::Disassembly,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Disassemble instructions at an address",
        full_desc: "Disassemble machine code starting at the given address. \
                    Returns assembly instructions with addresses and opcodes. \
                    Specify count to control how many instructions to disassemble.",
        example: r#"{"address": "0x1000", "count": 20}"#,
        default: false,
        keywords: &["disassemble", "disasm", "assembly", "instructions", "code"],
    },
    ToolInfo {
        name: "render_range",
        category: ToolCategory::Disassembly,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Render an IDA-style address range",
        full_desc: "Render IDA's disassembly text for a bounded half-open address range, \
                    including code and database-defined data directives. Returns stable \
                    continuation metadata when max_lines truncates the result. This is separate \
                    from disasm so existing instruction-oriented output stays unchanged.",
        example: r#"{"start": "0x1000", "end": "0x1100", "max_lines": 256}"#,
        default: false,
        keywords: &["render", "range", "ida", "view", "mixed", "data"],
    },
    ToolInfo {
        name: "disasm_by_name",
        category: ToolCategory::Disassembly,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Disassemble a function by name",
        full_desc: "Disassemble a function given its name. Resolves the name to an address \
                    and disassembles the specified number of instructions.",
        example: r#"{"name": "main", "count": 50}"#,
        default: false,
        keywords: &["disassemble", "function", "name", "assembly"],
    },
    ToolInfo {
        name: "disasm_function_at",
        category: ToolCategory::Disassembly,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Disassemble the function containing an address",
        full_desc: "Disassemble the function that contains the provided address. \
                    Useful when you only have a PC/LR.",
        example: r#"{"address": "0x1000", "count": 200}"#,
        default: false,
        keywords: &["disassemble", "function", "address", "pc", "lr"],
    },
    // === DECOMPILE ===
    ToolInfo {
        name: "decompile",
        category: ToolCategory::Decompile,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Decompile function to C pseudocode",
        full_desc: "Decompile a function using Hex-Rays decompiler (if available). \
                    Returns C-like pseudocode. Accepts address or function name.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["decompile", "pseudocode", "c", "source", "hex-rays"],
    },
    ToolInfo {
        name: "pseudocode_at",
        category: ToolCategory::Decompile,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Get pseudocode for specific address/range",
        full_desc: "Get decompiled pseudocode for a specific address or address range (e.g., a basic block). \
                    Unlike decompile which returns the full function, this returns only statements \
                    corresponding to the given address(es).",
        example: r#"{"address": "0x1000", "end_address": "0x1020"}"#,
        default: false,
        keywords: &["pseudocode", "decompile", "block", "range", "statement"],
    },
    // === XREFS ===
    ToolInfo {
        name: "xrefs_to",
        category: ToolCategory::Xrefs,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find all references TO an address",
        full_desc: "Find all cross-references pointing to the given address. \
                    Shows what code/data references this location. \
                    Useful for finding callers, data usage, etc.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["xrefs", "references", "to", "callers", "usage"],
    },
    ToolInfo {
        name: "xrefs_from",
        category: ToolCategory::Xrefs,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find all references FROM an address",
        full_desc: "Find all cross-references originating from the given address. \
                    Shows what this instruction/data references. \
                    Useful for finding callees, data accesses, etc.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["xrefs", "references", "from", "callees", "targets"],
    },
    ToolInfo {
        name: "xrefs_to_string",
        category: ToolCategory::Xrefs,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find xrefs to strings matching a query",
        full_desc: "Find strings that match a query and return xrefs to each match. \
                    Useful for 'xref to cstring' workflows.",
        example: r#"{"query": "value=%d", "limit": 10}"#,
        default: false,
        keywords: &["xrefs", "strings", "cstring", "references", "usage"],
    },
    ToolInfo {
        name: "xref_matrix",
        category: ToolCategory::Xrefs,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Build xref matrix between addresses",
        full_desc: "Build a cross-reference matrix showing relationships between multiple addresses. \
                    Returns a boolean matrix indicating which addresses reference which others.",
        example: r#"{"addresses": ["0x1000", "0x2000", "0x3000"]}"#,
        default: false,
        keywords: &["xrefs", "matrix", "relationships", "graph"],
    },
    // === CONTROL FLOW ===
    ToolInfo {
        name: "basic_blocks",
        category: ToolCategory::ControlFlow,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Get basic blocks of a function",
        full_desc: "Get the control flow graph basic blocks for a function. \
                    Returns block addresses, sizes, and successor relationships.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["basic", "blocks", "cfg", "control", "flow", "graph"],
    },
    ToolInfo {
        name: "callers",
        category: ToolCategory::ControlFlow,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find all callers of a function",
        full_desc: "Find all functions that call the specified function. \
                    Returns caller addresses and names.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["callers", "called", "by", "references", "xrefs"],
    },
    ToolInfo {
        name: "callees",
        category: ToolCategory::ControlFlow,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find all functions called by a function",
        full_desc: "Find all functions that are called by the specified function. \
                    Returns callee addresses and names.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["callees", "calls", "targets", "functions"],
    },
    ToolInfo {
        name: "callgraph",
        category: ToolCategory::ControlFlow,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Build call graph from a function",
        full_desc: "Build a call graph starting from a function. Direction is callees by default \
                    for compatibility, or callers/both when explicitly requested. Returns nodes \
                    and normalized caller-to-callee edges. The truncated flag is true when \
                    max_nodes prevented the complete requested traversal.",
        example: r#"{"roots": "0x1000", "direction": "both", "max_depth": 2, "max_nodes": 256}"#,
        default: false,
        keywords: &["callgraph", "call", "graph", "depth", "tree"],
    },
    ToolInfo {
        name: "find_paths",
        category: ToolCategory::ControlFlow,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find control-flow paths between two addresses",
        full_desc: "Find control-flow paths between two addresses within the same function. \
                    Returns all paths up to max_depth. Both addresses must be in the same function.",
        example: r#"{"start": "0x1000", "end": "0x2000", "max_depth": 5}"#,
        default: false,
        keywords: &["paths", "route", "flow", "between", "reach"],
    },
    // === MEMORY ===
    ToolInfo {
        name: "get_bytes",
        category: ToolCategory::Memory,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Read raw bytes from an address",
        full_desc: "Read raw bytes from the database at the specified address. \
                    Returns bytes as hex string. Useful for examining data. \
                    You can also supply a symbol/function name with an optional offset.",
        example: r#"{"name": "interesting_function", "offset": 0, "size": 32}"#,
        default: false,
        keywords: &["bytes", "read", "memory", "data", "raw", "hex"],
    },
    ToolInfo {
        name: "get_string",
        category: ToolCategory::Memory,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Read string at an address",
        full_desc: "Read a null-terminated string at the specified address. \
                    Supports C strings and other string types recognized by IDA.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["string", "read", "text", "ascii", "data"],
    },
    ToolInfo {
        name: "get_u8",
        category: ToolCategory::Memory,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Read 8-bit value",
        full_desc: "Read an unsigned 8-bit value (byte) at the specified address.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["byte", "u8", "read", "value"],
    },
    ToolInfo {
        name: "get_u16",
        category: ToolCategory::Memory,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Read 16-bit value",
        full_desc: "Read an unsigned 16-bit value (word) at the specified address.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["word", "u16", "read", "value"],
    },
    ToolInfo {
        name: "get_u32",
        category: ToolCategory::Memory,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Read 32-bit value",
        full_desc: "Read an unsigned 32-bit value (dword) at the specified address.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["dword", "u32", "read", "value"],
    },
    ToolInfo {
        name: "get_u64",
        category: ToolCategory::Memory,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Read 64-bit value",
        full_desc: "Read an unsigned 64-bit value (qword) at the specified address.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["qword", "u64", "read", "value"],
    },
    ToolInfo {
        name: "get_global_value",
        category: ToolCategory::Memory,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Read global value by name or address",
        full_desc: "Read a global value by name or address. Returns value and raw bytes.",
        example: r#"{"query": "g_flag"}"#,
        default: false,
        keywords: &["global", "value", "read", "symbol", "data"],
    },
    ToolInfo {
        name: "int_convert",
        category: ToolCategory::Memory,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Convert integers between bases",
        full_desc: "Convert integers between decimal/hex/binary and show ASCII bytes when possible.",
        example: r#"{"inputs": ["0x41424344", 1234]}"#,
        default: false,
        keywords: &["int", "convert", "hex", "decimal", "ascii"],
    },
    // === SEARCH ===
    ToolInfo {
        name: "find_bytes",
        category: ToolCategory::Search,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Search for byte pattern",
        full_desc: "Search for a byte pattern in the database. Supports wildcards. \
                    Returns all matching addresses up to the limit.",
        example: r#"{"pattern": "48 89 5C 24", "limit": 100}"#,
        default: false,
        keywords: &["find", "search", "bytes", "pattern", "hex"],
    },
    ToolInfo {
        name: "search",
        category: ToolCategory::Search,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Search for text or immediate values",
        full_desc: "General search tool. Searches for text strings or immediate values \
                    in instructions. Use find_bytes for byte-pattern searches.",
        example: r#"{"targets": "password", "kind": "text"}"#,
        default: false,
        keywords: &["search", "find", "text", "string", "immediate"],
    },
    ToolInfo {
        name: "strings",
        category: ToolCategory::Search,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List all strings in the database",
        full_desc: "List strings found in the database with pagination and optional \
                    substring filter (filter/query). Returns address and content.",
        example: r#"{"offset": 0, "limit": 100, "filter": "http"}"#,
        default: false,
        keywords: &["strings", "list", "text", "data"],
    },
    ToolInfo {
        name: "find_string",
        category: ToolCategory::Search,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find strings matching a query",
        full_desc: "Find strings that match a query (substring by default, optional exact match). \
                    Supports pagination.",
        example: r#"{"query": "value=%d", "limit": 20}"#,
        default: false,
        keywords: &["strings", "find", "search", "text"],
    },
    ToolInfo {
        name: "analyze_strings",
        category: ToolCategory::Search,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Analyze strings with filtering",
        full_desc: "List strings with optional substring filter and pagination. \
                    Useful for finding specific string patterns like URLs or paths.",
        example: r#"{"query": "http", "offset": 0, "limit": 100}"#,
        default: false,
        keywords: &["strings", "analyze", "filter", "pattern"],
    },
    ToolInfo {
        name: "find_insns",
        category: ToolCategory::Search,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find instruction sequences by mnemonic",
        full_desc: "Search for instruction mnemonic patterns. If patterns is an array, matches \
                    contiguous sequences. Each pattern matches the mnemonic substring unless it \
                    contains whitespace or commas (then full line match).",
        example: r#"{"patterns": ["mov", "bl"], "limit": 5}"#,
        default: false,
        keywords: &["find", "instructions", "sequence", "pattern"],
    },
    ToolInfo {
        name: "find_insn_operands",
        category: ToolCategory::Search,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Find instructions by operand substring",
        full_desc: "Search for instructions whose operand text matches any provided substring. \
                    Returns address, mnemonic, operands, and disasm line.",
        example: r#"{"patterns": ["sp", "0x10"], "limit": 5}"#,
        default: false,
        keywords: &["find", "operands", "instructions", "pattern"],
    },
    // === METADATA ===
    ToolInfo {
        name: "segments",
        category: ToolCategory::Metadata,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List all segments",
        full_desc: "List all segments in the database with their addresses, sizes, \
                    names, and permissions (read/write/execute).",
        example: r#"{}"#,
        default: false,
        keywords: &["segments", "sections", "memory", "layout"],
    },
    ToolInfo {
        name: "addr_info",
        category: ToolCategory::Metadata,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Resolve address to segment/function/symbol",
        full_desc: "Return address context including segment info, containing function, \
                    and nearest named symbol.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["address", "segment", "function", "symbol", "context"],
    },
    ToolInfo {
        name: "imports",
        category: ToolCategory::Metadata,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List imported functions",
        full_desc: "List all imported external symbols with their addresses and names.",
        example: r#"{"offset": 0, "limit": 100}"#,
        default: false,
        keywords: &["imports", "external", "libraries", "api"],
    },
    ToolInfo {
        name: "exports",
        category: ToolCategory::Metadata,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List exported functions",
        full_desc: "List all exported functions/symbols with their addresses and names.",
        example: r#"{"offset": 0, "limit": 100}"#,
        default: false,
        keywords: &["exports", "symbols", "public", "api"],
    },
    ToolInfo {
        name: "export_funcs",
        category: ToolCategory::Metadata,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Export functions (JSON)",
        full_desc: "Export functions in JSON format. If addrs is provided, only export those functions.",
        example: r#"{"addrs": ["0x1000", "0x2000"], "format": "json"}"#,
        default: false,
        keywords: &["export", "functions", "json", "dump"],
    },
    ToolInfo {
        name: "entrypoints",
        category: ToolCategory::Metadata,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List entry points",
        full_desc: "List all entry points in the binary (main, DllMain, etc.).",
        example: r#"{}"#,
        default: false,
        keywords: &["entry", "start", "main", "entrypoint"],
    },
    ToolInfo {
        name: "lumina_lookup",
        category: ToolCategory::Metadata,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Look up Lumina metadata for a function",
        full_desc: "Query the configured Lumina server for a function signature and metadata \
                    without changing the database. Requires explicit server startup with \
                    --allow-lumina or IDA_MCP_ALLOW_LUMINA=true.",
        example: r#"{"target_name": "sub_1000"}"#,
        default: false,
        keywords: &["lumina", "signature", "metadata", "lookup", "match"],
    },
    ToolInfo {
        name: "lumina_apply",
        category: ToolCategory::Editing,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Apply Lumina metadata to a function",
        full_desc: "Pull metadata from the configured Lumina server and apply it to one function. \
                    Uses IDA's upgrade policy by default; force=true may replace existing names, \
                    types, or comments. Requires explicit server startup with --allow-lumina or \
                    IDA_MCP_ALLOW_LUMINA=true.",
        example: r#"{"address": "0x1000", "force": false}"#,
        default: false,
        keywords: &["lumina", "signature", "metadata", "apply", "rename", "type"],
    },
    ToolInfo {
        name: "list_globals",
        category: ToolCategory::Metadata,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List global variables",
        full_desc: "List global variables and data items with their addresses, names, and types.",
        example: r#"{"offset": 0, "limit": 100}"#,
        default: false,
        keywords: &["globals", "variables", "data", "symbols"],
    },
    // === TYPES / STRUCTS ===
    ToolInfo {
        name: "local_types",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List local types",
        full_desc: "List local types (typedefs, enums, structs, etc.) with pagination and optional filter.",
        example: r#"{"query": "struct", "limit": 50}"#,
        default: false,
        keywords: &["types", "local", "typedef"],
    },
    ToolInfo {
        name: "xrefs_to_field",
        category: ToolCategory::Xrefs,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Xrefs to a struct field",
        full_desc: "Get cross-references to a struct field by struct name/ordinal and member name/index.",
        example: r#"{"name": "Outer", "member_name": "inner", "limit": 25}"#,
        default: false,
        keywords: &["xrefs", "struct", "field", "member"],
    },
    ToolInfo {
        name: "declare_type",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Declare a type in the local type library",
        full_desc: "Parse a C declaration and store it in the local type library (optionally replacing existing).",
        example: r#"{"decl": "typedef int mcp_int_t;", "replace": true}"#,
        default: false,
        keywords: &["type", "declare", "typedef"],
    },
    ToolInfo {
        name: "apply_types",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Apply a type to an address or stack variable",
        full_desc: "Apply a named type or C declaration to an address/symbol. \
                    For stack vars, provide stack_offset or stack_name plus decl.",
        example: r#"{"name": "interesting_function", "stack_offset": -16, "decl": "int mcp_local;"}"#,
        default: false,
        keywords: &["types", "apply", "annotations"],
    },
    ToolInfo {
        name: "infer_types",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Infer/guess type at an address",
        full_desc: "Guess a type for an address or symbol using IDA's heuristics.",
        example: r#"{"name": "interesting_function"}"#,
        default: false,
        keywords: &["types", "infer", "analysis"],
    },
    ToolInfo {
        name: "stack_frame",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Get stack frame info",
        full_desc: "Get stack frame layout for the function at an address, including \
                    args/locals ranges and per-member type info.",
        example: r#"{"address": "0x1000"}"#,
        default: false,
        keywords: &["stack", "frame", "locals"],
    },
    ToolInfo {
        name: "declare_stack",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Declare a stack variable",
        full_desc: "Define a stack variable in a function frame using a C declaration. \
                    Provide function address/name and stack offset (negative for locals).",
        example: r#"{"name": "interesting_function", "offset": -16, "var_name": "mcp_local", "decl": "int mcp_local;"}"#,
        default: false,
        keywords: &["stack", "declare", "variable"],
    },
    ToolInfo {
        name: "delete_stack",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Delete a stack variable",
        full_desc: "Delete a stack variable by name or offset in a function frame.",
        example: r#"{"name": "interesting_function", "offset": -16}"#,
        default: false,
        keywords: &["stack", "delete", "variable"],
    },
    ToolInfo {
        name: "structs",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List structs with pagination",
        full_desc: "List structs (UDTs) in the database with optional name filtering.",
        example: r#"{"limit": 50, "filter": "objc"}"#,
        default: false,
        keywords: &["structs", "types", "list"],
    },
    ToolInfo {
        name: "struct_info",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Get struct info by name or ordinal",
        full_desc: "Get struct details including member layout and sizes.",
        example: r#"{"name": "MyStruct"}"#,
        default: false,
        keywords: &["struct", "info", "types"],
    },
    ToolInfo {
        name: "read_struct",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Read a struct instance at an address",
        full_desc: "Read raw bytes for each struct member at a given address.",
        example: r#"{"address": "0x1000", "name": "MyStruct"}"#,
        default: false,
        keywords: &["struct", "read", "values"],
    },
    ToolInfo {
        name: "search_structs",
        category: ToolCategory::Types,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Search structs by name",
        full_desc: "Search for structs by name with optional filter and pagination. \
                    Returns the same structure list output as structs.",
        example: r#"{"query": "my_struct", "limit": 20}"#,
        default: false,
        keywords: &["struct", "search", "types"],
    },
    // === EDITING / PATCHING ===
    ToolInfo {
        name: "set_comments",
        category: ToolCategory::Editing,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Set comments at an address",
        full_desc: "Set a non-repeatable or repeatable comment at an address. \
                    Empty string clears the comment. You can also supply a symbol/function name \
                    with an optional offset.",
        example: r#"{"name": "interesting_function", "comment": "note", "repeatable": false}"#,
        default: false,
        keywords: &["comments", "set", "annotate"],
    },
    ToolInfo {
        name: "patch_asm",
        category: ToolCategory::Editing,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Patch instructions with assembly text",
        full_desc: "Assemble a single instruction line at the target address and patch the bytes. \
                    Requires a processor module with assembler support; may fail on some targets. \
                    You can supply an address or a symbol name with an optional offset.",
        example: r#"{"name": "interesting_function", "offset": 0, "line": "nop"}"#,
        default: false,
        keywords: &["patch", "asm", "edit", "modify"],
    },
    ToolInfo {
        name: "patch",
        category: ToolCategory::Editing,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Patch bytes at an address",
        full_desc: "Patch bytes in the database at the given address. \
                    You can also supply a symbol/function name with an optional offset.",
        example: r#"{"name": "interesting_function", "offset": 0, "bytes": "1f 20 03 d5"}"#,
        default: false,
        keywords: &["patch", "bytes", "edit", "modify"],
    },
    ToolInfo {
        name: "list_patches",
        category: ToolCategory::Editing,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "List patched bytes without mutating the database",
        full_desc: "List patched bytes recorded by IDA, coalesced into contiguous ranges and \
                    paginated. Optional start/end bounds use a half-open address range.",
        example: r#"{"start": "0x1000", "end": "0x2000", "offset": 0, "limit": 100}"#,
        default: false,
        keywords: &["patches", "diff", "original", "modified", "bytes"],
    },
    ToolInfo {
        name: "rename",
        category: ToolCategory::Editing,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Rename symbols",
        full_desc: "Rename a symbol at an address. Optional flags map to IDA set_name flags. \
                    You can also supply the current name instead of an address.",
        example: r#"{"current_name": "interesting_function", "name": "interesting_function_renamed", "flags": 0}"#,
        default: false,
        keywords: &["rename", "symbol", "edit"],
    },
    // === DEBUGGER (explicit --enable-debugger opt-in) ===
    ToolInfo {
        name: "debug_status",
        category: ToolCategory::Debug,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements::DEBUGGER,
        short_desc: "Report debugger backend and authorization readiness",
        full_desc: "Report whether headless debugger support is ready, requires a supported user authorization action, or is unavailable. On macOS ida-mcp uses IDA's signed loopback helper and never requests root, disables SIP, changes authorizationdb, or re-signs binaries.",
        example: r#"{}"#,
        default: false,
        keywords: &["debugger", "status", "availability", "authorization", "backend"],
    },
    ToolInfo {
        name: "debug_launch",
        category: ToolCategory::Debug,
        scope: ToolScope::Database,
        requirements: ToolRequirements::DEBUGGER,
        short_desc: "Launch and suspend a local debug target",
        full_desc: "Launch an executable through IDA's native debugger backend and wait for the initial suspended event. Requires an open database and explicit server startup with --enable-debugger.",
        example: r#"{"path":"/absolute/path/to/program","arguments":"--help","timeout_secs":30}"#,
        default: false,
        keywords: &["debugger", "launch", "process", "suspend", "runtime"],
    },
    ToolInfo {
        name: "debug_attach",
        category: ToolCategory::Debug,
        scope: ToolScope::Database,
        requirements: ToolRequirements::DEBUGGER,
        short_desc: "Attach and suspend a local process",
        full_desc: "Attach IDA's native debugger to a positive operating-system process ID. Platform policy may require an explicit user authorization action.",
        example: r#"{"pid":1234,"timeout_secs":30}"#,
        default: false,
        keywords: &["debugger", "attach", "pid", "process", "suspend"],
    },
    ToolInfo {
        name: "debug_modules",
        category: ToolCategory::Debug,
        scope: ToolScope::Database,
        requirements: ToolRequirements::DEBUGGER,
        short_desc: "List runtime modules from the suspended debuggee",
        full_desc: "List modules loaded in the active debuggee with runtime base, end, size, and IDA rebase target. The process must already be launched or attached.",
        example: r#"{}"#,
        default: false,
        keywords: &["debugger", "modules", "images", "libraries", "runtime", "base"],
    },
    ToolInfo {
        name: "debug_stop",
        category: ToolCategory::Debug,
        scope: ToolScope::Database,
        requirements: ToolRequirements::DEBUGGER,
        short_desc: "Detach or terminate the active debug target",
        full_desc: "Stop the active debug session. action=auto terminates targets launched by ida-mcp and detaches targets it attached; detach and terminate are available as explicit overrides.",
        example: r#"{"action":"auto","timeout_secs":10}"#,
        default: false,
        keywords: &["debugger", "stop", "detach", "terminate", "process"],
    },
    ToolInfo {
        name: "list_databases",
        category: ToolCategory::Core,
        scope: ToolScope::Runtime,
        requirements: ToolRequirements {
            workspace: true,
            debugger: false,
            experimental: false,
        },
        short_desc: "List open workspace database handles",
        full_desc: "List every database_id this workspace server currently routes, with the \
                    database path when a worker is bound and its lifecycle state: 'open', \
                    'busy' (a call is in flight), or 'no_worker' (allocated or opening in the \
                    background, or its worker was lost). Also reports idle seconds and whether \
                    the handle is pinned by a background task or a live debugger session. Use \
                    it to recover a database_id after a lost response or a stateless HTTP \
                    reconnect. Read-only: it never opens, closes, or modifies a database.",
        example: r#"{}"#,
        default: false,
        keywords: &["workspace", "databases", "list", "handles", "database_id", "discover"],
    },
    ToolInfo {
        name: "debug_open_module",
        category: ToolCategory::Debug,
        scope: ToolScope::Database,
        requirements: ToolRequirements {
            workspace: true,
            debugger: true,
            experimental: false,
        },
        short_desc: "Open a runtime module in a separate workspace database",
        full_desc: "Resolve a module from debug_modules and open it in a newly allocated workspace database. Standalone images open directly; cache-backed macOS system libraries are resolved through the target architecture's host dyld shared cache and loaded with IDA 9.4's in-process DSC service. idb_out is always required because runtime modules commonly live in read-only system directories. Returns the new database_id and a checked runtime slide; it does not replace the active debug database.",
        example: r#"{"database_id":"source UUID","module":"/usr/lib/libobjc.A.dylib","idb_out":"/tmp/libobjc.i64"}"#,
        default: false,
        keywords: &["debugger", "module", "open", "workspace", "slide", "database"],
    },
    // === SCRIPTING ===
    ToolInfo {
        name: "run_script",
        category: ToolCategory::Scripting,
        scope: ToolScope::Database,
        requirements: ToolRequirements::BASELINE,
        short_desc: "Execute Python code via IDAPython",
        full_desc: "Execute a Python script via IDAPython in the currently open database. \
                    Provide either 'code' (inline Python) or 'file' (path to a .py file). \
                    Has full access to all ida_* modules (ida_funcs, ida_bytes, ida_segment, etc.), \
                    idc, and idautils. stdout and stderr are captured and returned. \
                    Use this for custom analysis that goes beyond the built-in tools. \
                    Supports timeout_secs, records phase transitions in recent_operations, \
                    and requires that the IDAPython plugin is loaded (available by default in IDA Pro). \
                    API reference: https://python.docs.hex-rays.com",
        example: r#"{"code": "import idautils\nfor f in idautils.Functions():\n    print(hex(f))"}"#,
        default: false,
        keywords: &[
            "script",
            "python",
            "execute",
            "eval",
            "idapython",
            "run",
            "code",
            "file",
        ],
    },
];

/// Get tools in the default (core) set
pub fn default_tools() -> impl Iterator<Item = &'static ToolInfo> {
    TOOL_REGISTRY.iter().filter(|t| t.default)
}

/// Get all tools
pub fn all_tools() -> impl Iterator<Item = &'static ToolInfo> {
    TOOL_REGISTRY.iter()
}

/// Get tool by name
pub fn get_tool(name: &str) -> Option<&'static ToolInfo> {
    TOOL_REGISTRY.iter().find(|t| t.name == name)
}

/// Get tools by category
pub fn tools_by_category(category: ToolCategory) -> impl Iterator<Item = &'static ToolInfo> {
    TOOL_REGISTRY.iter().filter(move |t| t.category == category)
}

/// Search tools by query (simple keyword matching)
pub fn search_tools(query: &str, limit: usize) -> Vec<(&'static ToolInfo, Vec<&'static str>)> {
    let query_lower = query.to_lowercase();
    let query_words: Vec<&str> = query_lower.split_whitespace().collect();

    let mut results: Vec<(&'static ToolInfo, Vec<&'static str>, usize)> = Vec::new();

    for tool in TOOL_REGISTRY.iter() {
        let mut matched_keywords = Vec::new();
        let mut score = 0usize;

        // Check tool name
        let name_lower = tool.name.to_lowercase();
        for word in &query_words {
            if name_lower.contains(word) {
                score += 10;
                matched_keywords.push("name match");
            }
        }

        // Check short description
        let desc_lower = tool.short_desc.to_lowercase();
        for word in &query_words {
            if desc_lower.contains(word) {
                score += 5;
            }
        }

        // Check keywords
        for keyword in tool.keywords {
            let kw_lower = keyword.to_lowercase();
            for word in &query_words {
                if kw_lower.contains(word) || word.contains(&kw_lower) {
                    score += 3;
                    if !matched_keywords.contains(keyword) {
                        matched_keywords.push(keyword);
                    }
                }
            }
        }

        // Check category
        let cat_str = tool.category.as_str().to_lowercase();
        for word in &query_words {
            if cat_str.contains(word) {
                score += 2;
                matched_keywords.push(tool.category.as_str());
            }
        }

        if score > 0 {
            results.push((tool, matched_keywords, score));
        }
    }

    // Sort by score descending
    results.sort_by_key(|(_, _, score)| std::cmp::Reverse(*score));

    // Return top results
    results
        .into_iter()
        .take(limit)
        .map(|(tool, keywords, _)| (tool, keywords))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::tool_registry::*;

    #[test]
    fn test_default_tools() {
        let defaults: Vec<_> = default_tools().collect();
        assert!(defaults.iter().any(|t| t.name == "open_idb"));
        assert!(defaults.iter().any(|t| t.name == "tool_catalog"));
        assert!(defaults.iter().any(|t| t.name == "tool_help"));
        assert!(defaults.iter().any(|t| t.name == "idb_meta"));
    }

    #[test]
    fn test_search_tools() {
        let results = search_tools("find callers function", 5);
        assert!(!results.is_empty());
        // Should find "callers" tool
        assert!(results.iter().any(|(t, _)| t.name == "callers"));
    }

    #[test]
    fn test_get_tool() {
        assert!(get_tool("disasm").is_some());
        assert!(get_tool("nonexistent").is_none());
    }

    #[test]
    fn registry_names_are_unique_and_contracts_are_explicit() {
        let mut names = HashSet::new();
        for tool in all_tools() {
            assert!(names.insert(tool.name), "duplicate tool: {}", tool.name);
            if tool.category == ToolCategory::Debug {
                assert!(tool.requirements.debugger);
                assert!(!tool.requirements.experimental);
                assert_eq!(
                    tool.requirements.workspace,
                    tool.name == "debug_open_module"
                );
            } else if tool.name == "list_databases" {
                // The only non-debugger tool gated on a server capability:
                // opaque handles exist solely in workspace mode.
                assert_eq!(
                    tool.requirements,
                    ToolRequirements {
                        workspace: true,
                        debugger: false,
                        experimental: false,
                    }
                );
                assert_eq!(tool.scope, ToolScope::Runtime);
            } else {
                assert_eq!(tool.requirements, ToolRequirements::BASELINE);
            }
        }

        let runtime_tools: HashSet<_> = all_tools()
            .filter(|tool| tool.scope == ToolScope::Runtime)
            .map(|tool| tool.name)
            .collect();
        assert_eq!(
            runtime_tools,
            HashSet::from([
                "open_idb",
                "open_dsc",
                "tool_catalog",
                "tool_help",
                "recent_operations",
                "task_status",
                "int_convert",
                "debug_status",
                "list_databases",
            ])
        );
    }
}
