//! MCP tool request types.
//!
//! These structs define the parameters for each MCP tool exposed by the server.

use rmcp::schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenIdbRequest {
    #[schemars(
        description = "Path to an IDA database (.i64/.idb) or raw binary. Call close_idb when finished to release locks; in multi-client mode coordinate before closing."
    )]
    pub path: String,
    #[schemars(description = "If true, load external debug info (dSYM/DWARF) after open")]
    #[serde(alias = "load_dsym")]
    pub load_debug_info: Option<bool>,
    #[schemars(
        description = "Optional debug info path (dSYM DWARF). If omitted, tries sibling .dSYM"
    )]
    #[serde(alias = "dsym_path")]
    pub debug_info_path: Option<String>,
    #[schemars(description = "Verbose debug-info loading (default: false)")]
    pub debug_info_verbose: Option<bool>,
    #[schemars(
        description = "If true, clean up stale lock files from crashed sessions before opening. \
        Use this when a previous ida-mcp session crashed and left behind lock files."
    )]
    #[serde(alias = "recover")]
    pub force: Option<bool>,
    #[schemars(
        description = "IDA file type selector (-T flag). Used to choose a specific loader, \
        e.g. 'Apple DYLD cache for arm64e (single module(s))'. Only applies to raw binaries."
    )]
    pub file_type: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseIdbRequest {
    #[schemars(description = "Ownership token returned by open_idb (required for HTTP/SSE).")]
    #[serde(alias = "close_token", alias = "owner_token")]
    pub token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadDebugInfoRequest {
    #[schemars(
        description = "Path to debug info file (e.g., dSYM DWARF). If omitted, tries sibling .dSYM for the current database."
    )]
    pub path: Option<String>,
    #[schemars(description = "Whether to emit verbose load status (default: false)")]
    pub verbose: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmptyParams {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFunctionsRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum functions to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Optional filter - only return functions containing this text")]
    #[serde(alias = "query", alias = "queries", alias = "filter")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFuncsRequest {
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveFunctionRequest {
    #[schemars(description = "Function name to resolve (exact or partial match)")]
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddrInfoRequest {
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FunctionAtRequest {
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmFunctionAtRequest {
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Number of instructions (1-5000, default: 200)")]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmRequest {
    #[schemars(description = "Address(es) to disassemble (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Number of instructions (1-1000, default: 10)")]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmByNameRequest {
    #[schemars(description = "Function name to disassemble (exact or partial match)")]
    pub name: String,
    #[schemars(description = "Number of instructions (1-1000, default: 10)")]
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecompileRequest {
    #[schemars(description = "Address(es) of function to decompile (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StringsRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Optional filter - only return strings containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindStringRequest {
    #[schemars(description = "String to search for")]
    pub query: String,
    #[schemars(description = "Exact match (default: false)")]
    pub exact: Option<bool>,
    #[schemars(description = "Case-insensitive match (default: true)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefsToStringRequest {
    #[schemars(description = "String to search for")]
    pub query: String,
    #[schemars(description = "Exact match (default: false)")]
    pub exact: Option<bool>,
    #[schemars(description = "Case-insensitive match (default: true)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Maximum xrefs per string (default: 64, max: 1024)")]
    pub max_xrefs: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LocalTypesRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum types to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Optional filter - only return types containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeclareTypeRequest {
    #[schemars(description = "C declaration(s) to add to the local type library")]
    pub decl: String,
    #[schemars(description = "Relaxed parsing (allow unknown namespaces)")]
    pub relaxed: Option<bool>,
    #[schemars(description = "Replace existing type if it already exists")]
    pub replace: Option<bool>,
    #[schemars(description = "Parse multiple declarations in one input string")]
    pub multi: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StructsRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum structs to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Optional filter - only return structs containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StructInfoRequest {
    #[schemars(description = "Struct ordinal (numeric)")]
    pub ordinal: Option<u32>,
    #[schemars(description = "Struct name (exact match)")]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadStructRequest {
    #[schemars(description = "Address of struct instance (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Struct ordinal (numeric)")]
    pub ordinal: Option<u32>,
    #[schemars(description = "Struct name (exact match)")]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyTypesRequest {
    #[schemars(description = "Address to apply type (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Stack variable offset (negative for locals)")]
    pub stack_offset: Option<i64>,
    #[schemars(description = "Stack variable name (when applying to stack var)")]
    pub stack_name: Option<String>,
    #[schemars(description = "Named type to apply")]
    pub type_name: Option<String>,
    #[schemars(description = "C declaration to parse and apply")]
    pub decl: Option<String>,
    #[schemars(description = "Relaxed parsing for decl")]
    pub relaxed: Option<bool>,
    #[schemars(description = "Delay function creation if missing")]
    pub delay: Option<bool>,
    #[schemars(description = "Strict application (no type conversion)")]
    pub strict: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InferTypesRequest {
    #[schemars(description = "Address to infer type (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeclareStackRequest {
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function name (alternative to address)")]
    #[serde(alias = "function", alias = "name")]
    pub target_name: Option<String>,
    #[schemars(description = "Stack offset in bytes (negative for locals, positive for args)")]
    pub offset: i64,
    #[schemars(description = "Stack variable name (optional)")]
    pub var_name: Option<String>,
    #[schemars(description = "C declaration for the variable type")]
    pub decl: String,
    #[schemars(description = "Relaxed parsing for decl")]
    pub relaxed: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteStackRequest {
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function name (alternative to address)")]
    #[serde(alias = "function", alias = "name")]
    pub target_name: Option<String>,
    #[schemars(description = "Stack offset in bytes (negative for locals, positive for args)")]
    pub offset: Option<i64>,
    #[schemars(description = "Stack variable name (optional)")]
    pub var_name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefsToFieldRequest {
    #[schemars(description = "Struct ordinal (numeric)")]
    pub ordinal: Option<u32>,
    #[schemars(description = "Struct name (exact match)")]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
    #[schemars(description = "Struct member index (0-based)")]
    pub member_index: Option<u32>,
    #[schemars(description = "Struct member name (exact match)")]
    #[serde(alias = "member", alias = "field", alias = "field_name")]
    pub member_name: Option<String>,
    #[schemars(description = "Maximum xrefs to return (default: 1000, max: 10000)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddressRequest {
    #[schemars(description = "Address(es) (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetBytesRequest {
    #[schemars(description = "Address(es) to read from (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name to read from (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Number of bytes to read (1-65536, default: 256)")]
    #[serde(alias = "count")]
    pub size: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetCommentsRequest {
    #[schemars(description = "Address to comment (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name to comment (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Comment text (empty string clears comment)")]
    #[serde(alias = "text", alias = "comment")]
    pub comment: String,
    #[schemars(description = "Repeatable comment (default: false)")]
    #[serde(alias = "rptble", alias = "repeatable")]
    pub repeatable: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameRequest {
    #[schemars(description = "Address to rename (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Current name to resolve (alternative to address)")]
    #[serde(alias = "current", alias = "old_name", alias = "from")]
    pub current_name: Option<String>,
    #[schemars(description = "New name for the symbol")]
    #[serde(alias = "new_name", alias = "name")]
    pub name: String,
    #[schemars(description = "IDA set_name flags (optional)")]
    pub flags: Option<i32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchRequest {
    #[schemars(description = "Address to patch (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name to patch (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(
        description = "Bytes to patch (hex string like '90 90' or array of ints/hex strings)"
    )]
    #[serde(alias = "data", alias = "bytes")]
    pub bytes: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchAsmRequest {
    #[schemars(description = "Address to patch (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<Value>,
    #[schemars(description = "Function or symbol name to patch (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<u64>,
    #[schemars(description = "Assembly text to assemble and patch")]
    #[serde(alias = "asm", alias = "instruction")]
    pub line: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PaginatedRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum items to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LookupFuncsRequest {
    #[schemars(description = "Function queries (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "names")]
    pub queries: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListGlobalsRequest {
    #[schemars(description = "Optional filter for globals")]
    #[serde(alias = "filter")]
    pub query: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum globals to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeStringsRequest {
    #[schemars(description = "Optional filter for strings")]
    #[serde(alias = "filter")]
    pub query: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum strings to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindBytesRequest {
    #[schemars(description = "Pattern(s) to search for (string or array)")]
    #[serde(alias = "pattern", alias = "patterns")]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchRequest {
    #[schemars(description = "Targets to search for (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "targets")]
    pub targets: Value,
    #[schemars(description = "Search type: text or imm (optional)")]
    #[serde(alias = "type")]
    pub kind: Option<String>,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindInsnsRequest {
    #[schemars(description = "Instruction mnemonic(s) or sequence (string/number or array)")]
    #[serde(
        alias = "pattern",
        alias = "patterns",
        alias = "query",
        alias = "queries",
        alias = "mnemonic",
        alias = "mnemonics"
    )]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Case-insensitive match (default: false)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindInsnOperandsRequest {
    #[schemars(description = "Operand substring(s) to match (string/number or array)")]
    #[serde(
        alias = "pattern",
        alias = "patterns",
        alias = "query",
        alias = "queries",
        alias = "operands"
    )]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Case-insensitive match (default: false)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindPathsRequest {
    #[schemars(description = "Start address (string/number)")]
    pub start: Value,
    #[schemars(description = "End address (string/number)")]
    pub end: Value,
    #[schemars(description = "Maximum paths to return (default: 8)")]
    pub max_paths: Option<usize>,
    #[schemars(description = "Maximum path depth (default: 64)")]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CallGraphRequest {
    #[schemars(description = "Root function address(es) (string/number or array)")]
    #[serde(
        alias = "root",
        alias = "roots",
        alias = "addr",
        alias = "address",
        alias = "addrs"
    )]
    pub roots: Value,
    #[schemars(description = "Maximum depth (default: 2)")]
    pub max_depth: Option<usize>,
    #[schemars(description = "Maximum nodes (default: 256)")]
    pub max_nodes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefMatrixRequest {
    #[schemars(description = "Addresses to include in matrix (string/number or array)")]
    #[serde(alias = "addr", alias = "address", alias = "addresses")]
    pub addrs: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExportFuncsRequest {
    #[schemars(description = "Function address(es) to export (optional)")]
    #[serde(
        alias = "addrs",
        alias = "addr",
        alias = "address",
        alias = "functions"
    )]
    pub addrs: Option<Value>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum functions to return (default: 100)")]
    #[serde(alias = "count")]
    pub limit: Option<usize>,
    #[schemars(description = "Export format (only json supported)")]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStringRequest {
    #[schemars(description = "Address(es) to read string from (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Maximum length to read (default: 256)")]
    pub max_len: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetGlobalValueRequest {
    #[schemars(description = "Global name(s) or address(es) (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "names", alias = "addrs")]
    pub query: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IntConvertRequest {
    #[schemars(description = "Values to convert (string/number or array)")]
    #[serde(alias = "input", alias = "inputs")]
    pub inputs: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PseudocodeAtRequest {
    #[schemars(description = "Address(es) to get pseudocode for (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Optional end address for range query (for basic blocks)")]
    pub end_address: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ToolCatalogRequest {
    #[schemars(
        description = "What you're trying to accomplish (e.g., 'find all callers of a function')"
    )]
    pub query: Option<String>,
    #[schemars(
        description = "Filter by category: core, functions, disassembly, decompile, xrefs, control_flow, memory, search, metadata, types, editing, debug, ui, scripting"
    )]
    pub category: Option<String>,
    #[schemars(description = "Maximum number of tools to return (default: 7)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ToolHelpRequest {
    #[schemars(description = "Name of the tool to get help for")]
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunScriptRequest {
    #[schemars(
        description = "Python code to execute via IDAPython. Has full access to ida_* modules, \
        idc, idautils. stdout/stderr are captured and returned. \
        Provide either 'code' (inline) or 'file' (path to .py), not both."
    )]
    pub code: Option<String>,
    #[schemars(description = "Path to a .py file to execute via IDAPython. \
        Alternative to 'code' for longer scripts. The file is read server-side.")]
    pub file: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default: 120, max: 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaskStatusRequest {
    #[schemars(description = "Task ID returned by open_dsc (e.g. 'dsc-abc123')")]
    pub task_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenDscRequest {
    #[schemars(description = "Path to the dyld_shared_cache file")]
    pub path: String,
    #[schemars(description = "CPU architecture (e.g. 'arm64e', 'arm64', 'x86_64h')")]
    pub arch: String,
    #[schemars(description = "Primary dylib to load (e.g. '/usr/lib/libobjc.A.dylib')")]
    pub module: String,
    #[schemars(description = "Additional frameworks to load after opening \
        (e.g. ['/System/Library/Frameworks/Foundation.framework/Foundation'])")]
    pub frameworks: Option<Vec<String>>,
    #[schemars(description = "IDA version: 8 or 9. Determines the -T format string. Default: 9")]
    pub ida_version: Option<u8>,
}
