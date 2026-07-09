//! MCP tool request types.
//!
//! These structs define the parameters for each MCP tool exposed by the server.

use rmcp::schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenIdbRequest {
    #[schemars(description = "Path to .i64/.idb or raw binary.")]
    pub path: String,
    #[schemars(description = "Load external debug info (dSYM/DWARF) after open.")]
    #[serde(alias = "load_dsym")]
    pub load_debug_info: Option<bool>,
    #[schemars(
        description = "Debug info path; defaults to sibling .dSYM. Empty strings are ignored."
    )]
    #[serde(alias = "dsym_path")]
    pub debug_info_path: Option<String>,
    #[schemars(description = "Verbose debug-info loading.")]
    pub debug_info_verbose: Option<bool>,
    #[schemars(description = "Clean up stale lock files from crashed sessions before opening.")]
    #[serde(alias = "recover")]
    pub force: Option<bool>,
    #[schemars(
        description = "For raw binaries, rebuild and overwrite the generated <path>.i64 instead of reusing it. Use when the input binary changed or stale analysis must be replaced."
    )]
    pub rebuild: Option<bool>,
    #[schemars(
        description = "IDA file-type selector (-T). Raw binaries only. Empty strings are ignored."
    )]
    pub file_type: Option<String>,
    #[schemars(
        description = "Run full auto-analysis before returning (default: false). \
        For raw binaries, false returns fast with analysis incomplete; .i64/.idb ignore this. \
        Inputs >50 MiB may route to a background task (response includes analysis_task_id)."
    )]
    pub auto_analyse: Option<bool>,
    #[schemars(description = "Open timeout in seconds (default 300, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
    #[serde(default, rename = "_worker_extra_args")]
    #[schemars(skip)]
    pub worker_extra_args: Vec<String>,
}

impl OpenIdbRequest {
    pub fn normalized_debug_info_path(&self) -> Option<String> {
        non_empty_trimmed(self.debug_info_path.as_deref())
    }

    pub fn normalized_file_type(&self) -> Option<String> {
        non_empty_trimmed(self.file_type.as_deref())
    }
}

fn non_empty_trimmed(value: Option<&str>) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// Schema for the elicitation prompt used by `open_idb` when the input binary
/// exceeds the auto-background threshold.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct OpenIdbBackgroundChoice {
    #[schemars(
        description = "Run auto-analysis as a background task with no timeout. \
        Choose 'no' to run inline (capped by the foreground timeout)."
    )]
    pub background: Option<bool>,
}

rmcp::elicit_safe!(OpenIdbBackgroundChoice);

#[cfg(test)]
mod tests {
    use crate::server::requests::OpenIdbRequest;

    fn open_request(debug_info_path: Option<&str>, file_type: Option<&str>) -> OpenIdbRequest {
        OpenIdbRequest {
            path: "/tmp/sample".to_string(),
            load_debug_info: None,
            debug_info_path: debug_info_path.map(str::to_string),
            debug_info_verbose: None,
            force: None,
            rebuild: None,
            file_type: file_type.map(str::to_string),
            auto_analyse: None,
            timeout_secs: None,
            worker_extra_args: Vec::new(),
        }
    }

    #[test]
    fn open_idb_empty_optional_strings_are_ignored() {
        let req = open_request(Some(" \t "), Some(""));
        assert_eq!(req.normalized_debug_info_path(), None);
        assert_eq!(req.normalized_file_type(), None);
    }

    #[test]
    fn open_idb_optional_strings_are_trimmed() {
        let req = open_request(Some(" C:\\symbols\\sample.pdb "), Some(" pe "));
        assert_eq!(
            req.normalized_debug_info_path(),
            Some("C:\\symbols\\sample.pdb".to_string())
        );
        assert_eq!(req.normalized_file_type(), Some("pe".to_string()));
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseIdbRequest {
    #[schemars(description = "Ownership token returned by open_idb (required for HTTP/SSE).")]
    #[serde(alias = "close_token", alias = "owner_token")]
    pub token: Option<String>,
    #[schemars(
        description = "Force-close the database even if the original HTTP owner session or token was lost. Use only for recovery."
    )]
    #[serde(alias = "recover", alias = "override_owner")]
    pub force: Option<bool>,
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
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum functions to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Optional filter - only return functions containing this text")]
    #[serde(alias = "query", alias = "queries", alias = "filter")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFuncsRequest {
    #[schemars(
        description = "Return a task_id immediately and run analysis in the background. \
        Use for large binaries (kernelcache, full DSC) that exceed the request timeout."
    )]
    pub background: Option<bool>,
    #[schemars(
        description = "Foreground timeout in seconds (default 120, max 600). Ignored if background=true."
    )]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
    #[serde(default, rename = "_worker_no_timeout")]
    #[schemars(skip)]
    pub worker_no_timeout: bool,
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
    pub offset: Option<i64>,
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
    pub offset: Option<i64>,
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
    pub offset: Option<i64>,
    #[schemars(description = "Number of instructions (1-5000, default: 200)")]
    #[schemars(range(min = 1, max = 5000))]
    pub count: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmRequest {
    #[schemars(description = "Address(es) to disassemble (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Number of instructions (1-1000, default: 10)")]
    #[schemars(range(min = 1, max = 5000))]
    pub count: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmByNameRequest {
    #[schemars(description = "Function name to disassemble (exact or partial match)")]
    pub name: String,
    #[schemars(description = "Number of instructions (1-1000, default: 10)")]
    #[schemars(range(min = 1, max = 5000))]
    pub count: Option<i64>,
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
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Optional filter - only return strings containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
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
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
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
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Maximum xrefs per string (default: 64, max: 1024)")]
    #[schemars(range(min = 1, max = 1024))]
    pub max_xrefs: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LocalTypesRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum types to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Optional filter - only return types containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
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
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum structs to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Optional filter - only return structs containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StructInfoRequest {
    #[schemars(description = "Struct ordinal (numeric)")]
    #[schemars(range(min = 0, max = 4294967295_i64))]
    pub ordinal: Option<i64>,
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
    #[schemars(range(min = 0, max = 4294967295_i64))]
    pub ordinal: Option<i64>,
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
    pub offset: Option<i64>,
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
    pub offset: Option<i64>,
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
    #[schemars(range(min = 0, max = 4294967295_i64))]
    pub ordinal: Option<i64>,
    #[schemars(description = "Struct name (exact match)")]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
    #[schemars(description = "Struct member index (0-based)")]
    #[schemars(range(min = 0, max = 4294967295_i64))]
    pub member_index: Option<i64>,
    #[schemars(description = "Struct member name (exact match)")]
    #[serde(alias = "member", alias = "field", alias = "field_name")]
    pub member_name: Option<String>,
    #[schemars(description = "Maximum xrefs to return (default: 1000, max: 10000)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddressRequest {
    #[schemars(description = "Address(es) (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefsRequest {
    #[schemars(description = "Address(es) (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Maximum xrefs to return per address (1-10000, default: 1000)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
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
    pub offset: Option<i64>,
    #[schemars(description = "Number of bytes to read (1-65536, default: 256)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 1, max = 65536))]
    pub size: Option<i64>,
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
    pub offset: Option<i64>,
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
    pub flags: Option<i64>,
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
    pub offset: Option<i64>,
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
    pub offset: Option<i64>,
    #[schemars(description = "Assembly text to assemble and patch")]
    #[serde(alias = "asm", alias = "instruction")]
    pub line: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PaginatedRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum items to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
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
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum globals to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeStringsRequest {
    #[schemars(description = "Optional filter for strings")]
    #[serde(alias = "filter")]
    pub query: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum strings to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindBytesRequest {
    #[schemars(description = "Pattern(s) to search for (string or array)")]
    #[serde(alias = "pattern", alias = "patterns")]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
    #[serde(default, rename = "_worker_max_results")]
    #[schemars(skip)]
    pub worker_max_results: Option<i64>,
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
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
    #[serde(default, rename = "_worker_max_results")]
    #[schemars(skip)]
    pub worker_max_results: Option<i64>,
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
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Case-insensitive match (default: false)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
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
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Case-insensitive match (default: false)")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindPathsRequest {
    #[schemars(description = "Start address (string/number)")]
    pub start: Value,
    #[schemars(description = "End address (string/number)")]
    pub end: Value,
    #[schemars(description = "Maximum paths to return (default: 8)")]
    #[schemars(range(min = 1, max = 1024))]
    pub max_paths: Option<i64>,
    #[schemars(description = "Maximum path depth (default: 64)")]
    #[schemars(range(min = 1, max = 256))]
    pub max_depth: Option<i64>,
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
    #[schemars(range(min = 1, max = 256))]
    pub max_depth: Option<i64>,
    #[schemars(description = "Maximum nodes (default: 256)")]
    #[schemars(range(min = 1, max = 10000))]
    pub max_nodes: Option<i64>,
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
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum functions to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Export format (only json supported)")]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStringRequest {
    #[schemars(description = "Address(es) to read string from (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Value,
    #[schemars(description = "Maximum length to read (default: 256)")]
    #[schemars(range(min = 1, max = 4096))]
    pub max_len: Option<i64>,
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
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ToolHelpRequest {
    #[schemars(description = "Name of the tool to get help for")]
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecentOperationsRequest {
    #[schemars(description = "Maximum recent events to return (default: 20, max: 50)")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunScriptRequest {
    #[schemars(description = "Inline Python code (mutually exclusive with 'file').")]
    pub code: Option<String>,
    #[schemars(
        description = "Path to a .py file (mutually exclusive with 'code'). Read server-side."
    )]
    pub file: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default 120, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaskStatusRequest {
    #[schemars(description = "Task ID returned by open_dsc (e.g. 'dsc-abc123')")]
    pub task_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenDscRequest {
    #[schemars(description = "Path to the dyld_shared_cache file.")]
    pub path: String,
    #[schemars(description = "CPU arch (e.g. 'arm64e', 'arm64', 'x86_64h').")]
    pub arch: String,
    #[schemars(description = "Primary dylib path (e.g. '/usr/lib/libobjc.A.dylib').")]
    pub module: String,
    #[schemars(description = "Additional frameworks to load (absolute DSC paths).")]
    pub frameworks: Option<Vec<String>>,
    #[schemars(description = "IDA version 8 or 9 (default 9).")]
    #[schemars(range(min = 8, max = 9))]
    pub ida_version: Option<i64>,
    #[schemars(
        description = "Path for idat's log file (-L). Useful for debugging DSC load failures."
    )]
    pub log_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscAddDylibRequest {
    #[schemars(
        description = "DSC-internal dylib path (absolute, e.g. '/usr/lib/libSystem.B.dylib')."
    )]
    pub module: String,
    #[schemars(description = "Timeout in seconds (default 300, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscAddRegionRequest {
    #[schemars(description = "Single region address (hex '0x...' or decimal).")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: Value,
    #[schemars(description = "Timeout in seconds (default 300, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}
