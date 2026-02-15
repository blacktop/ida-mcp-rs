//! Headless IDA Pro MCP Server
//!
//! This library provides an MCP (Model Context Protocol) server for headless
//! IDA Pro access. It allows LLM agents to open IDA databases, list functions,
//! get disassembly, and decompile code.
//!
//! # Architecture
//!
//! IDA **must** run on the main thread. The architecture is:
//!
//! - **Main thread**: Runs the IDA worker loop (`ida::run_ida_loop`).
//!   All idalib operations happen here.
//!
//! - **Background thread**: Runs the tokio runtime with the async MCP server.
//!   Communicates with the main thread via channels.
//!
//! - **IdaWorker**: Handle for sending requests to the main thread.
//!
//! - **IdaMcpServer**: The MCP server that exposes tools for IDA operations.
//!   Uses the `rmcp` crate for MCP protocol handling.
//!
//! # Tools
//!
//! ## Database Management
//! - `open_idb`: Open an IDA database (.i64/.idb) or a raw binary (Mach-O/ELF/PE)
//! - `load_debug_info`: Load external debug info (e.g., dSYM/DWARF)
//! - `analysis_status`: Report auto-analysis status (auto_is_ok, auto_state)
//! - `close_idb`: Close the currently open database
//!
//! ## Function Analysis
//! - `list_functions`: List all functions (paginated)
//! - `list_funcs`: Alias for list_functions (ida-pro-mcp compatibility)
//! - `resolve_function`: Find a function by name
//! - `function_at`: Find the function containing an address
//! - `lookup_funcs`: Batch lookup by name/address (ida-pro-mcp compatibility)
//! - `disasm`: Get disassembly at an address
//! - `disasm_by_name`: Get disassembly for a function by name
//! - `disasm_function_at`: Disassemble the function containing an address
//! - `decompile`: Decompile a function using Hex-Rays
//! - `pseudocode_at`: Get decompiled pseudocode at an address or address range
//! - `list_globals`: List named globals (non-function symbols)
//! - `addr_info`: Resolve address to segment/function/symbol context
//!
//! ## Binary Structure
//! - `segments`: List all segments with permissions and types
//! - `strings`: List strings with optional filter
//! - `find_string`: Find strings matching a query
//! - `analyze_strings`: Strings plus xrefs (ida-pro-mcp compatibility)
//! - `imports`: List imported symbols
//! - `exports`: List exported/public symbols
//! - `export_funcs`: Export functions list (ida-pro-mcp compatibility)
//! - `entrypoints`: Get binary entry points
//!
//! ## Cross-References
//! - `xrefs_to`: Get references TO an address
//! - `xrefs_from`: Get references FROM an address
//! - `xrefs_to_string`: Find xrefs to strings matching a query
//!
//! ## Control/Call Flow
//! - `basic_blocks`: Get CFG basic blocks for a function
//! - `callees`: Get functions called by a function
//! - `callers`: Get functions that call a function
//! - `callgraph`: Build callgraph rooted at a function
//! - `find_paths`: Find CFG paths between addresses
//! - `xref_matrix`: Build xref adjacency matrix
//!
//! ## Memory
//! - `get_bytes`: Read raw bytes from an address
//! - `get_u8/get_u16/get_u32/get_u64`: Read integer values
//! - `get_string`: Read string at address
//! - `get_global_value`: Resolve global name/address and read value
//! - `find_bytes`: Find byte patterns
//! - `search`: Search text or immediates
//! - `int_convert`: Convert integers between bases
//!
//! ## Headless limitations
//! Debugger/UI/scripting features are not exposed in headless mode.

use std::path::PathBuf;

pub mod disasm;
pub mod dsc;
pub mod error;
pub mod ida;
pub mod server;
pub mod tool_registry;

pub use error::ToolError;
pub use ida::{
    run_ida_loop, AddressInfo, BasicBlockInfo, BytesResult, DbInfo, ExportInfo, FunctionInfo,
    FunctionListResult, FunctionRangeInfo, IdaRequest, IdaWorker, ImportInfo, SegmentInfo,
    StringInfo, StringListResult, StringXrefInfo, StringXrefsResult, SymbolInfo, XRefInfo,
};
pub use server::{IdaMcpServer, ServerMode};
pub use tool_registry::{ToolCategory, ToolInfo, TOOL_REGISTRY};

/// Expand `~/` prefix to the user's home directory.
pub fn expand_path(path: &str) -> PathBuf {
    path.strip_prefix("~/")
        .and_then(|stripped| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(stripped)))
        .unwrap_or_else(|| PathBuf::from(path))
}
