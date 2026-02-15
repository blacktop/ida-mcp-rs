//! MCP server implementation with IDA Pro tools.

mod requests;
pub mod task;

pub use requests::*;

use crate::error::ToolError;
use crate::ida::IdaWorker;
use crate::tool_registry::{self, ToolCategory};
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo, Tool},
    schemars::{schema_for, JsonSchema},
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

/// MCP server for IDA Pro analysis
#[derive(Clone)]
pub struct IdaMcpServer {
    worker: Arc<IdaWorker>,
    tool_mux: ToolMux<IdaMcpServer>,
    mode: ServerMode,
    task_registry: task::TaskRegistry,
}

#[derive(Clone, Copy, Debug)]
pub enum ServerMode {
    Stdio,
    Http,
}

#[derive(Clone)]
struct ToolMux<S> {
    call_router: ToolRouter<S>,
}

impl<S> ToolMux<S>
where
    S: Send + Sync + 'static,
{
    fn new(call_router: ToolRouter<S>) -> Self {
        Self { call_router }
    }

    async fn call(
        &self,
        context: ToolCallContext<'_, S>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.call_router.call(context).await
    }

    fn list_all(&self) -> Vec<Tool> {
        let mut tools = Vec::new();
        for info in tool_registry::all_tools() {
            if let Some(route) = self.call_router.map.get(info.name) {
                tools.push(route.attr.clone());
            }
        }
        tools
    }

    fn get(&self, name: &str) -> Option<&Tool> {
        self.call_router.map.get(name).map(|route| &route.attr)
    }
}

/// Parameters for the background DSC loading task.
struct DscBackgroundCtx {
    idat: std::path::PathBuf,
    idat_args: Vec<String>,
    log_path: std::path::PathBuf,
    out_i64: std::path::PathBuf,
    module: String,
    frameworks: Vec<String>,
}

impl IdaMcpServer {
    pub fn new(worker: Arc<IdaWorker>, mode: ServerMode) -> Self {
        info!("Creating IDA MCP server");
        let call_router = Self::tool_router();
        Self {
            worker,
            tool_mux: ToolMux::new(call_router),
            mode,
            task_registry: task::TaskRegistry::new(),
        }
    }

    fn close_hint(&self) -> &'static str {
        match self.mode {
            ServerMode::Stdio => {
                "Call close_idb when done to release locks for other sessions."
            }
            ServerMode::Http => {
                "In multi-client (HTTP/SSE) mode, close_idb requires the close_token returned by open_idb; only the opener should close."
            }
        }
    }

    fn instructions(&self) -> String {
        format!(
            "IDA Pro headless analysis server for reverse engineering binaries. \
                 \n\nWorkflow: \
                 \n1. open_idb: Open a .i64/.idb file or a raw binary (Mach-O/ELF/PE). Large DBs may take 30+ seconds. \
                 \n   load_debug_info: Optional for existing .i64 to load DWARF/dSYM \
                 \n2. tool_catalog: Discover tools for your task (e.g., 'find callers', 'decompile') \
                 \n3. tool_help: Get full docs for a specific tool \
                 \n4. Use the discovered tools to analyze the binary \
                 \n5. close_idb: Optionally close when done \
                 \n\nNote: tools/list exposes the full tool set by default; use tool_catalog/tool_help to discover usage. \
                 \n{close_hint} \
                 \n\nTool Categories: \
                 \n- core: open/close/discover (open_idb, close_idb, tool_catalog, tool_help, idb_meta) \
                 \n- functions: list, resolve, lookup functions \
                 \n- disassembly: disasm at addresses \
                 \n- decompile: Hex-Rays pseudocode \
                 \n- xrefs: cross-reference analysis \
                 \n- control_flow: CFG, callgraph, paths \
                 \n- memory: read bytes, strings, values \
                 \n- search: find patterns, strings \
                 \n- metadata: segments, imports, exports \
                 \n- types: declare_type, apply_types (addr/stack), infer_types, local_types, stack_frame, declare_stack, delete_stack, structs (list/info/read) \
                \n- editing: comments/rename/patch/patch_asm \
                 \n- scripting: run_script (execute IDAPython code) \
                 \n\nTip: Use tool_catalog(query='what you want to do') to find the right tool. \
                 \nTip: If xrefs/decompile look incomplete, call analysis_status to check auto-analysis.",
            close_hint = self.close_hint()
        )
    }

    fn validate_path(path: &str) -> bool {
        let path = path.trim();
        let expanded = if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                std::path::PathBuf::from(home).join(stripped)
            } else {
                return false;
            }
        } else {
            std::path::PathBuf::from(path)
        };
        let p = expanded.as_path();
        // Check: exists, is file, no path traversal
        // IDA can open many formats: .i64, .idb, ELF, Mach-O, PE, raw binaries, etc.
        p.exists() && p.is_file() && !path.contains("..")
    }

    fn parse_address(s: &str) -> Result<u64, ToolError> {
        let mut s = s.trim().to_string();
        s.retain(|c| c != '_');
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).map_err(|_| ToolError::InvalidAddress(s))
        } else if s.starts_with("0b") || s.starts_with("0B") {
            u64::from_str_radix(&s[2..], 2).map_err(|_| ToolError::InvalidAddress(s))
        } else if s.starts_with("0o") || s.starts_with("0O") {
            u64::from_str_radix(&s[2..], 8).map_err(|_| ToolError::InvalidAddress(s))
        } else {
            s.parse()
                .map_err(|_| ToolError::InvalidAddress(s.to_string()))
        }
    }

    fn value_to_strings(value: &Value) -> Result<Vec<String>, ToolError> {
        match value {
            Value::String(s) => {
                if s.contains(',') {
                    Ok(s.split(',')
                        .map(|t| t.trim())
                        .filter(|t| !t.is_empty())
                        .map(|t| t.to_string())
                        .collect())
                } else if s.trim().is_empty() {
                    Err(ToolError::IdaError("empty string".to_string()))
                } else {
                    Ok(vec![s.to_string()])
                }
            }
            Value::Number(n) => Ok(vec![n.to_string()]),
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::String(s) => out.push(s.to_string()),
                        Value::Number(n) => out.push(n.to_string()),
                        _ => {
                            return Err(ToolError::IdaError(
                                "expected string or number".to_string(),
                            ))
                        }
                    }
                }
                Ok(out)
            }
            _ => Err(ToolError::IdaError(
                "expected string, number, or array".to_string(),
            )),
        }
    }

    fn value_to_addresses(value: &Value) -> Result<Vec<u64>, ToolError> {
        let strings = Self::value_to_strings(value)?;
        if strings.is_empty() {
            return Err(ToolError::InvalidAddress(
                "no addresses provided".to_string(),
            ));
        }
        strings.iter().map(|s| Self::parse_address(s)).collect()
    }

    fn value_to_single_address(value: &Value) -> Result<u64, ToolError> {
        let addrs = Self::value_to_addresses(value)?;
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| ToolError::InvalidAddress("empty address list".to_string()))
    }

    fn value_to_bytes(value: &Value) -> Result<Vec<u8>, ToolError> {
        match value {
            Value::String(s) => {
                let mut cleaned = String::with_capacity(s.len());
                for c in s.chars() {
                    if c.is_ascii_hexdigit() {
                        cleaned.push(c);
                    } else if c.is_ascii_whitespace()
                        || matches!(c, ',' | '_' | ':' | '-')
                        || c == 'x'
                        || c == 'X'
                    {
                        continue;
                    } else {
                        return Err(ToolError::InvalidParams(format!(
                            "invalid hex character: {c}"
                        )));
                    }
                }
                if cleaned.is_empty() {
                    return Err(ToolError::InvalidParams("no bytes provided".to_string()));
                }
                if !cleaned.len().is_multiple_of(2) {
                    return Err(ToolError::InvalidParams(
                        "hex string has odd length".to_string(),
                    ));
                }
                let mut out = Vec::with_capacity(cleaned.len() / 2);
                for i in (0..cleaned.len()).step_by(2) {
                    let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
                        .map_err(|_| ToolError::InvalidParams("invalid hex byte".to_string()))?;
                    out.push(byte);
                }
                Ok(out)
            }
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::Number(n) => {
                            let byte = n.as_u64().ok_or_else(|| {
                                ToolError::InvalidParams("invalid byte".to_string())
                            })?;
                            if byte > u8::MAX as u64 {
                                return Err(ToolError::InvalidParams(
                                    "byte value out of range".to_string(),
                                ));
                            }
                            out.push(byte as u8);
                        }
                        Value::String(s) => {
                            let val = Self::parse_address(s)?;
                            if val > u8::MAX as u64 {
                                return Err(ToolError::InvalidParams(
                                    "byte value out of range".to_string(),
                                ));
                            }
                            out.push(val as u8);
                        }
                        _ => {
                            return Err(ToolError::InvalidParams(
                                "bytes must be numbers or strings".to_string(),
                            ))
                        }
                    }
                }
                if out.is_empty() {
                    Err(ToolError::InvalidParams("no bytes provided".to_string()))
                } else {
                    Ok(out)
                }
            }
            Value::Number(n) => {
                let byte = n
                    .as_u64()
                    .ok_or_else(|| ToolError::InvalidParams("invalid byte".to_string()))?;
                if byte > u8::MAX as u64 {
                    return Err(ToolError::InvalidParams(
                        "byte value out of range".to_string(),
                    ));
                }
                Ok(vec![byte as u8])
            }
            _ => Err(ToolError::InvalidParams(
                "expected hex string or array of bytes".to_string(),
            )),
        }
    }

    /// Open an existing DSC .i64 synchronously and return db_info.
    async fn open_dsc_i64(
        &self,
        out_i64: &std::path::Path,
        module: &str,
        frameworks: &[String],
    ) -> Result<CallToolResult, McpError> {
        info!(out_i64 = %out_i64.display(), "Opening existing DSC .i64");

        let i64_str = out_i64.display().to_string();
        let open_result = self
            .worker
            .open(&i64_str, false, None, false, false, None, true, Vec::new())
            .await;

        let db_info = match open_result {
            Ok(info) => info,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let close_token = if matches!(self.mode, ServerMode::Http) {
            self.worker.issue_close_token()
        } else {
            None
        };

        let mut value = match serde_json::to_value(&db_info) {
            Ok(v) => v,
            Err(_) => {
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "{db_info:?}"
                ))]))
            }
        };
        if let Value::Object(map) = &mut value {
            map.insert("module".to_string(), json!(module));
            if !frameworks.is_empty() {
                map.insert("frameworks_loaded".to_string(), json!(frameworks));
            }
            map.insert("close_hint".to_string(), json!(self.close_hint()));
            if let Some(token) = close_token {
                map.insert("close_token".to_string(), json!(token));
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value:?}")),
        )]))
    }

    /// Background task: run idat, then open the resulting .i64 with idalib.
    async fn run_dsc_background(
        task_id: String,
        registry: task::TaskRegistry,
        worker: Arc<IdaWorker>,
        mode: ServerMode,
        ctx: DscBackgroundCtx,
    ) {
        let DscBackgroundCtx {
            idat,
            idat_args,
            log_path,
            out_i64,
            module,
            frameworks,
        } = ctx;

        // Phase 1: run idat subprocess
        info!(task_id = %task_id, "Background: running idat");
        registry.update_message(&task_id, "Running idat to create .i64...");

        let idat_bin = idat;
        let module_env = module.clone();
        let out_i64_clone = out_i64.clone();
        let log_path_clone = log_path.clone();

        let spawn_result = tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new(&idat_bin);
            cmd.args(&idat_args);
            // Remove env vars that cause license conflicts when our
            // process links idalib and also spawns idat.
            cmd.env_remove("IDADIR");
            cmd.env_remove("DYLD_LIBRARY_PATH");
            cmd.env("IDA_DYLD_CACHE_MODULE", &module_env);
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());

            let output = cmd.output();

            match output {
                Ok(out) => {
                    let code = out.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    (code, stderr.to_string(), out_i64_clone, log_path_clone)
                }
                Err(e) => (
                    -1,
                    format!("Failed to spawn idat: {e}"),
                    out_i64_clone,
                    log_path_clone,
                ),
            }
        })
        .await;

        let (exit_code, stderr, out_path, log_out) = match spawn_result {
            Ok(tuple) => tuple,
            Err(e) => {
                registry.fail(&task_id, &format!("idat task panicked: {e}"));
                return;
            }
        };

        if exit_code != 0 || !out_path.exists() {
            let log_tail = std::fs::read_to_string(&log_out)
                .ok()
                .map(|s| {
                    let lines: Vec<&str> = s.lines().collect();
                    let start = lines.len().saturating_sub(20);
                    lines[start..].join("\n")
                })
                .unwrap_or_default();

            let msg = format!(
                "idat exited with code {exit_code}.\n\
                 stderr: {stderr}\n\
                 log (last 20 lines):\n{log_tail}"
            );
            warn!(exit_code, task_id = %task_id, "idat failed");
            registry.fail(&task_id, &msg);
            return;
        }

        info!(task_id = %task_id, "idat completed, opening .i64");
        registry.update_message(&task_id, "Opening database with idalib...");

        // Phase 2: open the .i64 with idalib
        let i64_str = out_i64.display().to_string();
        let open_result = worker
            .open(&i64_str, false, None, false, false, None, true, Vec::new())
            .await;

        let db_info = match open_result {
            Ok(info) => info,
            Err(e) => {
                registry.fail(&task_id, &e.to_string());
                return;
            }
        };

        let close_token = if matches!(mode, ServerMode::Http) {
            worker.issue_close_token()
        } else {
            None
        };

        let mut value = serde_json::to_value(&db_info)
            .unwrap_or_else(|_| json!({"info": format!("{db_info:?}")}));
        if let Value::Object(map) = &mut value {
            map.insert("module".to_string(), json!(module));
            if !frameworks.is_empty() {
                map.insert("frameworks_loaded".to_string(), json!(frameworks));
            }
            if let Some(token) = close_token {
                map.insert("close_token".to_string(), json!(token));
            }
        }

        info!(task_id = %task_id, "DSC background task completed");
        registry.complete(&task_id, value);
    }
}

// Tool implementations using the #[tool_router] attribute

#[tool_router]
impl IdaMcpServer {
    #[tool(
        description = "Open an IDA Pro database (.i64/.idb) or a raw binary (Mach-O/ELF/PE). \
        Raw binaries are auto-analyzed and saved as .i64 alongside the input. \
        If opening a raw binary with no existing .i64 and a sibling .dSYM is present, \
        its DWARF debug info is loaded automatically. \
        Set load_debug_info=true to force loading external debug info after open \
        (optionally specify debug_info_path). \
        Call close_idb when finished to release database locks; in multi-client servers, coordinate before closing. \
        In HTTP/SSE mode, open_idb returns a close_token that must be provided to close_idb. \
        NOTE: Opening large databases (like dyld_shared_cache) can take 30+ seconds. \
        The database stays open until close_idb is called, so you can make multiple \
        queries (list_functions, disasm, decompile, etc.) without reopening."
    )]
    #[instrument(skip(self), fields(path = %req.path))]
    async fn open_idb(
        &self,
        Parameters(req): Parameters<OpenIdbRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: open_idb");
        // Validate path (prevent directory traversal, check extension)
        if !Self::validate_path(&req.path) {
            return Ok(ToolError::InvalidPath(req.path).to_tool_result());
        }

        match self
            .worker
            .open(
                &req.path,
                req.load_debug_info.unwrap_or(false),
                req.debug_info_path.clone(),
                req.debug_info_verbose.unwrap_or(false),
                req.force.unwrap_or(false),
                req.file_type.clone(),
                true,
                Vec::new(),
            )
            .await
        {
            Ok(info) => {
                let close_token = if matches!(self.mode, ServerMode::Http) {
                    self.worker.issue_close_token()
                } else {
                    None
                };
                let mut value = match serde_json::to_value(&info) {
                    Ok(v) => v,
                    Err(_) => {
                        return Ok(CallToolResult::success(vec![Content::text(format!(
                            "{info:?}"
                        ))]))
                    }
                };
                if let Value::Object(map) = &mut value {
                    map.insert(
                        "quick_tools".to_string(),
                        json!([
                            "list_functions",
                            "resolve_function",
                            "disasm_by_name",
                            "decompile",
                            "xrefs_to",
                            "strings",
                            "close_idb"
                        ]),
                    );
                    map.insert("close_hint".to_string(), json!(self.close_hint()));
                    if let Some(token) = close_token {
                        map.insert("close_token".to_string(), json!(token));
                    }
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value:?}")),
                )]))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Load external debug info (e.g., DWARF/dSYM) into the current database. \
        If path is omitted, attempts to locate a sibling .dSYM for the currently-open database."
    )]
    #[instrument(skip(self))]
    async fn load_debug_info(
        &self,
        Parameters(req): Parameters<LoadDebugInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: load_debug_info");
        match self
            .worker
            .load_debug_info(req.path, req.verbose.unwrap_or(false))
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{info:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Report auto-analysis status (auto_is_ok, auto_state). \
        Use this to check whether analysis-dependent tools (xrefs, decompile) are fully ready.")]
    #[instrument(skip(self))]
    async fn analysis_status(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analysis_status");
        match self.worker.analysis_status().await {
            Ok(status) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&status).unwrap_or_else(|_| format!("{status:?}")),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Close the currently open IDA database. \
        Call this when you're done analyzing to free resources. \
        In HTTP/SSE mode, provide the close_token returned by open_idb. \
        The database can also be left open for the duration of the session.")]
    #[instrument(skip(self))]
    async fn close_idb(
        &self,
        Parameters(req): Parameters<CloseIdbRequest>,
    ) -> Result<CallToolResult, McpError> {
        info!("Tool call: close_idb received");
        if matches!(self.mode, ServerMode::Http)
            && !self.worker.close_token_matches(req.token.as_deref())
        {
            info!("close_idb ignored: owner token required");
            return Ok(CallToolResult::success(vec![Content::text(
                "close_idb ignored: owner token required",
            )]));
        }
        match self.worker.close().await {
            Ok(()) => {
                self.worker.clear_close_token();
                info!("Tool call: close_idb completed successfully");
                Ok(CallToolResult::success(vec![Content::text(
                    "Database closed",
                )]))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Discover available tools by query or category. \
        Use this to find the right tool for your task before calling tool_help for full details.")]
    #[instrument(skip(self))]
    async fn tool_catalog(
        &self,
        Parameters(req): Parameters<ToolCatalogRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_catalog");
        let limit = req.limit.unwrap_or(7).min(15);

        // If category specified, list tools in that category
        if let Some(cat_str) = &req.category {
            if let Ok(cat) = cat_str.parse::<ToolCategory>() {
                let tools: Vec<_> = tool_registry::tools_by_category(cat)
                    .take(limit)
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "description": t.short_desc,
                            "category": t.category.as_str(),
                        })
                    })
                    .collect();

                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "category": cat.as_str(),
                        "category_description": cat.description(),
                        "tools": tools,
                        "hint": "Use tool_help(name) for full documentation and examples"
                    }))
                    .unwrap(),
                )]));
            }
        }

        // If query specified, search for matching tools
        if let Some(query) = &req.query {
            let results = tool_registry::search_tools(query, limit);
            let tools: Vec<_> = results
                .iter()
                .map(|(t, keywords)| {
                    json!({
                        "name": t.name,
                        "description": t.short_desc,
                        "category": t.category.as_str(),
                        "matched": keywords,
                    })
                })
                .collect();

            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({
                    "query": query,
                    "tools": tools,
                    "hint": "Use tool_help(name) for full documentation and examples"
                }))
                .unwrap(),
            )]));
        }

        // No query or category - list all categories
        let categories: Vec<_> = ToolCategory::all()
            .iter()
            .map(|c| {
                let count = tool_registry::tools_by_category(*c).count();
                json!({
                    "category": c.as_str(),
                    "description": c.description(),
                    "tool_count": count,
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "categories": categories,
                "hint": "Use tool_catalog(category='...') to list tools in a category, or tool_catalog(query='...') to search. tools/list already includes all tools."
            }))
            .unwrap(),
        )]))
    }

    #[tool(
        description = "Get full documentation for a tool including description, parameters schema, and example."
    )]
    #[instrument(skip(self))]
    async fn tool_help(
        &self,
        Parameters(req): Parameters<ToolHelpRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_help for {}", req.name);

        if let Some(tool) = tool_registry::get_tool(&req.name) {
            let params = tool_params_schema(&req.name);
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({
                    "name": tool.name,
                    "category": tool.category.as_str(),
                    "description": tool.full_desc,
                    "parameters": params,
                    "example": tool.example,
                    "keywords": tool.keywords,
                }))
                .unwrap(),
            )]))
        } else {
            // Suggest similar tools
            let suggestions = tool_registry::search_tools(&req.name, 3);
            let suggestion_names: Vec<_> = suggestions.iter().map(|(t, _)| t.name).collect();

            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({
                    "error": format!("Tool '{}' not found", req.name),
                    "suggestions": suggestion_names,
                    "hint": "Use tool_catalog to discover available tools"
                }))
                .unwrap(),
            )]))
        }
    }

    #[tool(description = "List all functions in the database (paginated). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn list_functions(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_functions");
        // Clamp limit to prevent excessive responses
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let filter = req.filter.clone();

        match self
            .worker
            .list_functions(offset, limit, filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List functions (ida-pro-mcp compatible alias). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn list_funcs(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_funcs");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let filter = req.filter.clone();

        match self
            .worker
            .list_functions(offset, limit, filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Resolve a function name to its address")]
    #[instrument(skip(self), fields(name = %req.name))]
    async fn resolve_function(
        &self,
        Parameters(req): Parameters<ResolveFunctionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: resolve_function");
        match self.worker.resolve_function(&req.name).await {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{:?}", info)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get address context (segment, function, nearest symbol)")]
    async fn addr_info(
        &self,
        Parameters(req): Parameters<AddrInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .addr_info(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{:?}", info)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get the function that contains an address")]
    async fn function_at(
        &self,
        Parameters(req): Parameters<FunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .function_at(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(info) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&info).unwrap_or_else(|_| format!("{:?}", info)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get disassembly at an address")]
    #[instrument(skip(self), fields(address = %req.address, count = req.count))]
    async fn disasm(
        &self,
        Parameters(req): Parameters<DisasmRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disasm");
        // Clamp instruction count
        let count = req.count.unwrap_or(10).min(1000);
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.disasm(addrs[0], count).await {
                Ok(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.disasm(addr, count).await {
                    Ok(text) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "disasm": text
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get disassembly for a function by name")]
    #[instrument(skip(self), fields(name = %req.name, count = req.count))]
    async fn disasm_by_name(
        &self,
        Parameters(req): Parameters<DisasmByNameRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disasm_by_name");
        let count = req.count.unwrap_or(10).min(1000);

        match self.worker.disasm_by_name(&req.name, count).await {
            Ok(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Disassemble the function containing an address")]
    async fn disasm_function_at(
        &self,
        Parameters(req): Parameters<DisasmFunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let count = req.count.unwrap_or(200).min(5000);
        match self
            .worker
            .disasm_function_at(addr, req.target_name.clone(), offset, count)
            .await
        {
            Ok(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Decompile a function using Hex-Rays (if available)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn decompile(
        &self,
        Parameters(req): Parameters<DecompileRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: decompile");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.decompile(addrs[0]).await {
                Ok(code) => Ok(CallToolResult::success(vec![Content::text(code)])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.decompile(addr).await {
                    Ok(code) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "decompile": code
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(
        description = "Get decompiled pseudocode at a specific address or address range. \
        Unlike 'decompile' which returns the full function, this returns only the statements \
        that correspond to the given address(es). Useful for getting pseudocode for a basic block \
        or specific instruction. If end_address is provided, returns statements covering the range."
    )]
    #[instrument(skip(self), fields(address = %req.address, end_address = ?req.end_address))]
    async fn pseudocode_at(
        &self,
        Parameters(req): Parameters<PseudocodeAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: pseudocode_at");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let end_addr = if let Some(ref end_str) = req.end_address {
            match Self::parse_address(end_str) {
                Ok(a) => Some(a),
                Err(e) => return Ok(e.to_tool_result()),
            }
        } else {
            None
        };

        if addrs.len() == 1 {
            match self.worker.pseudocode_at(addrs[0], end_addr).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.pseudocode_at(addr, end_addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "pseudocode": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "List all segments in the database with their permissions and types")]
    #[instrument(skip(self))]
    async fn segments(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: segments");
        match self.worker.segments().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "List strings in the database with pagination and optional filter. \
        For large databases, consider setting timeout_secs (default: 120, max: 600)."
    )]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn strings(
        &self,
        Parameters(req): Parameters<StringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: strings");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self
            .worker
            .strings(offset, limit, req.filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Find strings matching a query (supports exact/case-insensitive options). \
        For large databases, consider setting timeout_secs (default: 120, max: 600)."
    )]
    async fn find_string(
        &self,
        Parameters(req): Parameters<FindStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let exact = req.exact.unwrap_or(false);
        let case_insensitive = req.case_insensitive.unwrap_or(true);
        match self
            .worker
            .find_string(
                req.query.clone(),
                exact,
                case_insensitive,
                offset,
                limit,
                req.timeout_secs,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find strings and return xrefs to each match. \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    async fn xrefs_to_string(
        &self,
        Parameters(req): Parameters<XrefsToStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let exact = req.exact.unwrap_or(false);
        let case_insensitive = req.case_insensitive.unwrap_or(true);
        let max_xrefs = req.max_xrefs.unwrap_or(64);
        match self
            .worker
            .xrefs_to_string(
                req.query.clone(),
                exact,
                case_insensitive,
                offset,
                limit,
                max_xrefs,
                req.timeout_secs,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get cross-references TO an address (who references this address)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn xrefs_to(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xrefs_to");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.xrefs_to(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.xrefs_to(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "xrefs": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get cross-references FROM an address (what this address references)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn xrefs_from(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xrefs_from");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.xrefs_from(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.xrefs_from(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "xrefs": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "List imports (external symbols) with pagination")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn imports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: imports");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self.worker.imports(offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List exports/names (public symbols) with pagination")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn exports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: exports");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self.worker.exports(offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get entry point addresses of the binary")]
    #[instrument(skip(self))]
    async fn entrypoints(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: entrypoints");
        match self.worker.entrypoints().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Read raw bytes from an address as hex string")]
    #[instrument(skip(self), fields(size = req.size))]
    async fn get_bytes(
        &self,
        Parameters(req): Parameters<GetBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_bytes");
        let size = req.size.unwrap_or(256).min(0x10000);
        if let Some(addr_value) = req.address.as_ref() {
            let addrs = match Self::value_to_addresses(addr_value) {
                Ok(a) => a,
                Err(e) => return Ok(e.to_tool_result()),
            };

            if addrs.len() == 1 {
                match self.worker.get_bytes(Some(addrs[0]), None, 0, size).await {
                    Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                        serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|_| format!("{:?}", result)),
                    )])),
                    Err(e) => Ok(e.to_tool_result()),
                }
            } else {
                let mut results = Vec::new();
                for addr in addrs {
                    match self.worker.get_bytes(Some(addr), None, 0, size).await {
                        Ok(result) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "bytes": result
                        })),
                        Err(e) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "error": e.to_string()
                        })),
                    }
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({ "results": results }))
                        .unwrap_or_else(|_| format!("{:?}", results)),
                )]))
            }
        } else if let Some(name) = req.target_name.as_ref() {
            let offset = req.offset.unwrap_or(0);
            match self
                .worker
                .get_bytes(None, Some(name.clone()), offset, size)
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            Ok(ToolError::InvalidParams("address or name required".to_string()).to_tool_result())
        }
    }

    #[tool(description = "Get basic blocks of a function (control flow graph nodes)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn basic_blocks(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: basic_blocks");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.basic_blocks(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.basic_blocks(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "basic_blocks": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get functions called BY a function (callees/children in call graph)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn callees(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callees");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.callees(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.callees(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "callees": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get functions that CALL a function (callers/parents in call graph)")]
    #[instrument(skip(self), fields(address = %req.address))]
    async fn callers(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callers");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.callers(addrs[0]).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.callers(addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "callers": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get IDB metadata (ida-pro-mcp compatibility)")]
    #[instrument(skip(self))]
    async fn idb_meta(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: idb_meta");
        match self.worker.idb_meta().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Lookup functions by name or address (batch)")]
    #[instrument(skip(self))]
    async fn lookup_funcs(
        &self,
        Parameters(req): Parameters<LookupFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: lookup_funcs");
        let queries = match Self::value_to_strings(&req.queries) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.lookup_funcs(queries).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List global names (non-function symbols). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn list_globals(
        &self,
        Parameters(req): Parameters<ListGlobalsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_globals");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .list_globals(req.query.clone(), offset, limit, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Analyze strings with xrefs (ida-pro-mcp compatibility). \
        For large databases, consider setting timeout_secs (default: 120, max: 600)."
    )]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn analyze_strings(
        &self,
        Parameters(req): Parameters<AnalyzeStringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analyze_strings");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .analyze_strings(req.query.clone(), offset, limit, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find byte patterns (ida-pro-mcp compatibility). \
        For large databases, consider setting timeout_secs (default: 120, max: 600).")]
    #[instrument(skip(self))]
    async fn find_bytes(
        &self,
        Parameters(req): Parameters<FindBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_bytes");
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let timeout_secs = req.timeout_secs;
        let mut results = Vec::new();

        for pattern in patterns {
            let max_results = (offset + limit).min(20000);
            match self
                .worker
                .find_bytes(pattern.clone(), max_results, timeout_secs)
                .await
            {
                Ok(value) => {
                    let matches = value
                        .get("matches")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let total = matches.len();
                    let sliced = matches
                        .into_iter()
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    let next_offset = if offset + limit < total {
                        Some(offset + limit)
                    } else {
                        None
                    };
                    results.push(json!({
                        "pattern": pattern,
                        "matches": sliced,
                        "total": total,
                        "next_offset": next_offset
                    }));
                }
                Err(e) => results.push(json!({
                    "pattern": pattern,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({ "results": results }))
                .unwrap_or_else(|_| format!("{:?}", results)),
        )]))
    }

    #[tool(
        description = "Search for text or immediates (ida-pro-mcp compatibility). \
        For large databases, consider setting timeout_secs (default: 120, max: 600)."
    )]
    #[instrument(skip(self))]
    async fn search(
        &self,
        Parameters(req): Parameters<SearchRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search");
        let targets = match Self::value_to_strings(&req.targets) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);
        let timeout_secs = req.timeout_secs;
        let kind = req.kind.as_deref().unwrap_or("auto").to_lowercase();

        let mut results = Vec::new();
        for target in targets {
            let max_results = (offset + limit).min(20000);
            let search_result = if kind == "imm" || kind == "immediate" {
                match Self::parse_address(&target) {
                    Ok(val) => self.worker.search_imm(val, max_results, timeout_secs).await,
                    Err(e) => {
                        results.push(json!({
                            "target": target,
                            "error": e.to_string()
                        }));
                        continue;
                    }
                }
            } else if kind == "text" || kind == "string" {
                self.worker
                    .search_text(target.clone(), max_results, timeout_secs)
                    .await
            } else if let Ok(val) = Self::parse_address(&target) {
                self.worker.search_imm(val, max_results, timeout_secs).await
            } else {
                self.worker
                    .search_text(target.clone(), max_results, timeout_secs)
                    .await
            };

            match search_result {
                Ok(value) => {
                    let matches = value
                        .get("matches")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let total = matches.len();
                    let sliced = matches
                        .into_iter()
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    let next_offset = if offset + limit < total {
                        Some(offset + limit)
                    } else {
                        None
                    };
                    results.push(json!({
                        "target": target,
                        "matches": sliced,
                        "total": total,
                        "next_offset": next_offset
                    }));
                }
                Err(e) => results.push(json!({
                    "target": target,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({ "results": results }))
                .unwrap_or_else(|_| format!("{:?}", results)),
        )]))
    }

    #[tool(description = "Read u8 values at address(es)")]
    #[instrument(skip(self))]
    async fn get_u8(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 1).await
    }

    #[tool(description = "Read u16 values at address(es)")]
    #[instrument(skip(self))]
    async fn get_u16(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 2).await
    }

    #[tool(description = "Read u32 values at address(es)")]
    #[instrument(skip(self))]
    async fn get_u32(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 4).await
    }

    #[tool(description = "Read u64 values at address(es)")]
    #[instrument(skip(self))]
    async fn get_u64(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 8).await
    }

    #[tool(description = "Read string(s) at address(es)")]
    #[instrument(skip(self))]
    async fn get_string(
        &self,
        Parameters(req): Parameters<GetStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_string");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_len = req.max_len.unwrap_or(256).min(0x10000);

        if addrs.len() == 1 {
            match self.worker.get_string(addrs[0], max_len).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.get_string(addr, max_len).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "string": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Get global value(s) by name or address")]
    #[instrument(skip(self))]
    async fn get_global_value(
        &self,
        Parameters(req): Parameters<GetGlobalValueRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_global_value");
        let queries = match Self::value_to_strings(&req.query) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if queries.len() == 1 {
            match self.worker.get_global_value(queries[0].clone()).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for query in queries {
                match self.worker.get_global_value(query.clone()).await {
                    Ok(result) => results.push(json!({
                        "query": query,
                        "value": result
                    })),
                    Err(e) => results.push(json!({
                        "query": query,
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Find paths between two addresses (CFG)")]
    #[instrument(skip(self))]
    async fn find_paths(
        &self,
        Parameters(req): Parameters<FindPathsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_paths");
        let start = match Self::value_to_single_address(&req.start) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let end = match Self::value_to_single_address(&req.end) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_paths = req.max_paths.unwrap_or(8).min(128);
        let max_depth = req.max_depth.unwrap_or(64).min(2048);

        match self
            .worker
            .find_paths(start, end, max_paths, max_depth)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Build a callgraph rooted at an address")]
    #[instrument(skip(self))]
    async fn callgraph(
        &self,
        Parameters(req): Parameters<CallGraphRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callgraph");
        let roots = match Self::value_to_addresses(&req.roots) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_depth = req.max_depth.unwrap_or(2).min(16);
        let max_nodes = req.max_nodes.unwrap_or(256).min(10000);

        if roots.len() == 1 {
            match self.worker.callgraph(roots[0], max_depth, max_nodes).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for root in roots {
                match self.worker.callgraph(root, max_depth, max_nodes).await {
                    Ok(result) => results.push(json!({
                        "root": format!("{:#x}", root),
                        "callgraph": result
                    })),
                    Err(e) => results.push(json!({
                        "root": format!("{:#x}", root),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Compute xref matrix for a set of addresses")]
    #[instrument(skip(self))]
    async fn xref_matrix(
        &self,
        Parameters(req): Parameters<XrefMatrixRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xref_matrix");
        let addrs = match Self::value_to_addresses(&req.addrs) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.xref_matrix(addrs).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Export functions (ida-pro-mcp compatibility)")]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit))]
    async fn export_funcs(
        &self,
        Parameters(req): Parameters<ExportFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: export_funcs");
        if let Some(fmt) = req.format.as_deref() {
            if fmt.to_lowercase() != "json" {
                return Ok(ToolError::NotSupported(format!(
                    "format {} not supported (only json)",
                    fmt
                ))
                .to_tool_result());
            }
        }
        if let Some(addrs) = req.addrs {
            let queries = match Self::value_to_strings(&addrs) {
                Ok(v) => v,
                Err(e) => return Ok(e.to_tool_result()),
            };
            match self.worker.lookup_funcs(queries).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let limit = req.limit.unwrap_or(100).min(10000);
            let offset = req.offset.unwrap_or(0);
            match self.worker.export_funcs(offset, limit).await {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        }
    }

    #[tool(description = "Convert integers between bases")]
    #[instrument(skip(self))]
    async fn int_convert(
        &self,
        Parameters(req): Parameters<IntConvertRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: int_convert");
        let inputs = match Self::value_to_strings(&req.inputs) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let mut results = Vec::new();
        for input in inputs {
            match Self::parse_address(&input) {
                Ok(value) => {
                    let le = value.to_le_bytes();
                    let be = value.to_be_bytes();
                    let le_trim = trim_bytes_le(&le);
                    let be_trim = trim_bytes_be(&be);
                    results.push(json!({
                        "input": input,
                        "value": value,
                        "dec": value.to_string(),
                        "hex": format!("0x{:x}", value),
                        "bin": format!("0b{:b}", value),
                        "bytes_le": hex_encode(&le_trim),
                        "bytes_be": hex_encode(&be_trim),
                        "ascii": bytes_to_ascii(&le_trim),
                    }));
                }
                Err(e) => results.push(json!({
                    "input": input,
                    "error": e.to_string()
                })),
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({ "results": results }))
                .unwrap_or_else(|_| format!("{:?}", results)),
        )]))
    }

    #[tool(description = "List local types")]
    async fn local_types(
        &self,
        Parameters(req): Parameters<LocalTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(100);
        match self
            .worker
            .local_types(offset, limit, req.filter.clone(), req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get xrefs to a struct field")]
    async fn xrefs_to_field(
        &self,
        Parameters(req): Parameters<XrefsToFieldRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = req.limit.unwrap_or(1000).min(10000);
        match self
            .worker
            .xrefs_to_field(
                req.ordinal,
                req.name.clone(),
                req.member_index,
                req.member_name.clone(),
                limit,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Set comments at an address")]
    async fn set_comments(
        &self,
        Parameters(req): Parameters<SetCommentsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let repeatable = req.repeatable.unwrap_or(false);
        let offset = req.offset.unwrap_or(0);
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .set_comments(
                addr,
                req.target_name.clone(),
                offset,
                req.comment.clone(),
                repeatable,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Patch instructions with assembly text")]
    async fn patch_asm(
        &self,
        Parameters(req): Parameters<PatchAsmRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .patch_asm(addr, req.target_name.clone(), offset, req.line.clone())
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Declare a type in the local type library")]
    async fn declare_type(
        &self,
        Parameters(req): Parameters<DeclareTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        let relaxed = req.relaxed.unwrap_or(false);
        let replace = req.replace.unwrap_or(false);
        let multi = req.multi.unwrap_or(false);
        match self
            .worker
            .declare_type(req.decl.clone(), relaxed, replace, multi)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get stack frame info")]
    async fn stack_frame(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match Self::value_to_single_address(&req.address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.stack_frame(addr).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Declare a stack variable in a function frame")]
    async fn declare_stack(
        &self,
        Parameters(req): Parameters<DeclareStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let relaxed = req.relaxed.unwrap_or(false);
        match self
            .worker
            .declare_stack(
                addr,
                req.target_name.clone(),
                req.offset,
                req.var_name.clone(),
                req.decl.clone(),
                relaxed,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Delete a stack variable from a function frame")]
    async fn delete_stack(
        &self,
        Parameters(req): Parameters<DeleteStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .delete_stack(
                addr,
                req.target_name.clone(),
                req.offset,
                req.var_name.clone(),
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "List structs in the database with pagination and optional filter. \
        For large databases, consider setting timeout_secs (default: 120, max: 600)."
    )]
    #[instrument(skip(self), fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: structs");
        let limit = req.limit.unwrap_or(100).min(10000);
        let offset = req.offset.unwrap_or(0);

        match self
            .worker
            .structs(offset, limit, req.filter, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get info about a struct by ordinal or name")]
    #[instrument(skip(self), fields(ordinal = req.ordinal, name = ?req.name))]
    async fn struct_info(
        &self,
        Parameters(req): Parameters<StructInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: struct_info");
        match self.worker.struct_info(req.ordinal, req.name).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Read values of a struct instance at an address")]
    #[instrument(skip(self), fields(address = %req.address, ordinal = req.ordinal, name = ?req.name))]
    async fn read_struct(
        &self,
        Parameters(req): Parameters<ReadStructRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_struct");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self
                .worker
                .read_struct(addrs[0], req.ordinal, req.name)
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self
                    .worker
                    .read_struct(addr, req.ordinal, req.name.clone())
                    .await
                {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "struct": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&json!({ "results": results }))
                    .unwrap_or_else(|_| format!("{:?}", results)),
            )]))
        }
    }

    #[tool(description = "Search structs by name")]
    async fn search_structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(100);
        match self
            .worker
            .structs(offset, limit, req.filter.clone(), req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find instruction sequences by mnemonic")]
    async fn find_insns(
        &self,
        Parameters(req): Parameters<FindInsnsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        if patterns.is_empty() {
            return Ok(ToolError::InvalidParams("empty patterns".to_string()).to_tool_result());
        }
        let max_results = req.limit.unwrap_or(100);
        let case_insensitive = req.case_insensitive.unwrap_or(false);
        match self
            .worker
            .find_insns(patterns, max_results, case_insensitive, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find instruction operands")]
    async fn find_insn_operands(
        &self,
        Parameters(req): Parameters<FindInsnOperandsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        if patterns.is_empty() {
            return Ok(ToolError::InvalidParams("empty patterns".to_string()).to_tool_result());
        }
        let max_results = req.limit.unwrap_or(100);
        let case_insensitive = req.case_insensitive.unwrap_or(false);
        match self
            .worker
            .find_insn_operands(patterns, max_results, case_insensitive, req.timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Apply a type to an address")]
    async fn apply_types(
        &self,
        Parameters(req): Parameters<ApplyTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let relaxed = req.relaxed.unwrap_or(false);
        let delay = req.delay.unwrap_or(false);
        let strict = req.strict.unwrap_or(false);
        match self
            .worker
            .apply_types(
                addr,
                req.target_name.clone(),
                offset,
                req.stack_offset,
                req.stack_name.clone(),
                req.decl.clone(),
                req.type_name.clone(),
                relaxed,
                delay,
                strict,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Infer/guess type at an address")]
    async fn infer_types(
        &self,
        Parameters(req): Parameters<InferTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .infer_types(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Analyze functions (not supported)")]
    async fn analyze_funcs(
        &self,
        Parameters(req): Parameters<AnalyzeFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        match self.worker.analyze_funcs(req.timeout_secs).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Rename symbols")]
    async fn rename(
        &self,
        Parameters(req): Parameters<RenameRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let flags = req.flags.unwrap_or(0);
        match self
            .worker
            .rename(addr, req.current_name.clone(), req.name.clone(), flags)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Patch bytes at an address")]
    async fn patch(
        &self,
        Parameters(req): Parameters<PatchRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match Self::value_to_single_address(val) {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let bytes = match Self::value_to_bytes(&req.bytes) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self
            .worker
            .patch_bytes(addr, req.target_name.clone(), offset, bytes)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Open a dyld_shared_cache file and load a single module (dylib) for analysis. \
        If the .i64 database already exists, opens it immediately and returns db_info. \
        If the .i64 must be created (first time), spawns idat in the background and returns \
        a task_id immediately. Poll task_status(task_id) to check progress — when completed, \
        the database is already open and ready for analysis tools. \
        Use this instead of open_idb when working with Apple's dyld_shared_cache files. \
        The module parameter specifies which dylib to extract (e.g. '/usr/lib/libobjc.A.dylib'). \
        Additional frameworks can be loaded to resolve cross-module references."
    )]
    #[instrument(skip(self), fields(path = %req.path, arch = %req.arch, module = %req.module))]
    async fn open_dsc(
        &self,
        Parameters(req): Parameters<OpenDscRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: open_dsc");

        if !Self::validate_path(&req.path) {
            return Ok(ToolError::InvalidPath(req.path).to_tool_result());
        }

        let ida_version = req.ida_version.unwrap_or(9);
        if ida_version != 8 && ida_version != 9 {
            return Ok(
                ToolError::InvalidParams("ida_version must be 8 or 9".into()).to_tool_result(),
            );
        }

        let file_type = crate::dsc::dsc_file_type(&req.arch, ida_version);
        let frameworks = req.frameworks.unwrap_or_default();
        let dsc_path = std::path::Path::new(&req.path);
        let out_i64 = dsc_path.with_extension("i64");

        // If .i64 already exists, open synchronously (fast path).
        if out_i64.exists() {
            return self.open_dsc_i64(&out_i64, &req.module, &frameworks).await;
        }

        // .i64 doesn't exist — need to run idat, which takes minutes.
        // Validate idat exists and write the load script before spawning.
        let idat = match crate::dsc::find_idat() {
            Ok(path) => path,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let script = crate::dsc::dsc_load_script(&req.module, &frameworks);
        let script_dir = dsc_path.parent().unwrap_or(std::path::Path::new("/tmp"));
        let script_path = script_dir.join("ida_mcp_dsc_load.py");
        if let Err(e) = std::fs::write(&script_path, &script) {
            return Ok(
                ToolError::InvalidParams(format!("Failed to write DSC load script: {e}"))
                    .to_tool_result(),
            );
        }

        let log_path = script_dir.join("ida_mcp_dsc.log");
        let idat_args = crate::dsc::idat_dsc_args(
            dsc_path,
            &out_i64,
            &script_path,
            &file_type,
            Some(&log_path),
        );

        // Create a background task and return immediately.
        // Use the .i64 path as dedup key to prevent concurrent idat
        // processes writing the same output file.
        let dedup_key = out_i64.display().to_string();
        let task_id = match self
            .task_registry
            .create_keyed(&dedup_key, "Running idat to create .i64 from DSC...")
        {
            Ok(id) => id,
            Err(existing_id) => {
                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "status": "already_running",
                        "task_id": existing_id,
                        "message": "A DSC loading task for this path is already in progress. Poll task_status(task_id) for progress.",
                    }))
                    .unwrap_or_default(),
                )]));
            }
        };

        info!(
            task_id = %task_id,
            idat = %idat.display(),
            module = %req.module,
            "Spawning background idat for DSC loading"
        );

        let registry = self.task_registry.clone();
        let worker = Arc::clone(&self.worker);
        let mode = self.mode;
        let module = req.module.clone();
        let tid = task_id.clone();

        let ctx = DscBackgroundCtx {
            idat,
            idat_args,
            log_path,
            out_i64,
            module,
            frameworks,
        };

        let handle = tokio::spawn(async move {
            Self::run_dsc_background(tid, registry, worker, mode, ctx).await;
        });
        self.task_registry.set_handle(&task_id, handle);

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "status": "started",
                "task_id": task_id,
                "message": "DSC loading started in background. Poll task_status(task_id) for progress.",
            }))
            .unwrap_or_default(),
        )]))
    }

    #[tool(
        description = "Check the status of a background task (e.g. DSC loading). \
        Returns the current status: 'running' (with a progress message), \
        'completed' (with the result — database is already open), \
        'failed' (with an error message), or 'cancelled'. \
        Use the task_id returned by open_dsc."
    )]
    #[instrument(skip(self), fields(task_id = %req.task_id))]
    async fn task_status(
        &self,
        Parameters(req): Parameters<TaskStatusRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: task_status");

        let state = match self.task_registry.get(&req.task_id) {
            Some(s) => s,
            None => {
                return Ok(
                    ToolError::InvalidParams(format!("Unknown task_id: {}", req.task_id))
                        .to_tool_result(),
                );
            }
        };

        let elapsed = state.created_at.elapsed().as_secs();
        let status_str = match state.status {
            task::TaskStatus::Running => "running",
            task::TaskStatus::Completed => "completed",
            task::TaskStatus::Failed => "failed",
            task::TaskStatus::Cancelled => "cancelled",
        };

        let mut response = json!({
            "task_id": state.id,
            "status": status_str,
            "message": state.message,
            "elapsed_secs": elapsed,
        });

        if let Some(result) = &state.result {
            if let Value::Object(map) = &mut response {
                map.insert("result".to_string(), result.clone());
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap_or_default(),
        )]))
    }

    #[tool(
        description = "Execute a Python script via IDAPython in the open database. \
        Has full access to all ida_* modules, idc, idautils. \
        stdout and stderr are captured and returned. \
        Provide either 'code' (inline Python) or 'file' (path to a .py file), not both. \
        Use this for custom analysis that goes beyond the built-in tools. \
        API reference: https://python.docs.hex-rays.com"
    )]
    #[instrument(skip(self))]
    async fn run_script(
        &self,
        Parameters(req): Parameters<RunScriptRequest>,
    ) -> Result<CallToolResult, McpError> {
        let code = match (req.code, req.file) {
            (Some(code), None) => code,
            (None, Some(path)) => {
                if !Self::validate_path(&path) {
                    return Ok(ToolError::InvalidPath(path).to_tool_result());
                }
                match std::fs::read_to_string(&path) {
                    Ok(contents) => contents,
                    Err(e) => {
                        return Ok(ToolError::InvalidPath(format!(
                            "Failed to read script file '{}': {}",
                            path, e
                        ))
                        .to_tool_result());
                    }
                }
            }
            (Some(_), Some(_)) => {
                return Ok(ToolError::InvalidParams(
                    "Provide either 'code' or 'file', not both".into(),
                )
                .to_tool_result());
            }
            (None, None) => {
                return Ok(ToolError::InvalidParams(
                    "Provide either 'code' (inline Python) or 'file' (path to .py)".into(),
                )
                .to_tool_result());
            }
        };
        let timeout = req.timeout_secs.map(|t| t.min(600));
        match self.worker.run_script(&code, timeout).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }
}

async fn get_int_values(
    worker: &IdaWorker,
    address: Value,
    size: usize,
) -> Result<CallToolResult, McpError> {
    let addrs = match IdaMcpServer::value_to_addresses(&address) {
        Ok(v) => v,
        Err(e) => return Ok(e.to_tool_result()),
    };

    if addrs.len() == 1 {
        match worker.read_int(addrs[0], size).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    } else {
        let mut results = Vec::new();
        for addr in addrs {
            match worker.read_int(addr, size).await {
                Ok(result) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "value": result
                })),
                Err(e) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "error": e.to_string()
                })),
            }
        }
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({ "results": results }))
                .unwrap_or_else(|_| format!("{:?}", results)),
        )]))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn trim_bytes_le(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    while out.len() > 1 && out.last() == Some(&0) {
        out.pop();
    }
    out
}

fn trim_bytes_be(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0usize;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    bytes[start..].to_vec()
}

fn bytes_to_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            let c = *b as char;
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '.'
            }
        })
        .collect()
}

fn tool_params_schema(name: &str) -> Option<Value> {
    fn schema<T: JsonSchema>() -> Value {
        serde_json::to_value(schema_for!(T)).unwrap_or_else(|_| json!({}))
    }

    match name {
        // Core
        "open_idb" => Some(schema::<OpenIdbRequest>()),
        "open_dsc" => Some(schema::<OpenDscRequest>()),
        "close_idb" => Some(schema::<CloseIdbRequest>()),
        "load_debug_info" => Some(schema::<LoadDebugInfoRequest>()),
        "analysis_status" => Some(schema::<EmptyParams>()),
        "tool_catalog" => Some(schema::<ToolCatalogRequest>()),
        "tool_help" => Some(schema::<ToolHelpRequest>()),
        "idb_meta" => Some(schema::<EmptyParams>()),

        // Functions
        "list_functions" | "list_funcs" => Some(schema::<ListFunctionsRequest>()),
        "resolve_function" => Some(schema::<ResolveFunctionRequest>()),
        "addr_info" => Some(schema::<AddrInfoRequest>()),
        "function_at" => Some(schema::<FunctionAtRequest>()),
        "lookup_funcs" => Some(schema::<LookupFuncsRequest>()),
        "analyze_funcs" => Some(schema::<AnalyzeFuncsRequest>()),

        // Disassembly / Decompile
        "disasm" => Some(schema::<DisasmRequest>()),
        "disasm_by_name" => Some(schema::<DisasmByNameRequest>()),
        "disasm_function_at" => Some(schema::<DisasmFunctionAtRequest>()),
        "decompile" => Some(schema::<DecompileRequest>()),
        "pseudocode_at" => Some(schema::<PseudocodeAtRequest>()),

        // Xrefs / Control flow
        "xrefs_to" | "xrefs_from" => Some(schema::<AddressRequest>()),
        "xref_matrix" => Some(schema::<XrefMatrixRequest>()),
        "basic_blocks" | "callers" | "callees" => Some(schema::<AddressRequest>()),
        "find_paths" => Some(schema::<FindPathsRequest>()),
        "callgraph" => Some(schema::<CallGraphRequest>()),

        // Memory / Search / Metadata
        "get_bytes" => Some(schema::<GetBytesRequest>()),
        "get_string" => Some(schema::<GetStringRequest>()),
        "get_u8" | "get_u16" | "get_u32" | "get_u64" => Some(schema::<AddressRequest>()),
        "get_global_value" => Some(schema::<GetGlobalValueRequest>()),
        "strings" => Some(schema::<StringsRequest>()),
        "find_string" => Some(schema::<FindStringRequest>()),
        "analyze_strings" => Some(schema::<AnalyzeStringsRequest>()),
        "xrefs_to_string" => Some(schema::<XrefsToStringRequest>()),
        "find_bytes" => Some(schema::<FindBytesRequest>()),
        "search" => Some(schema::<SearchRequest>()),
        "find_insns" => Some(schema::<FindInsnsRequest>()),
        "find_insn_operands" => Some(schema::<FindInsnOperandsRequest>()),
        "segments" => Some(schema::<EmptyParams>()),
        "imports" | "exports" => Some(schema::<PaginatedRequest>()),
        "export_funcs" => Some(schema::<ExportFuncsRequest>()),
        "entrypoints" => Some(schema::<EmptyParams>()),
        "list_globals" => Some(schema::<ListGlobalsRequest>()),
        "int_convert" => Some(schema::<IntConvertRequest>()),

        // Editing
        "set_comments" => Some(schema::<SetCommentsRequest>()),
        "rename" => Some(schema::<RenameRequest>()),
        "patch" => Some(schema::<PatchRequest>()),
        "patch_asm" => Some(schema::<PatchAsmRequest>()),

        // Types
        "structs" => Some(schema::<StructsRequest>()),
        "struct_info" => Some(schema::<StructInfoRequest>()),
        "read_struct" => Some(schema::<ReadStructRequest>()),
        "search_structs" => Some(schema::<StructsRequest>()),
        "local_types" => Some(schema::<LocalTypesRequest>()),
        "xrefs_to_field" => Some(schema::<XrefsToFieldRequest>()),
        "stack_frame" => Some(schema::<AddressRequest>()),
        "declare_type" => Some(schema::<DeclareTypeRequest>()),
        "apply_types" => Some(schema::<ApplyTypesRequest>()),
        "infer_types" => Some(schema::<InferTypesRequest>()),
        "declare_stack" => Some(schema::<DeclareStackRequest>()),
        "delete_stack" => Some(schema::<DeleteStackRequest>()),

        // Scripting
        "run_script" => Some(schema::<RunScriptRequest>()),

        _ => None,
    }
}

use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};

/// Convert our internal `TaskState` to the rmcp `Task` model.
fn task_state_to_mcp(state: &task::TaskState) -> rmcp::model::Task {
    let status = match state.status {
        task::TaskStatus::Running => rmcp::model::TaskStatus::Working,
        task::TaskStatus::Completed => rmcp::model::TaskStatus::Completed,
        task::TaskStatus::Failed => rmcp::model::TaskStatus::Failed,
        task::TaskStatus::Cancelled => rmcp::model::TaskStatus::Cancelled,
    };
    rmcp::model::Task {
        task_id: state.id.clone(),
        status,
        status_message: Some(state.message.clone()),
        created_at: state.created_at_iso.clone(),
        last_updated_at: None,
        ttl: None,
        poll_interval: Some(5000),
    }
}

#[tool_handler(router = self.tool_mux)]
impl ServerHandler for IdaMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks_with(rmcp::model::TasksCapability::server_default())
                .build(),
            instructions: Some(self.instructions()),
            ..Default::default()
        }
    }

    async fn enqueue_task(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CreateTaskResult, McpError> {
        // Delegate to the regular tool handler and wrap the result
        // into the task protocol.  For most tools the call completes
        // inline.  For `open_dsc`, the tool creates a background
        // task and returns a task_id — we re-use that ID.
        let result = self.call_tool(request, context).await?;

        // Check if the result contains a task_id from open_dsc.
        let task_id = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .and_then(|t| serde_json::from_str::<Value>(&t.text).ok())
            .and_then(|v| v.get("task_id")?.as_str().map(String::from));

        if let Some(tid) = task_id {
            let state = self
                .task_registry
                .get(&tid)
                .ok_or_else(|| McpError::internal_error(format!("Task {tid} disappeared"), None))?;
            Ok(CreateTaskResult {
                task: task_state_to_mcp(&state),
            })
        } else {
            // Inline completion — no background work.
            let now = task::iso_now();
            let id = format!("inline-{now}");
            Ok(CreateTaskResult {
                task: rmcp::model::Task {
                    task_id: id,
                    status: rmcp::model::TaskStatus::Completed,
                    status_message: Some("Completed".into()),
                    created_at: now,
                    last_updated_at: None,
                    ttl: None,
                    poll_interval: None,
                },
            })
        }
    }

    async fn list_tasks(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListTasksResult, McpError> {
        let tasks: Vec<rmcp::model::Task> = self
            .task_registry
            .list_all()
            .iter()
            .map(task_state_to_mcp)
            .collect();
        Ok(ListTasksResult {
            tasks,
            next_cursor: None,
            total: None,
        })
    }

    async fn get_task_info(
        &self,
        request: GetTaskInfoParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetTaskInfoResult, McpError> {
        let task = self
            .task_registry
            .get(&request.task_id)
            .map(|s| task_state_to_mcp(&s));
        Ok(GetTaskInfoResult { task })
    }

    async fn get_task_result(
        &self,
        request: GetTaskResultParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::TaskResult, McpError> {
        let state = self.task_registry.get(&request.task_id);
        match state {
            Some(s) if s.status == task::TaskStatus::Completed => Ok(rmcp::model::TaskResult {
                content_type: "application/json".into(),
                value: s.result.unwrap_or(Value::Null),
                summary: Some("DSC loading completed".into()),
            }),
            Some(s) if s.status == task::TaskStatus::Failed => {
                Err(McpError::internal_error(s.message, None))
            }
            Some(s) if s.status == task::TaskStatus::Cancelled => {
                Err(McpError::internal_error("Task was cancelled", None))
            }
            Some(_) => Err(McpError::internal_error(
                "Task is still running; poll tasks/get first",
                None,
            )),
            None => Err(McpError::invalid_params(
                "Unknown task_id",
                Some(json!({ "task_id": request.task_id })),
            )),
        }
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        if self.task_registry.cancel(&request.task_id) {
            Ok(())
        } else {
            Err(McpError::invalid_params(
                "Task not found or not running",
                Some(json!({ "task_id": request.task_id })),
            ))
        }
    }
}

/// Wrapper that sanitizes tool schemas by removing `$schema` fields.
///
/// Some MCP clients (like Claude Desktop) choke on the JSON Schema `$schema` field.
/// This wrapper intercepts `list_tools` to remove these fields while delegating
/// all other methods to the inner server.
pub struct SanitizedIdaServer<S>(pub S);

impl<S> std::ops::Deref for SanitizedIdaServer<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Tools that support task-based invocation (SEP-1686).
const TASK_CAPABLE_TOOLS: &[&str] = &["open_dsc"];

/// Strips `$schema` keys from tool input schemas and annotates
/// task-capable tools with `execution.taskSupport = "optional"`.
fn sanitize_tool_schemas(result: &mut ListToolsResult) {
    for tool in &mut result.tools {
        let schema_arc = &mut tool.input_schema;
        if let Some(map) = std::sync::Arc::get_mut(schema_arc) {
            map.remove("$schema");
        } else {
            let mut map = (**schema_arc).clone();
            map.remove("$schema");
            *schema_arc = std::sync::Arc::new(map);
        }

        if TASK_CAPABLE_TOOLS.contains(&&*tool.name) {
            tool.execution = Some(
                rmcp::model::ToolExecution::new()
                    .with_task_support(rmcp::model::TaskSupport::Optional),
            );
        }
    }
}

/// Patch a single tool definition with task support if applicable.
fn annotate_task_support(mut tool: Tool) -> Tool {
    if TASK_CAPABLE_TOOLS.contains(&&*tool.name) {
        tool.execution = Some(
            rmcp::model::ToolExecution::new().with_task_support(rmcp::model::TaskSupport::Optional),
        );
    }
    tool
}

impl<S: ServerHandler + Send + Sync> ServerHandler for SanitizedIdaServer<S> {
    async fn initialize(
        &self,
        params: InitializeRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        self.0.initialize(params, ctx).await
    }

    async fn list_tools(
        &self,
        params: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = self.0.list_tools(params, ctx).await?;
        sanitize_tool_schemas(&mut result);
        Ok(result)
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.0.call_tool(params, ctx).await
    }

    fn get_info(&self) -> ServerInfo {
        self.0.get_info()
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.0.get_tool(name).map(annotate_task_support)
    }

    async fn enqueue_task(
        &self,
        request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CreateTaskResult, McpError> {
        self.0.enqueue_task(request, ctx).await
    }

    async fn list_tasks(
        &self,
        request: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListTasksResult, McpError> {
        self.0.list_tasks(request, ctx).await
    }

    async fn get_task_info(
        &self,
        request: GetTaskInfoParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<GetTaskInfoResult, McpError> {
        self.0.get_task_info(request, ctx).await
    }

    async fn get_task_result(
        &self,
        request: GetTaskResultParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::TaskResult, McpError> {
        self.0.get_task_result(request, ctx).await
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.0.cancel_task(request, ctx).await
    }
}
