//! MCP server implementation with IDA Pro tools.

pub mod http_access;
pub mod http_config;
mod operation;
mod requests;
pub mod task;
pub mod tool_filter;

pub use requests::*;

use crate::error::ToolError;
use crate::ida::observability::{ProgressReceiver, ProgressSender};
use crate::ida::pool::CHILD_TIMEOUT_GRACE_SECS;
use crate::ida::types::{ConditionalCloseResult, DatabaseGeneration};
use crate::ida::worker::{
    CloseAuthorization, CloseTokenGrant, IdaWorker, WorkerBackend, MAX_TIMEOUT_SECS,
};
use crate::server::operation::{
    next_operation_id, OperationRegistry, OperationSnapshot, RecentOperations,
};
use crate::tool_registry::{self, ToolCategory};
use rmcp::{
    handler::server::{
        router::tool::ToolRouter,
        tool::{InputResponses as ToolInputResponses, RequestState, ToolCallContext},
        wrapper::Parameters,
    },
    model::{
        CallToolResult, ContentBlock as Content, ServerCapabilities, ServerInfo, Tool,
        ToolAnnotations,
    },
    schemars::{schema_for, JsonSchema},
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument, warn};

struct SessionLifetime {
    cancel: tokio_util::sync::CancellationToken,
}

/// State that must survive across handler instances created for stateless MCP
/// requests. Long-lived transports use one value per handler; single-worker
/// HTTP shares one value across legacy sessions and modern sessionless requests
/// because they all operate on the same IDA context.
#[derive(Clone)]
pub struct ServerRuntimeState {
    task_registry: task::TaskRegistry,
    operation_registry: OperationRegistry,
    operation_nonce: Arc<AtomicU64>,
    /// Parent lifetime for background tasks spawned by sessionless MCP 2026
    /// requests, whose handlers drop as soon as the response is sent. Cancelled
    /// only when the runtime state itself drops (process/transport shutdown).
    runtime_lifetime: Arc<SessionLifetime>,
    request_state_codec: rmcp::model::RequestStateCodec,
    /// True when the HTTP transport runs with `--stateless`: rmcp then builds
    /// a fresh handler per request even for legacy protocol versions, so every
    /// request must use the shared runtime task owner and lifetime — otherwise
    /// a legacy client's background task would be cancelled when its handler
    /// drops and owned by a session identity that never recurs.
    stateless_http: bool,
}

impl Default for ServerRuntimeState {
    fn default() -> Self {
        let signing_key = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        Self {
            task_registry: task::TaskRegistry::new(),
            operation_registry: OperationRegistry::new(),
            operation_nonce: Arc::new(AtomicU64::new(0)),
            runtime_lifetime: Arc::new(SessionLifetime::new()),
            request_state_codec: rmcp::model::RequestStateCodec::new(signing_key.into_bytes()),
            stateless_http: false,
        }
    }
}

impl ServerRuntimeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Runtime state for an HTTP transport started with `--stateless` (see
    /// [`Self::stateless_http`]).
    pub fn new_stateless_http() -> Self {
        Self {
            stateless_http: true,
            ..Self::default()
        }
    }
}

impl SessionLifetime {
    fn new() -> Self {
        Self {
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }

    fn child_token(&self) -> tokio_util::sync::CancellationToken {
        self.cancel.child_token()
    }
}

impl Drop for SessionLifetime {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// MCP server for IDA Pro analysis
#[derive(Clone)]
pub struct IdaMcpServer {
    worker: WorkerBackend,
    tool_mux: ToolMux<IdaMcpServer>,
    mode: ServerMode,
    task_registry: task::TaskRegistry,
    operation_registry: OperationRegistry,
    operation_nonce: Arc<AtomicU64>,
    /// Shared runtime lifetime (see [`ServerRuntimeState::runtime_lifetime`]).
    runtime_lifetime: Arc<SessionLifetime>,
    /// Per-handler lifetime. rmcp keeps a legacy session's handler alive for
    /// the whole session and drops it on session close, so background tasks
    /// parented here are cancelled when their legacy session ends. Sessionless
    /// MCP 2026 handlers drop per request, so their background tasks must use
    /// `runtime_lifetime` instead (see [`Self::background_lifetime`]).
    session_lifetime: Arc<SessionLifetime>,
    request_state_codec: rmcp::model::RequestStateCodec,
    /// Unique ID for this handler context. It is stable for a legacy session,
    /// while sessionless MCP 2026 HTTP creates a fresh value per request. It is
    /// also the ownership identity used by the legacy HTTP close-token path.
    session_id: String,
    /// Stable task owner for requests served through this handler. Sessionless
    /// MCP 2026 requests instead use the shared runtime owner.
    session_task_owner: task::TaskOwner,
    /// See [`ServerRuntimeState::stateless_http`].
    stateless_http: bool,
    /// Server-side tool filter (applied to tools/list, tools/call, and
    /// surfaced via tool_catalog / tool_help).
    filter: Arc<tool_filter::ToolFilter>,
}

#[derive(Clone, Copy, Debug)]
pub enum ServerMode {
    Stdio,
    Http,
    Worker,
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

    fn list_all(&self) -> Vec<Tool> {
        let mut tools = Vec::new();
        for info in tool_registry::all_tools() {
            if let Some(route) = self.call_router.map.get(info.name) {
                tools.push(apply_tool_metadata(route.attr.clone()));
            }
        }
        tools
    }

    fn get(&self, name: &str) -> Option<&Tool> {
        self.call_router.map.get(name).map(|route| &route.attr)
    }
}

/// Tools whose handlers consume MRTR `requestState`/`inputResponses`. Other
/// tools must reject those fields instead of silently executing a fresh call.
const MRTR_AWARE_TOOLS: &[&str] = &["open_idb"];

/// True when a request carries the complete MCP 2026 inline-metadata key set.
/// rmcp routes such requests through the sessionless per-request path
/// regardless of the protocol version the metadata declares (`is_legacy_request`,
/// tower.rs), so this is the authoritative "which handler lifetime am I running
/// under" predicate on HTTP transports.
fn is_sessionless_request_meta(meta: &rmcp::model::RequestMetaObject) -> bool {
    meta.missing_required_keys(&ProtocolVersion::V_2026_07_28)
        .is_empty()
}

impl ToolMux<IdaMcpServer> {
    async fn call(
        &self,
        context: ToolCallContext<'_, IdaMcpServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        // rmcp routes any request carrying the complete 2026 inline-metadata
        // key set through the sessionless path even when it declares a legacy
        // protocol version. Pooled workers bind their IDA lease to a legacy
        // HTTP session, so a sessionless tool call would mint (and leak) a
        // fresh worker lease per request. Reject it before it reaches the
        // worker pool; the version allowlist alone cannot catch this case.
        if context.service.worker.is_pooled()
            && is_sessionless_request_meta(&context.request_context().meta)
        {
            return Err(McpError::invalid_params(
                "pooled HTTP (--max-workers > 1) requires the legacy initialize lifecycle; \
                 sessionless inline request metadata is not supported here",
                None,
            ));
        }
        if !MRTR_AWARE_TOOLS.contains(&context.name())
            && (context.request_state.is_some() || context.input_responses.is_some())
        {
            return Err(McpError::invalid_params(
                format!(
                    "tool '{}' does not accept requestState/inputResponses",
                    context.name()
                ),
                None,
            ));
        }
        // SEP-2663 task handles exist from MCP 2026-07-28; older peers cannot
        // parse a `resultType: "task"` response even if they declared the
        // tasks extension capability.
        let should_materialize_task = context.name() == "open_dsc"
            && context
                .request_context()
                .protocol_version()
                .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
            && context
                .request_context()
                .client_capabilities()
                .is_some_and(|capabilities| capabilities.supports_tasks());
        let task_registry = context.service.task_registry.clone();
        let response = self.call_router.call(context).await?;
        materialize_task_response(&task_registry, should_materialize_task, response)
    }
}

/// Parameters for the background DSC loading task.
struct DscBackgroundCtx {
    open: DscBackgroundOpen,
    module: String,
    frameworks: Vec<String>,
    owner_session_id: Option<String>,
}

enum DscBackgroundOpen {
    DirectRawDsc {
        open_path: std::path::PathBuf,
        idb_out: std::path::PathBuf,
    },
    LegacyIdat {
        idat: std::path::PathBuf,
        idat_args: Vec<String>,
        script_path: std::path::PathBuf,
        log_path: Option<std::path::PathBuf>,
        out_i64: std::path::PathBuf,
    },
}

struct TemporaryFileCleanup {
    path: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DscOpenPlan {
    DirectExistingI64,
    BackgroundDirectRawDsc,
    LegacyIdatBackground,
}

fn dsc_open_plan(sdk_version: (i32, i32), i64_exists: bool) -> DscOpenPlan {
    // An existing database wins on every SDK: reopening it preserves prior
    // analysis (renames, comments, loaded modules) and skips the load. On 9.4
    // that database is the deterministic direct-path cache or a legacy
    // sibling; pre-9.4 it is the sibling idat produced.
    if i64_exists {
        DscOpenPlan::DirectExistingI64
    } else if sdk_version >= (9, 4) {
        DscOpenPlan::BackgroundDirectRawDsc
    } else {
        DscOpenPlan::LegacyIdatBackground
    }
}

fn sanitize_temp_component(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        "dsc".to_string()
    } else {
        sanitized
    }
}

/// Deterministic per-DSC database location for the IDA 9.4 direct open path.
///
/// DSCs commonly sit on read-only mounts, so the generated database cannot
/// reliably live next to them the way the legacy idat path's sibling `.i64`
/// does. Deriving the name from the absolute DSC path — never pid or time —
/// means every `open_dsc` of the same cache resolves to one file: repeat opens
/// reuse the analyzed database (with any renames/comments) instead of leaking
/// a fresh multi-GB orphan per call.
fn direct_dsc_cache_i64_path(dsc_path: &std::path::Path) -> std::path::PathBuf {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let absolute = dsc_path
        .canonicalize()
        .unwrap_or_else(|_| dsc_path.to_path_buf());
    let name = absolute
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_temp_component)
        .unwrap_or_else(|| "dsc".to_string());
    let mut hasher = DefaultHasher::new();
    absolute.hash(&mut hasher);
    let hash = hasher.finish();
    std::env::temp_dir().join(format!("ida-mcp-dsc-{name}-{hash:016x}.i64"))
}

impl TemporaryFileCleanup {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn cleanup_now(&mut self) {
        if let Some(path) = self.path.take() {
            remove_temporary_file(&path);
        }
    }
}

impl Drop for TemporaryFileCleanup {
    fn drop(&mut self) {
        self.cleanup_now();
    }
}

fn remove_temporary_file(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => warn!(
            path = %path.display(),
            error = %err,
            "failed to remove temporary file"
        ),
    }
}

/// Inputs above this size automatically route `open_idb(auto_analyse=true)`
/// to the background analysis path (asking the user via MCP elicitation when the
/// client supports it). 50 MiB chosen empirically — kernelcaches and DSCs are
/// typically larger than this and benefit from background analysis; smaller
/// binaries usually finish auto-analysis well within the foreground timeout.
const OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES: u64 = 50 * 1024 * 1024;
/// Bound the MCP elicitation prompt separately from IDA work. If the client
/// leaves the prompt unanswered, default to background analysis.
const OPEN_IDB_ELICITATION_TIMEOUT_SECS: u64 = 30;
const OPEN_IDB_REQUEST_STATE_TTL_SECS: u64 = 10 * 60;
/// Give foreground operations a short window to observe cancellation and clean
/// up owned resources before the MCP timeout/cancel response is returned.
const FOREGROUND_CANCEL_CLEANUP_TIMEOUT_SECS: u64 = 6;

fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|err| {
        warn!(error = %err, "failed to pretty-print JSON response");
        value.to_string()
    })
}

enum ForegroundOperationError {
    Tool(ToolError),
    TimedOut {
        timeout_secs: u64,
        snapshot: OperationSnapshot,
    },
    Cancelled {
        snapshot: OperationSnapshot,
    },
}

enum OpenIdbBackgroundDecision {
    Ready(bool),
    InputRequired(InputRequiredResult),
}

fn timeout_with_child_grace(timeout_secs: Option<u64>, default_timeout_secs: u64) -> u64 {
    timeout_secs
        .unwrap_or(default_timeout_secs)
        .min(MAX_TIMEOUT_SECS)
        .saturating_add(CHILD_TIMEOUT_GRACE_SECS)
}

/// Which side of the xref relation the `xrefs_to`/`xrefs_from` tools query.
#[derive(Clone, Copy)]
enum XrefDirection {
    To,
    From,
}

impl IdaMcpServer {
    pub fn new(worker: Arc<IdaWorker>, mode: ServerMode) -> Self {
        Self::with_filter(
            WorkerBackend::local(worker),
            mode,
            Arc::new(tool_filter::ToolFilter::unrestricted()),
        )
    }

    pub fn with_filter(
        worker: WorkerBackend,
        mode: ServerMode,
        filter: Arc<tool_filter::ToolFilter>,
    ) -> Self {
        Self::with_filter_and_state(worker, mode, filter, ServerRuntimeState::new())
    }

    pub fn with_filter_and_state(
        worker: WorkerBackend,
        mode: ServerMode,
        filter: Arc<tool_filter::ToolFilter>,
        state: ServerRuntimeState,
    ) -> Self {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session_task_owner = task::TaskOwner::Session(Arc::from(session_id.as_str()));
        // debug!: sessionless MCP 2026 HTTP constructs a handler per request,
        // so this is per-request noise there, not a once-per-server event.
        debug!(
            session_id = %session_id,
            tool_filter_active = filter.is_active(),
            enabled_tools = filter.enabled_count(),
            "Creating IDA MCP server handler"
        );
        let call_router = Self::tool_router();
        Self {
            worker,
            tool_mux: ToolMux::new(call_router),
            mode,
            task_registry: state.task_registry,
            operation_registry: state.operation_registry,
            operation_nonce: state.operation_nonce,
            runtime_lifetime: state.runtime_lifetime,
            session_lifetime: Arc::new(SessionLifetime::new()),
            request_state_codec: state.request_state_codec,
            session_id,
            session_task_owner,
            stateless_http: state.stateless_http,
            filter,
        }
    }

    /// Parent lifetime for background tasks spawned while serving `meta`'s
    /// request. Only HTTP uses metadata completeness to select rmcp's
    /// per-request sessionless route. Stdio always has one connection-scoped
    /// handler, even when an individual request carries the full key set.
    fn background_lifetime(&self, meta: &rmcp::model::RequestMetaObject) -> &SessionLifetime {
        if self.is_sessionless_http_request(meta) {
            &self.runtime_lifetime
        } else {
            &self.session_lifetime
        }
    }

    /// Owner identity for task admission and client-facing task operations.
    /// Sessionless HTTP requests share one owner because MCP 2026 supplies no
    /// stable session identifier across requests. Stdio remains bound to its
    /// connection-scoped handler regardless of per-request metadata shape.
    fn task_owner(&self, meta: &rmcp::model::RequestMetaObject) -> task::TaskOwner {
        if self.is_sessionless_http_request(meta) {
            task::TaskOwner::Runtime
        } else {
            self.session_task_owner.clone()
        }
    }

    fn is_sessionless_http_request(&self, meta: &rmcp::model::RequestMetaObject) -> bool {
        // Under `--stateless` every HTTP request is per-handler regardless of
        // protocol version, so legacy requests must also use the runtime
        // owner and lifetime (see `ServerRuntimeState::stateless_http`).
        matches!(self.mode, ServerMode::Http)
            && (self.stateless_http || is_sessionless_request_meta(meta))
    }

    pub fn filter(&self) -> &Arc<tool_filter::ToolFilter> {
        &self.filter
    }

    pub fn task_registry(&self) -> &task::TaskRegistry {
        &self.task_registry
    }

    fn close_hint(&self) -> &'static str {
        close_hint_for(self.mode, self.worker.is_pooled())
    }

    fn http_close_grant(&self) -> Option<Result<CloseTokenGrant, String>> {
        if matches!(self.mode, ServerMode::Http) && self.worker.uses_close_tokens() {
            self.worker.issue_close_token_for_session(&self.session_id)
        } else {
            None
        }
    }

    fn apply_close_metadata(
        &self,
        map: &mut serde_json::Map<String, Value>,
        grant: Option<Result<CloseTokenGrant, String>>,
    ) {
        apply_close_metadata(map, grant, self.close_hint());
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
                 \n- core: open/close/discover (open_idb, close_idb, tool_catalog, tool_help, recent_operations, idb_meta) \
                 \n- functions: list, resolve, lookup functions \
                 \n- disassembly: disasm at addresses \
                 \n- decompile: Hex-Rays pseudocode \
                 \n- xrefs: cross-reference analysis \
                 \n- control_flow: CFG, callgraph, paths \
                 \n- memory: read bytes, strings, values \
                 \n- search: find patterns, strings \
                 \n- metadata: segments, imports, exports, Lumina lookup \
                 \n- types: declare_type, apply_types (addr/stack), infer_types, local_types, stack_frame, declare_stack, delete_stack, structs (list/info/read) \
                \n- editing: comments/rename/patch/patch_asm/Lumina apply \
                 \n- scripting: run_script (execute IDAPython code) \
                 \n\nTip: Use tool_catalog(query='what you want to do') to find the right tool. \
                 \nTip: If xrefs/decompile look incomplete, call analysis_status to check auto-analysis. \
                 \nTip: After a timeout or cancellation, call recent_operations to inspect the last recorded foreground phase. \
                 \nTip: After dsc_add_dylib or dsc_add_region, call analysis_status; if auto_is_ok=false, run analyze_funcs before xrefs/decompile.",
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
                let trimmed = s.trim();
                if trimmed.starts_with('[')
                    && let Ok(Value::Array(arr)) = serde_json::from_str(trimmed)
                {
                    let mut out = Vec::with_capacity(arr.len());
                    for v in &arr {
                        match v {
                            Value::String(s) => out.push(s.to_string()),
                            Value::Number(n) => out.push(n.to_string()),
                            _ => {
                                return Err(ToolError::IdaError(
                                    "expected string or number".to_string(),
                                ));
                            }
                        }
                    }
                    return Ok(out);
                }
                if trimmed.contains(',') {
                    Ok(trimmed
                        .split(',')
                        .map(|t| t.trim())
                        .filter(|t| !t.is_empty())
                        .map(|t| t.to_string())
                        .collect())
                } else if trimmed.is_empty() {
                    Err(ToolError::IdaError("empty string".to_string()))
                } else {
                    Ok(vec![trimmed.to_string()])
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
                            ));
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

    fn value_to_exactly_one_address(value: &Value, field_name: &str) -> Result<u64, ToolError> {
        let addresses = Self::value_to_addresses(value)?;
        match addresses.as_slice() {
            [address] => Ok(*address),
            _ => Err(ToolError::InvalidParams(format!(
                "{field_name} must contain exactly one value"
            ))),
        }
    }

    /// Default page size for xref listings when the caller omits `limit`.
    const DEFAULT_XREFS_LIMIT: usize = 1000;
    /// Hard cap on a single xref page, mirroring other paginated tools.
    const MAX_XREFS_LIMIT: usize = 10000;

    /// Parse and clamp the pagination inputs shared by `xrefs_to`/`xrefs_from`.
    ///
    /// Returns `(offset, limit, timeout_secs)`. The limit is clamped to
    /// `1..=MAX_XREFS_LIMIT`: the upper bound stops a high-frequency target from
    /// forcing an unbounded enumeration, and the lower bound of 1 guarantees a
    /// paginating caller always makes forward progress (a `limit` of 0 would
    /// return an empty-but-truncated page whose `next_offset` never advances).
    fn parse_xrefs_paging(req: &XrefsRequest) -> Result<(usize, usize, Option<u64>), ToolError> {
        let limit = parse_optional_unsigned::<usize>(req.limit, "limit")?
            .unwrap_or(Self::DEFAULT_XREFS_LIMIT)
            .clamp(1, Self::MAX_XREFS_LIMIT);
        let offset = parse_optional_unsigned::<usize>(req.offset, "offset")?.unwrap_or(0);
        let timeout_secs = parse_optional_unsigned::<u64>(req.timeout_secs, "timeout_secs")?;
        Ok((offset, limit, timeout_secs))
    }

    /// Wrap a per-address xref result for the multi-address response, injecting
    /// the queried address into the serialized listing.
    fn xrefs_entry(addr: u64, result: crate::ida::types::XRefListResult) -> Value {
        let mut entry = serde_json::to_value(&result).unwrap_or_else(|_| json!({}));
        if let Value::Object(map) = &mut entry {
            map.insert("address".to_string(), json!(format!("{:#x}", addr)));
        }
        entry
    }

    /// Fetch one paginated xref listing in the given direction.
    async fn xrefs_for(
        &self,
        addr: u64,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
        direction: XrefDirection,
    ) -> Result<crate::ida::types::XRefListResult, ToolError> {
        match direction {
            XrefDirection::To => {
                self.worker
                    .xrefs_to(addr, offset, limit, timeout_secs)
                    .await
            }
            XrefDirection::From => {
                self.worker
                    .xrefs_from(addr, offset, limit, timeout_secs)
                    .await
            }
        }
    }

    /// Shared body of the `xrefs_to`/`xrefs_from` tools: parse pagination,
    /// resolve addresses, and assemble the single- or multi-address response.
    async fn xrefs_lookup(
        &self,
        req: XrefsRequest,
        direction: XrefDirection,
    ) -> Result<CallToolResult, McpError> {
        let (offset, limit, timeout_secs) = match Self::parse_xrefs_paging(&req) {
            Ok(paging) => paging,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self
                .xrefs_for(addrs[0], offset, limit, timeout_secs, direction)
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
                    .xrefs_for(addr, offset, limit, timeout_secs, direction)
                    .await
                {
                    Ok(result) => results.push(Self::xrefs_entry(addr, result)),
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
                            ));
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

    fn new_operation_id(&self) -> String {
        next_operation_id(self.operation_nonce.as_ref())
    }

    async fn finish_cancelled_foreground<T, Fut>(
        tool_name: &'static str,
        operation_fut: Pin<&mut Fut>,
    ) where
        Fut: std::future::Future<Output = Result<T, ToolError>>,
    {
        let cleanup = tokio::time::timeout(
            Duration::from_secs(FOREGROUND_CANCEL_CLEANUP_TIMEOUT_SECS),
            operation_fut,
        )
        .await;
        if cleanup.is_err() {
            warn!(
                tool_name,
                timeout_secs = FOREGROUND_CANCEL_CLEANUP_TIMEOUT_SECS,
                "foreground operation did not finish cancellation cleanup before response"
            );
        }
    }

    fn foreground_timeout_secs(
        &self,
        timeout_secs: Option<u64>,
        default_timeout_secs: u64,
    ) -> Option<u64> {
        if self.worker.is_pooled() {
            return Some(timeout_with_child_grace(timeout_secs, default_timeout_secs));
        }
        timeout_secs
    }

    async fn run_foreground_operation<T, F, Fut>(
        &self,
        ctx: &RequestContext<RoleServer>,
        tool_name: &'static str,
        target_summary: String,
        timeout_secs: Option<u64>,
        default_timeout_secs: u64,
        run: F,
    ) -> Result<T, ForegroundOperationError>
    where
        F: FnOnce(ProgressSender, tokio_util::sync::CancellationToken) -> Fut,
        Fut: std::future::Future<Output = Result<T, ToolError>>,
    {
        enum Outcome<T> {
            Finished(Result<T, ToolError>),
            TimedOut(u64),
            Cancelled,
        }

        let op_id = self.new_operation_id();
        self.operation_registry
            .start(op_id.clone(), tool_name, target_summary);

        let (progress_tx, mut progress_rx): (ProgressSender, ProgressReceiver) =
            tokio::sync::mpsc::unbounded_channel();
        // No `notifications/progress` are emitted: on stdio they race with the
        // response when fast tools coalesce into a single Node stdin `data`
        // event, dropping the Claude Code transport with "unknown progress
        // token". Phases remain observable via `recent_operations`.
        let drain_task = tokio::spawn({
            let registry = self.operation_registry.clone();
            let op_id = op_id.clone();
            async move {
                while let Some(update) = progress_rx.recv().await {
                    registry.record_progress(&op_id, update.phase, update.message);
                }
            }
        });
        let worker_cancel = tokio_util::sync::CancellationToken::new();
        let timeout = timeout_secs
            .unwrap_or(default_timeout_secs)
            .min(MAX_TIMEOUT_SECS);
        let client_cancel = ctx.ct.clone();

        let operation_fut = run(progress_tx, worker_cancel.clone());
        tokio::pin!(operation_fut);

        let outcome = tokio::select! {
            biased;
            result = &mut operation_fut => Outcome::Finished(result),
            _ = client_cancel.cancelled() => {
                worker_cancel.cancel();
                Outcome::Cancelled
            }
            _ = tokio::time::sleep(Duration::from_secs(timeout)) => {
                worker_cancel.cancel();
                Outcome::TimedOut(timeout)
            }
        };

        match outcome {
            Outcome::Finished(result) => {
                let _ = drain_task.await;
                match result {
                    Ok(value) => {
                        let _ = self.operation_registry.finish_completed(
                            &op_id,
                            format!("{tool_name} completed successfully"),
                        );
                        Ok(value)
                    }
                    Err(ToolError::Cancelled(_)) => {
                        let snapshot = self
                            .operation_registry
                            .finish_cancelled(&op_id, format!("{tool_name} cancelled"))
                            .or_else(|| self.operation_registry.snapshot(&op_id))
                            .unwrap_or_else(|| {
                                Self::fallback_operation_snapshot(
                                    &op_id,
                                    tool_name,
                                    "cancelled",
                                    operation::OperationStatus::Cancelled,
                                    format!("{tool_name} cancelled"),
                                )
                            });
                        Err(ForegroundOperationError::Cancelled { snapshot })
                    }
                    Err(error) => {
                        let _ = self
                            .operation_registry
                            .finish_failed(&op_id, format!("{tool_name} failed: {error}"));
                        Err(ForegroundOperationError::Tool(error))
                    }
                }
            }
            Outcome::TimedOut(timeout_secs) => {
                Self::finish_cancelled_foreground(tool_name, operation_fut.as_mut()).await;
                drain_task.abort();
                let _ = drain_task.await;
                let snapshot = self
                    .operation_registry
                    .finish_timed_out(
                        &op_id,
                        format!("{tool_name} timed out after {timeout_secs}s"),
                    )
                    .or_else(|| self.operation_registry.snapshot(&op_id))
                    .unwrap_or_else(|| {
                        Self::fallback_operation_snapshot(
                            &op_id,
                            tool_name,
                            "timed_out",
                            operation::OperationStatus::TimedOut,
                            format!("{tool_name} timed out after {timeout_secs}s"),
                        )
                    });
                Err(ForegroundOperationError::TimedOut {
                    timeout_secs,
                    snapshot,
                })
            }
            Outcome::Cancelled => {
                Self::finish_cancelled_foreground(tool_name, operation_fut.as_mut()).await;
                drain_task.abort();
                let _ = drain_task.await;
                let snapshot = self
                    .operation_registry
                    .finish_cancelled(&op_id, format!("{tool_name} cancelled by client"))
                    .or_else(|| self.operation_registry.snapshot(&op_id))
                    .unwrap_or_else(|| {
                        Self::fallback_operation_snapshot(
                            &op_id,
                            tool_name,
                            "cancelled",
                            operation::OperationStatus::Cancelled,
                            format!("{tool_name} cancelled by client"),
                        )
                    });
                Err(ForegroundOperationError::Cancelled { snapshot })
            }
        }
    }

    fn operation_timeout_message(
        tool_name: &str,
        timeout_secs: u64,
        snapshot: &OperationSnapshot,
        detail: Option<String>,
    ) -> String {
        let mut message = format!(
            "{tool_name} timed out after {timeout_secs} seconds.\n\
             Last known phase: {}.\n\
             Operation id: {}.\n\
             Elapsed: {} ms.\n\
             Check recent_operations for the recorded event trail.",
            snapshot.phase, snapshot.op_id, snapshot.elapsed_ms
        );
        if let Some(detail) = detail {
            message.push_str("\n\n");
            message.push_str(&detail);
        }
        message
    }

    fn operation_cancelled_message(tool_name: &str, snapshot: &OperationSnapshot) -> String {
        format!(
            "{tool_name} was cancelled by the client.\n\
             Last known phase: {}.\n\
             Operation id: {}.\n\
             Elapsed: {} ms.\n\
             Check recent_operations for the recorded event trail.",
            snapshot.phase, snapshot.op_id, snapshot.elapsed_ms
        )
    }

    fn fallback_operation_snapshot(
        op_id: &str,
        tool_name: &str,
        phase: &str,
        status: operation::OperationStatus,
        message: String,
    ) -> OperationSnapshot {
        OperationSnapshot {
            op_id: op_id.to_string(),
            tool: tool_name.to_string(),
            target_summary: "unknown".to_string(),
            phase: phase.to_string(),
            status,
            message,
            started_at_ms: 0,
            last_update_ms: 0,
            elapsed_ms: 0,
        }
    }

    fn start_dsc_background(
        &self,
        owner: &task::TaskOwner,
        dedup_key: String,
        initial_message: &str,
        ctx: DscBackgroundCtx,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, McpError> {
        let task_id = match self.task_registry.create_keyed(
            owner,
            "dsc",
            &dedup_key,
            initial_message,
        ) {
            Ok(id) => id,
            Err(task::TaskCreateError::AlreadyRunning(existing_id)) => {
                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "status": "already_running",
                        "task_id": existing_id,
                        "message": "A DSC loading task for this path is already in progress. Poll task_status(task_id) for progress.",
                    }))
                    .unwrap_or_default(),
                )]));
            }
            Err(error) => return Ok(task_create_error_to_tool_error(error).to_tool_result()),
        };

        let backend = match &ctx.open {
            DscBackgroundOpen::DirectRawDsc { .. } => "dscu",
            DscBackgroundOpen::LegacyIdat { .. } => "idat",
        };
        info!(
            module = %ctx.module,
            backend,
            "Spawning background DSC loading"
        );

        let registry = self.task_registry.clone();
        let worker = self.worker.clone();
        let mode = self.mode;
        let tid = task_id.clone();
        let task_cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            Self::run_dsc_background(tid, registry, worker, mode, ctx, task_cancel_token).await;
        });
        self.task_registry.set_cancel_token(&task_id, cancel_token);

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&json!({
                "status": "started",
                "task_id": task_id,
                "message": "DSC loading started in background. Poll task_status(task_id) for progress.",
            }))
            .unwrap_or_default(),
        )]))
    }

    /// Open a DSC database synchronously, load the requested images, and return db_info.
    async fn open_dsc_direct(
        &self,
        open_path: &std::path::Path,
        file_type: Option<&str>,
        module: &str,
        frameworks: &[String],
    ) -> Result<CallToolResult, McpError> {
        info!(path = %open_path.display(), file_type, "Opening DSC directly through idalib");

        let open_path_str = open_path.display().to_string();
        // Bind the image loads below to the database this call opened. The IDA
        // worker serves every session, so another session's close_idb between
        // the open and a load would otherwise redirect the load — which
        // mutates the database — into whatever database is current.
        let open_result = self
            .worker
            .open_observed_with_generation(
                &open_path_str,
                false,
                None,
                false,
                false,
                false,
                file_type.map(str::to_string),
                false,
                Vec::new(),
                None,
                None,
                None,
                None,
            )
            .await;

        let (db_info, generation) = match open_result {
            Ok(opened) => (opened.info, Some(opened.generation)),
            Err(e) => return Ok(e.to_tool_result()),
        };

        let mut loaded_images = Vec::with_capacity(frameworks.len() + 1);
        let mut dsc_warning = None;
        match self
            .worker
            .dsc_load_image_for_generation(module, Some(600), generation)
            .await
        {
            Ok(image) => loaded_images.push(image),
            Err(ToolError::NotSupported(message)) if file_type.is_none() => {
                dsc_warning = Some(format!(
                    "Opened existing IDA database, but native DSC loading is unavailable: {message}"
                ));
            }
            Err(e) => return Ok(e.to_tool_result()),
        }
        if dsc_warning.is_none() {
            for framework in frameworks {
                match self
                    .worker
                    .dsc_load_image_for_generation(framework, Some(600), generation)
                    .await
                {
                    Ok(image) => loaded_images.push(image),
                    Err(e) => return Ok(e.to_tool_result()),
                }
            }
        }

        let analysis_status = match self.worker.analysis_status_for_generation(generation).await {
            Ok(status) => Some(status),
            Err(err) => {
                warn!(module = %module, error = %err, "failed to fetch analysis_status after open_dsc");
                None
            }
        };
        let analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
        let next_step_hint = if dsc_warning.is_some() {
            "Existing .i64 opened, but native DSC loading was unavailable; inspect loaded modules before xrefs/decompile/list_functions."
        } else {
            "Proceed with xrefs/decompile/list_functions for the loaded DSC module."
        };
        let next_steps = dsc_analysis_next_steps(analysis_ready, next_step_hint);

        let close_token = self.http_close_grant();

        let mut value = match serde_json::to_value(&db_info) {
            Ok(v) => v,
            Err(_) => {
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "{db_info:?}"
                ))]));
            }
        };
        if let Value::Object(map) = &mut value {
            map.insert("module".to_string(), json!(module));
            if !frameworks.is_empty() {
                map.insert("frameworks_loaded".to_string(), json!(frameworks));
            }
            if let Some(module_info) = loaded_images.first() {
                map.insert("module_info".to_string(), json!(module_info));
            }
            let dsc_backend = if dsc_warning.is_some() {
                "unavailable"
            } else {
                "dscu"
            };
            map.insert("dsc_backend".to_string(), json!(dsc_backend));
            map.insert("loaded_images".to_string(), json!(loaded_images));
            if let Some(warning) = dsc_warning {
                map.insert("dsc_warning".to_string(), json!(warning));
            }
            map.insert("analysis_status".to_string(), json!(analysis_status));
            map.insert("analysis_ready".to_string(), json!(analysis_ready));
            map.insert("next_steps".to_string(), json!(next_steps));
            if !matches!(self.mode, ServerMode::Worker) {
                self.apply_close_metadata(map, close_token);
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value:?}")),
        )]))
    }

    fn complete_background_tool_error(
        task_id: &str,
        registry: &task::TaskRegistry,
        error: &ToolError,
        cancel_token: &tokio_util::sync::CancellationToken,
        cancel_message: &str,
    ) -> task::TaskSettlement {
        registry.complete_with_cancel_token(
            task_id,
            call_tool_result_to_value(&error.to_tool_result()),
            cancel_token,
            cancel_message,
        )
    }

    async fn finish_dsc_tool_error_after_open(
        task_id: &str,
        registry: &task::TaskRegistry,
        worker: &WorkerBackend,
        generation: DatabaseGeneration,
        error: ToolError,
        cancel_token: &tokio_util::sync::CancellationToken,
    ) {
        match worker.close_if_generation(generation).await {
            Ok(ConditionalCloseResult::Closed | ConditionalCloseResult::NotCurrent) => {
                Self::complete_background_tool_error(
                    task_id,
                    registry,
                    &error,
                    cancel_token,
                    "Cancelled after the failed DSC operation settled",
                );
            }
            Err(close_error) => {
                let message = format!(
                    "{error}; cleanup failed for database generation {}: {close_error}",
                    generation.0
                );
                warn!(error = %message, "background DSC failure cleanup did not settle safely");
                registry.fail_after_cleanup_error(task_id, &message);
            }
        }
    }

    async fn finish_dsc_cancellation_after_open(
        task_id: &str,
        registry: &task::TaskRegistry,
        worker: &WorkerBackend,
        generation: DatabaseGeneration,
    ) {
        match worker.close_if_generation(generation).await {
            Ok(ConditionalCloseResult::Closed) => {
                registry.finish_cancelled(
                    task_id,
                    "Cancelled after the active DSC operation settled and its database closed",
                );
            }
            Ok(ConditionalCloseResult::NotCurrent) => {
                registry.finish_cancelled(
                    task_id,
                    "Cancelled after the active DSC operation settled; its database generation was already replaced",
                );
            }
            Err(error) => {
                let message = format!(
                    "Cancellation cleanup failed for database generation {}: {error}",
                    generation.0
                );
                warn!(error = %error, "failed to close cancelled DSC database generation");
                registry.fail_after_cleanup_error(task_id, &message);
            }
        }
    }

    /// Background task: open a DSC through the selected backend, then load images.
    async fn run_dsc_background(
        task_id: String,
        registry: task::TaskRegistry,
        worker: WorkerBackend,
        mode: ServerMode,
        ctx: DscBackgroundCtx,
        cancel_token: tokio_util::sync::CancellationToken,
    ) {
        let DscBackgroundCtx {
            open,
            module,
            frameworks,
            owner_session_id,
        } = ctx;

        if cancel_token.is_cancelled() {
            registry.finish_cancelled(&task_id, "Cancelled by session shutdown");
            return;
        }

        let (open_path, idb_out, auto_analyse, load_images_with_dscu) = match open {
            DscBackgroundOpen::DirectRawDsc { open_path, idb_out } => {
                info!(
                    path = %open_path.display(),
                    idb_out = %idb_out.display(),
                    "Background: opening raw DSC through idalib"
                );
                registry.update_message(&task_id, "Opening DSC directly with idalib...");
                (open_path, Some(idb_out), false, true)
            }
            DscBackgroundOpen::LegacyIdat {
                idat,
                idat_args,
                script_path,
                log_path,
                out_i64,
            } => {
                let mut script_cleanup = TemporaryFileCleanup::new(script_path);

                // Phase 1: run idat subprocess
                info!("Background: running idat");
                registry.update_message(&task_id, "Running idat to create .i64...");

                let mut cmd = tokio::process::Command::new(&idat);
                cmd.args(&idat_args);
                // Remove env vars that cause license conflicts when our
                // process links idalib and also spawns idat.
                cmd.env_remove("IDADIR");
                cmd.env_remove("DYLD_LIBRARY_PATH");
                cmd.env("IDA_DYLD_CACHE_MODULE", &module);
                // idat's diagnostics go to stderr and the -L log file; stdout
                // is never read, and leaving it on an undrained pipe could
                // block idat once the buffer fills.
                cmd.stdout(std::process::Stdio::null());
                cmd.stderr(std::process::Stdio::piped());

                let (exit_code, stderr) = match cmd.spawn() {
                    Ok(mut child) => {
                        let mut stderr_pipe = child.stderr.take();
                        let mut stderr_buf = Vec::new();
                        let status = {
                            let wait = async {
                                if let Some(pipe) = stderr_pipe.as_mut() {
                                    use tokio::io::AsyncReadExt as _;
                                    let _ = pipe.read_to_end(&mut stderr_buf).await;
                                }
                                child.wait().await
                            };
                            tokio::pin!(wait);
                            tokio::select! {
                                status = &mut wait => Some(status),
                                () = cancel_token.cancelled() => None,
                            }
                        };
                        let Some(status) = status else {
                            // Kill idat and reap it before publishing the
                            // terminal state, so no IDA work survives a task
                            // that reports itself cancelled. A killed idat can
                            // leave partial database files that dsc_open_plan
                            // would reuse on the next call — remove them.
                            stop_idat_and_remove_partial_outputs(&mut child, &out_i64).await;
                            registry.finish_cancelled(
                                &task_id,
                                "Cancelled; the idat subprocess was killed and its partial output removed",
                            );
                            return;
                        };
                        let exit_code = match status {
                            Ok(status) => status.code().unwrap_or(-1),
                            Err(e) => {
                                stop_idat_and_remove_partial_outputs(&mut child, &out_i64).await;
                                registry.fail(&task_id, &format!("failed to wait for idat: {e}"));
                                return;
                            }
                        };
                        (exit_code, String::from_utf8_lossy(&stderr_buf).into_owned())
                    }
                    Err(e) => (-1, format!("Failed to spawn idat: {e}")),
                };

                if cancel_token.is_cancelled() {
                    registry
                        .finish_cancelled(&task_id, "Cancelled after the idat subprocess settled");
                    return;
                }

                // Clean up the temporary load script now; the guard still covers early returns above.
                script_cleanup.cleanup_now();

                if exit_code != 0 || !out_i64.exists() {
                    let log_tail = log_path
                        .as_ref()
                        .and_then(|p| std::fs::read_to_string(p).ok())
                        .map(|s| {
                            let lines: Vec<&str> = s.lines().collect();
                            let start = lines.len().saturating_sub(20);
                            lines[start..].join("\n")
                        });

                    let mut msg = format!("idat exited with code {exit_code}.\nstderr: {stderr}");
                    if let Some(tail) = log_tail {
                        msg.push_str(&format!("\nlog (last 20 lines):\n{tail}"));
                    }
                    remove_partial_idat_outputs(&out_i64);
                    warn!(exit_code, "idat failed");
                    Self::complete_background_tool_error(
                        &task_id,
                        &registry,
                        &ToolError::OpenFailed(msg),
                        &cancel_token,
                        "Cancelled after the idat subprocess settled",
                    );
                    return;
                }

                info!("idat completed, opening .i64");
                registry.update_message(&task_id, "Opening database with idalib...");
                (out_i64, None, true, false)
            }
        };

        // Phase 2: open the database with idalib.
        let open_path_str = open_path.display().to_string();
        let open_result = worker
            .open_observed_with_generation(
                &open_path_str,
                false,
                None,
                false,
                false,
                false,
                None,
                auto_analyse,
                Vec::new(),
                idb_out.as_ref().map(|path| path.display().to_string()),
                None,
                None,
                Some(cancel_token.clone()),
            )
            .await;

        let opened = match open_result {
            Ok(opened) => {
                if cancel_token.is_cancelled() {
                    Self::finish_dsc_cancellation_after_open(
                        &task_id,
                        &registry,
                        &worker,
                        opened.generation,
                    )
                    .await;
                    return;
                }
                opened
            }
            Err(e) => {
                Self::complete_background_tool_error(
                    &task_id,
                    &registry,
                    &e,
                    &cancel_token,
                    "Cancelled after the DSC open operation settled",
                );
                return;
            }
        };
        let db_info = opened.info;
        let database_generation = opened.generation;

        let mut loaded_images = Vec::new();
        let mut analysis_status = None;
        let mut analysis_ready = None;
        let mut next_steps = None;
        if load_images_with_dscu {
            registry.update_message(&task_id, "Loading DSC module through ida_dscu...");
            let module_result = worker
                .dsc_load_image_for_generation(&module, Some(600), Some(database_generation))
                .await;
            if cancel_token.is_cancelled() {
                Self::finish_dsc_cancellation_after_open(
                    &task_id,
                    &registry,
                    &worker,
                    database_generation,
                )
                .await;
                return;
            }
            match module_result {
                Ok(image) => loaded_images.push(image),
                Err(e) => {
                    Self::finish_dsc_tool_error_after_open(
                        &task_id,
                        &registry,
                        &worker,
                        database_generation,
                        ToolError::IdaError(format!("Failed to load DSC module {module}: {e}")),
                        &cancel_token,
                    )
                    .await;
                    return;
                }
            }

            for framework in &frameworks {
                if cancel_token.is_cancelled() {
                    Self::finish_dsc_cancellation_after_open(
                        &task_id,
                        &registry,
                        &worker,
                        database_generation,
                    )
                    .await;
                    return;
                }
                registry.update_message(&task_id, &format!("Loading DSC framework {framework}..."));
                let framework_result = worker
                    .dsc_load_image_for_generation(framework, Some(600), Some(database_generation))
                    .await;
                if cancel_token.is_cancelled() {
                    Self::finish_dsc_cancellation_after_open(
                        &task_id,
                        &registry,
                        &worker,
                        database_generation,
                    )
                    .await;
                    return;
                }
                match framework_result {
                    Ok(image) => loaded_images.push(image),
                    Err(e) => {
                        Self::finish_dsc_tool_error_after_open(
                            &task_id,
                            &registry,
                            &worker,
                            database_generation,
                            ToolError::IdaError(format!(
                                "Failed to load DSC framework {framework}: {e}"
                            )),
                            &cancel_token,
                        )
                        .await;
                        return;
                    }
                }
            }

            let analysis_status_result = worker
                .analysis_status_for_generation(Some(database_generation))
                .await;
            if cancel_token.is_cancelled() {
                Self::finish_dsc_cancellation_after_open(
                    &task_id,
                    &registry,
                    &worker,
                    database_generation,
                )
                .await;
                return;
            }
            analysis_status = match analysis_status_result {
                Ok(status) => Some(status),
                Err(err) => {
                    warn!(module = %module, error = %err, "failed to fetch analysis_status after background open_dsc");
                    None
                }
            };
            analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
            next_steps = Some(dsc_analysis_next_steps(
                analysis_ready,
                "Proceed with xrefs/decompile/list_functions for the loaded DSC module.",
            ));
        }

        if cancel_token.is_cancelled() {
            Self::finish_dsc_cancellation_after_open(
                &task_id,
                &registry,
                &worker,
                database_generation,
            )
            .await;
            return;
        }

        let close_token = match (mode, owner_session_id.as_deref()) {
            (ServerMode::Http, Some(owner_session_id)) => {
                worker.issue_close_token_for_session(owner_session_id)
            }
            _ => None,
        };

        let mut value = serde_json::to_value(&db_info)
            .unwrap_or_else(|_| json!({"info": format!("{db_info:?}")}));
        if let Value::Object(map) = &mut value {
            map.insert("module".to_string(), json!(module));
            if !frameworks.is_empty() {
                map.insert("frameworks_loaded".to_string(), json!(frameworks));
            }
            if load_images_with_dscu {
                if let Some(module_info) = loaded_images.first() {
                    map.insert("module_info".to_string(), json!(module_info));
                }
                map.insert("dsc_backend".to_string(), json!("dscu"));
                map.insert("loaded_images".to_string(), json!(loaded_images));
                map.insert("analysis_status".to_string(), json!(analysis_status));
                map.insert("analysis_ready".to_string(), json!(analysis_ready));
                map.insert("next_steps".to_string(), json!(next_steps));
            }
            apply_close_metadata(map, close_token, close_hint_for(mode, worker.is_pooled()));
        }

        match registry.complete_or_defer_cancellation(&task_id, value, &cancel_token) {
            task::TaskCompletionDecision::Completed => {
                info!("DSC background task completed");
            }
            task::TaskCompletionDecision::CancellationPending => {
                Self::finish_dsc_cancellation_after_open(
                    &task_id,
                    &registry,
                    &worker,
                    database_generation,
                )
                .await;
            }
            task::TaskCompletionDecision::Unchanged => {}
        }
    }
}

/// Convert an optional i64 wire field into an unsigned Rust type used by the
/// worker. Returns InvalidParams if the value is negative or exceeds the
/// destination type's range — schema `#[schemars(range(...))]` bounds should
/// keep this from firing in practice, but non-conforming clients still get a
/// clear error instead of a silent cast.
fn parse_optional_unsigned<T>(value: Option<i64>, name: &str) -> Result<Option<T>, ToolError>
where
    T: TryFrom<i64>,
{
    match value {
        Some(v) => T::try_from(v).map(Some).map_err(|_| {
            ToolError::InvalidParams(format!(
                "{name} ({v}) is out of range for {}",
                std::any::type_name::<T>()
            ))
        }),
        None => Ok(None),
    }
}

/// Short-circuit on a `Result<_, ToolError>` from within a `#[tool]` async fn,
/// surfacing the error to the client as an `is_error: true` CallToolResult
/// (matching the existing `Err(e) => Ok(e.to_tool_result())` pattern used by
/// the rest of the handlers).
macro_rules! try_param {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        }
    };
}

fn close_hint_for(mode: ServerMode, pooled: bool) -> &'static str {
    match (mode, pooled) {
        (ServerMode::Http, true) => {
            "In pooled HTTP/SSE mode, close_idb releases this session's child worker lease. Sessions do not share one global close_token."
        }
        (ServerMode::Stdio, _) => "Call close_idb when done to release locks for other sessions.",
        (ServerMode::Http, false) => {
            "In HTTP/SSE mode, keep the close_token returned by open_idb. Sessionless MCP 2026 and non-owning legacy contexts must pass it to close_idb; the owning legacy session can close directly. If the token is lost, close_idb(force=true) can recover the shared IDA context."
        }
        (ServerMode::Worker, _) => {
            "Child worker mode is managed by the parent router; close_idb is normally called by the parent."
        }
    }
}

/// Stop and reap an idat child before removing database artifacts that cannot
/// be trusted after cancellation or a wait failure.
async fn stop_idat_and_remove_partial_outputs(
    child: &mut tokio::process::Child,
    out_i64: &std::path::Path,
) {
    let _ = child.start_kill();
    let _ = child.wait().await;
    remove_partial_idat_outputs(out_i64);
}

/// Best-effort removal of what an incomplete idat run leaves behind: the packed
/// `.i64` (which `dsc_open_plan` would reuse as-is on the next `open_dsc`)
/// and the unpacked database components idat works in before packing.
fn remove_partial_idat_outputs(out_i64: &std::path::Path) {
    let mut paths = vec![out_i64.to_path_buf()];
    for ext in ["id0", "id1", "id2", "nam", "til"] {
        paths.push(out_i64.with_extension(ext));
    }
    for path in paths {
        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!(path = %path.display(), "removed untrusted partial idat output");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to remove partial idat output");
            }
        }
    }
}

/// Insert close-ownership metadata onto a tool result, identical for foreground
/// `open_idb` and the DSC background task so clients see one shape via both
/// paths.
fn apply_close_metadata(
    map: &mut serde_json::Map<String, Value>,
    grant: Option<Result<CloseTokenGrant, String>>,
    close_hint: &str,
) {
    match grant {
        Some(Ok(grant)) => {
            map.insert("close_hint".to_string(), json!(close_hint));
            map.insert(
                "close_owner_session_id".to_string(),
                json!(grant.owner_session_id),
            );
            map.insert("close_token".to_string(), json!(grant.token));
            if grant.reused {
                map.insert("close_token_reused".to_string(), json!(true));
            }
        }
        Some(Err(owner_session_id)) => {
            map.insert(
                "close_hint".to_string(),
                json!(format!(
                    "The open database is currently owned by HTTP context {owner_session_id}. Provide its close_token to close_idb, or call close_idb(force=true) if that token was lost."
                )),
            );
            map.insert(
                "close_owner_session_id".to_string(),
                json!(owner_session_id),
            );
            map.insert(
                "close_recovery_hint".to_string(),
                json!(
                    "If the original close_token was lost, call close_idb(force=true) from a trusted client."
                ),
            );
        }
        None => {
            map.insert("close_hint".to_string(), json!(close_hint));
        }
    }
}

// Tool implementations using the #[tool_router] attribute

#[tool_router]
impl IdaMcpServer {
    #[tool(
        description = "Open an IDA database (.i64/.idb) or raw binary (Mach-O/ELF/PE). \
        Raw binaries are saved as .i64 alongside the input and later raw-path opens reuse \
        that database unless rebuild=true is set. \
        For raw binaries, auto-analysis is OFF by default — check analysis_status; \
        call analyze_funcs(background=true) for full xrefs/decompile. \
        Returns close_token in HTTP/SSE mode (provide to close_idb). \
        Inputs >50 MiB with auto_analyse=true may route to a background task; \
        poll task_status(analysis_task_id) when present. \
        Call tool_help('open_idb') for full details."
    )]
    #[instrument(skip_all, fields(path = %req.path, mrtr_retry = request_state.is_some()))]
    async fn open_idb(
        &self,
        ctx: RequestContext<RoleServer>,
        RequestState(request_state): RequestState,
        ToolInputResponses(input_responses): ToolInputResponses,
        Parameters(req): Parameters<OpenIdbRequest>,
    ) -> Result<CallToolResponse, McpError> {
        debug!("Tool call: open_idb");
        let path = req.path.trim().to_string();
        // Validate path (prevent directory traversal, check extension)
        if !Self::validate_path(&path) {
            return Ok(ToolError::InvalidPath(path).to_tool_result().into());
        }
        let timeout_secs = match parse_optional_unsigned::<u64>(req.timeout_secs, "timeout_secs") {
            Ok(timeout_secs) => timeout_secs,
            Err(error) => return Ok(error.to_tool_result().into()),
        };

        let debug_info_path = req.normalized_debug_info_path();
        let file_type = req.normalized_file_type();
        let worker_extra_args = if matches!(self.mode, ServerMode::Worker) {
            req.worker_extra_args.clone()
        } else {
            Vec::new()
        };
        let worker_idb_out = if matches!(self.mode, ServerMode::Worker) {
            req.worker_idb_out.clone()
        } else {
            None
        };
        let open_timeout_secs = timeout_secs.unwrap_or(300).min(MAX_TIMEOUT_SECS);
        let foreground_timeout_secs = self.foreground_timeout_secs(timeout_secs, 300);
        let user_auto_analyse = req.auto_analyse.unwrap_or(false);
        let large_input_size = if !matches!(self.mode, ServerMode::Worker)
            && user_auto_analyse
            && !Self::is_database_path(&path)
        {
            Self::input_size_above_threshold(&path)
        } else {
            None
        };
        let route_to_background = match large_input_size {
            Some(size) => match self
                .choose_open_idb_background(
                    &ctx,
                    &path,
                    size,
                    timeout_secs,
                    request_state,
                    input_responses,
                )
                .await?
            {
                OpenIdbBackgroundDecision::Ready(background) => background,
                OpenIdbBackgroundDecision::InputRequired(result) => return Ok(result.into()),
            },
            None if request_state.is_some() || input_responses.is_some() => {
                return Err(McpError::invalid_params(
                    "requestState/inputResponses do not match an active open_idb elicitation",
                    None,
                ));
            }
            None => false,
        };
        // Open the database with auto_analyse disabled when we plan to spawn
        // analysis as a background task; the open call itself stays fast and
        // analysis runs without the foreground timeout cap.
        let effective_auto_analyse = user_auto_analyse && !route_to_background;

        match self
            .run_foreground_operation(
                &ctx,
                "open_idb",
                path.clone(),
                foreground_timeout_secs,
                300,
                |progress_tx, cancel| {
                    self.worker.open_observed(
                        &path,
                        req.load_debug_info.unwrap_or(false),
                        debug_info_path.clone(),
                        req.debug_info_verbose.unwrap_or(false),
                        req.force.unwrap_or(false),
                        req.rebuild.unwrap_or(false),
                        file_type.clone(),
                        effective_auto_analyse,
                        worker_extra_args.clone(),
                        worker_idb_out.clone(),
                        Some(open_timeout_secs),
                        Some(progress_tx),
                        Some(cancel),
                    )
                },
            )
            .await
        {
            Ok(info) => {
                let close_token = self.http_close_grant();
                let analysis_task = if route_to_background && !info.analysis_status.auto_is_ok {
                    let cancel_token = self.background_lifetime(&ctx.meta).child_token();
                    let owner = self.task_owner(&ctx.meta);
                    Some(match self.spawn_analyze_funcs_task(&owner, cancel_token) {
                        Ok(task_id) => Ok((task_id, "started")),
                        Err(task::TaskCreateError::AlreadyRunning(existing_id)) => {
                            Ok((existing_id, "already_running"))
                        }
                        Err(error) => Err(task_create_error_to_tool_error(error).to_string()),
                    })
                } else {
                    None
                };
                let mut value = match serde_json::to_value(&info) {
                    Ok(v) => v,
                    Err(_) => {
                        return Ok(CallToolResult::success(vec![Content::text(format!(
                            "{info:?}"
                        ))])
                        .into());
                    }
                };
                if let Value::Object(map) = &mut value {
                    let mut quick_tools = vec![
                        "list_functions",
                        "resolve_function",
                        "disasm_by_name",
                        "strings",
                        "analysis_status",
                        "analyze_funcs",
                        "close_idb",
                    ];
                    if info.analysis_status.auto_is_ok {
                        quick_tools.extend(["decompile", "xrefs_to"]);
                    }
                    map.insert("quick_tools".to_string(), json!(quick_tools));
                    if !matches!(self.mode, ServerMode::Worker) {
                        map.insert("session_id".to_string(), json!(self.session_id));
                        self.apply_close_metadata(map, close_token);
                    }
                    if let Some(analysis_task) = analysis_task {
                        match analysis_task {
                            Ok((task_id, status)) => {
                                let reason = format!(
                                    "Input size exceeded {} MiB; auto-analysis routed to a background task. Poll task_status(task_id) for progress.",
                                    OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES / (1024 * 1024)
                                );
                                map.insert("analysis_background".to_string(), json!(true));
                                map.insert("analysis_started".to_string(), json!(true));
                                map.insert("analysis_task_id".to_string(), json!(task_id));
                                map.insert("analysis_task_status".to_string(), json!(status));
                                map.insert("analysis_background_reason".to_string(), json!(reason));
                            }
                            Err(error) => {
                                map.insert("analysis_background".to_string(), json!(false));
                                map.insert("analysis_started".to_string(), json!(false));
                                map.insert(
                                    "analysis_task_status".to_string(),
                                    json!("not_started"),
                                );
                                map.insert("analysis_background_error".to_string(), json!(error));
                            }
                        }
                    }
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{value:?}")),
                )])
                .into())
            }
            Err(ForegroundOperationError::TimedOut {
                timeout_secs,
                snapshot,
            }) => Ok(ToolError::TimeoutDetailed(Self::operation_timeout_message(
                "open_idb",
                timeout_secs,
                &snapshot,
                None,
            ))
            .to_tool_result()
            .into()),
            Err(ForegroundOperationError::Cancelled { snapshot }) => Ok(ToolError::Cancelled(
                Self::operation_cancelled_message("open_idb", &snapshot),
            )
            .to_tool_result()
            .into()),
            Err(ForegroundOperationError::Tool(error)) => Ok(error.to_tool_result().into()),
        }
    }

    /// Returns the input size in bytes when it strictly exceeds the
    /// auto-background threshold; `None` otherwise (including when the path
    /// can't be stat'd, e.g. for raw arguments that aren't real files).
    fn input_size_above_threshold(path: &str) -> Option<u64> {
        let meta = std::fs::metadata(crate::expand_path(path.trim())).ok()?;
        if !meta.is_file() {
            return None;
        }
        let size = meta.len();
        (size > OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES).then_some(size)
    }

    fn is_database_path(path: &str) -> bool {
        crate::expand_path(path.trim())
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| {
                let ext = ext.to_ascii_lowercase();
                ext == "i64" || ext == "idb" || ext == "id0"
            })
            .unwrap_or(false)
    }

    fn open_idb_elicitation_timeout_secs(request_timeout_secs: Option<u64>) -> u64 {
        request_timeout_secs
            .unwrap_or(OPEN_IDB_ELICITATION_TIMEOUT_SECS)
            .min(MAX_TIMEOUT_SECS)
            .min(OPEN_IDB_ELICITATION_TIMEOUT_SECS)
    }

    fn open_idb_background_prompt(path: &str, size_bytes: u64) -> String {
        let size_mib = size_bytes / (1024 * 1024);
        let threshold_mib = OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES / (1024 * 1024);
        format!(
            "'{path}' is {size_mib} MiB (threshold {threshold_mib} MiB). \
             Run auto-analysis as a background task with no timeout? \
             Choosing 'no' runs it inline (capped at the foreground timeout)."
        )
    }

    /// Decide whether `open_idb` should route auto-analysis to a background
    /// task. Asks the user via MCP elicitation when the client advertises the
    /// capability; falls back to "background" silently otherwise so large
    /// binaries don't get killed by the foreground timeout. Unanswered prompts
    /// time out to "background"; explicit decline/cancel from a capable client
    /// preserves the legacy foreground behavior.
    async fn choose_open_idb_background(
        &self,
        ctx: &RequestContext<RoleServer>,
        path: &str,
        size_bytes: u64,
        request_timeout_secs: Option<u64>,
        request_state: Option<String>,
        input_responses: Option<InputResponses>,
    ) -> Result<OpenIdbBackgroundDecision, McpError> {
        use rmcp::service::{ElicitationError, ServiceError};

        let size_mib = size_bytes / (1024 * 1024);
        let modern_protocol = ctx
            .protocol_version()
            .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28);
        if modern_protocol {
            return self.modern_choose_open_idb_background(
                ctx,
                path,
                size_bytes,
                request_state,
                input_responses,
            );
        }

        if request_state.is_some() || input_responses.is_some() {
            return Err(McpError::invalid_params(
                "requestState and inputResponses require MCP 2026-07-28",
                None,
            ));
        }

        if ctx.peer.supported_elicitation_modes().is_empty() {
            info!(
                path,
                size_mib, "client lacks elicitation; routing open_idb auto-analysis to background"
            );
            return Ok(OpenIdbBackgroundDecision::Ready(true));
        }

        let prompt = Self::open_idb_background_prompt(path, size_bytes);

        let elicitation_timeout_secs =
            Self::open_idb_elicitation_timeout_secs(request_timeout_secs);
        let client_cancel = ctx.ct.clone();
        let elicitation = ctx.peer.elicit_with_timeout::<OpenIdbBackgroundChoice>(
            prompt,
            Some(Duration::from_secs(elicitation_timeout_secs)),
        );

        let result = tokio::select! {
            biased;
            _ = client_cancel.cancelled() => {
                info!(
                    path,
                    size_mib,
                    "open_idb elicitation cancelled with client request"
                );
                return Ok(OpenIdbBackgroundDecision::Ready(false));
            }
            result = elicitation => result,
        };

        let background = match result {
            Ok(Some(choice)) => choice.background.unwrap_or(true),
            // Some clients return Accept with no content for action-only
            // confirmations; treat that as a "yes, background".
            // `Ok(None)` is not expected from the current typed API, but keep
            // the arm defensive in case that contract broadens later.
            Ok(None) | Err(ElicitationError::NoContent) => true,
            Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => false,
            Err(ElicitationError::CapabilityNotSupported) => true,
            Err(ElicitationError::Service(ServiceError::Timeout { .. })) => {
                info!(
                    path,
                    size_mib,
                    elicitation_timeout_secs,
                    "open_idb elicitation timed out; routing auto-analysis to background"
                );
                true
            }
            Err(err) => {
                warn!(
                    path,
                    size_mib, elicitation_timeout_secs, %err,
                    "open_idb elicitation failed; routing to background to avoid timeout regression"
                );
                true
            }
        };
        Ok(OpenIdbBackgroundDecision::Ready(background))
    }

    /// MCP 2026 (MRTR) preamble for the background decision: validates the
    /// requestState/capability pairing before the sealed-state round-trip.
    fn modern_choose_open_idb_background(
        &self,
        ctx: &RequestContext<RoleServer>,
        path: &str,
        size_bytes: u64,
        request_state: Option<String>,
        input_responses: Option<InputResponses>,
    ) -> Result<OpenIdbBackgroundDecision, McpError> {
        if request_state.is_none() && input_responses.is_some() {
            return Err(McpError::invalid_params(
                "inputResponses require a matching requestState",
                None,
            ));
        }
        let supports_form_elicitation = ctx
            .client_capabilities()
            .and_then(|capabilities| capabilities.elicitation)
            .and_then(|elicitation| elicitation.form)
            .is_some();
        if request_state.is_none() && !supports_form_elicitation {
            info!(
                path,
                size_mib = size_bytes / (1024 * 1024),
                "client lacks form elicitation; routing open_idb auto-analysis to background"
            );
            return Ok(OpenIdbBackgroundDecision::Ready(true));
        }
        if !supports_form_elicitation {
            return Err(McpError::invalid_params(
                "MRTR retry omitted the form elicitation capability",
                None,
            ));
        }
        self.modern_open_idb_background_decision(path, size_bytes, request_state, input_responses)
    }

    fn modern_open_idb_background_decision(
        &self,
        path: &str,
        size_bytes: u64,
        request_state: Option<String>,
        input_responses: Option<InputResponses>,
    ) -> Result<OpenIdbBackgroundDecision, McpError> {
        const STAGE: &[u8] = b"open_idb/background-confirmation/v1";
        const INPUT_KEY: &str = "background";

        let associated_data = format!("tools/call:open_idb\0{path}\0{size_bytes}");
        let Some(sealed) = request_state else {
            if input_responses.is_some() {
                return Err(McpError::invalid_params(
                    "inputResponses require a matching requestState",
                    None,
                ));
            }
            let sealed = self.request_state_codec.seal_with(
                STAGE,
                &SealOptions::new()
                    .associated_data(associated_data.as_bytes())
                    .ttl(Duration::from_secs(OPEN_IDB_REQUEST_STATE_TTL_SECS)),
            );
            // Reuse the same schema the legacy elicitation path derives from
            // `OpenIdbBackgroundChoice`, so the two protocols cannot drift.
            let requested_schema = ElicitationSchema::from_type::<OpenIdbBackgroundChoice>()
                .map_err(|error| {
                    McpError::internal_error(
                        format!("failed to build open_idb elicitation schema: {error}"),
                        None,
                    )
                })?;
            let mut input_requests = InputRequests::new();
            input_requests.insert(
                INPUT_KEY.to_string(),
                InputRequest::Elicitation(ElicitRequest::new(
                    ElicitRequestParams::FormElicitationParams {
                        meta: None,
                        message: Self::open_idb_background_prompt(path, size_bytes),
                        requested_schema,
                    },
                )),
            );
            return Ok(OpenIdbBackgroundDecision::InputRequired(
                InputRequiredResult::new(Some(input_requests), Some(sealed)),
            ));
        };

        let opened = self
            .request_state_codec
            .open_with(&sealed, associated_data.as_bytes())
            .map_err(|_| {
                McpError::invalid_params("expired, tampered, or unknown requestState", None)
            })?;
        if opened != STAGE {
            return Err(McpError::invalid_params(
                "requestState belongs to a different MRTR stage",
                None,
            ));
        }
        let response = input_responses
            .as_ref()
            .and_then(|responses| responses.get(INPUT_KEY))
            .ok_or_else(|| {
                McpError::invalid_params("missing background elicitation response", None)
            })?;
        let response: ElicitResult = serde_json::from_value(response.clone()).map_err(|_| {
            McpError::invalid_params("invalid background elicitation response action", None)
        })?;
        let background = match response.action {
            ElicitationAction::Accept => response
                .content
                .and_then(|content| serde_json::from_value::<OpenIdbBackgroundChoice>(content).ok())
                .and_then(|choice| choice.background)
                .unwrap_or(true),
            ElicitationAction::Decline | ElicitationAction::Cancel => false,
            // `ElicitationAction` is #[non_exhaustive]; treat unknown future
            // actions as a decline so we never background without consent.
            _ => false,
        };
        Ok(OpenIdbBackgroundDecision::Ready(background))
    }

    #[tool(
        description = "Load external debug info (e.g., DWARF/dSYM) into the current database. \
        If path is omitted, attempts to locate a sibling .dSYM for the currently-open database."
    )]
    #[instrument(skip_all, fields(has_path = req.path.is_some()))]
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
    #[instrument(skip_all)]
    async fn analysis_status(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analysis_status");
        match self.worker.analysis_status().await {
            Ok(status) => {
                let mut value =
                    serde_json::to_value(&status).unwrap_or_else(|_| json!(format!("{status:?}")));
                if !matches!(self.mode, ServerMode::Worker)
                    && let Value::Object(map) = &mut value
                {
                    map.insert("session_id".to_string(), json!(self.session_id));
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{status:?}")),
                )]))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Close the currently open IDA database. \
        Call this when you're done analyzing to free resources. \
        In legacy HTTP/SSE, the owning session can close directly. Otherwise, \
        including MCP 2026, provide the close_token returned by open_idb, or \
        set force=true from a trusted client if that token was lost. \
        Stdio clients can close directly without a token.")]
    #[instrument(skip_all, fields(has_token = req.token.is_some(), force = ?req.force))]
    async fn close_idb(
        &self,
        Parameters(req): Parameters<CloseIdbRequest>,
    ) -> Result<CallToolResult, McpError> {
        info!("Tool call: close_idb received");
        if matches!(self.mode, ServerMode::Http) && self.worker.uses_close_tokens() {
            match self.worker.authorize_close(
                &self.session_id,
                req.token.as_deref(),
                req.force.unwrap_or(false),
            ) {
                CloseAuthorization::Granted => {}
                CloseAuthorization::GrantedByOverride {
                    previous_owner_session_id,
                } => {
                    info!(
                        previous_owner_session_id = ?previous_owner_session_id,
                        "close_idb overriding previous HTTP owner session"
                    );
                }
                CloseAuthorization::Denied { owner_session_id } => {
                    info!(owner_session_id = ?owner_session_id, "close_idb ignored: owner token required");
                    return Ok(CallToolResult::success(vec![Content::text(
                        serde_json::to_string_pretty(&json!({
                            "closed": false,
                            "reason": "owner token required",
                            "owner_session_id": owner_session_id,
                            "hint": "Provide the close_token from open_idb, or call close_idb(force=true) from a trusted client if that token was lost."
                        }))
                        .unwrap_or_else(|_| "close_idb ignored: owner token required".to_string()),
                    )]));
                }
            }
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
    #[instrument(skip_all)]
    async fn tool_catalog(
        &self,
        Parameters(req): Parameters<ToolCatalogRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_catalog");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(7)
            .min(15);
        let filter = self.filter.clone();
        let filtering_active = filter.is_active();

        // If category specified, list tools in that category
        if let Some(cat_str) = &req.category
            && let Ok(cat) = cat_str.parse::<ToolCategory>()
        {
            let tools: Vec<_> = tool_registry::tools_by_category(cat)
                .filter(|t| filter.is_enabled(t.name))
                .take(limit)
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.short_desc,
                        "category": t.category.as_str(),
                    })
                })
                .collect();

            let mut payload = json!({
                "category": cat.as_str(),
                "category_description": cat.description(),
                "tools": tools,
                "hint": "Use tool_help(name) for full documentation and examples"
            });
            if filtering_active {
                payload["filtering_active"] = json!(true);
            }
            return Ok(CallToolResult::success(vec![Content::text(pretty_json(
                &payload,
            ))]));
        }

        // If query specified, search for matching tools
        if let Some(query) = &req.query {
            let results = tool_registry::search_tools(query, tool_registry::all_tools().count());
            let tools: Vec<_> = results
                .iter()
                .filter(|(t, _)| filter.is_enabled(t.name))
                .take(limit)
                .map(|(t, keywords)| {
                    json!({
                        "name": t.name,
                        "description": t.short_desc,
                        "category": t.category.as_str(),
                        "matched": keywords,
                    })
                })
                .collect();

            let mut payload = json!({
                "query": query,
                "tools": tools,
                "hint": "Use tool_help(name) for full documentation and examples"
            });
            if filtering_active {
                payload["filtering_active"] = json!(true);
            }
            return Ok(CallToolResult::success(vec![Content::text(pretty_json(
                &payload,
            ))]));
        }

        // No query or category - list all categories. Counts reflect enabled
        // tools so users see exactly what's available under the active filter.
        let categories: Vec<_> = ToolCategory::all()
            .iter()
            .map(|c| {
                let count = tool_registry::tools_by_category(*c)
                    .filter(|t| filter.is_enabled(t.name))
                    .count();
                json!({
                    "category": c.as_str(),
                    "description": c.description(),
                    "tool_count": count,
                })
            })
            .collect();

        let hint = if filtering_active {
            "Use tool_catalog(category='...') to list enabled tools in a category, or tool_catalog(query='...') to search enabled tools. tools/list includes only tools enabled by the current filter."
        } else {
            "Use tool_catalog(category='...') to list tools in a category, or tool_catalog(query='...') to search. tools/list already includes all tools."
        };

        let mut payload = json!({
            "categories": categories,
            "hint": hint
        });
        if filtering_active {
            payload["filtering_active"] = json!(true);
            payload["enabled_tool_count"] = json!(filter.enabled_count());
        }

        Ok(CallToolResult::success(vec![Content::text(pretty_json(
            &payload,
        ))]))
    }

    #[tool(
        description = "Get full documentation for a tool including description, parameters schema, and example."
    )]
    #[instrument(skip_all)]
    async fn tool_help(
        &self,
        Parameters(req): Parameters<ToolHelpRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_help for {}", req.name);

        // If the tool exists in the registry but is filter-disabled, do not
        // leak its schema as available — return a clear disabled message.
        if self.filter.is_active()
            && tool_registry::get_tool(&req.name).is_some()
            && !self.filter.is_enabled(&req.name)
        {
            return Ok(CallToolResult::success(vec![Content::text(pretty_json(
                &json!({
                    "error": format!(
                        "tool '{}' is disabled by current filter \
                         (--toolsets/--tools/--exclude-tools/--read-only)",
                        req.name
                    ),
                    "filtering_active": true,
                    "hint": "call tool_catalog to see enabled tools",
                }),
            ))]));
        }

        if let Some(tool) = tool_registry::get_tool(&req.name) {
            let params = tool_params_schema(&req.name);
            Ok(CallToolResult::success(vec![Content::text(pretty_json(
                &json!({
                    "name": tool.name,
                    "category": tool.category.as_str(),
                    "description": tool.full_desc,
                    "parameters": params,
                    "example": tool.example,
                    "keywords": tool.keywords,
                }),
            ))]))
        } else {
            // Suggest similar tools
            let suggestions = tool_registry::search_tools(&req.name, 3);
            let suggestion_names: Vec<_> = suggestions.iter().map(|(t, _)| t.name).collect();

            Ok(CallToolResult::success(vec![Content::text(pretty_json(
                &json!({
                    "error": format!("Tool '{}' not found", req.name),
                    "suggestions": suggestion_names,
                    "hint": "Use tool_catalog to discover available tools"
                }),
            ))]))
        }
    }

    #[tool(description = "List all functions in the database (paginated).")]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit))]
    async fn list_functions(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_functions");
        // Clamp limit to prevent excessive responses
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let filter = req.filter.clone();

        match self
            .worker
            .list_functions(offset, limit, filter, timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List functions (ida-pro-mcp compatible alias).")]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn list_funcs(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_funcs");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let filter = req.filter.clone();

        match self
            .worker
            .list_functions(offset, limit, filter, timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Resolve a function name to its address")]
    #[instrument(skip_all, fields(name = %req.name))]
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
    #[instrument(skip_all, fields(address = %req.address, count = req.count))]
    async fn disasm(
        &self,
        Parameters(req): Parameters<DisasmRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disasm");
        // Clamp instruction count
        let count = try_param!(parse_optional_unsigned::<usize>(req.count, "count"))
            .unwrap_or(10)
            .min(1000);
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
    #[instrument(skip_all, fields(name = %req.name, count = req.count))]
    async fn disasm_by_name(
        &self,
        Parameters(req): Parameters<DisasmByNameRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disasm_by_name");
        let count = try_param!(parse_optional_unsigned::<usize>(req.count, "count"))
            .unwrap_or(10)
            .min(1000);

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
        let count = try_param!(parse_optional_unsigned::<usize>(req.count, "count"))
            .unwrap_or(200)
            .min(5000);
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
    #[instrument(skip_all, fields(address = %req.address))]
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
    #[instrument(skip_all, fields(address = %req.address, end_address = ?req.end_address))]
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
    #[instrument(skip_all)]
    async fn segments(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: segments");
        match self.worker.segments().await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List strings in the database with pagination and optional filter.")]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn strings(
        &self,
        Parameters(req): Parameters<StringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: strings");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        match self
            .worker
            .strings(offset, limit, req.filter, timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Find strings matching a query (supports exact/case-insensitive options)."
    )]
    async fn find_string(
        &self,
        Parameters(req): Parameters<FindStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
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
                timeout_secs,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find strings and return xrefs to each match.")]
    async fn xrefs_to_string(
        &self,
        Parameters(req): Parameters<XrefsToStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let max_xrefs =
            try_param!(parse_optional_unsigned::<usize>(req.max_xrefs, "max_xrefs")).unwrap_or(64);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let exact = req.exact.unwrap_or(false);
        let case_insensitive = req.case_insensitive.unwrap_or(true);
        match self
            .worker
            .xrefs_to_string(
                req.query.clone(),
                exact,
                case_insensitive,
                offset,
                limit,
                max_xrefs,
                timeout_secs,
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
        description = "Get cross-references TO an address (who references this address). \
        Paginated (default limit 1000, max 10000); when truncated=true, pass next_offset back \
        as offset to page through high-frequency targets."
    )]
    #[instrument(skip_all, fields(address = %req.address))]
    async fn xrefs_to(
        &self,
        Parameters(req): Parameters<XrefsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xrefs_to");
        self.xrefs_lookup(req, XrefDirection::To).await
    }

    #[tool(
        description = "Get cross-references FROM an address (what this address references). \
        Paginated (default limit 1000, max 10000); when truncated=true, pass next_offset back \
        as offset to page through the remaining references."
    )]
    #[instrument(skip_all, fields(address = %req.address))]
    async fn xrefs_from(
        &self,
        Parameters(req): Parameters<XrefsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xrefs_from");
        self.xrefs_lookup(req, XrefDirection::From).await
    }

    #[tool(description = "List imports (external symbols) with pagination")]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit))]
    async fn imports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: imports");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);

        match self.worker.imports(offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "List exports/names (public symbols) with pagination")]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit))]
    async fn exports(
        &self,
        Parameters(req): Parameters<PaginatedRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: exports");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);

        match self.worker.exports(offset, limit).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get entry point addresses of the binary")]
    #[instrument(skip_all)]
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
    #[instrument(skip_all, fields(size = req.size))]
    async fn get_bytes(
        &self,
        Parameters(req): Parameters<GetBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_bytes");
        let size = try_param!(parse_optional_unsigned::<usize>(req.size, "size"))
            .unwrap_or(256)
            .min(0x10000);
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
    #[instrument(skip_all, fields(address = %req.address))]
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
    #[instrument(skip_all, fields(address = %req.address))]
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
    #[instrument(skip_all, fields(address = %req.address))]
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
    #[instrument(skip_all)]
    async fn idb_meta(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: idb_meta");
        match self.worker.idb_meta().await {
            Ok(result) => {
                let mut value =
                    serde_json::to_value(&result).unwrap_or_else(|_| json!(format!("{result:?}")));
                if !matches!(self.mode, ServerMode::Worker)
                    && let Value::Object(map) = &mut value
                {
                    map.insert("session_id".to_string(), json!(self.session_id));
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| format!("{result:?}")),
                )]))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Lookup functions by name or address (batch)")]
    #[instrument(skip_all)]
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

    #[tool(description = "List global names (non-function symbols).")]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn list_globals(
        &self,
        Parameters(req): Parameters<ListGlobalsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_globals");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        match self
            .worker
            .list_globals(req.query.clone(), offset, limit, timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Analyze strings with xrefs (ida-pro-mcp compatibility).")]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn analyze_strings(
        &self,
        Parameters(req): Parameters<AnalyzeStringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analyze_strings");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        match self
            .worker
            .analyze_strings(req.query.clone(), offset, limit, timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Find byte patterns (ida-pro-mcp compatibility).")]
    #[instrument(skip_all)]
    async fn find_bytes(
        &self,
        Parameters(req): Parameters<FindBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_bytes");
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let worker_max_results = if matches!(self.mode, ServerMode::Worker) {
            try_param!(parse_optional_unsigned::<usize>(
                req.worker_max_results,
                "_worker_max_results"
            ))
            .map(|value| value.min(20000))
        } else {
            None
        };
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let response_limit = worker_max_results.unwrap_or(limit);
        let mut results = Vec::new();

        for pattern in patterns {
            let max_results = worker_max_results.unwrap_or_else(|| (offset + limit).min(20000));
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
                        .take(response_limit)
                        .collect::<Vec<_>>();
                    let next_offset = if offset + response_limit < total {
                        Some(offset + response_limit)
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

    #[tool(description = "Search for text or immediates (ida-pro-mcp compatibility).")]
    #[instrument(skip_all)]
    async fn search(
        &self,
        Parameters(req): Parameters<SearchRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search");
        let targets = match Self::value_to_strings(&req.targets) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let worker_max_results = if matches!(self.mode, ServerMode::Worker) {
            try_param!(parse_optional_unsigned::<usize>(
                req.worker_max_results,
                "_worker_max_results"
            ))
            .map(|value| value.min(20000))
        } else {
            None
        };
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let kind = req.kind.as_deref().unwrap_or("auto").to_lowercase();

        let response_limit = worker_max_results.unwrap_or(limit);
        let mut results = Vec::new();
        for target in targets {
            let max_results = worker_max_results.unwrap_or_else(|| (offset + limit).min(20000));
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
                        .take(response_limit)
                        .collect::<Vec<_>>();
                    let next_offset = if offset + response_limit < total {
                        Some(offset + response_limit)
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
    #[instrument(skip_all)]
    async fn get_u8(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 1).await
    }

    #[tool(description = "Read u16 values at address(es)")]
    #[instrument(skip_all)]
    async fn get_u16(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 2).await
    }

    #[tool(description = "Read u32 values at address(es)")]
    #[instrument(skip_all)]
    async fn get_u32(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 4).await
    }

    #[tool(description = "Read u64 values at address(es)")]
    #[instrument(skip_all)]
    async fn get_u64(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 8).await
    }

    #[tool(description = "Read string(s) at address(es)")]
    #[instrument(skip_all)]
    async fn get_string(
        &self,
        Parameters(req): Parameters<GetStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_string");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_len = try_param!(parse_optional_unsigned::<usize>(req.max_len, "max_len"))
            .unwrap_or(256)
            .min(0x10000);

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
    #[instrument(skip_all)]
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
    #[instrument(skip_all)]
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
        let max_paths = try_param!(parse_optional_unsigned::<usize>(req.max_paths, "max_paths"))
            .unwrap_or(8)
            .min(128);
        let max_depth = try_param!(parse_optional_unsigned::<usize>(req.max_depth, "max_depth"))
            .unwrap_or(64)
            .min(2048);

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
    #[instrument(skip_all)]
    async fn callgraph(
        &self,
        Parameters(req): Parameters<CallGraphRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callgraph");
        let roots = match Self::value_to_addresses(&req.roots) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_depth = try_param!(parse_optional_unsigned::<usize>(req.max_depth, "max_depth"))
            .unwrap_or(2)
            .min(16);
        let max_nodes = try_param!(parse_optional_unsigned::<usize>(req.max_nodes, "max_nodes"))
            .unwrap_or(256)
            .min(10000);

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
    #[instrument(skip_all)]
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
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit))]
    async fn export_funcs(
        &self,
        Parameters(req): Parameters<ExportFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: export_funcs");
        if let Some(fmt) = req.format.as_deref()
            && fmt.to_lowercase() != "json"
        {
            return Ok(ToolError::NotSupported(format!(
                "format {} not supported (only json)",
                fmt
            ))
            .to_tool_result());
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
            let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
                .unwrap_or(100)
                .min(10000);
            let offset =
                try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
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
    #[instrument(skip_all)]
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
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit")).unwrap_or(100);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        match self
            .worker
            .local_types(offset, limit, req.filter.clone(), timeout_secs)
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
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(1000)
            .min(10000);
        let ordinal = try_param!(parse_optional_unsigned::<u32>(req.ordinal, "ordinal"));
        let member_index = try_param!(parse_optional_unsigned::<u32>(
            req.member_index,
            "member_index"
        ));
        match self
            .worker
            .xrefs_to_field(
                ordinal,
                req.name.clone(),
                member_index,
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

    #[tool(description = "Look up Lumina metadata for a function without applying it")]
    #[instrument(skip_all, fields(target_name = ?req.target_name))]
    async fn lumina_lookup(
        &self,
        Parameters(req): Parameters<LuminaLookupRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let addr = try_param!(req
            .address
            .as_ref()
            .map(Self::value_to_single_address)
            .transpose());
        match self
            .worker
            .lumina_lookup(addr, req.target_name.clone(), offset, timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{result:?}")),
            )])),
            Err(err) => Ok(err.to_tool_result()),
        }
    }

    #[tool(description = "Pull and apply Lumina metadata to a function")]
    #[instrument(skip_all, fields(target_name = ?req.target_name, force = req.force))]
    async fn lumina_apply(
        &self,
        Parameters(req): Parameters<LuminaApplyRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let force = req.force.unwrap_or(false);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let addr = try_param!(req
            .address
            .as_ref()
            .map(Self::value_to_single_address)
            .transpose());
        match self
            .worker
            .lumina_apply(addr, req.target_name.clone(), offset, force, timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{result:?}")),
            )])),
            Err(err) => Ok(err.to_tool_result()),
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

    #[tool(description = "List structs in the database with pagination and optional filter.")]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: structs");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        match self
            .worker
            .structs(offset, limit, req.filter, timeout_secs)
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Get info about a struct by ordinal or name")]
    #[instrument(skip_all, fields(ordinal = req.ordinal, name = ?req.name))]
    async fn struct_info(
        &self,
        Parameters(req): Parameters<StructInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: struct_info");
        let ordinal = try_param!(parse_optional_unsigned::<u32>(req.ordinal, "ordinal"));
        match self.worker.struct_info(ordinal, req.name).await {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(description = "Read values of a struct instance at an address")]
    #[instrument(skip_all, fields(address = %req.address, ordinal = req.ordinal, name = ?req.name))]
    async fn read_struct(
        &self,
        Parameters(req): Parameters<ReadStructRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_struct");
        let addrs = match Self::value_to_addresses(&req.address) {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let ordinal = try_param!(parse_optional_unsigned::<u32>(req.ordinal, "ordinal"));

        if addrs.len() == 1 {
            match self.worker.read_struct(addrs[0], ordinal, req.name).await {
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
                    .read_struct(addr, ordinal, req.name.clone())
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
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit")).unwrap_or(100);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        match self
            .worker
            .structs(offset, limit, req.filter.clone(), timeout_secs)
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
        let max_results =
            try_param!(parse_optional_unsigned::<usize>(req.limit, "limit")).unwrap_or(100);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let case_insensitive = req.case_insensitive.unwrap_or(false);
        match self
            .worker
            .find_insns(patterns, max_results, case_insensitive, timeout_secs)
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
        let max_results =
            try_param!(parse_optional_unsigned::<usize>(req.limit, "limit")).unwrap_or(100);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let case_insensitive = req.case_insensitive.unwrap_or(false);
        match self
            .worker
            .find_insn_operands(patterns, max_results, case_insensitive, timeout_secs)
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

    #[tool(description = "Run IDA auto-analysis to completion. \
        Use background=true for large binaries (returns task_id; poll task_status).")]
    async fn analyze_funcs(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(req): Parameters<AnalyzeFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if matches!(self.mode, ServerMode::Worker) && req.worker_no_timeout {
            return match self
                .worker
                .analyze_funcs_unbounded_observed(None, Some(ctx.ct.clone()))
                .await
            {
                Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )])),
                Err(e) => Ok(e.to_tool_result()),
            };
        }
        if req.background.unwrap_or(false) {
            let cancel_token = self.background_lifetime(&ctx.meta).child_token();
            let owner = self.task_owner(&ctx.meta);
            return Ok(self.analyze_funcs_background(&owner, cancel_token));
        }

        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let analyze_timeout_secs = timeout_secs.unwrap_or(120).min(MAX_TIMEOUT_SECS);
        let foreground_timeout_secs = self.foreground_timeout_secs(timeout_secs, 120);
        match self
            .run_foreground_operation(
                &ctx,
                "analyze_funcs",
                "current database".to_string(),
                foreground_timeout_secs,
                120,
                |progress_tx, cancel| {
                    self.worker.analyze_funcs_observed(
                        Some(progress_tx),
                        Some(cancel),
                        Some(analyze_timeout_secs),
                    )
                },
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)),
            )])),
            Err(ForegroundOperationError::TimedOut {
                timeout_secs,
                snapshot,
            }) => Ok(ToolError::TimeoutDetailed(Self::operation_timeout_message(
                "analyze_funcs",
                timeout_secs,
                &snapshot,
                None,
            ))
            .to_tool_result()),
            Err(ForegroundOperationError::Cancelled { snapshot }) => Ok(ToolError::Cancelled(
                Self::operation_cancelled_message("analyze_funcs", &snapshot),
            )
            .to_tool_result()),
            Err(ForegroundOperationError::Tool(error)) => Ok(error.to_tool_result()),
        }
    }

    /// Spawn auto-analysis as a background task. Returns a task_id immediately;
    /// the IDA worker thread runs auto_wait() while task_status reads the registry
    /// without going through the worker. Only one analysis runs at a time (single
    /// worker thread), so a fixed dedup key blocks another analysis while one
    /// is already in flight. Only the same legacy session receives its existing
    /// task ID; sessionless Runtime requests never do.
    fn analyze_funcs_background(
        &self,
        owner: &task::TaskOwner,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> CallToolResult {
        let payload = match self.spawn_analyze_funcs_task(owner, cancel_token) {
            Ok(task_id) => json!({
                "status": "started",
                "task_id": task_id,
                "message": "Auto-analysis started in background. Poll task_status(task_id) for progress. Other tool calls will block until the IDA worker thread is free.",
            }),
            Err(task::TaskCreateError::AlreadyRunning(existing_id)) => json!({
                "status": "already_running",
                "task_id": existing_id,
                "message": "Auto-analysis is already running. Poll task_status(task_id) for progress.",
            }),
            Err(error) => return task_create_error_to_tool_error(error).to_tool_result(),
        };
        CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&payload).unwrap_or_default(),
        )])
    }

    /// Create the background auto-analysis task and spawn its worker future.
    /// Returns `Ok(task_id)` on success or an error if keyed work is already in
    /// flight. The error carries an existing ID only for the same legacy session.
    fn spawn_analyze_funcs_task(
        &self,
        owner: &task::TaskOwner,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<String, task::TaskCreateError> {
        let task_id = self.task_registry.create_keyed(
            owner,
            "analyze",
            "analyze_funcs",
            "Waiting for IDA auto-analysis to finish",
        )?;

        info!("Spawning background auto-analysis");

        let registry = self.task_registry.clone();
        let worker = self.worker.clone();
        let tid = task_id.clone();
        let worker_cancel_token = cancel_token.clone();

        tokio::spawn(async move {
            // Bridge worker progress updates → task registry messages.
            // The drain task ends when tx is dropped after analyze_funcs_observed returns.
            let (tx, mut rx): (ProgressSender, ProgressReceiver) =
                tokio::sync::mpsc::unbounded_channel();
            let drain_registry = registry.clone();
            let drain_tid = tid.clone();
            tokio::spawn(async move {
                while let Some(update) = rx.recv().await {
                    drain_registry.update_message(&drain_tid, &update.message);
                }
            });

            match worker
                .analyze_funcs_unbounded_observed(Some(tx), Some(worker_cancel_token.clone()))
                .await
            {
                Ok(value) => match registry.complete_with_cancel_token(
                    &tid,
                    value,
                    &worker_cancel_token,
                    "Cancelled after auto-analysis settled",
                ) {
                    task::TaskSettlement::Completed => {
                        info!("Background auto-analysis completed");
                    }
                    task::TaskSettlement::Cancelled => {
                        info!("Background auto-analysis cancelled after work settled");
                    }
                    task::TaskSettlement::Failed | task::TaskSettlement::Unchanged => {}
                },
                Err(e) => match registry.complete_with_cancel_token(
                    &tid,
                    call_tool_result_to_value(&e.to_tool_result()),
                    &worker_cancel_token,
                    "Cancelled after auto-analysis settled",
                ) {
                    task::TaskSettlement::Completed => {
                        warn!(error = %e, "Background auto-analysis completed with a tool error");
                    }
                    task::TaskSettlement::Cancelled => {
                        info!("Background auto-analysis cancelled after work settled");
                    }
                    task::TaskSettlement::Failed | task::TaskSettlement::Unchanged => {}
                },
            }
        });
        self.task_registry.set_cancel_token(&task_id, cancel_token);
        Ok(task_id)
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
        let flags = try_param!(parse_optional_unsigned::<i32>(req.flags, "flags")).unwrap_or(0);
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
        description = "Open a dyld_shared_cache and load a single dylib (e.g. \
        '/usr/lib/libobjc.A.dylib'). Use instead of open_idb for Apple DSCs. \
        If a previously generated .i64 exists for this DSC, opens it immediately, \
        preserving prior analysis. Otherwise on IDA 9.4, opens the DSC header \
        directly in a background task and loads modules through ida_dscu; on \
        older IDA builds, returns task_id and creates the .i64 with idat in the \
        background. Poll task_status(task_id). \
        Use dsc_add_dylib to load more modules, dsc_add_region for raw regions. \
        Call tool_help('open_dsc') for full details."
    )]
    #[instrument(skip_all, fields(path = %req.path, arch = %req.arch, module = %req.module))]
    async fn open_dsc(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(req): Parameters<OpenDscRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: open_dsc");

        if !Self::validate_path(&req.path) {
            return Ok(ToolError::InvalidPath(req.path).to_tool_result());
        }

        let ida_version = try_param!(parse_optional_unsigned::<u8>(
            req.ida_version,
            "ida_version"
        ))
        .unwrap_or(9);
        if ida_version != 8 && ida_version != 9 {
            return Ok(
                ToolError::InvalidParams("ida_version must be 8 or 9".into()).to_tool_result(),
            );
        }

        let file_type = crate::dsc::dsc_file_type(&req.arch, ida_version);
        let frameworks = req.frameworks.unwrap_or_default();
        let dsc_path = std::path::Path::new(&req.path);
        let out_i64 = dsc_path.with_extension("i64");
        // Reuse order: a sibling .i64 (legacy idat output or user-provided)
        // first, then the 9.4 direct-path cache. Pre-9.4 never considers the
        // cache — those databases were written by a newer IDA and cannot be
        // opened there.
        let cache_i64 = direct_dsc_cache_i64_path(dsc_path);
        let existing_i64 = if out_i64.exists() {
            Some(out_i64.clone())
        } else if idalib::SDK_VERSION >= (9, 4) && cache_i64.exists() {
            Some(cache_i64.clone())
        } else {
            None
        };

        match dsc_open_plan(idalib::SDK_VERSION, existing_i64.is_some()) {
            // Existing .i64 databases are already in IDA's database format.
            DscOpenPlan::DirectExistingI64 => {
                // `existing_i64` is Some whenever this plan is selected; the
                // fallback only guards the type system.
                let existing = existing_i64.unwrap_or(out_i64);
                return self
                    .open_dsc_direct(&existing, None, &req.module, &frameworks)
                    .await;
            }
            // IDA 9.4 exposes ida_dscu/dscu_svc_t: the loader can open the DSC
            // header first, then load images on demand in the same idalib process.
            //
            // Do not pass the legacy -T file-type selector here. IDA 9.4's
            // direct idalib open path rejects it with "Unknown switch '-T'".
            DscOpenPlan::BackgroundDirectRawDsc => {
                let idb_out = cache_i64;
                let dsc_ctx = DscBackgroundCtx {
                    open: DscBackgroundOpen::DirectRawDsc {
                        open_path: dsc_path.to_path_buf(),
                        idb_out: idb_out.clone(),
                    },
                    module: req.module.clone(),
                    frameworks: frameworks.clone(),
                    owner_session_id: matches!(self.mode, ServerMode::Http)
                        .then(|| self.session_id.clone()),
                };
                return self.start_dsc_background(
                    &self.task_owner(&ctx.meta),
                    dsc_path.display().to_string(),
                    &format!(
                        "Opening DSC directly with idalib (idb_out={})...",
                        idb_out.display()
                    ),
                    dsc_ctx,
                    self.background_lifetime(&ctx.meta).child_token(),
                );
            }
            DscOpenPlan::LegacyIdatBackground => {}
        }

        // Legacy path: create the .i64 with idat, which takes minutes.
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

        let log_path = req.log_path.map(std::path::PathBuf::from);
        if let Some(ref lp) = log_path
            && lp.to_string_lossy().contains("..")
        {
            return Ok(ToolError::InvalidParams(
                "log_path must not contain '..' path traversal".into(),
            )
            .to_tool_result());
        }
        let idat_args = crate::dsc::idat_dsc_args(
            dsc_path,
            &out_i64,
            &script_path,
            &file_type,
            log_path.as_deref(),
        );
        let dedup_key = out_i64.display().to_string();

        let dsc_ctx = DscBackgroundCtx {
            open: DscBackgroundOpen::LegacyIdat {
                idat,
                idat_args,
                script_path,
                log_path,
                out_i64,
            },
            module: req.module.clone(),
            frameworks,
            owner_session_id: matches!(self.mode, ServerMode::Http)
                .then(|| self.session_id.clone()),
        };
        self.start_dsc_background(
            &self.task_owner(&ctx.meta),
            dedup_key,
            "Running idat to create .i64 from DSC...",
            dsc_ctx,
            self.background_lifetime(&ctx.meta).child_token(),
        )
    }

    #[tool(description = "Load an additional dylib into an open DSC database \
        (requires prior open_dsc). Skips full auto-analysis for speed; \
        check analysis_status and run analyze_funcs if needed.")]
    #[instrument(skip_all, fields(module = %req.module))]
    async fn dsc_add_dylib(
        &self,
        Parameters(req): Parameters<DscAddDylibRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dsc_add_dylib");

        let module = req.module.trim().to_string();
        if module.is_empty() {
            return Ok(ToolError::InvalidParams("module must not be empty".into()).to_tool_result());
        }
        if !module.starts_with('/') {
            return Ok(ToolError::InvalidParams(
                "module must be an absolute path (start with '/')".into(),
            )
            .to_tool_result());
        }
        if module.contains("..") {
            return Ok(ToolError::InvalidParams(
                "module must not contain '..' path traversal".into(),
            )
            .to_tool_result());
        }

        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .unwrap_or(300)
        .min(MAX_TIMEOUT_SECS);
        match self
            .worker
            .dsc_load_image(&module, Some(timeout_secs))
            .await
        {
            Ok(image) => {
                let analysis_status = match self.worker.analysis_status().await {
                    Ok(status) => Some(status),
                    Err(err) => {
                        warn!(module = %module, error = %err, "failed to fetch analysis_status after dsc_add_dylib");
                        None
                    }
                };
                let analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
                let next_steps = dsc_analysis_next_steps(
                    analysis_ready,
                    "Proceed with xrefs/decompile/list_functions for the newly loaded module.",
                );
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "module": module,
                        "message": format!(
                            "Successfully loaded {module} into the database. \
                             Full auto-analysis was not forced."
                        ),
                        "dsc_backend": "dscu",
                        "image": image,
                        "analysis_status": analysis_status,
                        "analysis_ready": analysis_ready,
                        "next_steps": next_steps,
                    }))
                    .unwrap_or_default(),
                )]))
            }
            Err(ToolError::Timeout(secs)) => {
                let message =
                    format!("dsc_add_dylib timed out after {secs} seconds while loading {module}");
                warn!(module = %module, timeout_secs = secs, "dsc_add_dylib timed out");
                Ok(ToolError::IdaError(message).to_tool_result())
            }
            Err(ToolError::TimeoutDetailed(message)) => {
                warn!(module = %module, timeout_secs, "dsc_add_dylib timed out");
                Ok(ToolError::IdaError(format!(
                    "dsc_add_dylib timed out while loading {module}: {message}"
                ))
                .to_tool_result())
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Load a DSC region by address into an open DSC database \
        (data/GOT/stub areas; one address per call; requires prior open_dsc). \
        Skips full auto-analysis."
    )]
    #[instrument(skip_all, fields(address = ?req.address))]
    async fn dsc_add_region(
        &self,
        Parameters(req): Parameters<DscAddRegionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dsc_add_region");

        let ea = match Self::value_to_exactly_one_address(&req.address, "address") {
            Ok(value) => value,
            Err(ToolError::InvalidAddress(addr)) => {
                return Ok(
                    ToolError::InvalidParams(format!("Invalid address: {addr}")).to_tool_result()
                );
            }
            Err(e) => return Ok(e.to_tool_result()),
        };
        let ea_hex = format!("0x{ea:x}");
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .unwrap_or(300)
        .min(MAX_TIMEOUT_SECS);
        match self.worker.dsc_load_region(ea, Some(timeout_secs)).await {
            Ok(region) => {
                let analysis_status = match self.worker.analysis_status().await {
                    Ok(status) => Some(status),
                    Err(err) => {
                        warn!(
                            address = %ea_hex,
                            error = %err,
                            "failed to fetch analysis_status after dsc_add_region"
                        );
                        None
                    }
                };
                let analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
                let next_steps = dsc_analysis_next_steps(
                    analysis_ready,
                    "Proceed with xrefs/decompile/list_functions for symbols near this region.",
                );
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&json!({
                        "success": true,
                        "address": ea_hex,
                        "address_value": ea,
                        "message": format!(
                            "Successfully loaded DSC region at 0x{ea:x}. \
                             Full auto-analysis was not forced."
                        ),
                        "dsc_backend": "dscu",
                        "region": region,
                        "analysis_status": analysis_status,
                        "analysis_ready": analysis_ready,
                        "next_steps": next_steps,
                    }))
                    .unwrap_or_default(),
                )]))
            }
            Err(ToolError::Timeout(secs)) => {
                let message = format!(
                    "dsc_add_region timed out after {secs} seconds while loading region {ea_hex}"
                );
                warn!(
                    address = %ea_hex,
                    timeout_secs = secs,
                    "dsc_add_region timed out"
                );
                Ok(ToolError::IdaError(message).to_tool_result())
            }
            Err(ToolError::TimeoutDetailed(message)) => {
                warn!(
                    address = %ea_hex,
                    timeout_secs,
                    "dsc_add_region timed out"
                );
                Ok(ToolError::IdaError(format!(
                    "dsc_add_region timed out while loading region {ea_hex}: {message}"
                ))
                .to_tool_result())
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Check the status of a background task (e.g. DSC loading). \
        Returns the current status: 'running' (with a progress message), \
        'completed' (with the result — database is already open), \
        'failed' (with an error message), or 'cancelled'. \
        Use the task_id returned by open_dsc."
    )]
    #[instrument(skip_all)]
    async fn task_status(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(req): Parameters<TaskStatusRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: task_status");

        let owner = self.task_owner(&ctx.meta);
        let state = match self.task_registry.get_for_owner(&owner, &req.task_id) {
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

        if let Some(result) = &state.result
            && let Value::Object(map) = &mut response
        {
            map.insert("result".to_string(), result.clone());
        }

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap_or_default(),
        )]))
    }

    #[tool(description = "Inspect recent foreground operation history. \
        Returns the currently active foreground operation (if any) and the last \
        recorded phase transitions for open_idb, run_script, and analyze_funcs.")]
    async fn recent_operations(
        &self,
        Parameters(req): Parameters<RecentOperationsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"));
        let recent: RecentOperations = self.operation_registry.recent(limit);
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&recent).unwrap_or_else(|_| format!("{recent:?}")),
        )]))
    }

    #[tool(
        description = "Execute IDAPython in the open database. Provide 'code' (inline) \
        or 'file' (path to .py), not both. Returns captured stdout/stderr. \
        Full access to ida_*, idc, idautils."
    )]
    #[instrument(skip_all, fields(code_len = req.code.as_ref().map_or(0, String::len)))]
    async fn run_script(
        &self,
        ctx: RequestContext<RoleServer>,
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
        let timeout = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .unwrap_or(120)
        .min(MAX_TIMEOUT_SECS);
        let foreground_timeout_secs = self.foreground_timeout_secs(Some(timeout), 120);
        match self
            .run_foreground_operation(
                &ctx,
                "run_script",
                format!("code_len={}", code.len()),
                foreground_timeout_secs,
                120,
                |progress_tx, cancel| {
                    self.worker.run_script_observed(
                        &code,
                        Some(progress_tx),
                        Some(cancel),
                        Some(timeout),
                    )
                },
            )
            .await
        {
            Ok(result) => {
                if !run_script_succeeded(&result) {
                    let message = run_script_failure_message(&result);
                    warn!(code_len = code.len(), error = %message, "run_script failed");
                    return Ok(ToolError::IdaError(message).to_tool_result());
                }
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| format!("{:?}", result)),
                )]))
            }
            Err(ForegroundOperationError::TimedOut {
                timeout_secs,
                snapshot,
            }) => {
                let detail = run_script_timeout_message(timeout_secs, &code);
                warn!(timeout_secs, code_len = code.len(), "run_script timed out");
                Ok(ToolError::TimeoutDetailed(Self::operation_timeout_message(
                    "run_script",
                    timeout_secs,
                    &snapshot,
                    Some(detail),
                ))
                .to_tool_result())
            }
            Err(ForegroundOperationError::Cancelled { snapshot }) => Ok(ToolError::Cancelled(
                Self::operation_cancelled_message("run_script", &snapshot),
            )
            .to_tool_result()),
            Err(ForegroundOperationError::Tool(error)) => Ok(error.to_tool_result()),
        }
    }
}

const RUN_SCRIPT_PREVIEW_CHARS: usize = 220;
const RUN_SCRIPT_TAIL_LINES: usize = 12;
const RUN_SCRIPT_TAIL_CHARS: usize = 1600;

fn run_script_succeeded(result: &Value) -> bool {
    result.get("success").and_then(Value::as_bool) == Some(true)
}

fn run_script_field<'a>(result: &'a Value, field: &str) -> Option<&'a str> {
    result.get(field).and_then(Value::as_str)
}

fn run_script_last_non_empty_line(text: &str) -> Option<&str> {
    text.lines().rev().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn run_script_truncate_chars(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, ch) in input.chars().enumerate() {
        if count >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

fn run_script_tail_lines(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

fn run_script_error_hint(error_details: &str) -> Option<&'static str> {
    let lowered = error_details.to_ascii_lowercase();
    if lowered.contains("syntaxerror") || lowered.contains("invalid syntax") {
        return Some("Python syntax error detected. Regenerate valid Python and retry.");
    }
    if lowered.contains("nameerror") {
        return Some("NameError detected. Check variable/module names before rerunning.");
    }
    if lowered.contains("attributeerror") {
        return Some("AttributeError detected. Verify IDA API object names/methods.");
    }
    if lowered.contains("importerror") || lowered.contains("modulenotfounderror") {
        return Some("Import failure detected. Ensure the required module exists in IDAPython.");
    }
    if lowered.contains("failed to execute wrapper") {
        return Some(
            "IDAPython wrapper execution failed before user code completed. Check stderr for details.",
        );
    }
    None
}

fn run_script_failure_message(result: &Value) -> String {
    let stderr = run_script_field(result, "stderr").unwrap_or_default();
    let stdout = run_script_field(result, "stdout").unwrap_or_default();
    let summary = run_script_field(result, "error_summary")
        .or_else(|| run_script_field(result, "error"))
        .or_else(|| run_script_last_non_empty_line(stderr))
        .unwrap_or("Unknown IDAPython script failure (no error details captured)");

    let stderr_tail = run_script_truncate_chars(
        &run_script_tail_lines(stderr, RUN_SCRIPT_TAIL_LINES),
        RUN_SCRIPT_TAIL_CHARS,
    );
    let stdout_tail = run_script_truncate_chars(
        &run_script_tail_lines(stdout, RUN_SCRIPT_TAIL_LINES),
        RUN_SCRIPT_TAIL_CHARS,
    );

    let mut parts = vec![format!("IDAPython script execution failed: {summary}")];
    if let Some(kind) = run_script_field(result, "error_kind") {
        parts.push(format!("Error kind: {kind}"));
    }
    if !stderr_tail.is_empty() {
        parts.push(format!("stderr (tail):\n{stderr_tail}"));
    }
    if !stdout_tail.is_empty() {
        parts.push(format!("stdout (tail):\n{stdout_tail}"));
    }
    let combined_details = format!("{summary}\n{stderr_tail}");
    if let Some(hint) = run_script_error_hint(&combined_details) {
        parts.push(format!("Hint: {hint}"));
    }
    parts.join("\n\n")
}

fn run_script_timeout_message(timeout_secs: u64, code: &str) -> String {
    let compact_preview = code
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let preview = if compact_preview.is_empty() {
        "<empty script>".to_string()
    } else {
        run_script_truncate_chars(&compact_preview, RUN_SCRIPT_PREVIEW_CHARS)
    };
    format!(
        "run_script timed out after {timeout_secs} seconds.\n\
         The script may be blocked in a long-running loop or waiting on IDA state.\n\
         Script preview: {preview}\n\
         Hint: while iterating with LLM-generated code, use a smaller timeout_secs and avoid scripts that block indefinitely."
    )
}

fn dsc_analysis_next_steps(
    analysis_ready: Option<bool>,
    ready_message: &'static str,
) -> Vec<String> {
    if analysis_ready == Some(true) {
        vec![ready_message.to_string()]
    } else {
        vec![
            "Call analysis_status to check auto-analysis progress.".to_string(),
            "If auto_is_ok is false, run analyze_funcs and wait for completion before xrefs/decompile."
                .to_string(),
        ]
    }
}

async fn get_int_values(
    worker: &WorkerBackend,
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
        let mut value = serde_json::to_value(schema_for!(T)).unwrap_or_else(|_| json!({}));
        normalize_schema_value(&mut value);
        value
    }

    match name {
        // Core
        "open_idb" => Some(schema::<OpenIdbRequest>()),
        "open_dsc" => Some(schema::<OpenDscRequest>()),
        "dsc_add_dylib" => Some(schema::<DscAddDylibRequest>()),
        "dsc_add_region" => Some(schema::<DscAddRegionRequest>()),
        "close_idb" => Some(schema::<CloseIdbRequest>()),
        "load_debug_info" => Some(schema::<LoadDebugInfoRequest>()),
        "analysis_status" => Some(schema::<EmptyParams>()),
        "tool_catalog" => Some(schema::<ToolCatalogRequest>()),
        "tool_help" => Some(schema::<ToolHelpRequest>()),
        "recent_operations" => Some(schema::<RecentOperationsRequest>()),
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
        "xrefs_to" | "xrefs_from" => Some(schema::<XrefsRequest>()),
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
        "lumina_lookup" => Some(schema::<LuminaLookupRequest>()),
        "lumina_apply" => Some(schema::<LuminaApplyRequest>()),
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

/// All supported versions, oldest first. The final entry must stay the only
/// modern (sessionless) protocol: pooled workers advertise everything before
/// it, because their worker lease is bound to a legacy HTTP session.
const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2024_11_05,
    ProtocolVersion::V_2025_03_26,
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_11_25,
    ProtocolVersion::V_2026_07_28,
];

fn supported_protocol_versions(pooled: bool) -> Cow<'static, [ProtocolVersion]> {
    if pooled {
        let (legacy, _modern) =
            SUPPORTED_PROTOCOL_VERSIONS.split_at(SUPPORTED_PROTOCOL_VERSIONS.len() - 1);
        Cow::Borrowed(legacy)
    } else {
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }
}

/// Convert our internal `TaskState` to the base rmcp `Task` model.
fn task_state_to_mcp_task(state: &task::TaskState) -> rmcp::model::Task {
    let status = match state.status {
        task::TaskStatus::Running => rmcp::model::TaskStatus::Working,
        task::TaskStatus::Completed => rmcp::model::TaskStatus::Completed,
        task::TaskStatus::Failed => rmcp::model::TaskStatus::Failed,
        task::TaskStatus::Cancelled => rmcp::model::TaskStatus::Cancelled,
    };
    rmcp::model::Task::new(
        state.id.clone(),
        status,
        state.created_at_iso.clone(),
        state.updated_at_iso.clone(),
    )
    .with_status_message(state.message.clone())
    .with_ttl_ms(task::TASK_RETENTION_TTL_MS)
    .with_poll_interval_ms(5000)
}

fn value_as_json_object(value: Value) -> JsonObject {
    match value {
        Value::Object(object) => object,
        other => {
            let mut object = JsonObject::new();
            object.insert("value".to_string(), other);
            object
        }
    }
}

fn task_state_to_detailed_task(state: task::TaskState) -> DetailedTask {
    let base = task_state_to_mcp_task(&state);
    let payload = match state.status {
        task::TaskStatus::Running => TaskPayload::Working,
        task::TaskStatus::Completed => TaskPayload::Completed {
            result: value_as_json_object(task_payload_result_value(state.result)),
        },
        task::TaskStatus::Failed => TaskPayload::Failed {
            error: value_as_json_object(json!({
                "code": ErrorCode::INTERNAL_ERROR.0,
                "message": state.message,
            })),
        },
        task::TaskStatus::Cancelled => TaskPayload::Cancelled,
    };
    DetailedTask::new(base, payload)
}

fn call_tool_result_to_value(result: &CallToolResult) -> Value {
    serde_json::to_value(result).unwrap_or_else(|_| {
        json!({
            "content": [{
                "type": "text",
                "text": "Failed to serialize CallToolResult"
            }],
            "isError": true
        })
    })
}

fn looks_like_call_tool_result(value: &Value) -> bool {
    serde_json::from_value::<CallToolResult>(value.clone()).is_ok()
}

fn wrap_as_call_tool_result(value: &Value) -> Value {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| format!("{value:?}"));
    call_tool_result_to_value(&CallToolResult::success(vec![Content::text(text)]))
}

fn task_payload_result_value(result: Option<Value>) -> Value {
    match result {
        Some(value) if looks_like_call_tool_result(&value) => value,
        Some(value) => wrap_as_call_tool_result(&value),
        None => wrap_as_call_tool_result(&Value::Null),
    }
}

fn task_id_from_call_tool_result(result: &CallToolResult) -> Option<String> {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .and_then(|text| serde_json::from_str::<Value>(&text.text).ok())
        .and_then(|value| value.get("task_id")?.as_str().map(str::to_string))
}

fn task_create_error_to_tool_error(error: task::TaskCreateError) -> ToolError {
    match error {
        task::TaskCreateError::AlreadyRunning(_) => ToolError::Busy,
        task::TaskCreateError::ExistingTaskIdIsPrivate => ToolError::BackgroundTaskHandlePrivate,
        task::TaskCreateError::CapacityExceeded { max_entries } => {
            ToolError::BackgroundTaskRegistryFull { max: max_entries }
        }
    }
}

/// SEP-2663 `tasks/update` semantics: unknown task ids are an invalid-params
/// error, while responses delivered to a known task are acknowledged with an
/// empty result even when unknown or superseded. No task here ever enters
/// input_required (open_idb's MRTR happens at call level), so every delivered
/// response falls into that ignored-not-error bucket.
fn apply_task_update(
    task_registry: &task::TaskRegistry,
    owner: &task::TaskOwner,
    task_id: &str,
) -> Result<(), McpError> {
    if task_registry.get_for_owner(owner, task_id).is_none() {
        return Err(McpError::invalid_params(
            "Unknown task_id",
            Some(json!({ "task_id": task_id })),
        ));
    }
    Ok(())
}

fn materialize_task_response(
    task_registry: &task::TaskRegistry,
    should_materialize: bool,
    response: CallToolResponse,
) -> Result<CallToolResponse, McpError> {
    if !should_materialize {
        return Ok(response);
    }
    let CallToolResponse::Complete(result) = response else {
        return Ok(response);
    };
    let Some(task_id) = task_id_from_call_tool_result(&result) else {
        return Ok(CallToolResponse::Complete(result));
    };
    let state = task_registry
        .get(&task_id)
        .ok_or_else(|| McpError::internal_error(format!("Task {task_id} disappeared"), None))?;
    Ok(CreateTaskResult::new(task_state_to_mcp_task(&state)).into())
}

#[tool_handler(router = self.tool_mux)]
impl ServerHandler for IdaMcpServer {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        supported_protocol_versions(self.worker.is_pooled())
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks()
                .build(),
        )
        .with_instructions(self.instructions())
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        let owner = self.task_owner(&context.meta);
        let state = self
            .task_registry
            .get_for_owner(&owner, &request.task_id)
            .ok_or_else(|| {
                McpError::invalid_params(
                    "Unknown task_id",
                    Some(json!({ "task_id": request.task_id })),
                )
            })?;
        Ok(GetTaskResult::new(task_state_to_detailed_task(state)))
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let owner = self.task_owner(&context.meta);
        apply_task_update(&self.task_registry, &owner, &request.task_id)
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let owner = self.task_owner(&context.meta);
        let Some(state) = self.task_registry.get_for_owner(&owner, &request.task_id) else {
            return Err(McpError::invalid_params(
                "Unknown task_id",
                Some(json!({ "task_id": request.task_id })),
            ));
        };
        if state.status == task::TaskStatus::Running {
            self.task_registry
                .cancel_for_owner(&owner, &request.task_id);
        }
        Ok(())
    }
}

/// Wrapper that sanitizes tool schemas by removing `$schema` fields.
///
/// Some MCP clients (like Claude Desktop) choke on the JSON Schema `$schema` field.
/// This wrapper intercepts `list_tools` to remove these fields while delegating
/// all other methods to the inner server.
pub struct SanitizedIdaServer<S> {
    inner: S,
    filter: Arc<tool_filter::ToolFilter>,
}

impl<S> SanitizedIdaServer<S> {
    /// Wrap an inner server with no filtering. Convenience for paths
    /// that don't read CLI/env (e.g. tests).
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            filter: Arc::new(tool_filter::ToolFilter::unrestricted()),
        }
    }

    /// Wrap with an explicit filter (built from CLI/env at startup).
    pub fn with_filter(inner: S, filter: Arc<tool_filter::ToolFilter>) -> Self {
        Self { inner, filter }
    }
}

impl<S> std::ops::Deref for SanitizedIdaServer<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

fn tool_annotations_for(name: &str) -> ToolAnnotations {
    match name {
        "lumina_lookup" => ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(true),
        "lumina_apply" => ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .open_world(true),
        "run_script" => ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .open_world(true),
        "patch" | "patch_asm" => ToolAnnotations::new().read_only(false).destructive(true),
        "open_idb" | "open_dsc" | "dsc_add_dylib" | "dsc_add_region" | "close_idb"
        | "load_debug_info" | "declare_type" | "apply_types" | "declare_stack" | "delete_stack"
        | "rename" | "set_comments" => ToolAnnotations::new()
            .read_only(false)
            .destructive(name == "close_idb")
            .open_world(false),
        _ => ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    }
}

fn set_tool_metadata(tool: &mut Tool) {
    tool.annotations = Some(tool_annotations_for(&tool.name));
}

fn apply_tool_metadata(mut tool: Tool) -> Tool {
    set_tool_metadata(&mut tool);
    tool
}

fn is_null_schema(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|schema| schema.get("type"))
        .and_then(Value::as_str)
        == Some("null")
}

fn nullable_any_of_replacement(schema: &Map<String, Value>) -> Option<Map<String, Value>> {
    let any_of = schema.get("anyOf")?.as_array()?;
    let mut non_null = None;
    let mut null_count = 0usize;

    for branch in any_of {
        if is_null_schema(branch) {
            null_count += 1;
        } else if non_null.replace(branch).is_some() {
            return None;
        }
    }

    if null_count != 1 {
        return None;
    }

    let mut replacement = match non_null? {
        Value::Object(branch) => branch.clone(),
        Value::Bool(true) => Map::new(),
        _ => return None,
    };

    for (key, value) in schema {
        if key != "anyOf" {
            replacement.insert(key.clone(), value.clone());
        }
    }
    if replacement.get("default").is_some_and(Value::is_null) {
        replacement.remove("default");
    }

    Some(replacement)
}

fn nullable_type_array_replacement(schema: &Map<String, Value>) -> Option<Option<Value>> {
    let types = schema.get("type")?.as_array()?;
    let mut non_null_types = Vec::new();
    let mut saw_null = false;

    for value in types {
        if value.as_str() == Some("null") {
            saw_null = true;
        } else {
            non_null_types.push(value.clone());
        }
    }

    if !saw_null {
        return None;
    }

    Some(match non_null_types.len() {
        0 => None,
        1 => non_null_types.into_iter().next(),
        _ => Some(Value::Array(non_null_types)),
    })
}

/// Normalize a JSON Schema produced by schemars into a portable shape
/// that tool-calling bridges (OpenAPI-strict validators, function-call
/// translators) can consume without surprises:
///
/// - drops `$schema` (Claude Desktop and other clients choke on it);
/// - collapses `anyOf: [T, {type:"null"}]` (and the `[null, T]` order)
///   into `T`, lifting schemars' `Option<T>` shape into "field is
///   optional via `required` array, not via a null-typed branch";
/// - flattens `type: ["X", "null"]` to `type: "X"` for the same reason.
///
/// Existing schema keywords (`description`, `minimum`, `maximum`,
/// `format`) are preserved. This is general schema cleanup, not a
/// provider workaround — we keep the request structs portable at the
/// source (see `src/server/requests.rs`), and the normalizer only
/// removes shapes schemars emits that are poor for downstream bridges.
fn normalize_schema_value(value: &mut Value) {
    match value {
        Value::Object(schema) => {
            if let Some(replacement) = nullable_any_of_replacement(schema) {
                *schema = replacement;
            }
            schema.remove("$schema");

            if let Some(type_replacement) = nullable_type_array_replacement(schema) {
                match type_replacement {
                    Some(replacement) => {
                        schema.insert("type".to_string(), replacement);
                    }
                    None => {
                        schema.remove("type");
                    }
                }
            }

            for child in schema.values_mut() {
                normalize_schema_value(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize_schema_value(item);
            }
        }
        _ => {}
    }
}

fn normalize_tool_input_schema(tool: &mut Tool) {
    let schema_arc = &mut tool.input_schema;
    if let Some(map) = std::sync::Arc::get_mut(schema_arc) {
        let mut value = Value::Object(std::mem::take(map));
        normalize_schema_value(&mut value);
        if let Value::Object(sanitized) = value {
            *map = sanitized;
        }
    } else {
        let mut value = Value::Object((**schema_arc).clone());
        normalize_schema_value(&mut value);
        if let Value::Object(sanitized) = value {
            *schema_arc = std::sync::Arc::new(sanitized);
        }
    }
}

/// Normalize tool input schemas (see [`normalize_schema_value`]) and attach
/// safety annotations.
fn normalize_tool_schemas(result: &mut ListToolsResult) {
    for tool in &mut result.tools {
        normalize_tool_input_schema(tool);
        set_tool_metadata(tool);
    }
}

/// Error message for a filter-rejected tool/call. Centralized so the
/// dispatch and tool_help paths return identical wording.
fn disabled_tool_message(name: &str) -> String {
    format!(
        "tool '{name}' is disabled by current filter \
         (--toolsets/--tools/--exclude-tools/--read-only); \
         call tool_catalog to see enabled tools"
    )
}

impl<S: ServerHandler + Send + Sync> ServerHandler for SanitizedIdaServer<S> {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        self.inner.supported_protocol_versions()
    }

    // `discover` is intentionally NOT forwarded to the inner handler: the
    // trait default builds its result from `self.supported_protocol_versions()`
    // and `self.get_info()`, so leaving it unoverridden binds those calls to
    // this sanitizing wrapper instead of bypassing it.

    async fn initialize(
        &self,
        params: InitializeRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        self.inner.initialize(params, ctx).await
    }

    async fn list_tools(
        &self,
        params: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = self.inner.list_tools(params, ctx).await?;
        if self.filter.is_active() {
            result
                .tools
                .retain(|tool| self.filter.is_enabled(&tool.name));
        }
        normalize_tool_schemas(&mut result);
        Ok(result)
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if self.filter.is_active() && !self.filter.is_enabled(&params.name) {
            return Err(McpError::invalid_params(
                disabled_tool_message(&params.name),
                None,
            ));
        }
        self.inner.call_tool(params, ctx).await
    }

    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        if self.filter.is_active() && !self.filter.is_enabled(name) {
            return None;
        }
        self.inner.get_tool(name).map(|mut tool| {
            normalize_tool_input_schema(&mut tool);
            apply_tool_metadata(tool)
        })
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        self.inner.get_task(request, ctx).await
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.update_task(request, ctx).await
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.cancel_task(request, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::worker::{CloseTokenGrant, WorkerBackend};
    use crate::server::{
        apply_close_metadata, apply_task_update, call_tool_result_to_value, close_hint_for,
        dsc_open_plan, is_sessionless_request_meta, materialize_task_response,
        normalize_schema_value,
        operation::{OperationSnapshot, OperationStatus},
        run_script_failure_message, run_script_succeeded, run_script_timeout_message,
        run_script_truncate_chars, supported_protocol_versions, task, task_payload_result_value,
        task_state_to_detailed_task, task_state_to_mcp_task, timeout_with_child_grace,
        tool_params_schema, DscOpenPlan, IdaMcpServer, OpenIdbBackgroundDecision,
        RecentOperationsRequest, ServerRuntimeState, ToolCatalogRequest, ToolHelpRequest,
        XrefsRequest,
    };
    use rmcp::handler::server::wrapper::Parameters;
    use rmcp::model::{CallToolResponse, CallToolResult, InputResponses, ProtocolVersion};
    use rmcp::ServerHandler;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};

    const TASK_OWNER: task::TaskOwner = task::TaskOwner::Runtime;

    /// In-memory writer so a test can assert on exactly what the fmt layer
    /// would have written to stderr, span field prefixes included.
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLog {
        fn text(&self) -> String {
            let guard = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut guard = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `body` with a thread-local subscriber at `directives` and return
    /// everything it logged. `set_default` keeps this off the global
    /// dispatcher, so tests stay independent.
    async fn capture_logs<F, Fut>(directives: &str, body: F) -> String
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::Layer as _;

        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(captured.clone())
                .with_filter(tracing_subscriber::EnvFilter::new(directives)),
        );
        let _guard = tracing::subscriber::set_default(subscriber);
        body().await;
        captured.text()
    }

    fn test_server() -> IdaMcpServer {
        let (tx, _rx) = mpsc::sync_channel(1);
        IdaMcpServer::new(
            Arc::new(crate::IdaWorker::new(tx)),
            crate::ServerMode::Stdio,
        )
    }

    /// Sentinels chosen so a substring hit can only come from the payload we
    /// passed in, never from incidental log text.
    const SECRET_CLOSE_TOKEN: &str = "close-token-9d41f2c7";
    const SECRET_COMMENT: &str = "comment-secret-3a7f11de";
    const SECRET_RENAME: &str = "rename-secret-5c2b90aa";
    const SECRET_PATCH_BYTES: &str = "de ad be ef ca fe 41 42";

    /// Drive every unit-invocable handler that receives sensitive payloads.
    /// Each call fails fast (the test worker has no receiver), which is
    /// exactly the path that logs — spans render whenever an event fires
    /// inside them.
    async fn exercise_sensitive_handlers(server: &IdaMcpServer) {
        let _ = server
            .close_idb(Parameters(crate::server::CloseIdbRequest {
                token: Some(SECRET_CLOSE_TOKEN.to_string()),
                force: Some(false),
            }))
            .await;
        let _ = server
            .set_comments(Parameters(crate::server::SetCommentsRequest {
                address: Some(json!("0x1000")),
                target_name: None,
                offset: None,
                comment: SECRET_COMMENT.to_string(),
                repeatable: None,
            }))
            .await;
        let _ = server
            .rename(Parameters(crate::server::RenameRequest {
                address: Some(json!("0x1000")),
                current_name: None,
                name: SECRET_RENAME.to_string(),
                flags: None,
            }))
            .await;
        let _ = server
            .patch(Parameters(crate::server::PatchRequest {
                address: Some(json!("0x1000")),
                target_name: None,
                offset: None,
                bytes: json!(SECRET_PATCH_BYTES),
            }))
            .await;
    }

    fn assert_no_secrets(logs: &str, level: &str) {
        for (label, secret) in [
            ("close_idb ownership token", SECRET_CLOSE_TOKEN),
            ("set_comments payload", SECRET_COMMENT),
            ("rename payload", SECRET_RENAME),
            ("patch bytes", SECRET_PATCH_BYTES),
        ] {
            assert!(
                !logs.contains(secret),
                "{label} leaked into logs at {level}:\n{logs}"
            );
        }
        // The whole-struct render is the mechanism behind every leak; catching
        // it directly means a future handler cannot regress quietly.
        for struct_render in [
            "CloseIdbRequest {",
            "SetCommentsRequest {",
            "RenameRequest {",
            "PatchRequest {",
            "req=",
        ] {
            assert!(
                !logs.contains(struct_render),
                "a handler argument was recorded ({struct_render}) at {level}:\n{logs}"
            );
        }
    }

    /// The shipped default is `ida_mcp=info`, and `close_idb` logs at INFO
    /// unconditionally — so before this fix the ownership bearer token
    /// rendered on an out-of-the-box server, not just under trace logging.
    #[tokio::test]
    async fn spans_never_record_secret_payloads_at_the_shipped_level() {
        let server = test_server();
        let logs = capture_logs("ida_mcp=info", || async {
            exercise_sensitive_handlers(&server).await;
        })
        .await;

        // Positive control: prove the capture is wired and the level admits
        // output, so the absence assertions below cannot pass vacuously.
        assert!(
            logs.contains("Tool call: close_idb received"),
            "expected close_idb to log at ida_mcp=info; got:\n{logs}"
        );
        assert_no_secrets(&logs, "ida_mcp=info");
        assert!(
            logs.contains("has_token=true"),
            "expected the sanitized has_token field; got:\n{logs}"
        );
    }

    /// Strictly stronger than the shipped level, and the level `just test-*`
    /// recipes run at: nothing sensitive may appear even at trace.
    #[tokio::test]
    async fn spans_never_record_secret_payloads_at_trace() {
        let server = test_server();
        let logs = capture_logs("ida_mcp=trace", || async {
            exercise_sensitive_handlers(&server).await;
        })
        .await;

        assert!(
            logs.contains("Tool call: close_idb received"),
            "expected handler events at trace; got:\n{logs}"
        );
        assert_no_secrets(&logs, "ida_mcp=trace");
    }

    /// Reassemble every `#[instrument(...)]` attribute in a source file,
    /// joining continuation lines by paren balance.
    fn instrument_attributes(source: &str) -> Vec<String> {
        let mut attributes = Vec::new();
        let mut current: Option<(String, i32)> = None;
        for line in source.lines() {
            let trimmed = line.trim();
            let start = current.is_none() && trimmed.starts_with("#[instrument");
            if start || current.is_some() {
                let (mut text, mut depth) = current.take().unwrap_or_default();
                text.push_str(trimmed);
                depth += i32::try_from(trimmed.matches('(').count()).unwrap_or(0);
                depth -= i32::try_from(trimmed.matches(')').count()).unwrap_or(0);
                if depth <= 0 {
                    attributes.push(text);
                } else {
                    current = Some((text, depth));
                }
            }
        }
        attributes
    }

    /// `skip_all` is the only form that suppresses handler arguments:
    /// tracing-attributes records every parameter binding via `Debug`, and a
    /// `fields(...)` entry only suppresses a parameter whose ident exactly
    /// matches the field name — so `fields(path = %req.path)` still records
    /// the whole `req`. This is the only coverage for handlers that take a
    /// `RequestContext` (`open_idb`, `run_script`) since `Peer`'s constructor
    /// is `pub(crate)` and they cannot be invoked from a unit test.
    #[test]
    fn instrument_attributes_never_capture_handler_arguments() {
        for (path, source) in [
            ("src/server/mod.rs", include_str!("mod.rs")),
            ("src/server/task.rs", include_str!("task.rs")),
            ("src/server/http_config.rs", include_str!("http_config.rs")),
        ] {
            let attributes = instrument_attributes(source);
            for attribute in &attributes {
                assert!(
                    attribute.contains("skip_all"),
                    "{path}: `{attribute}` must use skip_all; \
                     skip(self) still records every request argument"
                );
            }
            if path == "src/server/mod.rs" {
                assert!(
                    attributes.len() >= 50,
                    "expected the full handler set in {path}, found {}",
                    attributes.len()
                );
            }
        }
    }

    /// The two handlers that cannot be exercised at runtime must expose only
    /// derived facts, never the sensitive binding itself.
    #[test]
    fn uninvokable_handlers_record_only_derived_fields() {
        let attributes = instrument_attributes(include_str!("mod.rs"));

        let open_idb = attributes
            .iter()
            .find(|attribute| attribute.contains("mrtr_retry"))
            .expect("open_idb should record whether this is an MRTR retry");
        // A bool derived from the sealed state, never the replayable handle
        // or the raw elicitation answers.
        assert!(open_idb.contains("request_state.is_some()"), "{open_idb}");
        assert!(!open_idb.contains("%request_state"), "{open_idb}");
        assert!(!open_idb.contains("?request_state"), "{open_idb}");
        assert!(!open_idb.contains("input_responses"), "{open_idb}");

        let run_script = attributes
            .iter()
            .find(|attribute| attribute.contains("code_len"))
            .expect("run_script should record only the source length");
        assert!(!run_script.contains("%req.code"), "{run_script}");
        assert!(!run_script.contains("?req.code"), "{run_script}");
    }

    #[test]
    fn tracing_never_records_task_bearer_ids() {
        let bearer_field = ["task", "id"].join("_");
        for (path, source) in [
            ("src/server/mod.rs", include_str!("mod.rs")),
            ("src/server/task.rs", include_str!("task.rs")),
        ] {
            for formatter in ['%', '?'] {
                let forbidden = format!("{bearer_field} = {formatter}");
                assert!(
                    !source.contains(&forbidden),
                    "{path}: task bearer IDs must not be recorded by tracing: found `{forbidden}`"
                );
            }
            for level in ["trace", "debug", "info", "warn", "error"] {
                let forbidden = format!("{level}!({bearer_field}");
                assert!(
                    !source.contains(&forbidden),
                    "{path}: task bearer IDs must not be recorded by tracing: found `{forbidden}`"
                );
            }

            for attribute in instrument_attributes(source) {
                assert!(
                    !attribute.contains(&bearer_field),
                    "{path}: task bearer IDs must not be recorded by instrumentation: `{attribute}`"
                );
            }
        }
    }

    fn xrefs_request(limit: Option<i64>, offset: Option<i64>) -> XrefsRequest {
        XrefsRequest {
            address: json!("0x1000"),
            limit,
            offset,
            timeout_secs: None,
        }
    }

    #[test]
    fn xrefs_paging_clamps_zero_limit_to_one() {
        // limit 0 would yield an empty-but-truncated page whose next_offset never
        // advances; the parser must clamp it so pagination always progresses.
        let (offset, limit, _) =
            IdaMcpServer::parse_xrefs_paging(&xrefs_request(Some(0), None)).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn xrefs_paging_applies_default_and_upper_bound() {
        let (_, default_limit, _) =
            IdaMcpServer::parse_xrefs_paging(&xrefs_request(None, Some(7))).unwrap();
        assert_eq!(default_limit, IdaMcpServer::DEFAULT_XREFS_LIMIT);

        let (offset, capped_limit, _) =
            IdaMcpServer::parse_xrefs_paging(&xrefs_request(Some(999_999), Some(7))).unwrap();
        assert_eq!(offset, 7);
        assert_eq!(capped_limit, IdaMcpServer::MAX_XREFS_LIMIT);
    }

    #[test]
    fn xrefs_paging_rejects_negative_values() {
        assert!(IdaMcpServer::parse_xrefs_paging(&xrefs_request(Some(-1), None)).is_err());
        assert!(IdaMcpServer::parse_xrefs_paging(&xrefs_request(None, Some(-1))).is_err());
    }

    #[test]
    fn dsc_open_plan_backgrounds_ida_94_raw_dsc() {
        assert_eq!(
            dsc_open_plan((9, 4), false),
            DscOpenPlan::BackgroundDirectRawDsc
        );
        assert_eq!(
            dsc_open_plan((10, 0), false),
            DscOpenPlan::BackgroundDirectRawDsc
        );
    }

    #[test]
    fn dsc_open_plan_keeps_legacy_idat_for_pre_94_raw_dsc() {
        assert_eq!(
            dsc_open_plan((9, 3), false),
            DscOpenPlan::LegacyIdatBackground
        );
        assert_eq!(
            dsc_open_plan((8, 4), false),
            DscOpenPlan::LegacyIdatBackground
        );
    }

    /// An existing database wins on every SDK: it preserves prior analysis
    /// and, on 9.4, prevents the direct path from minting a fresh multi-GB
    /// database per open_dsc call.
    #[test]
    fn dsc_open_plan_prefers_existing_i64_on_every_sdk() {
        assert_eq!(dsc_open_plan((9, 3), true), DscOpenPlan::DirectExistingI64);
        assert_eq!(dsc_open_plan((9, 4), true), DscOpenPlan::DirectExistingI64);
        assert_eq!(dsc_open_plan((10, 0), true), DscOpenPlan::DirectExistingI64);
    }

    /// The direct-path database name must depend only on the DSC's absolute
    /// path — never pid or time — so repeat opens resolve to one reusable
    /// file instead of accumulating orphans.
    #[test]
    fn direct_dsc_cache_path_is_deterministic_per_dsc() {
        let dsc = std::path::Path::new("/nonexistent/A/dyld_shared_cache_arm64e");
        let first = crate::server::direct_dsc_cache_i64_path(dsc);
        let second = crate::server::direct_dsc_cache_i64_path(dsc);
        let other = crate::server::direct_dsc_cache_i64_path(std::path::Path::new(
            "/nonexistent/B/dyld_shared_cache_arm64e",
        ));

        assert_eq!(first, second);
        assert_ne!(first, other, "different DSC paths must not collide");
        let name = first
            .file_name()
            .and_then(|name| name.to_str())
            .expect("cache path should have a printable file name");
        assert!(name.starts_with("ida-mcp-dsc-dyld_shared_cache_arm64e-"));
        assert!(name.ends_with(".i64"));
    }

    fn tool_result_text(result: CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(|content| content.as_text())
            .map(|text| text.text.to_string())
            .unwrap_or_default()
    }

    fn contains_nullable_any_of(value: &Value) -> bool {
        match value {
            Value::Object(map) => {
                map.get("anyOf")
                    .and_then(Value::as_array)
                    .is_some_and(|branches| {
                        branches.iter().any(|branch| {
                            branch
                                .as_object()
                                .and_then(|schema| schema.get("type"))
                                .and_then(Value::as_str)
                                == Some("null")
                        })
                    })
                    || map.values().any(contains_nullable_any_of)
            }
            Value::Array(items) => items.iter().any(contains_nullable_any_of),
            _ => false,
        }
    }

    fn contains_schema_key(value: &Value) -> bool {
        match value {
            Value::Object(map) => {
                map.contains_key("$schema") || map.values().any(contains_schema_key)
            }
            Value::Array(items) => items.iter().any(contains_schema_key),
            _ => false,
        }
    }

    fn contains_unsigned_format(value: &Value) -> bool {
        match value {
            Value::Object(map) => {
                let format_is_unsigned = map
                    .get("format")
                    .and_then(Value::as_str)
                    .is_some_and(|f| f.starts_with("uint") || f == "uint");
                format_is_unsigned || map.values().any(contains_unsigned_format)
            }
            Value::Array(items) => items.iter().any(contains_unsigned_format),
            _ => false,
        }
    }

    #[test]
    fn run_script_succeeded_only_for_explicit_true() {
        assert!(run_script_succeeded(&json!({ "success": true })));
        assert!(!run_script_succeeded(&json!({ "success": false })));
        assert!(!run_script_succeeded(&json!({})));
    }

    #[test]
    fn run_script_failure_message_adds_syntax_hint() {
        let value = json!({
            "success": false,
            "stdout": "",
            "stderr": "Traceback (most recent call last):\n  File \"<string>\", line 1\nSyntaxError: invalid syntax",
            "error": "invalid syntax"
        });
        let message = run_script_failure_message(&value);
        assert!(message.contains("IDAPython script execution failed"));
        assert!(message.contains("SyntaxError"));
        assert!(message.contains("Hint: Python syntax error detected"));
    }

    #[test]
    fn pooled_foreground_timeout_gets_child_grace() {
        assert_eq!(timeout_with_child_grace(None, 300), 310);
        assert_eq!(timeout_with_child_grace(Some(120), 300), 130);
        assert_eq!(timeout_with_child_grace(Some(9999), 300), 610);
    }

    #[test]
    fn run_script_timeout_message_includes_preview() {
        let code = "import idaapi\nfor _ in range(1000000000):\n    pass\n";
        let message = run_script_timeout_message(120, code);
        assert!(message.contains("run_script timed out after 120 seconds"));
        assert!(message.contains("Script preview: import idaapi for _ in range(1000000000): pass"));
    }

    #[test]
    fn operation_timeout_message_includes_phase_snapshot() {
        let snapshot = OperationSnapshot {
            op_id: "fg-1".to_string(),
            tool: "open_idb".to_string(),
            target_summary: "/tmp/sample.i64".to_string(),
            phase: "opening".to_string(),
            status: OperationStatus::TimedOut,
            message: "open_idb timed out".to_string(),
            started_at_ms: 1,
            last_update_ms: 2,
            elapsed_ms: 3456,
        };
        let message = IdaMcpServer::operation_timeout_message(
            "open_idb",
            300,
            &snapshot,
            Some("detail".to_string()),
        );
        assert!(message.contains("Last known phase: opening"));
        assert!(message.contains("Operation id: fg-1"));
        assert!(message.contains("detail"));
    }

    #[tokio::test]
    async fn foreground_cancel_cleanup_polls_cancelled_future() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let observed = Arc::new(AtomicBool::new(false));
        let observed_for_future = observed.clone();
        let future = async move {
            cancel.cancelled().await;
            observed_for_future.store(true, Ordering::SeqCst);
            Err::<(), ToolError>(ToolError::Cancelled("cancelled".to_string()))
        };
        tokio::pin!(future);

        IdaMcpServer::finish_cancelled_foreground("test_tool", future.as_mut()).await;

        assert!(observed.load(Ordering::SeqCst));
    }

    #[test]
    fn input_size_above_threshold_is_strictly_greater_than_threshold() {
        let threshold = crate::server::OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES;
        let exact_path =
            create_sparse_test_file("exact-threshold", threshold).expect("create exact file");
        let above_path =
            create_sparse_test_file("above-threshold", threshold + 1).expect("create above file");

        assert_eq!(
            IdaMcpServer::input_size_above_threshold(
                exact_path.to_str().expect("exact path should be UTF-8")
            ),
            None
        );

        let above_path_text = above_path.to_str().expect("above path should be UTF-8");
        assert_eq!(
            IdaMcpServer::input_size_above_threshold(&format!(" {above_path_text} ")),
            Some(threshold + 1)
        );

        let _ = std::fs::remove_file(exact_path);
        let _ = std::fs::remove_file(above_path);
    }

    #[test]
    fn is_database_path_matches_existing_ida_database_extensions() {
        assert!(IdaMcpServer::is_database_path(" /tmp/sample.I64 "));
        assert!(IdaMcpServer::is_database_path("/tmp/sample.idb"));
        assert!(IdaMcpServer::is_database_path("/tmp/sample.id0"));
        assert!(!IdaMcpServer::is_database_path("/tmp/sample.macho"));
        assert!(!IdaMcpServer::is_database_path("/tmp/sample"));
    }

    #[test]
    fn open_idb_elicitation_timeout_is_bounded_by_prompt_and_request_timeouts() {
        assert_eq!(
            IdaMcpServer::open_idb_elicitation_timeout_secs(None),
            crate::server::OPEN_IDB_ELICITATION_TIMEOUT_SECS
        );
        assert_eq!(
            IdaMcpServer::open_idb_elicitation_timeout_secs(Some(10)),
            10
        );
        assert_eq!(
            IdaMcpServer::open_idb_elicitation_timeout_secs(Some(600)),
            crate::server::OPEN_IDB_ELICITATION_TIMEOUT_SECS
        );
    }

    #[test]
    fn normalizer_collapses_nullable_any_of_and_preserves_constraints() {
        let mut schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "timeout_secs": {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "description": "Timeout in seconds",
                    "anyOf": [
                        { "type": "integer", "format": "int64", "minimum": 0, "maximum": 600 },
                        { "type": "null" }
                    ],
                    "default": null
                },
                "query": {
                    "type": ["string", "null"],
                    "description": "Optional query"
                }
            }
        });

        normalize_schema_value(&mut schema);

        assert!(!contains_schema_key(&schema));
        assert!(!contains_nullable_any_of(&schema));

        let timeout = schema
            .pointer("/properties/timeout_secs")
            .and_then(Value::as_object)
            .expect("timeout_secs schema");
        assert_eq!(timeout.get("type"), Some(&json!("integer")));
        // Standard JSON Schema keywords (`description`, `minimum`,
        // `maximum`, `format: int32/int64`) are preserved by the normalizer.
        assert_eq!(timeout.get("format"), Some(&json!("int64")));
        assert_eq!(timeout.get("minimum"), Some(&json!(0)));
        assert_eq!(timeout.get("maximum"), Some(&json!(600)));
        assert_eq!(
            timeout.get("description"),
            Some(&json!("Timeout in seconds"))
        );
        assert!(!timeout.contains_key("anyOf"));
        assert!(!timeout.contains_key("default"));

        let query = schema
            .pointer("/properties/query")
            .and_then(Value::as_object)
            .expect("query schema");
        assert_eq!(query.get("type"), Some(&json!("string")));
    }

    #[test]
    fn generated_tool_param_schemas_are_portable() {
        // Every registered tool's `parameters` schema must be portable across
        // strict JSON-schema-subset consumers (notably Vertex/Gemini): no
        // `$schema` key, no nullable-anyOf shape, and no `uint*` formats
        // emitted by schemars from unsigned Rust integer types — those would
        // be rejected by OpenAPI-3-flavored validators.
        for tool in crate::tool_registry::all_tools() {
            let Some(schema) = tool_params_schema(tool.name) else {
                continue;
            };
            assert!(
                !contains_schema_key(&schema),
                "{} parameters still contain $schema",
                tool.name
            );
            assert!(
                !contains_nullable_any_of(&schema),
                "{} parameters still contain nullable anyOf",
                tool.name
            );
            assert!(
                !contains_unsigned_format(&schema),
                "{} parameters still contain a uint* format — convert the field to i64 + #[schemars(range(...))]",
                tool.name
            );
        }
    }

    #[test]
    fn normalizer_preserves_standard_formats() {
        // The normalizer is intentionally conservative on formats: it
        // does not strip anything. Wire-side cleanup (no uint*) is done
        // at the source in src/server/requests.rs, not here.
        let mut schema = json!({ "type": "integer", "format": "int64", "minimum": 0 });
        normalize_schema_value(&mut schema);
        assert_eq!(schema.get("format"), Some(&json!("int64")));

        let mut schema = json!({ "type": "string", "format": "date-time" });
        normalize_schema_value(&mut schema);
        assert_eq!(schema.get("format"), Some(&json!("date-time")));

        let mut schema = json!({ "type": "number", "format": "double" });
        normalize_schema_value(&mut schema);
        assert_eq!(schema.get("format"), Some(&json!("double")));
    }

    #[tokio::test]
    async fn recent_operations_tool_reports_queued_active_operation() {
        let server = test_server();
        server.operation_registry.start(
            "fg-test".to_string(),
            "open_idb",
            "/tmp/sample.i64".to_string(),
        );

        let result = server
            .recent_operations(Parameters(RecentOperationsRequest { limit: Some(5) }))
            .await
            .expect("recent_operations call should succeed");
        let value: serde_json::Value =
            serde_json::from_str(&tool_result_text(result)).expect("recent_operations JSON");

        assert_eq!(value["active_operation"]["op_id"], "fg-test");
        assert_eq!(value["active_operation"]["phase"], "queued");
        assert_eq!(value["recent_events"][0]["tool"], "open_idb");
    }

    #[tokio::test]
    async fn tool_help_and_catalog_include_recent_operations() {
        let server = test_server();

        let help_result = server
            .tool_help(Parameters(ToolHelpRequest {
                name: "recent_operations".to_string(),
            }))
            .await
            .expect("tool_help should succeed");
        let help_value: serde_json::Value =
            serde_json::from_str(&tool_result_text(help_result)).expect("tool_help JSON");
        assert_eq!(help_value["name"], "recent_operations");
        assert!(help_value["parameters"].get("properties").is_some());
        assert!(help_value["parameters"]["properties"]
            .get("limit")
            .is_some());

        let catalog_result = server
            .tool_catalog(Parameters(ToolCatalogRequest {
                query: Some("recent operation history".to_string()),
                category: None,
                limit: Some(5),
            }))
            .await
            .expect("tool_catalog should succeed");
        let catalog_value: serde_json::Value =
            serde_json::from_str(&tool_result_text(catalog_result)).expect("tool_catalog JSON");
        let tools = catalog_value["tools"]
            .as_array()
            .expect("tool_catalog tools array");
        assert!(tools
            .iter()
            .any(|tool| tool.get("name") == Some(&json!("recent_operations"))));
    }

    #[test]
    fn run_script_truncate_chars_appends_ellipsis() {
        let truncated = run_script_truncate_chars("abcdef", 3);
        assert_eq!(truncated, "abc...");
        let unchanged = run_script_truncate_chars("abc", 10);
        assert_eq!(unchanged, "abc");
    }

    #[test]
    fn task_payload_preserves_valid_call_tool_result() {
        let result = CallToolResult::success(vec![rmcp::model::ContentBlock::text("ok")]);
        let as_value = serde_json::to_value(&result).expect("serialize CallToolResult");
        assert_eq!(task_payload_result_value(Some(as_value.clone())), as_value);
    }

    #[test]
    fn task_payload_wraps_content_array_shape_that_is_not_call_tool_result() {
        let input = json!({ "content": [1, 2, 3] });
        let wrapped = task_payload_result_value(Some(input.clone()));
        assert_ne!(wrapped, input);

        let parsed: CallToolResult =
            serde_json::from_value(wrapped).expect("wrapped payload should be CallToolResult");
        assert_eq!(parsed.is_error, Some(false));
        let wrapped_text = parsed
            .content
            .first()
            .and_then(|c| c.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or_default();
        assert!(wrapped_text.contains("\"content\""));
    }

    #[test]
    fn modern_protocol_is_excluded_from_pooled_workers() {
        let local = supported_protocol_versions(false);
        assert!(local.contains(&ProtocolVersion::V_2026_07_28));

        let pooled = supported_protocol_versions(true);
        assert!(!pooled.contains(&ProtocolVersion::V_2026_07_28));
        assert!(pooled.contains(&ProtocolVersion::V_2025_11_25));
    }

    #[test]
    fn server_advertises_tasks_extension() {
        assert!(ServerHandler::get_info(&test_server())
            .capabilities
            .supports_tasks());
    }

    #[test]
    fn task_seed_uses_retention_ttl_and_poll_interval() {
        let registry = crate::server::task::TaskRegistry::new();
        let id = registry
            .create_keyed(&TASK_OWNER, "test", "seed", "Working")
            .expect("create task");
        let state = registry.get(&id).expect("task state");
        let value = serde_json::to_value(task_state_to_mcp_task(&state)).expect("serialize task");

        assert_eq!(value["status"], "working");
        assert_eq!(value["ttlMs"], task::TASK_RETENTION_TTL_MS);
        assert_eq!(value["pollIntervalMs"], 5000);
    }

    #[test]
    fn completed_task_inlines_original_tool_result() {
        let registry = crate::server::task::TaskRegistry::new();
        let tool_result = CallToolResult::success(vec![rmcp::model::ContentBlock::text("done")]);
        let payload = serde_json::to_value(tool_result).expect("serialize tool result");
        let id = registry
            .create_completed(&TASK_OWNER, "Completed", payload)
            .expect("create completed task");
        let state = registry.get(&id).expect("task state");
        let value =
            serde_json::to_value(task_state_to_detailed_task(state)).expect("serialize task");

        assert_eq!(value["status"], "completed");
        assert_eq!(value["result"]["content"][0]["text"], "done");
        assert_eq!(value["result"]["isError"], false);
    }

    #[test]
    fn tool_error_is_a_completed_task_result_not_a_json_rpc_failure() {
        let registry = crate::server::task::TaskRegistry::new();
        let id = registry
            .create_keyed(&TASK_OWNER, "dsc", "tool-error", "Opening DSC")
            .expect("create task");
        let error_result =
            ToolError::OpenFailed("idat exited with code 4".to_string()).to_tool_result();
        registry.complete(&id, call_tool_result_to_value(&error_result));

        let state = registry.get(&id).expect("task state");
        let value =
            serde_json::to_value(task_state_to_detailed_task(state)).expect("serialize task");

        assert_eq!(value["status"], "completed");
        assert_eq!(value["result"]["isError"], true);
        assert!(value["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("idat exited with code 4")));
        assert!(value.get("error").is_none());
    }

    #[test]
    fn open_dsc_background_result_materializes_tasks_extension_handle() {
        let registry = crate::server::task::TaskRegistry::new();
        let task_id = registry
            .create_keyed(&TASK_OWNER, "dsc", "/tmp/cache", "Opening DSC")
            .expect("create task");
        let result = CallToolResult::success(vec![rmcp::model::ContentBlock::text(
            serde_json::to_string(&json!({"task_id": task_id})).expect("serialize result"),
        )]);
        let response =
            materialize_task_response(&registry, true, CallToolResponse::Complete(result))
                .expect("materialize task");

        let CallToolResponse::Task(created) = response else {
            panic!("task-capable open_dsc call must return a task handle");
        };
        assert_eq!(created.task.task_id, task_id);
        assert_eq!(created.task.status, rmcp::model::TaskStatus::Working);
        assert_eq!(created.task.poll_interval_ms, Some(5000));
        assert_eq!(created.task.ttl_ms, Some(task::TASK_RETENTION_TTL_MS));
    }

    #[test]
    fn update_task_acknowledges_known_tasks_and_rejects_unknown() {
        let registry = crate::server::task::TaskRegistry::new();
        let id = registry
            .create_keyed(&TASK_OWNER, "dsc", "update-task", "Working")
            .expect("create task");

        // SEP-2663: responses delivered to a known task are ignored with an
        // empty result, never an error — including after a raced transition
        // to a terminal state.
        assert!(apply_task_update(&registry, &TASK_OWNER, &id).is_ok());
        registry.complete(&id, json!({"ok": true}));
        assert!(apply_task_update(&registry, &TASK_OWNER, &id).is_ok());

        let other_owner = task::TaskOwner::Session(Arc::from("other-session"));
        let err = apply_task_update(&registry, &other_owner, &id)
            .expect_err("another owner must not update the task");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);

        let err = apply_task_update(&registry, &TASK_OWNER, "missing-1")
            .expect_err("unknown task must error");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn failed_task_inlines_json_rpc_error() {
        let registry = crate::server::task::TaskRegistry::new();
        let id = registry
            .create_keyed(&TASK_OWNER, "test", "failed", "Working")
            .expect("create task");
        registry.fail(&id, "IDA worker exited");
        let state = registry.get(&id).expect("task state");
        let value =
            serde_json::to_value(task_state_to_detailed_task(state)).expect("serialize task");

        assert_eq!(value["status"], "failed");
        assert_eq!(value["error"]["code"], -32603);
        assert_eq!(value["error"]["message"], "IDA worker exited");
    }

    #[test]
    fn runtime_state_survives_handler_recreation() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let backend = WorkerBackend::local(Arc::new(crate::IdaWorker::new(tx)));
        let filter = Arc::new(crate::server::tool_filter::ToolFilter::unrestricted());
        let runtime = ServerRuntimeState::new();
        let first = IdaMcpServer::with_filter_and_state(
            backend.clone(),
            crate::ServerMode::Http,
            filter.clone(),
            runtime.clone(),
        );
        let second =
            IdaMcpServer::with_filter_and_state(backend, crate::ServerMode::Http, filter, runtime);
        let id = first
            .task_registry
            .create_completed(&first.session_task_owner, "Completed", json!({"ok": true}))
            .expect("create completed task");

        assert!(second.task_registry.get(&id).is_some());
        assert!(Arc::ptr_eq(
            &first.runtime_lifetime,
            &second.runtime_lifetime
        ));
        // Each handler owns its own session lifetime so that dropping a legacy
        // session's handler cancels only that session's background tasks.
        assert!(!Arc::ptr_eq(
            &first.session_lifetime,
            &second.session_lifetime
        ));
    }

    #[test]
    fn shared_runtime_keeps_legacy_task_ownership_session_scoped() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let backend = WorkerBackend::local(Arc::new(crate::IdaWorker::new(tx)));
        let filter = Arc::new(crate::server::tool_filter::ToolFilter::unrestricted());
        let runtime = ServerRuntimeState::new();
        let first = IdaMcpServer::with_filter_and_state(
            backend.clone(),
            crate::ServerMode::Http,
            filter.clone(),
            runtime.clone(),
        );
        let second =
            IdaMcpServer::with_filter_and_state(backend, crate::ServerMode::Http, filter, runtime);

        let task_id = first
            .task_registry
            .create_keyed(
                &first.session_task_owner,
                "dsc",
                "/tmp/shared-cache",
                "Opening DSC",
            )
            .expect("first session should create the task");
        assert_eq!(
            second.task_registry.create_keyed(
                &second.session_task_owner,
                "dsc",
                "/tmp/shared-cache",
                "Opening DSC",
            ),
            Err(task::TaskCreateError::ExistingTaskIdIsPrivate)
        );
        assert!(
            second
                .task_registry
                .get_for_owner(&second.session_task_owner, &task_id)
                .is_none(),
            "another legacy session must not poll the task"
        );
        assert!(!second
            .task_registry
            .cancel_for_owner(&second.session_task_owner, &task_id));
        assert!(first
            .task_registry
            .get_for_owner(&first.session_task_owner, &task_id)
            .is_some());
    }

    #[test]
    fn handler_drop_cancels_session_background_tasks_only() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let backend = WorkerBackend::local(Arc::new(crate::IdaWorker::new(tx)));
        let filter = Arc::new(crate::server::tool_filter::ToolFilter::unrestricted());
        let runtime = ServerRuntimeState::new();
        let server = IdaMcpServer::with_filter_and_state(
            backend,
            crate::ServerMode::Http,
            filter,
            runtime.clone(),
        );

        let legacy_meta = rmcp::model::RequestMetaObject::new();
        let mut sessionless_meta = rmcp::model::RequestMetaObject::new();
        sessionless_meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
        sessionless_meta.set_client_capabilities(rmcp::model::ClientCapabilities::default());

        let session_token = server.background_lifetime(&legacy_meta).child_token();
        let runtime_token = server.background_lifetime(&sessionless_meta).child_token();
        drop(server);

        // Legacy session close (= handler drop) cancels the session's tasks...
        assert!(session_token.is_cancelled());
        // ...but sessionless MCP 2026 tasks outlive their per-request handler.
        assert!(!runtime_token.is_cancelled());

        drop(runtime);
        assert!(runtime_token.is_cancelled());
    }

    /// Under `--stateless`, rmcp drops the handler after every request even
    /// for legacy protocol versions, so legacy requests must also use the
    /// shared runtime owner and lifetime — otherwise their background tasks
    /// would be cancelled on response and owned by an unreachable session ID.
    #[test]
    fn stateless_http_routes_legacy_requests_to_the_runtime_owner() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let backend = WorkerBackend::local(Arc::new(crate::IdaWorker::new(tx)));
        let filter = Arc::new(crate::server::tool_filter::ToolFilter::unrestricted());
        let runtime = ServerRuntimeState::new_stateless_http();
        let server = IdaMcpServer::with_filter_and_state(
            backend,
            crate::ServerMode::Http,
            filter,
            runtime.clone(),
        );

        let legacy_meta = rmcp::model::RequestMetaObject::new();
        assert_eq!(server.task_owner(&legacy_meta), task::TaskOwner::Runtime);
        let background_token = server.background_lifetime(&legacy_meta).child_token();
        drop(server);
        assert!(
            !background_token.is_cancelled(),
            "stateless-mode tasks must outlive their per-request handler"
        );

        drop(runtime);
        assert!(background_token.is_cancelled());
    }

    #[test]
    fn sessionless_meta_predicate_requires_complete_2026_key_set() {
        let mut meta = rmcp::model::RequestMetaObject::new();
        assert!(!is_sessionless_request_meta(&meta));

        meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
        assert!(!is_sessionless_request_meta(&meta));

        meta.set_client_capabilities(rmcp::model::ClientCapabilities::default());
        assert!(is_sessionless_request_meta(&meta));

        // rmcp routes on key completeness, not the declared version: a legacy
        // version with the full key set still dispatches sessionless.
        let mut legacy_declared = rmcp::model::RequestMetaObject::new();
        legacy_declared.set_protocol_version(ProtocolVersion::V_2025_11_25);
        legacy_declared.set_client_capabilities(rmcp::model::ClientCapabilities::default());
        assert!(is_sessionless_request_meta(&legacy_declared));
    }

    #[test]
    fn legacy_stdio_task_owner_stays_stable_when_request_metadata_changes() {
        let server = test_server();
        let mut full_meta = rmcp::model::RequestMetaObject::new();
        full_meta.set_protocol_version(ProtocolVersion::V_2025_11_25);
        full_meta.set_client_capabilities(rmcp::model::ClientCapabilities::default());
        let empty_meta = rmcp::model::RequestMetaObject::new();

        let task_id = server
            .task_registry
            .create_keyed(
                &server.task_owner(&full_meta),
                "analyze",
                "stdio-owner-regression",
                "Working",
            )
            .expect("full-metadata request should create a task");

        assert!(
            server
                .task_registry
                .get_for_owner(&server.task_owner(&empty_meta), &task_id)
                .is_some(),
            "later requests on the same stdio connection must retain ownership"
        );
        assert!(std::ptr::eq(
            server.background_lifetime(&full_meta),
            server.background_lifetime(&empty_meta)
        ));
    }

    #[test]
    fn modern_open_idb_mrtr_is_bound_and_integrity_checked() {
        let server = test_server();
        let path = "/tmp/large-macho";
        let size = crate::server::OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES + 1;
        let first = server
            .modern_open_idb_background_decision(path, size, None, None)
            .expect("first MRTR round");
        let OpenIdbBackgroundDecision::InputRequired(input_required) = first else {
            panic!("first round must request input");
        };
        let request_state = input_required.request_state.expect("request state");
        let requests = input_required.input_requests.expect("input requests");
        let request = requests.get("background").expect("background request");
        let request_value = serde_json::to_value(request).expect("serialize request");
        assert_eq!(
            request_value["params"]["requestedSchema"]["properties"]["background"]["type"],
            "boolean"
        );

        let mut responses = InputResponses::new();
        responses.insert(
            "background".to_string(),
            json!({"action": "accept", "content": {"background": true}}),
        );
        let retry = server
            .modern_open_idb_background_decision(
                path,
                size,
                Some(request_state.clone()),
                Some(responses),
            )
            .expect("valid retry");
        assert!(matches!(retry, OpenIdbBackgroundDecision::Ready(true)));

        assert!(server
            .modern_open_idb_background_decision(
                "/tmp/different-macho",
                size,
                Some(request_state.clone()),
                Some(InputResponses::new()),
            )
            .is_err());
        assert!(server
            .modern_open_idb_background_decision(
                path,
                size,
                Some(format!("{request_state}tampered")),
                Some(InputResponses::new()),
            )
            .is_err());
    }

    #[test]
    fn modern_open_idb_mrtr_decline_keeps_foreground_behavior() {
        let server = test_server();
        let path = "/tmp/large-macho";
        let size = crate::server::OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES + 1;
        let first = server
            .modern_open_idb_background_decision(path, size, None, None)
            .expect("first MRTR round");
        let OpenIdbBackgroundDecision::InputRequired(input_required) = first else {
            panic!("first round must request input");
        };
        let mut responses = InputResponses::new();
        responses.insert("background".to_string(), json!({"action": "decline"}));
        let retry = server
            .modern_open_idb_background_decision(
                path,
                size,
                input_required.request_state,
                Some(responses),
            )
            .expect("valid decline");

        assert!(matches!(retry, OpenIdbBackgroundDecision::Ready(false)));
    }

    /// A killed idat leaves partial artifacts that `dsc_open_plan` would
    /// otherwise reuse; cancellation cleanup must remove exactly those.
    #[test]
    fn remove_partial_idat_outputs_deletes_packed_and_unpacked_artifacts() {
        let dir = std::env::temp_dir().join(format!("ida-mcp-partial-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let out_i64 = dir.join("cache.i64");
        let unpacked = dir.join("cache.id0");
        let unrelated = dir.join("keep.txt");
        std::fs::write(&out_i64, b"partial").expect("write i64");
        std::fs::write(&unpacked, b"partial").expect("write id0");
        std::fs::write(&unrelated, b"keep").expect("write unrelated");

        crate::server::remove_partial_idat_outputs(&out_i64);

        assert!(!out_i64.exists(), "packed database must be removed");
        assert!(!unpacked.exists(), "unpacked component must be removed");
        assert!(unrelated.exists(), "unrelated files must be untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn create_sparse_test_file(name: &str, len: u64) -> std::io::Result<std::path::PathBuf> {
        let path = std::env::temp_dir().join(format!("ida-mcp-{name}-{}", uuid::Uuid::new_v4()));
        let file = std::fs::File::create(&path)?;
        file.set_len(len)?;
        Ok(path)
    }

    fn metadata_map(
        grant: Option<Result<CloseTokenGrant, String>>,
    ) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        apply_close_metadata(
            &mut map,
            grant,
            close_hint_for(crate::ServerMode::Http, false),
        );
        map
    }

    #[test]
    fn close_metadata_grant_emits_token_owner_and_hint() {
        let map = metadata_map(Some(Ok(CloseTokenGrant {
            token: "tok-1".into(),
            reused: false,
            owner_session_id: "session-a".into(),
        })));
        assert_eq!(
            map.get("close_token").and_then(Value::as_str),
            Some("tok-1")
        );
        assert_eq!(
            map.get("close_owner_session_id").and_then(Value::as_str),
            Some("session-a")
        );
        assert!(map.contains_key("close_hint"));
        assert!(!map.contains_key("close_token_reused"));
        assert!(!map.contains_key("close_recovery_hint"));
    }

    #[test]
    fn close_metadata_marks_reused_grant() {
        let map = metadata_map(Some(Ok(CloseTokenGrant {
            token: "tok-2".into(),
            reused: true,
            owner_session_id: "session-a".into(),
        })));
        assert_eq!(
            map.get("close_token_reused").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn close_metadata_denial_emits_owner_recovery_hint_and_no_token() {
        let map = metadata_map(Some(Err("session-original".into())));
        assert!(!map.contains_key("close_token"));
        assert_eq!(
            map.get("close_owner_session_id").and_then(Value::as_str),
            Some("session-original")
        );
        let recovery = map
            .get("close_recovery_hint")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(recovery.contains("force=true"));
        let hint = map
            .get("close_hint")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(hint.contains("session-original"));
    }

    #[test]
    fn close_metadata_none_emits_only_hint() {
        let map = metadata_map(None);
        assert!(map.contains_key("close_hint"));
        assert!(!map.contains_key("close_token"));
        assert!(!map.contains_key("close_owner_session_id"));
        assert!(!map.contains_key("close_recovery_hint"));
    }
}
