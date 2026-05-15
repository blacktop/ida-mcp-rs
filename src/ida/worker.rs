//! IDA worker handle for async requests.

use crate::error::ToolError;
use crate::ida::observability::ProgressSender;
use crate::ida::pool::PooledSessionState;
use crate::ida::request::IdaRequest;
use crate::ida::types::*;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Default timeout for IDA operations (2 minutes)
const DEFAULT_TIMEOUT_SECS: u64 = 120;
/// Maximum allowed timeout (10 minutes)
pub const MAX_TIMEOUT_SECS: u64 = 600;
/// Maximum time to retry enqueuing close requests when the queue is full.
const CLOSE_SEND_TIMEOUT_SECS: u64 = 5;
/// Backoff between control enqueue retries (milliseconds).
const CONTROL_SEND_BACKOFF_MS: u64 = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CloseTokenLease {
    token: String,
    owner_session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloseTokenGrant {
    pub token: String,
    pub reused: bool,
    pub owner_session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloseAuthorization {
    Granted,
    GrantedByOverride { previous_owner_session_id: String },
    Denied { owner_session_id: String },
}

/// Internal state for close token ownership.
#[derive(Debug)]
struct CloseTokenState {
    token: Mutex<Option<CloseTokenLease>>,
    nonce: AtomicU64,
}

impl CloseTokenState {
    fn new() -> Self {
        Self {
            token: Mutex::new(None),
            nonce: AtomicU64::new(0),
        }
    }

    fn lock_token(&self) -> std::sync::MutexGuard<'_, Option<CloseTokenLease>> {
        match self.token.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn generate_token(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        format!("{now:x}-{pid:x}-{nonce:x}")
    }

    fn issue_for_session(&self, session_id: &str) -> Result<CloseTokenGrant, String> {
        let mut guard = self.lock_token();
        if let Some(lease) = guard.as_ref() {
            if lease.owner_session_id == session_id {
                return Ok(CloseTokenGrant {
                    token: lease.token.clone(),
                    reused: true,
                    owner_session_id: lease.owner_session_id.clone(),
                });
            }
            return Err(lease.owner_session_id.clone());
        }

        let token = self.generate_token();
        let lease = CloseTokenLease {
            token: token.clone(),
            owner_session_id: session_id.to_string(),
        };
        *guard = Some(lease.clone());
        Ok(CloseTokenGrant {
            token,
            reused: false,
            owner_session_id: lease.owner_session_id,
        })
    }

    fn authorize_close(
        &self,
        session_id: &str,
        token: Option<&str>,
        force: bool,
    ) -> CloseAuthorization {
        let guard = self.lock_token();
        let Some(lease) = guard.as_ref() else {
            return CloseAuthorization::Granted;
        };

        if token == Some(lease.token.as_str()) || lease.owner_session_id == session_id {
            CloseAuthorization::Granted
        } else if force {
            CloseAuthorization::GrantedByOverride {
                previous_owner_session_id: lease.owner_session_id.clone(),
            }
        } else {
            CloseAuthorization::Denied {
                owner_session_id: lease.owner_session_id.clone(),
            }
        }
    }

    fn clear(&self) {
        let mut guard = self.lock_token();
        *guard = None;
    }
}

/// Handle for sending requests to the main thread IDA worker
#[derive(Clone)]
pub struct IdaWorker {
    tx: mpsc::SyncSender<IdaRequest>,
    close_token: Arc<CloseTokenState>,
}

impl IdaWorker {
    /// Create a new worker handle with the given sender.
    pub fn new(tx: mpsc::SyncSender<IdaRequest>) -> Self {
        Self {
            tx,
            close_token: Arc::new(CloseTokenState::new()),
        }
    }

    pub(crate) fn issue_close_token_for_session(
        &self,
        session_id: &str,
    ) -> Result<CloseTokenGrant, String> {
        self.close_token.issue_for_session(session_id)
    }

    pub(crate) fn authorize_close(
        &self,
        session_id: &str,
        token: Option<&str>,
        force: bool,
    ) -> CloseAuthorization {
        self.close_token.authorize_close(session_id, token, force)
    }

    pub(crate) fn clear_close_token(&self) {
        self.close_token.clear();
    }

    fn try_send(&self, req: IdaRequest) -> Result<(), ToolError> {
        match self.tx.try_send(req) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => Err(ToolError::Busy),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(ToolError::WorkerClosed),
        }
    }

    async fn send_with_retry(
        &self,
        req: IdaRequest,
        max_wait: Option<Duration>,
    ) -> Result<(), ToolError> {
        let start = Instant::now();
        let mut pending = req;
        loop {
            match self.tx.try_send(pending) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(req)) => {
                    if let Some(max_wait) = max_wait {
                        if Instant::now().duration_since(start) >= max_wait {
                            return Err(ToolError::Busy);
                        }
                    }
                    pending = req;
                    tokio::time::sleep(Duration::from_millis(CONTROL_SEND_BACKOFF_MS)).await;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => return Err(ToolError::WorkerClosed),
            }
        }
    }

    /// Helper to receive with optional timeout
    async fn recv_with_timeout<T>(
        rx: oneshot::Receiver<Result<T, ToolError>>,
        timeout_secs: Option<u64>,
    ) -> Result<T, ToolError> {
        let timeout = Duration::from_secs(
            timeout_secs
                .unwrap_or(DEFAULT_TIMEOUT_SECS)
                .min(MAX_TIMEOUT_SECS),
        );
        match tokio::time::timeout(timeout, rx).await {
            Ok(result) => result?,
            Err(_) => Err(ToolError::Timeout(timeout.as_secs())),
        }
    }

    async fn recv<T>(rx: oneshot::Receiver<Result<T, ToolError>>) -> Result<T, ToolError> {
        rx.await?
    }

    /// Open an IDA database file.
    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        &self,
        path: &str,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        extra_args: Vec<String>,
    ) -> Result<DbInfo, ToolError> {
        self.open_observed(
            path,
            load_debug_info,
            debug_info_path,
            debug_info_verbose,
            force,
            file_type,
            auto_analyse,
            extra_args,
            None,
            None,
        )
        .await
    }

    /// Open an IDA database file and stream foreground progress updates.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_observed(
        &self,
        path: &str,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        extra_args: Vec<String>,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<DbInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Open {
            path: path.to_string(),
            load_debug_info,
            debug_info_path,
            debug_info_verbose,
            force,
            file_type,
            auto_analyse,
            extra_args,
            progress_tx,
            cancel,
            resp: tx,
        })?;
        Self::recv(rx).await
    }

    /// Close the currently open database.
    pub async fn close(&self) -> Result<(), ToolError> {
        let (tx, rx) = oneshot::channel();
        self.send_with_retry(
            IdaRequest::Close { resp: tx },
            Some(Duration::from_secs(CLOSE_SEND_TIMEOUT_SECS)),
        )
        .await?;
        rx.await.map_err(|_| ToolError::WorkerClosed)
    }

    pub async fn close_for_shutdown(&self) -> Result<(), ToolError> {
        let (tx, rx) = oneshot::channel();
        self.send_with_retry(IdaRequest::Close { resp: tx }, None)
            .await?;
        rx.await.map_err(|_| ToolError::WorkerClosed)
    }

    /// Load external debug info (e.g., dSYM/DWARF) into the current database.
    pub async fn load_debug_info(
        &self,
        path: Option<String>,
        verbose: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::LoadDebugInfo {
            path,
            verbose,
            resp: tx,
        })?;
        rx.await?
    }

    /// Report current auto-analysis status.
    pub async fn analysis_status(&self) -> Result<AnalysisStatus, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AnalysisStatus { resp: tx })?;
        rx.await?
    }

    /// Shutdown the IDA worker loop.
    pub async fn shutdown(&self) -> Result<(), ToolError> {
        self.send_with_retry(IdaRequest::Shutdown, None).await
    }

    /// List functions in the database with pagination.
    pub async fn list_functions(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<FunctionListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ListFunctions {
            offset,
            limit,
            filter,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Resolve a function by name (exact or partial match).
    pub async fn resolve_function(&self, name: &str) -> Result<FunctionInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ResolveFunction {
            name: name.to_string(),
            resp: tx,
        })?;
        rx.await?
    }

    /// Disassemble a function by name (exact or partial match).
    pub async fn disasm_by_name(&self, name: &str, count: usize) -> Result<String, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DisasmByName {
            name: name.to_string(),
            count,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get disassembly at an address.
    pub async fn disasm(&self, addr: u64, count: usize) -> Result<String, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Disasm {
            addr,
            count,
            resp: tx,
        })?;
        rx.await?
    }

    /// Decompile a function using Hex-Rays.
    pub async fn decompile(&self, addr: u64) -> Result<String, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Decompile { addr, resp: tx })?;
        rx.await?
    }

    /// List all segments.
    pub async fn segments(&self) -> Result<Vec<SegmentInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Segments { resp: tx })?;
        rx.await?
    }

    /// List strings with pagination and optional filter.
    pub async fn strings(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Strings {
            offset,
            limit,
            filter,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// List local types with pagination and optional filter.
    pub async fn local_types(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<LocalTypeListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::LocalTypes {
            offset,
            limit,
            filter,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Declare a type (single or multi).
    pub async fn declare_type(
        &self,
        decl: String,
        relaxed: bool,
        replace: bool,
        multi: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DeclareType {
            decl,
            relaxed,
            replace,
            multi,
            resp: tx,
        })?;
        rx.await?
    }

    /// Apply a type to an address.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_types(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        stack_offset: Option<i64>,
        stack_name: Option<String>,
        decl: Option<String>,
        type_name: Option<String>,
        relaxed: bool,
        delay: bool,
        strict: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ApplyTypes {
            addr,
            name,
            offset,
            stack_offset,
            stack_name,
            decl,
            type_name,
            relaxed,
            delay,
            strict,
            resp: tx,
        })?;
        rx.await?
    }

    /// Infer/guess a type for an address.
    pub async fn infer_types(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<GuessTypeResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::InferTypes {
            addr,
            name,
            offset,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get address context (segment, function, symbol).
    pub async fn addr_info(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<AddressInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AddrInfo {
            addr,
            name,
            offset,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get function containing an address.
    pub async fn function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<FunctionRangeInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FunctionAt {
            addr,
            name,
            offset,
            resp: tx,
        })?;
        rx.await?
    }

    /// Disassemble the function containing an address.
    pub async fn disasm_function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        count: usize,
    ) -> Result<String, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DisasmFunctionAt {
            addr,
            name,
            offset,
            count,
            resp: tx,
        })?;
        rx.await?
    }

    /// Declare a stack variable in a function frame.
    pub async fn declare_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        var_name: Option<String>,
        decl: String,
        relaxed: bool,
    ) -> Result<StackVarResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DeclareStack {
            addr,
            name,
            offset,
            var_name,
            decl,
            relaxed,
            resp: tx,
        })?;
        rx.await?
    }

    /// Delete a stack variable from a function frame.
    pub async fn delete_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: Option<i64>,
        var_name: Option<String>,
    ) -> Result<StackVarResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DeleteStack {
            addr,
            name,
            offset,
            var_name,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get stack frame info for a function at an address.
    pub async fn stack_frame(&self, addr: u64) -> Result<FrameInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::StackFrame { addr, resp: tx })?;
        rx.await?
    }

    /// List structs with pagination and optional filter.
    pub async fn structs(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<StructListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Structs {
            offset,
            limit,
            filter,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Get struct info by ordinal or name.
    pub async fn struct_info(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::StructInfo {
            ordinal,
            name,
            resp: tx,
        })?;
        rx.await?
    }

    /// Read a struct instance at an address.
    pub async fn read_struct(
        &self,
        addr: u64,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructReadResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ReadStruct {
            addr,
            ordinal,
            name,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get cross-references to an address.
    pub async fn xrefs_to(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XRefsTo { addr, resp: tx })?;
        rx.await?
    }

    /// Get cross-references from an address.
    pub async fn xrefs_from(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XRefsFrom { addr, resp: tx })?;
        rx.await?
    }

    /// Get xrefs to a struct field.
    pub async fn xrefs_to_field(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
        member_index: Option<u32>,
        member_name: Option<String>,
        limit: usize,
    ) -> Result<XrefsToFieldResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XRefsToField {
            ordinal,
            name,
            member_index,
            member_name,
            limit,
            resp: tx,
        })?;
        rx.await?
    }

    /// List imports with pagination.
    pub async fn imports(&self, offset: usize, limit: usize) -> Result<Vec<ImportInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Imports {
            offset,
            limit,
            resp: tx,
        })?;
        rx.await?
    }

    /// List exports with pagination.
    pub async fn exports(&self, offset: usize, limit: usize) -> Result<Vec<ExportInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Exports {
            offset,
            limit,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get entry points.
    pub async fn entrypoints(&self) -> Result<Vec<String>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Entrypoints { resp: tx })?;
        rx.await?
    }

    /// Read bytes from an address.
    pub async fn get_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        size: usize,
    ) -> Result<BytesResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::GetBytes {
            addr,
            name,
            offset,
            size,
            resp: tx,
        })?;
        rx.await?
    }

    /// Set a comment at an address.
    pub async fn set_comments(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        comment: String,
        repeatable: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::SetComments {
            addr,
            name,
            offset,
            comment,
            repeatable,
            resp: tx,
        })?;
        rx.await?
    }

    /// Rename a symbol at an address.
    pub async fn rename(
        &self,
        addr: Option<u64>,
        current_name: Option<String>,
        new_name: String,
        flags: i32,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Rename {
            addr,
            current_name,
            new_name,
            flags,
            resp: tx,
        })?;
        rx.await?
    }

    /// Patch bytes at an address.
    pub async fn patch_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        bytes: Vec<u8>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::PatchBytes {
            addr,
            name,
            offset,
            bytes,
            resp: tx,
        })?;
        rx.await?
    }

    /// Patch instructions with assembly text at an address.
    pub async fn patch_asm(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        line: String,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::PatchAsm {
            addr,
            name,
            offset,
            line,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get basic blocks for a function.
    pub async fn basic_blocks(&self, addr: u64) -> Result<Vec<BasicBlockInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::BasicBlocks { addr, resp: tx })?;
        rx.await?
    }

    /// Get functions called by a function.
    pub async fn callees(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Callees { addr, resp: tx })?;
        rx.await?
    }

    /// Get functions that call a function.
    pub async fn callers(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Callers { addr, resp: tx })?;
        rx.await?
    }

    /// Get IDB metadata.
    pub async fn idb_meta(&self) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::IdbMeta { resp: tx })?;
        rx.await?
    }

    /// Lookup functions by name or address (batch).
    pub async fn lookup_funcs(&self, queries: Vec<String>) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::LookupFunctions { queries, resp: tx })?;
        rx.await?
    }

    /// List globals (named addresses outside functions).
    pub async fn list_globals(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ListGlobals {
            query,
            offset,
            limit,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Analyze strings (with xrefs).
    pub async fn analyze_strings(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AnalyzeStrings {
            query,
            offset,
            limit,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Find strings matching a query.
    pub async fn find_string(
        &self,
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindString {
            query,
            exact,
            case_insensitive,
            offset,
            limit,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Get xrefs to strings matching a query.
    #[allow(clippy::too_many_arguments)]
    pub async fn xrefs_to_string(
        &self,
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        max_xrefs: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringXrefsResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XrefsToString {
            query,
            exact,
            case_insensitive,
            offset,
            limit,
            max_xrefs,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Run auto-analysis (functions) and wait for completion.
    pub async fn analyze_funcs(&self, timeout_secs: Option<u64>) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AnalyzeFuncs {
            progress_tx: None,
            cancel: None,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Run auto-analysis (functions) and stream progress for foreground callers.
    pub async fn analyze_funcs_observed(
        &self,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AnalyzeFuncs {
            progress_tx,
            cancel,
            resp: tx,
        })?;
        Self::recv(rx).await
    }

    /// Find byte pattern in the database.
    pub async fn find_bytes(
        &self,
        pattern: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindBytes {
            pattern,
            max_results,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Search text in the database.
    pub async fn search_text(
        &self,
        text: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::SearchText {
            text,
            max_results,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Search immediate values in the database.
    pub async fn search_imm(
        &self,
        imm: u64,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::SearchImm {
            imm,
            max_results,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Find instruction sequences by mnemonic patterns.
    pub async fn find_insns(
        &self,
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindInsns {
            patterns,
            max_results,
            case_insensitive,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Find instruction operands by operand substring patterns.
    pub async fn find_insn_operands(
        &self,
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindInsnOperands {
            patterns,
            max_results,
            case_insensitive,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Read integer value of size (1/2/4/8) at address.
    pub async fn read_int(&self, addr: u64, size: usize) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ReadInt {
            addr,
            size,
            resp: tx,
        })?;
        rx.await?
    }

    /// Read string at address.
    pub async fn get_string(&self, addr: u64, max_len: usize) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::GetString {
            addr,
            max_len,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get value for a global (by name or address).
    pub async fn get_global_value(&self, query: String) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::GetGlobalValue { query, resp: tx })?;
        rx.await?
    }

    /// Find paths between addresses (CFG).
    pub async fn find_paths(
        &self,
        start: u64,
        end: u64,
        max_paths: usize,
        max_depth: usize,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindPaths {
            start,
            end,
            max_paths,
            max_depth,
            resp: tx,
        })?;
        rx.await?
    }

    /// Build a call graph rooted at a function address.
    pub async fn callgraph(
        &self,
        addr: u64,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::CallGraph {
            addr,
            max_depth,
            max_nodes,
            resp: tx,
        })?;
        rx.await?
    }

    /// Compute xref matrix for a set of addresses.
    pub async fn xref_matrix(&self, addrs: Vec<u64>) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XrefMatrix { addrs, resp: tx })?;
        rx.await?
    }

    /// Export functions (paginated).
    pub async fn export_funcs(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<FunctionListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ExportFuncs {
            offset,
            limit,
            resp: tx,
        })?;
        rx.await?
    }

    /// Run a Python script via IDAPython in the open database.
    pub async fn run_script(
        &self,
        code: &str,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::RunScript {
            code: code.to_string(),
            progress_tx: None,
            cancel: None,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Run a Python script via IDAPython and stream progress for foreground callers.
    pub async fn run_script_observed(
        &self,
        code: &str,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::RunScript {
            code: code.to_string(),
            progress_tx,
            cancel,
            resp: tx,
        })?;
        Self::recv(rx).await
    }

    /// Get decompiled pseudocode at a specific address or address range.
    /// If end_addr is provided, returns pseudocode for the range [addr, end_addr).
    /// Otherwise returns pseudocode for statements at the single address.
    pub async fn pseudocode_at(
        &self,
        addr: u64,
        end_addr: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::PseudocodeAt {
            addr,
            end_addr,
            resp: tx,
        })?;
        rx.await?
    }
}

/// Dispatch surface used by MCP handlers.
///
/// The local variant preserves the existing in-process worker path. The pooled
/// variant routes calls through a per-session child process lease.
#[derive(Clone)]
pub enum WorkerBackend {
    Local(Arc<IdaWorker>),
    Pooled(Arc<PooledSessionState>),
}

impl WorkerBackend {
    pub fn local(worker: Arc<IdaWorker>) -> Self {
        Self::Local(worker)
    }

    pub fn pooled(state: Arc<PooledSessionState>) -> Self {
        Self::Pooled(state)
    }

    pub(crate) fn uses_close_tokens(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    pub(crate) fn is_pooled(&self) -> bool {
        matches!(self, Self::Pooled(_))
    }

    pub(crate) fn issue_close_token_for_session(
        &self,
        session_id: &str,
    ) -> Option<Result<CloseTokenGrant, String>> {
        match self {
            Self::Local(worker) => Some(worker.issue_close_token_for_session(session_id)),
            Self::Pooled(_) => None,
        }
    }

    pub(crate) fn authorize_close(
        &self,
        session_id: &str,
        token: Option<&str>,
        force: bool,
    ) -> CloseAuthorization {
        match self {
            Self::Local(worker) => worker.authorize_close(session_id, token, force),
            // Pooled HTTP workers are private to one rmcp session, so close_idb
            // cannot affect another client's database and does not need a
            // cross-session recovery token.
            Self::Pooled(_) => CloseAuthorization::Granted,
        }
    }

    pub(crate) fn clear_close_token(&self) {
        if let Self::Local(worker) = self {
            worker.clear_close_token();
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        &self,
        path: &str,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        extra_args: Vec<String>,
    ) -> Result<DbInfo, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .open(
                        path,
                        load_debug_info,
                        debug_info_path,
                        debug_info_verbose,
                        force,
                        file_type,
                        auto_analyse,
                        extra_args,
                    )
                    .await
            }
            Self::Pooled(state) => {
                state
                    .open(
                        path,
                        load_debug_info,
                        debug_info_path,
                        debug_info_verbose,
                        force,
                        file_type,
                        auto_analyse,
                        extra_args,
                    )
                    .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_observed(
        &self,
        path: &str,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        extra_args: Vec<String>,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<DbInfo, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .open_observed(
                        path,
                        load_debug_info,
                        debug_info_path,
                        debug_info_verbose,
                        force,
                        file_type,
                        auto_analyse,
                        extra_args,
                        progress_tx,
                        cancel,
                    )
                    .await
            }
            Self::Pooled(state) => {
                state
                    .open_observed(
                        path,
                        load_debug_info,
                        debug_info_path,
                        debug_info_verbose,
                        force,
                        file_type,
                        auto_analyse,
                        extra_args,
                        progress_tx,
                        cancel,
                    )
                    .await
            }
        }
    }

    pub async fn close(&self) -> Result<(), ToolError> {
        match self {
            Self::Local(worker) => worker.close().await,
            Self::Pooled(state) => state.close().await,
        }
    }

    pub async fn close_for_shutdown(&self) -> Result<(), ToolError> {
        match self {
            Self::Local(worker) => worker.close_for_shutdown().await,
            Self::Pooled(state) => state.close().await,
        }
    }

    pub async fn shutdown(&self) -> Result<(), ToolError> {
        match self {
            Self::Local(worker) => worker.shutdown().await,
            Self::Pooled(_) => Ok(()),
        }
    }

    pub async fn load_debug_info(
        &self,
        path: Option<String>,
        verbose: bool,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.load_debug_info(path, verbose).await,
            Self::Pooled(state) => state.load_debug_info(path, verbose).await,
        }
    }

    pub async fn analysis_status(&self) -> Result<AnalysisStatus, ToolError> {
        match self {
            Self::Local(worker) => worker.analysis_status().await,
            Self::Pooled(state) => state.analysis_status().await,
        }
    }

    pub async fn list_functions(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<FunctionListResult, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .list_functions(offset, limit, filter, timeout_secs)
                    .await
            }
            Self::Pooled(state) => {
                state
                    .list_functions(offset, limit, filter, timeout_secs)
                    .await
            }
        }
    }

    pub async fn resolve_function(&self, name: &str) -> Result<FunctionInfo, ToolError> {
        match self {
            Self::Local(worker) => worker.resolve_function(name).await,
            Self::Pooled(state) => state.resolve_function(name).await,
        }
    }

    pub async fn disasm_by_name(&self, name: &str, count: usize) -> Result<String, ToolError> {
        match self {
            Self::Local(worker) => worker.disasm_by_name(name, count).await,
            Self::Pooled(state) => state.disasm_by_name(name, count).await,
        }
    }

    pub async fn disasm(&self, addr: u64, count: usize) -> Result<String, ToolError> {
        match self {
            Self::Local(worker) => worker.disasm(addr, count).await,
            Self::Pooled(state) => state.disasm(addr, count).await,
        }
    }

    pub async fn decompile(&self, addr: u64) -> Result<String, ToolError> {
        match self {
            Self::Local(worker) => worker.decompile(addr).await,
            Self::Pooled(state) => state.decompile(addr).await,
        }
    }

    pub async fn segments(&self) -> Result<Vec<SegmentInfo>, ToolError> {
        match self {
            Self::Local(worker) => worker.segments().await,
            Self::Pooled(state) => state.segments().await,
        }
    }

    pub async fn strings(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError> {
        match self {
            Self::Local(worker) => worker.strings(offset, limit, filter, timeout_secs).await,
            Self::Pooled(state) => state.strings(offset, limit, filter, timeout_secs).await,
        }
    }

    pub async fn local_types(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<LocalTypeListResult, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .local_types(offset, limit, filter, timeout_secs)
                    .await
            }
            Self::Pooled(state) => state.local_types(offset, limit, filter, timeout_secs).await,
        }
    }

    pub async fn declare_type(
        &self,
        decl: String,
        relaxed: bool,
        replace: bool,
        multi: bool,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.declare_type(decl, relaxed, replace, multi).await,
            Self::Pooled(state) => state.declare_type(decl, relaxed, replace, multi).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn apply_types(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        stack_offset: Option<i64>,
        stack_name: Option<String>,
        decl: Option<String>,
        type_name: Option<String>,
        relaxed: bool,
        delay: bool,
        strict: bool,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .apply_types(
                        addr,
                        name,
                        offset,
                        stack_offset,
                        stack_name,
                        decl,
                        type_name,
                        relaxed,
                        delay,
                        strict,
                    )
                    .await
            }
            Self::Pooled(state) => {
                state
                    .apply_types(
                        addr,
                        name,
                        offset,
                        stack_offset,
                        stack_name,
                        decl,
                        type_name,
                        relaxed,
                        delay,
                        strict,
                    )
                    .await
            }
        }
    }

    pub async fn infer_types(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<GuessTypeResult, ToolError> {
        match self {
            Self::Local(worker) => worker.infer_types(addr, name, offset).await,
            Self::Pooled(state) => state.infer_types(addr, name, offset).await,
        }
    }

    pub async fn addr_info(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<AddressInfo, ToolError> {
        match self {
            Self::Local(worker) => worker.addr_info(addr, name, offset).await,
            Self::Pooled(state) => state.addr_info(addr, name, offset).await,
        }
    }

    pub async fn function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<FunctionRangeInfo, ToolError> {
        match self {
            Self::Local(worker) => worker.function_at(addr, name, offset).await,
            Self::Pooled(state) => state.function_at(addr, name, offset).await,
        }
    }

    pub async fn disasm_function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        count: usize,
    ) -> Result<String, ToolError> {
        match self {
            Self::Local(worker) => worker.disasm_function_at(addr, name, offset, count).await,
            Self::Pooled(state) => state.disasm_function_at(addr, name, offset, count).await,
        }
    }

    pub async fn declare_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        var_name: Option<String>,
        decl: String,
        relaxed: bool,
    ) -> Result<StackVarResult, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .declare_stack(addr, name, offset, var_name, decl, relaxed)
                    .await
            }
            Self::Pooled(state) => {
                state
                    .declare_stack(addr, name, offset, var_name, decl, relaxed)
                    .await
            }
        }
    }

    pub async fn delete_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: Option<i64>,
        var_name: Option<String>,
    ) -> Result<StackVarResult, ToolError> {
        match self {
            Self::Local(worker) => worker.delete_stack(addr, name, offset, var_name).await,
            Self::Pooled(state) => state.delete_stack(addr, name, offset, var_name).await,
        }
    }

    pub async fn stack_frame(&self, addr: u64) -> Result<FrameInfo, ToolError> {
        match self {
            Self::Local(worker) => worker.stack_frame(addr).await,
            Self::Pooled(state) => state.stack_frame(addr).await,
        }
    }

    pub async fn structs(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<StructListResult, ToolError> {
        match self {
            Self::Local(worker) => worker.structs(offset, limit, filter, timeout_secs).await,
            Self::Pooled(state) => state.structs(offset, limit, filter, timeout_secs).await,
        }
    }

    pub async fn struct_info(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructInfo, ToolError> {
        match self {
            Self::Local(worker) => worker.struct_info(ordinal, name).await,
            Self::Pooled(state) => state.struct_info(ordinal, name).await,
        }
    }

    pub async fn read_struct(
        &self,
        addr: u64,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructReadResult, ToolError> {
        match self {
            Self::Local(worker) => worker.read_struct(addr, ordinal, name).await,
            Self::Pooled(state) => state.read_struct(addr, ordinal, name).await,
        }
    }

    pub async fn xrefs_to(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
        match self {
            Self::Local(worker) => worker.xrefs_to(addr).await,
            Self::Pooled(state) => state.xrefs_to(addr).await,
        }
    }

    pub async fn xrefs_from(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
        match self {
            Self::Local(worker) => worker.xrefs_from(addr).await,
            Self::Pooled(state) => state.xrefs_from(addr).await,
        }
    }

    pub async fn xrefs_to_field(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
        member_index: Option<u32>,
        member_name: Option<String>,
        limit: usize,
    ) -> Result<XrefsToFieldResult, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .xrefs_to_field(ordinal, name, member_index, member_name, limit)
                    .await
            }
            Self::Pooled(state) => {
                state
                    .xrefs_to_field(ordinal, name, member_index, member_name, limit)
                    .await
            }
        }
    }

    pub async fn imports(&self, offset: usize, limit: usize) -> Result<Vec<ImportInfo>, ToolError> {
        match self {
            Self::Local(worker) => worker.imports(offset, limit).await,
            Self::Pooled(state) => state.imports(offset, limit).await,
        }
    }

    pub async fn exports(&self, offset: usize, limit: usize) -> Result<Vec<ExportInfo>, ToolError> {
        match self {
            Self::Local(worker) => worker.exports(offset, limit).await,
            Self::Pooled(state) => state.exports(offset, limit).await,
        }
    }

    pub async fn entrypoints(&self) -> Result<Vec<String>, ToolError> {
        match self {
            Self::Local(worker) => worker.entrypoints().await,
            Self::Pooled(state) => state.entrypoints().await,
        }
    }

    pub async fn get_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        size: usize,
    ) -> Result<BytesResult, ToolError> {
        match self {
            Self::Local(worker) => worker.get_bytes(addr, name, offset, size).await,
            Self::Pooled(state) => state.get_bytes(addr, name, offset, size).await,
        }
    }

    pub async fn set_comments(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        comment: String,
        repeatable: bool,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .set_comments(addr, name, offset, comment, repeatable)
                    .await
            }
            Self::Pooled(state) => {
                state
                    .set_comments(addr, name, offset, comment, repeatable)
                    .await
            }
        }
    }

    pub async fn rename(
        &self,
        addr: Option<u64>,
        current_name: Option<String>,
        new_name: String,
        flags: i32,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.rename(addr, current_name, new_name, flags).await,
            Self::Pooled(state) => state.rename(addr, current_name, new_name, flags).await,
        }
    }

    pub async fn patch_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        bytes: Vec<u8>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.patch_bytes(addr, name, offset, bytes).await,
            Self::Pooled(state) => state.patch_bytes(addr, name, offset, bytes).await,
        }
    }

    pub async fn patch_asm(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        line: String,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.patch_asm(addr, name, offset, line).await,
            Self::Pooled(state) => state.patch_asm(addr, name, offset, line).await,
        }
    }

    pub async fn basic_blocks(&self, addr: u64) -> Result<Vec<BasicBlockInfo>, ToolError> {
        match self {
            Self::Local(worker) => worker.basic_blocks(addr).await,
            Self::Pooled(state) => state.basic_blocks(addr).await,
        }
    }

    pub async fn callees(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
        match self {
            Self::Local(worker) => worker.callees(addr).await,
            Self::Pooled(state) => state.callees(addr).await,
        }
    }

    pub async fn callers(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
        match self {
            Self::Local(worker) => worker.callers(addr).await,
            Self::Pooled(state) => state.callers(addr).await,
        }
    }

    pub async fn idb_meta(&self) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.idb_meta().await,
            Self::Pooled(state) => state.idb_meta().await,
        }
    }

    pub async fn lookup_funcs(&self, queries: Vec<String>) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.lookup_funcs(queries).await,
            Self::Pooled(state) => state.lookup_funcs(queries).await,
        }
    }

    pub async fn list_globals(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .list_globals(query, offset, limit, timeout_secs)
                    .await
            }
            Self::Pooled(state) => state.list_globals(query, offset, limit, timeout_secs).await,
        }
    }

    pub async fn analyze_strings(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .analyze_strings(query, offset, limit, timeout_secs)
                    .await
            }
            Self::Pooled(state) => {
                state
                    .analyze_strings(query, offset, limit, timeout_secs)
                    .await
            }
        }
    }

    pub async fn find_string(
        &self,
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .find_string(query, exact, case_insensitive, offset, limit, timeout_secs)
                    .await
            }
            Self::Pooled(state) => {
                state
                    .find_string(query, exact, case_insensitive, offset, limit, timeout_secs)
                    .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn xrefs_to_string(
        &self,
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        max_xrefs: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringXrefsResult, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .xrefs_to_string(
                        query,
                        exact,
                        case_insensitive,
                        offset,
                        limit,
                        max_xrefs,
                        timeout_secs,
                    )
                    .await
            }
            Self::Pooled(state) => {
                state
                    .xrefs_to_string(
                        query,
                        exact,
                        case_insensitive,
                        offset,
                        limit,
                        max_xrefs,
                        timeout_secs,
                    )
                    .await
            }
        }
    }

    pub async fn analyze_funcs(&self, timeout_secs: Option<u64>) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.analyze_funcs(timeout_secs).await,
            Self::Pooled(state) => state.analyze_funcs(timeout_secs).await,
        }
    }

    pub async fn analyze_funcs_observed(
        &self,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.analyze_funcs_observed(progress_tx, cancel).await,
            Self::Pooled(state) => state.analyze_funcs_observed(progress_tx, cancel).await,
        }
    }

    pub async fn find_bytes(
        &self,
        pattern: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.find_bytes(pattern, max_results, timeout_secs).await,
            Self::Pooled(state) => state.find_bytes(pattern, max_results, timeout_secs).await,
        }
    }

    pub async fn search_text(
        &self,
        text: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.search_text(text, max_results, timeout_secs).await,
            Self::Pooled(state) => state.search_text(text, max_results, timeout_secs).await,
        }
    }

    pub async fn search_imm(
        &self,
        imm: u64,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.search_imm(imm, max_results, timeout_secs).await,
            Self::Pooled(state) => state.search_imm(imm, max_results, timeout_secs).await,
        }
    }

    pub async fn find_insns(
        &self,
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .find_insns(patterns, max_results, case_insensitive, timeout_secs)
                    .await
            }
            Self::Pooled(state) => {
                state
                    .find_insns(patterns, max_results, case_insensitive, timeout_secs)
                    .await
            }
        }
    }

    pub async fn find_insn_operands(
        &self,
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => {
                worker
                    .find_insn_operands(patterns, max_results, case_insensitive, timeout_secs)
                    .await
            }
            Self::Pooled(state) => {
                state
                    .find_insn_operands(patterns, max_results, case_insensitive, timeout_secs)
                    .await
            }
        }
    }

    pub async fn read_int(&self, addr: u64, size: usize) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.read_int(addr, size).await,
            Self::Pooled(state) => state.read_int(addr, size).await,
        }
    }

    pub async fn get_string(&self, addr: u64, max_len: usize) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.get_string(addr, max_len).await,
            Self::Pooled(state) => state.get_string(addr, max_len).await,
        }
    }

    pub async fn get_global_value(&self, query: String) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.get_global_value(query).await,
            Self::Pooled(state) => state.get_global_value(query).await,
        }
    }

    pub async fn find_paths(
        &self,
        start: u64,
        end: u64,
        max_paths: usize,
        max_depth: usize,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.find_paths(start, end, max_paths, max_depth).await,
            Self::Pooled(state) => state.find_paths(start, end, max_paths, max_depth).await,
        }
    }

    pub async fn callgraph(
        &self,
        addr: u64,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.callgraph(addr, max_depth, max_nodes).await,
            Self::Pooled(state) => state.callgraph(addr, max_depth, max_nodes).await,
        }
    }

    pub async fn xref_matrix(&self, addrs: Vec<u64>) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.xref_matrix(addrs).await,
            Self::Pooled(state) => state.xref_matrix(addrs).await,
        }
    }

    pub async fn export_funcs(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<FunctionListResult, ToolError> {
        match self {
            Self::Local(worker) => worker.export_funcs(offset, limit).await,
            Self::Pooled(state) => state.export_funcs(offset, limit).await,
        }
    }

    pub async fn run_script(
        &self,
        code: &str,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.run_script(code, timeout_secs).await,
            Self::Pooled(state) => state.run_script(code, timeout_secs).await,
        }
    }

    pub async fn run_script_observed(
        &self,
        code: &str,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.run_script_observed(code, progress_tx, cancel).await,
            Self::Pooled(state) => state.run_script_observed(code, progress_tx, cancel).await,
        }
    }

    pub async fn pseudocode_at(
        &self,
        addr: u64,
        end_addr: Option<u64>,
    ) -> Result<Value, ToolError> {
        match self {
            Self::Local(worker) => worker.pseudocode_at(addr, end_addr).await,
            Self::Pooled(state) => state.pseudocode_at(addr, end_addr).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ida::worker::{CloseAuthorization, IdaWorker};
    use std::sync::mpsc;

    fn test_worker() -> IdaWorker {
        let (tx, _rx) = mpsc::sync_channel(1);
        IdaWorker::new(tx)
    }

    #[test]
    fn close_token_is_reused_for_same_session() {
        let worker = test_worker();
        let first = worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");
        let second = worker
            .issue_close_token_for_session("session-a")
            .expect("same session should reuse token");

        assert_eq!(first.token, second.token);
        assert!(!first.reused);
        assert!(second.reused);
    }

    #[test]
    fn close_token_is_denied_for_different_session() {
        let worker = test_worker();
        worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");

        let denied = worker
            .issue_close_token_for_session("session-b")
            .expect_err("different session should be denied");
        assert_eq!(denied, "session-a");
    }

    #[test]
    fn owner_session_can_close_without_token() {
        let worker = test_worker();
        worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");

        assert_eq!(
            worker.authorize_close("session-a", None, false),
            CloseAuthorization::Granted
        );
    }

    #[test]
    fn force_close_can_override_other_session() {
        let worker = test_worker();
        worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");

        assert_eq!(
            worker.authorize_close("session-b", None, true),
            CloseAuthorization::GrantedByOverride {
                previous_owner_session_id: "session-a".to_string(),
            }
        );
    }

    #[test]
    fn token_grants_close_from_any_session() {
        let worker = test_worker();
        let grant = worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");

        assert_eq!(
            worker.authorize_close("session-b", Some(&grant.token), false),
            CloseAuthorization::Granted
        );
    }

    #[test]
    fn close_is_granted_when_no_lease_exists() {
        let worker = test_worker();
        assert_eq!(
            worker.authorize_close("session-x", None, false),
            CloseAuthorization::Granted
        );
    }
}
