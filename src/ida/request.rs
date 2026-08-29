//! Request types for the IDA worker.

use crate::error::ToolError;
use crate::ida::observability::ProgressSender;
use crate::ida::types::*;
use serde_json::Value;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

const SIDE_EFFECT_QUEUED: u8 = 0;
const SIDE_EFFECT_STARTED: u8 = 1;
const SIDE_EFFECT_CANCELLED: u8 = 2;

/// Admission state for a queued request that can change external or IDA state.
///
/// A receiver timeout may cancel only while the request is still queued. Once
/// the IDA thread claims it, the caller must wait for the operation's real
/// result instead of reporting a timeout while the side effect continues.
#[derive(Clone, Default)]
pub struct SideEffectAdmission {
    state: Arc<AtomicU8>,
}

impl SideEffectAdmission {
    pub fn start(&self) -> Result<(), ToolError> {
        self.state
            .compare_exchange(
                SIDE_EFFECT_QUEUED,
                SIDE_EFFECT_STARTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| {
                ToolError::Cancelled(
                    "request expired while queued; no side effects were started".to_string(),
                )
            })
    }

    pub fn cancel_if_queued(&self) -> bool {
        self.state
            .compare_exchange(
                SIDE_EFFECT_QUEUED,
                SIDE_EFFECT_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// Request types for the IDA worker
pub enum IdaRequest {
    Open {
        path: String,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        rebuild: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        raw_target: RawBinaryTarget,
        extra_args: Vec<String>,
        idb_out: Option<String>,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
        resp: oneshot::Sender<Result<OpenedDatabase, ToolError>>,
    },
    Close {
        resp: oneshot::Sender<Result<(), ToolError>>,
    },
    CloseIfGeneration {
        generation: DatabaseGeneration,
        resp: oneshot::Sender<Result<ConditionalCloseResult, ToolError>>,
    },
    LoadDebugInfo {
        path: Option<String>,
        verbose: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    DebugLaunch {
        path: String,
        arguments: Option<String>,
        start_directory: Option<String>,
        timeout_seconds: u32,
        admission: SideEffectAdmission,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    DebugAttach {
        pid: u32,
        timeout_seconds: u32,
        admission: SideEffectAdmission,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    DebugModules {
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    DebugStop {
        action: DebugStopAction,
        timeout_seconds: u32,
        admission: SideEffectAdmission,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    AnalysisStatus {
        /// When set, the request is refused unless this database lifetime is
        /// still current, so a background task cannot observe the database
        /// that replaced the one it opened.
        expected_generation: Option<DatabaseGeneration>,
        resp: oneshot::Sender<Result<AnalysisStatus, ToolError>>,
    },
    DscLoadImage {
        module: String,
        /// See [`IdaRequest::AnalysisStatus::expected_generation`]. Loading an
        /// image mutates the database, so a stale task must be refused before
        /// it writes into a database it does not own.
        expected_generation: Option<DatabaseGeneration>,
        admission: SideEffectAdmission,
        resp: oneshot::Sender<Result<DscImageInfo, ToolError>>,
    },
    DscLoadRegion {
        addr: u64,
        admission: SideEffectAdmission,
        resp: oneshot::Sender<Result<DscRegionInfo, ToolError>>,
    },
    ListFunctions {
        offset: usize,
        limit: usize,
        filter: Option<String>,
        resp: oneshot::Sender<Result<FunctionListResult, ToolError>>,
    },
    ResolveFunction {
        name: String,
        resp: oneshot::Sender<Result<FunctionInfo, ToolError>>,
    },
    DisasmByName {
        name: String,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    Disasm {
        addr: u64,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    RenderRange {
        start: u64,
        end: u64,
        max_lines: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    Decompile {
        addr: u64,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    Segments {
        resp: oneshot::Sender<Result<Vec<SegmentInfo>, ToolError>>,
    },
    Strings {
        offset: usize,
        limit: usize,
        filter: Option<String>,
        resp: oneshot::Sender<Result<StringListResult, ToolError>>,
    },
    LocalTypes {
        offset: usize,
        limit: usize,
        filter: Option<String>,
        resp: oneshot::Sender<Result<LocalTypeListResult, ToolError>>,
    },
    DeclareType {
        decl: String,
        relaxed: bool,
        replace: bool,
        multi: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ApplyTypes {
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
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    InferTypes {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        resp: oneshot::Sender<Result<GuessTypeResult, ToolError>>,
    },
    AddrInfo {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        resp: oneshot::Sender<Result<AddressInfo, ToolError>>,
    },
    FunctionAt {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        resp: oneshot::Sender<Result<FunctionRangeInfo, ToolError>>,
    },
    DisasmFunctionAt {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    DeclareStack {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        var_name: Option<String>,
        decl: String,
        relaxed: bool,
        resp: oneshot::Sender<Result<StackVarResult, ToolError>>,
    },
    DeleteStack {
        addr: Option<u64>,
        name: Option<String>,
        offset: Option<i64>,
        var_name: Option<String>,
        resp: oneshot::Sender<Result<StackVarResult, ToolError>>,
    },
    StackFrame {
        addr: u64,
        resp: oneshot::Sender<Result<FrameInfo, ToolError>>,
    },
    Structs {
        offset: usize,
        limit: usize,
        filter: Option<String>,
        resp: oneshot::Sender<Result<StructListResult, ToolError>>,
    },
    StructInfo {
        ordinal: Option<u32>,
        name: Option<String>,
        resp: oneshot::Sender<Result<StructInfo, ToolError>>,
    },
    ReadStruct {
        addr: u64,
        ordinal: Option<u32>,
        name: Option<String>,
        resp: oneshot::Sender<Result<StructReadResult, ToolError>>,
    },
    XRefsTo {
        addr: u64,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<XRefListResult, ToolError>>,
    },
    XRefsFrom {
        addr: u64,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<XRefListResult, ToolError>>,
    },
    XRefsToField {
        ordinal: Option<u32>,
        name: Option<String>,
        member_index: Option<u32>,
        member_name: Option<String>,
        limit: usize,
        resp: oneshot::Sender<Result<XrefsToFieldResult, ToolError>>,
    },
    Imports {
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Vec<ImportInfo>, ToolError>>,
    },
    Exports {
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Vec<ExportInfo>, ToolError>>,
    },
    Entrypoints {
        resp: oneshot::Sender<Result<Vec<String>, ToolError>>,
    },
    LuminaLookup {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    LuminaApply {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        force: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetBytes {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        size: usize,
        resp: oneshot::Sender<Result<BytesResult, ToolError>>,
    },
    ListPatches {
        start: Option<u64>,
        end: Option<u64>,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SetComments {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        comment: String,
        repeatable: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    Rename {
        addr: Option<u64>,
        current_name: Option<String>,
        new_name: String,
        flags: i32,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    PatchBytes {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        bytes: Vec<u8>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    PatchAsm {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        line: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    BasicBlocks {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<BasicBlockInfo>, ToolError>>,
    },
    Callees {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<FunctionInfo>, ToolError>>,
    },
    Callers {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<FunctionInfo>, ToolError>>,
    },
    IdbMeta {
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    LookupFunctions {
        queries: Vec<String>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ListGlobals {
        query: Option<String>,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    AnalyzeStrings {
        query: Option<String>,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindString {
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<StringListResult, ToolError>>,
    },
    XrefsToString {
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        max_xrefs: usize,
        resp: oneshot::Sender<Result<StringXrefsResult, ToolError>>,
    },
    AnalyzeFuncs {
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
        admission: SideEffectAdmission,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindBytes {
        pattern: String,
        max_results: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SearchText {
        text: String,
        max_results: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SearchImm {
        imm: u64,
        max_results: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindInsns {
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindInsnOperands {
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ReadInt {
        addr: u64,
        size: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetString {
        addr: u64,
        max_len: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetGlobalValue {
        query: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindPaths {
        start: u64,
        end: u64,
        max_paths: usize,
        max_depth: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    CallGraph {
        addr: u64,
        direction: CallGraphDirection,
        max_depth: usize,
        max_nodes: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    XrefMatrix {
        addrs: Vec<u64>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ExportFuncs {
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<FunctionListResult, ToolError>>,
    },
    PseudocodeAt {
        addr: u64,
        end_addr: Option<u64>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    RunScript {
        code: String,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
        admission: SideEffectAdmission,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    Shutdown,
}

impl IdaRequest {
    pub fn progress_sender(&self) -> Option<&ProgressSender> {
        match self {
            IdaRequest::Open { progress_tx, .. }
            | IdaRequest::AnalyzeFuncs { progress_tx, .. }
            | IdaRequest::RunScript { progress_tx, .. } => progress_tx.as_ref(),
            _ => None,
        }
    }

    pub fn cancel_token(&self) -> Option<&CancellationToken> {
        match self {
            IdaRequest::Open { cancel, .. }
            | IdaRequest::AnalyzeFuncs { cancel, .. }
            | IdaRequest::RunScript { cancel, .. } => cancel.as_ref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ida::request::SideEffectAdmission;

    #[test]
    fn queued_side_effect_has_one_winner() {
        let admission = SideEffectAdmission::default();
        assert!(admission.cancel_if_queued());
        assert!(admission.start().is_err());

        let admission = SideEffectAdmission::default();
        admission.start().expect("IDA thread claims the request");
        assert!(!admission.cancel_if_queued());
    }
}
