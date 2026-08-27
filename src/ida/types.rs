//! Response types for IDA worker operations.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugStopAction {
    Auto,
    Detach,
    Terminate,
}

impl DebugStopAction {
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("auto").trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "detach" => Ok(Self::Detach),
            "terminate" | "kill" => Ok(Self::Terminate),
            value => Err(format!(
                "action must be auto, detach, or terminate (got {value:?})"
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Detach => "detach",
            Self::Terminate => "terminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallGraphDirection {
    Callees,
    Callers,
    Both,
}

impl CallGraphDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Callees => "callees",
            Self::Callers => "callers",
            Self::Both => "both",
        }
    }

    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value
            .unwrap_or("callees")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "callees" | "callee" | "outgoing" => Ok(Self::Callees),
            "callers" | "caller" | "incoming" => Ok(Self::Callers),
            "both" => Ok(Self::Both),
            value => Err(format!(
                "direction must be callees, callers, or both (got {value:?})"
            )),
        }
    }
}

/// Typed loader configuration for a newly-created raw-binary database.
#[derive(Debug, Clone, Default)]
pub struct RawBinaryTarget {
    pub processor: Option<String>,
    pub bitness: Option<idalib::segment::Bitness>,
    pub base_address: Option<u64>,
    pub entry_point: Option<u64>,
}

impl RawBinaryTarget {
    pub fn is_empty(&self) -> bool {
        self.processor.is_none()
            && self.bitness.is_none()
            && self.base_address.is_none()
            && self.entry_point.is_none()
    }
}

/// Database info returned after opening
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DbInfo {
    pub path: String,
    pub file_type: String,
    pub processor: String,
    pub bits: u32,
    pub function_count: usize,
    pub debug_info: Option<DebugInfoLoad>,
    pub analysis_status: AnalysisStatus,
}

/// Opaque identity for one database-open lifetime within a worker backend.
///
/// A background task captures this at open and passes it back for every later
/// operation on that database, so a close/reopen cannot silently redirect the
/// task's remaining work onto whatever database is current. It scopes both
/// cleanup (a stale task may close the database it opened, never a newer one)
/// and post-open work (a stale task must not read or mutate a newer one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseGeneration(pub(crate) u64);

/// Internal open result that carries the database lifetime identity without
/// exposing it in the public MCP tool response.
#[derive(Debug, Clone)]
pub struct OpenedDatabase {
    pub(crate) info: DbInfo,
    pub(crate) generation: DatabaseGeneration,
}

/// Result of closing only when an expected database lifetime is still active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalCloseResult {
    Closed,
    NotCurrent,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DebugInfoLoad {
    pub path: String,
    pub loaded: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalysisStatus {
    pub auto_enabled: bool,
    pub auto_is_ok: bool,
    pub auto_state: String,
    pub auto_state_id: i32,
    pub analysis_running: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscImageInfo {
    pub index: i32,
    pub name: String,
    pub file_name: String,
    pub address: String,
    pub address_value: u64,
    pub total_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_index: Option<u64>,
    pub loaded: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscRegionInfo {
    pub start: String,
    pub start_value: u64,
    pub size: u64,
    pub kind: String,
    pub image_index: i32,
    pub name: String,
    pub loaded: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: String,
    pub delta: i64,
    pub exact: bool,
    pub is_public: bool,
    pub is_weak: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionRangeInfo {
    pub address: String,
    pub name: String,
    pub start: String,
    pub end: String,
    pub size: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddressInfo {
    pub address: String,
    pub segment: Option<SegmentInfo>,
    pub function: Option<FunctionRangeInfo>,
    pub symbol: Option<SymbolInfo>,
}

/// Function info for listing
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionInfo {
    pub address: String,
    pub name: String,
    pub size: usize,
}

/// Paginated function list result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionListResult {
    pub functions: Vec<FunctionInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Segment info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SegmentInfo {
    pub name: String,
    pub start: String,
    pub end: String,
    pub size: usize,
    pub permissions: String,
    pub r#type: String,
    pub bitness: u32,
}

/// String info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringInfo {
    pub address: String,
    pub content: String,
    pub length: usize,
}

/// String list result with pagination
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringListResult {
    pub strings: Vec<StringInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringXrefInfo {
    pub address: String,
    pub content: String,
    pub length: usize,
    pub xrefs: Vec<String>,
    pub xref_count: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringXrefsResult {
    pub strings: Vec<StringXrefInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Local type info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalTypeInfo {
    pub ordinal: u32,
    pub name: String,
    pub decl: String,
    pub kind: String,
}

/// Local types list result with pagination
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalTypeListResult {
    pub types: Vec<LocalTypeInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Frame range info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrameRange {
    pub start: String,
    pub end: String,
}

/// Stack frame member info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrameMemberInfo {
    pub name: String,
    pub type_name: String,
    pub offset_bits: u64,
    pub size_bits: u64,
    pub offset: u64,
    pub size: u64,
    pub is_bitfield: bool,
    pub part: String,
}

/// Stack frame info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrameInfo {
    pub address: String,
    pub frame_size: u64,
    pub ret_size: i32,
    pub frsize: u64,
    pub frregs: u16,
    pub argsize: u64,
    pub fpd: u64,
    pub args_range: FrameRange,
    pub retaddr_range: FrameRange,
    pub savregs_range: FrameRange,
    pub locals_range: FrameRange,
    pub member_count: u32,
    pub members: Vec<FrameMemberInfo>,
}

/// Struct summary info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructSummary {
    pub ordinal: u32,
    pub name: String,
    pub size: u64,
    pub is_union: bool,
    pub member_count: u32,
}

/// Struct list result with pagination
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructListResult {
    pub structs: Vec<StructSummary>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Struct member info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructMemberInfo {
    pub name: String,
    pub type_name: String,
    pub offset_bits: u64,
    pub size_bits: u64,
    pub offset: u64,
    pub size: u64,
    pub is_bitfield: bool,
}

/// Struct detailed info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructInfo {
    pub ordinal: u32,
    pub name: String,
    pub size: u64,
    pub is_union: bool,
    pub member_count: u32,
    pub members: Vec<StructMemberInfo>,
}

/// Struct member value
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructMemberValue {
    pub name: String,
    pub type_name: String,
    pub offset_bits: u64,
    pub size_bits: u64,
    pub offset: u64,
    pub size: u64,
    pub is_bitfield: bool,
    pub bytes: String,
}

/// Struct read result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructReadResult {
    pub address: String,
    pub ordinal: u32,
    pub name: String,
    pub size: u64,
    pub members: Vec<StructMemberValue>,
}

/// Cross-reference info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XRefInfo {
    pub from: String,
    pub to: String,
    pub r#type: String,
    pub is_code: bool,
}

/// Paginated cross-reference listing.
///
/// `truncated` is true when more references exist beyond `limit`; in that case
/// `next_offset` carries the offset to pass on the next call to page through
/// the remaining references. High-frequency targets can have enormous xref
/// counts, so enumeration is always bounded.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XRefListResult {
    pub xrefs: Vec<XRefInfo>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Declared type result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeclareTypeResult {
    pub code: i32,
    pub name: String,
    pub decl: String,
    pub kind: String,
    pub replaced: bool,
}

/// Declare multiple types result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeclareTypesResult {
    pub errors: i32,
}

/// Applied type result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplyTypeResult {
    pub address: String,
    pub applied: bool,
    pub source: String,
}

/// Guess type result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GuessTypeResult {
    pub address: String,
    pub code: i32,
    pub status: String,
    pub decl: String,
    pub kind: String,
}

/// Stack variable operation result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StackVarResult {
    pub function: String,
    pub name: String,
    pub offset: i64,
    pub code: i32,
    pub status: String,
}

/// Xrefs to a struct field
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XrefsToFieldResult {
    pub struct_ordinal: u32,
    pub struct_name: String,
    pub member_index: u32,
    pub member_name: String,
    pub member_type: String,
    pub member_offset_bits: u64,
    pub member_size_bits: u64,
    pub tid: String,
    pub xrefs: Vec<XRefInfo>,
    pub truncated: bool,
}

/// Import info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImportInfo {
    pub address: String,
    pub name: String,
    pub ordinal: usize,
}

/// Export/Name info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExportInfo {
    pub address: String,
    pub name: String,
    pub is_public: bool,
}

/// Global variable/name info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalInfo {
    pub address: String,
    pub name: String,
    pub is_public: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_weak: Option<bool>,
}

/// Basic block info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BasicBlockInfo {
    pub start: String,
    pub end: String,
    pub size: usize,
    pub block_type: String,
    pub successors: Vec<String>,
    pub predecessors: Vec<String>,
}

/// Bytes result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BytesResult {
    pub address: String,
    pub bytes: String,
    pub length: usize,
}
