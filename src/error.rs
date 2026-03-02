//! Error types for the IDA MCP server.
//!
//! Tool execution errors are returned with `is_error: true` in CallToolResult,
//! while protocol errors (invalid tool name, malformed args) are handled by rmcp.

use rmcp::model::{CallToolResult, Content};
use thiserror::Error;

/// Tool execution errors - returned with is_error: true in CallToolResult
#[derive(Error, Debug)]
pub enum ToolError {
    #[error("No database is currently open")]
    NoDatabaseOpen,

    #[error("A database is already open: {0}. Use close_idb first.")]
    DatabaseAlreadyOpen(String),

    #[error("Failed to open database: {0}")]
    OpenFailed(String),

    #[error("Database appears to be open in another instance: {0}")]
    DatabaseLocked(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    #[error("Invalid database path: {0}")]
    InvalidPath(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Invalid tool category: {0}")]
    InvalidToolCategory(String),

    #[error("Invalid tool name: {0}")]
    InvalidToolName(String),

    #[error("Address {0:#x} is outside valid range")]
    AddressOutOfRange(u64),

    #[error("Function not found at address {0:#x}")]
    FunctionNotFound(u64),

    #[error("Function not found: {0}")]
    FunctionNameNotFound(String),

    #[error("Decompiler not available")]
    DecompilerUnavailable,

    #[error("Operation timed out after {0} seconds")]
    Timeout(u64),

    #[error("Server is busy (request queue full). Please retry.")]
    Busy,

    #[error("IDA error: {0}")]
    IdaError(String),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("Worker channel closed")]
    WorkerClosed,

    #[error("SDK version mismatch: {0}")]
    SdkVersionMismatch(String),
}

impl ToolError {
    /// Convert to MCP CallToolResult with is_error: true
    pub fn to_tool_result(&self) -> CallToolResult {
        CallToolResult {
            content: vec![Content::text(self.to_string())],
            is_error: Some(true),
            meta: None,
            structured_content: None,
        }
    }
}

impl From<idalib::IDAError> for ToolError {
    fn from(e: idalib::IDAError) -> Self {
        ToolError::IdaError(e.to_string())
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for ToolError {
    fn from(_: std::sync::mpsc::SendError<T>) -> Self {
        ToolError::WorkerClosed
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for ToolError {
    fn from(_: tokio::sync::oneshot::error::RecvError) -> Self {
        ToolError::WorkerClosed
    }
}
