//! IDA operation handlers organized by domain.

pub mod address;
pub mod analysis;
pub mod annotations;
pub mod controlflow;
pub mod database;
pub mod disasm;
pub mod functions;
pub mod globals;
pub mod imports;
pub mod memory;
pub mod script;
pub mod search;
pub mod segments;
pub mod strings;
pub mod structs;
pub mod types;
pub mod xrefs;

use crate::error::ToolError;
use idalib::IDB;

// ============================================================================
// Shared utility functions used across multiple handlers
// ============================================================================

/// Parse an address string supporting hex (0x), binary (0b), octal (0o), and decimal.
pub(crate) fn parse_address_str(s: &str) -> Result<u64, ToolError> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| ToolError::InvalidAddress(s.to_string()))
    } else if s.starts_with("0b") || s.starts_with("0B") {
        u64::from_str_radix(&s[2..], 2).map_err(|_| ToolError::InvalidAddress(s.to_string()))
    } else if s.starts_with("0o") || s.starts_with("0O") {
        u64::from_str_radix(&s[2..], 8).map_err(|_| ToolError::InvalidAddress(s.to_string()))
    } else {
        s.parse::<u64>()
            .map_err(|_| ToolError::InvalidAddress(s.to_string()))
    }
}

/// Try to parse an address string, returning None on failure.
pub(crate) fn try_parse_address(s: &str) -> Option<u64> {
    parse_address_str(s).ok()
}

/// Encode bytes as hex string.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Resolve an address by name (function or symbol).
pub(crate) fn resolve_address_by_name(idb: &Option<IDB>, name: &str) -> Result<u64, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name() {
            if func_name == name || func_name.contains(name) {
                return Ok(func.start_address());
            }
        }
    }
    for item in db.names().iter() {
        let item_name = item.name();
        if item_name == name || item_name.contains(name) {
            return Ok(item.address());
        }
    }
    Err(ToolError::FunctionNameNotFound(name.to_string()))
}

/// Resolve an address from either explicit address, name, or name+offset.
pub(crate) fn resolve_address(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: u64,
) -> Result<u64, ToolError> {
    let base = if let Some(addr) = addr {
        addr
    } else if let Some(name) = name {
        resolve_address_by_name(idb, name)?
    } else {
        return Err(ToolError::InvalidParams(
            "expected address or name".to_string(),
        ));
    };
    Ok(base.saturating_add(offset))
}

/// Parse a byte pattern string supporting wildcards.
pub(crate) fn parse_pattern(pattern: &str) -> Result<Vec<Option<u8>>, ToolError> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err(ToolError::IdaError("empty pattern".to_string()));
    }

    let tokens: Vec<String> = if trimmed.contains(' ') {
        trimmed.split_whitespace().map(|s| s.to_string()).collect()
    } else {
        if !trimmed.len().is_multiple_of(2) {
            return Err(ToolError::IdaError(format!(
                "invalid hex pattern length: {}",
                trimmed
            )));
        }
        trimmed
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect()
    };

    let mut bytes = Vec::with_capacity(tokens.len());
    for tok in tokens {
        if tok == "?" || tok == "??" {
            bytes.push(None);
            continue;
        }
        let b = u8::from_str_radix(tok.trim_start_matches("0x"), 16)
            .map_err(|_| ToolError::IdaError(format!("invalid byte: {}", tok)))?;
        bytes.push(Some(b));
    }

    Ok(bytes)
}
