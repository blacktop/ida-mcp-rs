//! Memory read/write handlers.

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use crate::ida::types::BytesResult;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_get_bytes(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    size: usize,
) -> Result<BytesResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;

    // Limit size to prevent huge reads
    let size = size.min(0x10000); // 64KB max

    let bytes = db.get_bytes(addr, size);
    let hex_string = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(BytesResult {
        address: format!("{:#x}", addr),
        bytes: hex_string,
        length: bytes.len(),
    })
}

pub fn handle_patch_bytes(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    bytes: &[u8],
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    db.patch_bytes(addr, bytes)?;
    Ok(json!({
        "address": format!("{:#x}", addr),
        "length": bytes.len(),
    }))
}

pub fn handle_patch_asm(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    line: &str,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    let bytes = db
        .assemble_line(addr, line)
        .map_err(|e| ToolError::IdaError(e.to_string()))?;
    db.patch_bytes(addr, &bytes)?;
    let hex = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(json!({
        "address": format!("{:#x}", addr),
        "line": line,
        "length": bytes.len(),
        "bytes": hex,
    }))
}

pub fn handle_read_int(idb: &Option<IDB>, addr: u64, size: usize) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let value = match size {
        1 => db.get_byte(addr) as u64,
        2 => db.get_word(addr) as u64,
        4 => db.get_dword(addr) as u64,
        8 => db.get_qword(addr),
        _ => {
            return Err(ToolError::IdaError(format!(
                "unsupported integer size: {}",
                size
            )));
        }
    };

    Ok(json!({
        "address": format!("{:#x}", addr),
        "size": size,
        "value": value,
        "hex": format!("0x{:x}", value)
    }))
}
