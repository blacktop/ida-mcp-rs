//! Global variable handlers.

use crate::error::ToolError;
use crate::ida::handlers::{hex_encode, try_parse_address};
use crate::ida::types::GlobalInfo;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_list_globals(
    idb: &Option<IDB>,
    query: Option<&str>,
    offset: usize,
    limit: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let filter_lower = query.map(|q| q.to_lowercase());

    let mut globals = Vec::new();
    let mut total = 0usize;

    for name in db.names().iter() {
        if let Some(f) = &filter_lower
            && !name.name().to_lowercase().contains(f)
        {
            continue;
        }

        // Only consider named addresses outside of functions
        if db.function_at(name.address()).is_some() {
            continue;
        }

        total += 1;
        if total <= offset {
            continue;
        }
        if globals.len() >= limit {
            continue;
        }

        globals.push(GlobalInfo {
            address: format!("{:#x}", name.address()),
            name: name.name().to_string(),
            is_public: name.is_public(),
            is_weak: Some(name.is_weak()),
        });
    }

    let next_offset = if offset.saturating_add(globals.len()) < total {
        Some(offset.saturating_add(globals.len()))
    } else {
        None
    };

    Ok(json!({
        "globals": globals,
        "total": total,
        "next_offset": next_offset
    }))
}

pub fn handle_get_global_value(idb: &Option<IDB>, query: &str) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let addr = if let Some(a) = try_parse_address(query) {
        a
    } else {
        let mut found = None;
        for name in db.names().iter() {
            if name.name() == query {
                found = Some(name.address());
                break;
            }
        }
        found.ok_or_else(|| ToolError::FunctionNameNotFound(query.to_string()))?
    };

    let bytes = db.get_bytes(addr, 8);
    let mut val: u64 = 0;
    for (i, b) in bytes.iter().take(8).enumerate() {
        val |= (*b as u64) << (i * 8);
    }

    Ok(json!({
        "address": format!("{:#x}", addr),
        "value": val,
        "hex": format!("0x{:x}", val),
        "bytes": hex_encode(&bytes),
    }))
}

pub fn handle_idb_meta(idb: &Option<IDB>) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let meta = db.meta();

    let bits = if meta.is_64bit() {
        64
    } else if meta.is_32bit_exactly() {
        32
    } else {
        16
    };

    let md5 = hex_encode(&meta.input_file_md5());
    let sha256 = hex_encode(&meta.input_file_sha256());

    Ok(json!({
        "file_type": format!("{:?}", meta.filetype()),
        "processor": db.processor().long_name(),
        "bits": bits,
        "function_count": db.function_count(),
        "input_file_path": meta.input_file_path(),
        "input_file_size": meta.input_file_size(),
        "md5": md5,
        "sha256": sha256,
        "base_address": meta.base_address().map(|a| format!("{:#x}", a)),
        "min_address": format!("{:#x}", meta.min_address()),
        "max_address": format!("{:#x}", meta.max_address()),
        "main_address": meta.main_address().map(|a| format!("{:#x}", a)),
    }))
}
