//! String-related handlers.

use crate::error::ToolError;
use crate::ida::handlers::hex_encode;
use crate::ida::types::{StringInfo, StringListResult, StringXrefInfo, StringXrefsResult};
use idalib::xref::XRefQuery;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_strings(
    idb: &Option<IDB>,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> Result<StringListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let string_list = db.strings();
    let filter_lower = filter.map(|f| f.to_lowercase());
    let mut total = 0usize;
    let mut strings = Vec::new();

    for (addr, content) in string_list.iter() {
        // Apply filter if provided
        if let Some(f) = &filter_lower
            && !content.to_lowercase().contains(f)
        {
            continue;
        }

        total += 1;
        if total <= offset {
            continue;
        }
        if strings.len() >= limit {
            continue;
        }

        strings.push(StringInfo {
            address: format!("{:#x}", addr),
            content: content.clone(),
            length: content.len(),
        });
    }

    let next_offset = if offset.saturating_add(strings.len()) < total {
        Some(offset.saturating_add(strings.len()))
    } else {
        None
    };

    Ok(StringListResult {
        strings,
        total,
        next_offset,
    })
}

pub fn handle_analyze_strings(
    idb: &Option<IDB>,
    query: Option<&str>,
    offset: usize,
    limit: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let filter_lower = query.map(|q| q.to_lowercase());

    let string_list = db.strings();
    let mut total = 0usize;
    let mut results = Vec::new();

    for (addr, content) in string_list.iter() {
        if let Some(f) = &filter_lower
            && !content.to_lowercase().contains(f)
        {
            continue;
        }

        total += 1;
        if total <= offset {
            continue;
        }
        if results.len() >= limit {
            continue;
        }

        let mut xrefs = Vec::new();
        let mut current = db.first_xref_to(addr, XRefQuery::ALL);
        while let Some(xref) = current {
            xrefs.push(format!("{:#x}", xref.from()));
            if xrefs.len() >= 64 {
                break;
            }
            current = xref.next_to();
        }

        results.push(json!({
            "address": format!("{:#x}", addr),
            "content": content,
            "length": content.len(),
            "xrefs": xrefs,
            "xref_count": xrefs.len(),
        }));
    }

    let next_offset = if offset.saturating_add(results.len()) < total {
        Some(offset.saturating_add(results.len()))
    } else {
        None
    };

    Ok(json!({
        "strings": results,
        "total": total,
        "next_offset": next_offset
    }))
}

pub fn handle_get_string(idb: &Option<IDB>, addr: u64, max_len: usize) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let max_len = max_len.min(0x10000);
    let bytes = db.get_bytes(addr, max_len);
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..len]).into_owned();

    Ok(json!({
        "address": format!("{:#x}", addr),
        "string": s,
        "length": len,
        "bytes": hex_encode(&bytes[..len]),
    }))
}

pub fn handle_find_string(
    idb: &Option<IDB>,
    query: &str,
    exact: bool,
    case_insensitive: bool,
    offset: usize,
    limit: usize,
) -> Result<StringListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let query_norm = if case_insensitive {
        query.to_lowercase()
    } else {
        query.to_string()
    };

    let mut total = 0usize;
    let mut strings = Vec::new();

    for (addr, content) in db.strings().iter() {
        let hay = if case_insensitive {
            content.to_lowercase()
        } else {
            content.clone()
        };
        let matched = if exact {
            hay == query_norm
        } else {
            hay.contains(&query_norm)
        };
        if !matched {
            continue;
        }

        total += 1;
        if total <= offset {
            continue;
        }
        if strings.len() >= limit {
            continue;
        }

        strings.push(StringInfo {
            address: format!("{:#x}", addr),
            content: content.clone(),
            length: content.len(),
        });
    }

    let next_offset = if offset.saturating_add(strings.len()) < total {
        Some(offset.saturating_add(strings.len()))
    } else {
        None
    };

    Ok(StringListResult {
        strings,
        total,
        next_offset,
    })
}

pub fn handle_xrefs_to_string(
    idb: &Option<IDB>,
    query: &str,
    exact: bool,
    case_insensitive: bool,
    offset: usize,
    limit: usize,
    max_xrefs: usize,
) -> Result<StringXrefsResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let query_norm = if case_insensitive {
        query.to_lowercase()
    } else {
        query.to_string()
    };

    let mut total = 0usize;
    let mut strings = Vec::new();
    let max_xrefs = max_xrefs.clamp(1, 1024);

    for (addr, content) in db.strings().iter() {
        let hay = if case_insensitive {
            content.to_lowercase()
        } else {
            content.clone()
        };
        let matched = if exact {
            hay == query_norm
        } else {
            hay.contains(&query_norm)
        };
        if !matched {
            continue;
        }

        total += 1;
        if total <= offset {
            continue;
        }
        if strings.len() >= limit {
            continue;
        }

        let mut xrefs = Vec::new();
        let mut current = db.first_xref_to(addr, XRefQuery::ALL);
        while let Some(xref) = current {
            xrefs.push(format!("{:#x}", xref.from()));
            if xrefs.len() >= max_xrefs {
                break;
            }
            current = xref.next_to();
        }

        let xref_count = xrefs.len();
        strings.push(StringXrefInfo {
            address: format!("{:#x}", addr),
            content: content.clone(),
            length: content.len(),
            xrefs,
            xref_count,
        });
    }

    let next_offset = if offset.saturating_add(strings.len()) < total {
        Some(offset.saturating_add(strings.len()))
    } else {
        None
    };

    Ok(StringXrefsResult {
        strings,
        total,
        next_offset,
    })
}
