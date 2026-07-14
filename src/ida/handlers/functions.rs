//! Function-related handlers.

use crate::error::ToolError;
use crate::ida::handlers::parse_address_str;
use crate::ida::observability::{
    emit_progress, ensure_not_cancelled, ProgressHeartbeat, ProgressSender,
    SINGLE_PHASE_PROGRESS_TOTAL,
};
use crate::ida::types::{FunctionInfo, FunctionListResult, FunctionRangeInfo};
use idalib::IDB;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

pub fn handle_list_functions(
    idb: &Option<IDB>,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> Result<FunctionListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let filter_lower = filter.map(|f| f.to_lowercase());
    let mut functions = Vec::with_capacity(limit);
    let mut total = 0usize;

    for (_id, func) in db.functions() {
        let addr = func.start_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));
        let size = func.len();

        if let Some(f) = &filter_lower
            && !name.to_lowercase().contains(f)
        {
            continue;
        }

        total += 1;
        if total <= offset {
            continue;
        }
        if functions.len() >= limit {
            continue;
        }

        functions.push(FunctionInfo {
            address: format!("{:#x}", addr),
            name,
            size,
        });
    }

    let next_offset = if offset.saturating_add(functions.len()) < total {
        Some(offset.saturating_add(functions.len()))
    } else {
        None
    };

    Ok(FunctionListResult {
        functions,
        total,
        next_offset,
    })
}

pub fn handle_resolve_function(idb: &Option<IDB>, name: &str) -> Result<FunctionInfo, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name()
            && (func_name == name || func_name.contains(name))
        {
            let addr = func.start_address();
            let size = func.len();
            return Ok(FunctionInfo {
                address: format!("{:#x}", addr),
                name: func_name,
                size,
            });
        }
    }

    Err(ToolError::FunctionNameNotFound(name.to_string()))
}

pub fn handle_lookup_funcs(idb: &Option<IDB>, queries: &[String]) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut results = Vec::with_capacity(queries.len());

    // Precompute functions for name lookups
    let funcs: Vec<FunctionInfo> = db
        .functions()
        .map(|(_id, func)| {
            let addr = func.start_address();
            let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));
            let size = func.len();
            FunctionInfo {
                address: format!("{:#x}", addr),
                name,
                size,
            }
        })
        .collect();

    for query in queries {
        if let Ok(addr) = parse_address_str(query) {
            if let Some(func) = db.function_at(addr) {
                let info = FunctionInfo {
                    address: format!("{:#x}", func.start_address()),
                    name: func
                        .name()
                        .unwrap_or_else(|| format!("sub_{:x}", func.start_address())),
                    size: func.len(),
                };
                results.push(json!({"query": query, "result": info}));
            } else {
                results.push(json!({"query": query, "error": "Function not found"}));
            }
            continue;
        }

        if let Some(info) = funcs
            .iter()
            .find(|f| f.name == *query || f.name.contains(query))
        {
            results.push(json!({"query": query, "result": info}));
        } else {
            results.push(json!({"query": query, "error": "Function not found"}));
        }
    }

    Ok(json!({ "results": results }))
}

pub fn handle_analyze_funcs(
    idb: &mut Option<IDB>,
    progress_tx: Option<ProgressSender>,
    cancel: Option<CancellationToken>,
) -> Result<Value, ToolError> {
    let db = idb.as_mut().ok_or(ToolError::NoDatabaseOpen)?;
    ensure_not_cancelled(cancel.as_ref())?;
    let _heartbeat = ProgressHeartbeat::start(
        progress_tx.clone(),
        "analyzing",
        0.0,
        0.95,
        Some(SINGLE_PHASE_PROGRESS_TOTAL),
        "Waiting for IDA auto-analysis to finish",
    );
    let completed = db.auto_wait();
    ensure_not_cancelled(cancel.as_ref())?;
    emit_progress(
        progress_tx.as_ref(),
        "analyzing",
        0.95,
        Some(SINGLE_PHASE_PROGRESS_TOTAL),
        "IDA auto-analysis finished; collecting result",
    );
    Ok(json!({
        "completed": completed,
        "function_count": db.function_count(),
    }))
}

pub fn handle_function_at(idb: &Option<IDB>, addr: u64) -> Result<FunctionRangeInfo, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;
    let start = func.start_address();
    let end = func.end_address();
    let name = func.name().unwrap_or_else(|| format!("sub_{:x}", start));
    Ok(FunctionRangeInfo {
        address: format!("{:#x}", start),
        name,
        start: format!("{:#x}", start),
        end: format!("{:#x}", end),
        size: func.len(),
    })
}
