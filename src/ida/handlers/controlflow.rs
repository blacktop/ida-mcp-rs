//! Control flow analysis handlers.

use crate::error::ToolError;
use crate::ida::handlers::parse_address_str;
use crate::ida::types::{BasicBlockInfo, FunctionInfo};
use idalib::xref::{CodeRef, XRefQuery, XRefType};
use idalib::IDB;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};

pub fn handle_basic_blocks(idb: &Option<IDB>, addr: u64) -> Result<Vec<BasicBlockInfo>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    let cfg = func.cfg().map_err(|e| ToolError::IdaError(e.to_string()))?;

    let mut blocks = Vec::new();
    for block in cfg.blocks() {
        let block_type = if block.is_normal() {
            "normal"
        } else if block.is_ret() {
            "ret"
        } else if block.is_cndret() {
            "cndret"
        } else if block.is_noret() {
            "noret"
        } else if block.is_indjump() {
            "indjump"
        } else if block.is_extern() {
            "extern"
        } else if block.is_error() {
            "error"
        } else {
            "unknown"
        };

        let succs: Vec<String> = block
            .succs_with(&cfg)
            .map(|b| format!("{:#x}", b.start_address()))
            .collect();

        let preds: Vec<String> = block
            .preds_with(&cfg)
            .map(|b| format!("{:#x}", b.start_address()))
            .collect();

        blocks.push(BasicBlockInfo {
            start: format!("{:#x}", block.start_address()),
            end: format!("{:#x}", block.end_address()),
            size: block.len(),
            block_type: block_type.to_string(),
            successors: succs,
            predecessors: preds,
        });
    }

    Ok(blocks)
}

pub fn handle_callees(idb: &Option<IDB>, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    let mut callees = Vec::new();
    let mut seen = HashSet::new();

    // Iterate through the function's addresses and find call xrefs
    let start = func.start_address();
    let end = func.end_address();
    let mut current_addr = start;

    while current_addr < end {
        if let Some(xref) = db.first_xref_from(current_addr, XRefQuery::ALL) {
            let mut xr = Some(xref);
            while let Some(x) = xr {
                // Only follow NearCall / FarCall xrefs — skip Code(Flow) and data refs
                let is_call = matches!(
                    x.type_(),
                    XRefType::Code(CodeRef::NearCall) | XRefType::Code(CodeRef::FarCall)
                );
                if is_call {
                    let target = x.to();
                    if let Some(target_func) = db.function_at(target) {
                        // Deduplicate by function start address, not by xref target
                        let callee_start = target_func.start_address();
                        if !seen.contains(&callee_start) {
                            seen.insert(callee_start);
                            callees.push(FunctionInfo {
                                address: format!("{:#x}", callee_start),
                                name: target_func
                                    .name()
                                    .unwrap_or_else(|| format!("sub_{:x}", callee_start)),
                                size: target_func.len(),
                            });
                        }
                    }
                }
                xr = x.next_from();
            }
        }

        // Move to next instruction
        if let Some(next) = db.next_head(current_addr) {
            if next <= current_addr {
                break;
            }
            current_addr = next;
        } else {
            break;
        }
    }

    Ok(callees)
}

pub fn handle_callers(idb: &Option<IDB>, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    let mut callers = Vec::new();
    let mut seen = HashSet::new();

    // Get xrefs to the function's start address
    let mut current = db.first_xref_to(func.start_address(), XRefQuery::ALL);

    while let Some(xref) = current {
        if xref.is_code() {
            let from_addr = xref.from();
            if let Some(caller_func) = db.function_at(from_addr) {
                let caller_start = caller_func.start_address();
                if !seen.contains(&caller_start) {
                    seen.insert(caller_start);
                    callers.push(FunctionInfo {
                        address: format!("{:#x}", caller_start),
                        name: caller_func
                            .name()
                            .unwrap_or_else(|| format!("sub_{:x}", caller_start)),
                        size: caller_func.len(),
                    });
                }
            }
        }
        current = xref.next_to();
    }

    Ok(callers)
}

pub fn handle_find_paths(
    idb: &Option<IDB>,
    start: u64,
    end: u64,
    max_paths: usize,
    max_depth: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let func = db
        .function_at(start)
        .ok_or(ToolError::FunctionNotFound(start))?;
    if !func.contains_address(end) {
        return Err(ToolError::NotSupported(
            "find_paths only supports addresses within the same function".to_string(),
        ));
    }

    let cfg = func.cfg().map_err(|e| ToolError::IdaError(e.to_string()))?;
    let blocks: Vec<_> = cfg.blocks().collect();
    let mut index_by_start = HashMap::new();
    for (idx, blk) in blocks.iter().enumerate() {
        index_by_start.insert(blk.start_address(), idx);
    }

    let start_idx = blocks
        .iter()
        .position(|b| b.contains_address(start))
        .ok_or(ToolError::AddressOutOfRange(start))?;
    let end_idx = blocks
        .iter()
        .position(|b| b.contains_address(end))
        .ok_or(ToolError::AddressOutOfRange(end))?;

    let mut results: Vec<Vec<String>> = Vec::new();
    let mut path = Vec::new();

    #[allow(clippy::too_many_arguments)]
    fn dfs(
        cfg: &idalib::func::FunctionCFG<'_>,
        blocks: &[idalib::func::BasicBlock<'_>],
        index_by_start: &HashMap<u64, usize>,
        cur: usize,
        end: usize,
        max_depth: usize,
        max_paths: usize,
        path: &mut Vec<usize>,
        results: &mut Vec<Vec<String>>,
    ) {
        if results.len() >= max_paths {
            return;
        }
        if path.len() > max_depth {
            return;
        }
        path.push(cur);
        if cur == end {
            let p = path
                .iter()
                .map(|idx| format!("{:#x}", blocks[*idx].start_address()))
                .collect::<Vec<_>>();
            results.push(p);
            path.pop();
            return;
        }

        for succ in blocks[cur].succs_with(cfg) {
            if let Some(&next_idx) = index_by_start.get(&succ.start_address()) {
                if path.contains(&next_idx) {
                    continue;
                }
                dfs(
                    cfg,
                    blocks,
                    index_by_start,
                    next_idx,
                    end,
                    max_depth,
                    max_paths,
                    path,
                    results,
                );
                if results.len() >= max_paths {
                    break;
                }
            }
        }

        path.pop();
    }

    let max_depth = max_depth.max(1);
    let max_paths = max_paths.max(1);
    dfs(
        &cfg,
        &blocks,
        &index_by_start,
        start_idx,
        end_idx,
        max_depth,
        max_paths,
        &mut path,
        &mut results,
    );

    Ok(json!({ "paths": results, "count": results.len() }))
}

pub fn handle_callgraph(
    idb: &Option<IDB>,
    addr: u64,
    max_depth: usize,
    max_nodes: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let root = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    let mut nodes: HashMap<u64, FunctionInfo> = HashMap::new();
    let mut edges: Vec<(u64, u64)> = Vec::new();
    let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
    let max_depth = max_depth.max(1);
    let max_nodes = max_nodes.max(1);

    let root_addr = root.start_address();
    nodes.insert(
        root_addr,
        FunctionInfo {
            address: format!("{:#x}", root_addr),
            name: root
                .name()
                .unwrap_or_else(|| format!("sub_{:x}", root_addr)),
            size: root.len(),
        },
    );
    queue.push_back((root_addr, 0));

    while let Some((cur_addr, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if nodes.len() >= max_nodes {
            break;
        }

        let callees = handle_callees(idb, cur_addr).unwrap_or_default();
        for callee in callees {
            if let Ok(target_addr) = parse_address_str(&callee.address) {
                edges.push((cur_addr, target_addr));
                if !nodes.contains_key(&target_addr) && nodes.len() < max_nodes {
                    nodes.insert(target_addr, callee.clone());
                    queue.push_back((target_addr, depth + 1));
                }
            }
        }
    }

    let nodes_vec: Vec<Value> = nodes
        .values()
        .map(|f| json!({ "address": f.address, "name": f.name, "size": f.size }))
        .collect();
    let edges_vec: Vec<Value> = edges
        .iter()
        .map(|(from, to)| json!({ "from": format!("{:#x}", from), "to": format!("{:#x}", to) }))
        .collect();

    Ok(json!({ "nodes": nodes_vec, "edges": edges_vec }))
}
