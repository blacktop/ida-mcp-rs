//! Disassembly and decompilation handlers.

use crate::disasm::generate_disasm_line;
use crate::error::ToolError;
use idalib::{Address, PatchedByte, IDB};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;

pub fn handle_disasm_by_name(
    idb: &Option<IDB>,
    name: &str,
    count: usize,
) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name()
            && (func_name == name || func_name.contains(name))
        {
            let addr = func.start_address();
            return handle_disasm(idb, addr, count);
        }
    }

    Err(ToolError::FunctionNameNotFound(name.to_string()))
}

/// Address of the item after `current`, or `None` when the walk cannot
/// advance. Prefers the decoded instruction length and falls back to IDA's
/// next head, bounded by `limit` when the caller renders a fixed range.
/// Never returns an address at or before `current`, so no caller can loop.
fn next_disasm_address(db: &IDB, current: Address, limit: Option<u64>) -> Option<Address> {
    let next = match db.insn_at(current) {
        Some(insn) => current.checked_add(insn.len() as u64)?,
        None => match limit {
            Some(limit) => db.next_head_with(current, limit)?,
            None => db.next_head(current)?,
        },
    };
    (next > current).then_some(next)
}

pub fn handle_disasm(idb: &Option<IDB>, addr: u64, count: usize) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut lines = Vec::with_capacity(count);
    let mut current_addr: Address = addr;

    for _ in 0..count {
        // Get disassembly line
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            // No more valid instructions
            break;
        }

        let Some(next) = next_disasm_address(db, current_addr, None) else {
            break;
        };
        current_addr = next;
    }

    if lines.is_empty() {
        return Err(ToolError::AddressOutOfRange(addr));
    }

    Ok(lines.join("\n"))
}

pub fn handle_render_range(
    idb: &Option<IDB>,
    start: u64,
    end: u64,
    max_lines: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    if end <= start {
        return Err(ToolError::InvalidParams(
            "end must be greater than start".to_string(),
        ));
    }
    if end - start > 0x1_0000 {
        return Err(ToolError::InvalidParams(
            "render_range is limited to 65536 bytes per call".to_string(),
        ));
    }

    let max_lines = max_lines.clamp(1, 4096);
    let mut lines = Vec::with_capacity(max_lines.min(512));
    let mut current = start;
    let mut next_address = None;

    while current < end {
        let line = generate_disasm_line(db, current);
        let next = next_disasm_address(db, current, Some(end));

        if let Some(line) = line {
            lines.push(format!("{:#x}:\t{}", current, line));
            if lines.len() >= max_lines {
                if let Some(next) = next.filter(|address| *address < end && *address > current) {
                    next_address = Some(next);
                } else {
                    current = end;
                }
                break;
            }
        }

        match next {
            Some(next) if next > current && next < end => current = next,
            _ => {
                current = end;
                break;
            }
        }
    }

    if lines.is_empty() {
        return Err(ToolError::AddressOutOfRange(start));
    }

    let rendered_until = next_address.unwrap_or(current.min(end));
    let text = lines.join("\n");
    Ok(json!({
        "start": format!("{:#x}", start),
        "end": format!("{:#x}", end),
        "rendered_until": format!("{:#x}", rendered_until),
        "truncated": next_address.is_some(),
        "next_address": next_address.map(|address| format!("{:#x}", address)),
        "line_count": lines.len(),
        "lines": lines,
        "text": text,
    }))
}

#[derive(Debug, Clone, Serialize)]
struct PatchRange {
    start: String,
    end: String,
    length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_offset: Option<i64>,
    original_values: Vec<u64>,
    patched_values: Vec<u64>,
    original_hex: String,
    patched_hex: String,
}

fn format_patch_values(values: &[u64]) -> String {
    values
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn coalesce_patched_bytes(bytes: &[PatchedByte]) -> Vec<PatchRange> {
    let mut ranges = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        let first = bytes[index];
        let mut end_index = index + 1;
        while end_index < bytes.len() {
            let previous = bytes[end_index - 1];
            let current = bytes[end_index];
            let addresses_touch = current.address == previous.address.saturating_add(1);
            let offsets_touch = if previous.file_offset < 0 || current.file_offset < 0 {
                previous.file_offset < 0 && current.file_offset < 0
            } else {
                current.file_offset == previous.file_offset.saturating_add(1)
            };
            if !addresses_touch || !offsets_touch {
                break;
            }
            end_index += 1;
        }

        let original_values = bytes[index..end_index]
            .iter()
            .map(|byte| byte.original_value)
            .collect::<Vec<_>>();
        let patched_values = bytes[index..end_index]
            .iter()
            .map(|byte| byte.patched_value)
            .collect::<Vec<_>>();
        let end = bytes[end_index - 1].address.saturating_add(1);
        ranges.push(PatchRange {
            start: format!("{:#x}", first.address),
            end: format!("{:#x}", end),
            length: end_index - index,
            file_offset: (first.file_offset >= 0).then_some(first.file_offset),
            original_hex: format_patch_values(&original_values),
            patched_hex: format_patch_values(&patched_values),
            original_values,
            patched_values,
        });
        index = end_index;
    }

    ranges
}

pub fn handle_list_patches(
    idb: &Option<IDB>,
    start: Option<u64>,
    end: Option<u64>,
    offset: usize,
    limit: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let meta = db.meta();
    let start = start.unwrap_or_else(|| meta.min_address());
    let end = end.unwrap_or_else(|| meta.max_address());
    if end <= start {
        return Err(ToolError::InvalidParams(
            "end must be greater than start".to_string(),
        ));
    }

    let patches = db
        .patched_bytes(start, end)
        .map_err(|error| ToolError::IdaError(error.to_string()))?;
    let ranges = coalesce_patched_bytes(&patches);
    let total = ranges.len();
    let page = ranges
        .into_iter()
        .skip(offset)
        .take(limit.max(1))
        .collect::<Vec<_>>();
    let next_offset =
        (offset.saturating_add(page.len()) < total).then_some(offset.saturating_add(page.len()));

    Ok(json!({
        "start": format!("{:#x}", start),
        "end": format!("{:#x}", end),
        "ranges": page,
        "total": total,
        "next_offset": next_offset,
    }))
}

pub fn handle_disasm_function_at(
    idb: &Option<IDB>,
    addr: u64,
    count: usize,
) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;
    let start = func.start_address();
    let end = func.end_address();

    let mut lines = Vec::new();
    let mut current_addr: Address = start;

    while current_addr < end && lines.len() < count {
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            break;
        }

        if let Some(insn) = db.insn_at(current_addr) {
            current_addr += insn.len() as u64;
        } else if let Some(next) = db.next_head(current_addr) {
            if next <= current_addr {
                break;
            }
            current_addr = next;
        } else {
            break;
        }
    }

    if lines.is_empty() {
        return Err(ToolError::AddressOutOfRange(addr));
    }

    Ok(lines.join("\n"))
}

pub fn handle_decompile(idb: &Option<IDB>, addr: u64) -> Result<String, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    if !db.decompiler_available() {
        return Err(ToolError::DecompilerUnavailable);
    }

    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    let cfunc = db
        .decompile(&func)
        .map_err(|e| ToolError::IdaError(e.to_string()))?;

    Ok(cfunc.pseudocode())
}

/// Get decompiled pseudocode statements at a specific address or address range.
pub fn handle_pseudocode_at(
    idb: &Option<IDB>,
    addr: u64,
    end_addr: Option<u64>,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    // Check if decompiler is available
    if !db.decompiler_available() {
        return Err(ToolError::DecompilerUnavailable);
    }

    // Find the function at this address
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    let func_start = func.start_address();
    let func_end = func.end_address();
    let func_name = func
        .name()
        .unwrap_or_else(|| format!("sub_{:x}", func_start));

    let cfunc = db
        .decompile(&func)
        .map_err(|e| ToolError::IdaError(e.to_string()))?;

    let eamap_ready = cfunc.has_eamap();

    let mut statements = Vec::new();
    let mut seen_eas = HashSet::new();

    if let Some(end) = end_addr {
        // Range query - collect unique statements that cover any address in [addr, end)
        let mut cur = addr;
        while cur < end {
            if let Some(stmts) = cfunc.statements_at(cur) {
                for stmt in stmts {
                    let stmt_ea = stmt.address();
                    if seen_eas.insert(stmt_ea) {
                        let text = stmt.to_string();
                        let bounds = stmt.bounds();
                        statements.push(json!({
                            "address": format!("{:#x}", stmt_ea),
                            "text": text.trim(),
                            "opcode": stmt.opcode(),
                            "bounds": bounds.map(|b| json!({
                                "start": format!("{:#x}", b.start),
                                "end": format!("{:#x}", b.end),
                            })),
                        }));
                    }
                }
            }
            cur += 1;
        }
    } else {
        // Single address query
        if let Some(stmts) = cfunc.statements_at(addr) {
            for stmt in stmts {
                let stmt_ea = stmt.address();
                if seen_eas.insert(stmt_ea) {
                    let text = stmt.to_string();
                    let bounds = stmt.bounds();
                    statements.push(json!({
                        "address": format!("{:#x}", stmt_ea),
                        "text": text.trim(),
                        "opcode": stmt.opcode(),
                        "bounds": bounds.map(|b| json!({
                            "start": format!("{:#x}", b.start),
                            "end": format!("{:#x}", b.end),
                        })),
                    }));
                }
            }
        }
    }

    Ok(json!({
        "function": {
            "address": format!("{:#x}", func_start),
            "name": func_name,
            "start": format!("{:#x}", func_start),
            "end": format!("{:#x}", func_end),
        },
        "query_address": format!("{:#x}", addr),
        "query_end_address": end_addr.map(|a| format!("{:#x}", a)),
        "eamap_ready": eamap_ready,
        "statements": statements,
        "count": statements.len(),
    }))
}

#[cfg(test)]
mod tests {
    use crate::ida::handlers::disasm::coalesce_patched_bytes;
    use idalib::PatchedByte;

    #[test]
    fn patched_bytes_coalesce_only_when_address_and_file_offset_are_contiguous() {
        let ranges = coalesce_patched_bytes(&[
            PatchedByte {
                address: 0x1000,
                file_offset: 0x20,
                original_value: 0xaa,
                patched_value: 0x11,
            },
            PatchedByte {
                address: 0x1001,
                file_offset: 0x21,
                original_value: 0xbb,
                patched_value: 0x22,
            },
            PatchedByte {
                address: 0x1003,
                file_offset: 0x23,
                original_value: 0xcc,
                patched_value: 0x33,
            },
        ]);

        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, "0x1000");
        assert_eq!(ranges[0].end, "0x1002");
        assert_eq!(ranges[0].original_hex, "aa bb");
        assert_eq!(ranges[0].patched_hex, "11 22");
        assert_eq!(ranges[1].start, "0x1003");
    }

    #[test]
    fn unmapped_patches_can_coalesce_without_a_file_offset() {
        let ranges = coalesce_patched_bytes(&[
            PatchedByte {
                address: 0x2000,
                file_offset: -1,
                original_value: 0,
                patched_value: 1,
            },
            PatchedByte {
                address: 0x2001,
                file_offset: -1,
                original_value: 0,
                patched_value: 2,
            },
        ]);

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].file_offset, None);
        assert_eq!(ranges[0].length, 2);
    }

    #[test]
    fn unmapped_patch_does_not_coalesce_with_file_offset_zero() {
        let ranges = coalesce_patched_bytes(&[
            PatchedByte {
                address: 0x3000,
                file_offset: -1,
                original_value: 0xaa,
                patched_value: 0x11,
            },
            PatchedByte {
                address: 0x3001,
                file_offset: 0,
                original_value: 0xbb,
                patched_value: 0x22,
            },
        ]);

        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].file_offset, None);
        assert_eq!(ranges[1].file_offset, Some(0));
    }
}
