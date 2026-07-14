//! Search handlers.

use crate::disasm::generate_disasm_line;
use crate::error::ToolError;
use crate::ida::handlers::parse_pattern;
use idalib::IDB;
use serde_json::{json, Value};

fn strip_comment(line: &str) -> &str {
    line.split(';').next().unwrap_or(line)
}

fn split_disasm_line(line: &str) -> (String, String, String) {
    let trimmed = strip_comment(line).trim();
    if trimmed.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    let mut parts = trimmed.splitn(2, |c: char| c.is_whitespace());
    let mnemonic = parts.next().unwrap_or("").trim().to_string();
    let operands = parts.next().unwrap_or("").trim().to_string();
    (mnemonic, operands, trimmed.to_string())
}

fn next_addr(db: &IDB, current: u64) -> Option<u64> {
    if let Some(insn) = db.insn_at(current) {
        let len = insn.len() as u64;
        if len == 0 {
            return None;
        }
        return Some(current.saturating_add(len));
    }
    db.next_head(current).filter(|next| *next > current)
}

fn matches_pattern(haystack: &str, pattern: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        haystack
            .to_ascii_lowercase()
            .contains(&pattern.to_ascii_lowercase())
    } else {
        haystack.contains(pattern)
    }
}

pub fn handle_find_bytes(
    idb: &Option<IDB>,
    pattern: &str,
    max_results: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let pat = parse_pattern(pattern)?;
    if pat.is_empty() {
        return Err(ToolError::IdaError("empty pattern".to_string()));
    }

    let mut matches = Vec::new();
    let pat_len = pat.len();
    let chunk_size: usize = 1024 * 1024;

    for (_id, seg) in db.segments() {
        let seg_start = seg.start_address();
        let seg_len = seg.len();
        let mut offset = 0usize;

        while offset < seg_len && matches.len() < max_results {
            let remaining = seg_len - offset;
            let read_len = remaining.min(chunk_size + pat_len.saturating_sub(1));
            let bytes = db.get_bytes(seg_start + offset as u64, read_len);
            if bytes.len() < pat_len {
                break;
            }

            for i in 0..=bytes.len() - pat_len {
                if matches.len() >= max_results {
                    break;
                }
                let mut ok = true;
                for (j, pb) in pat.iter().enumerate() {
                    if let Some(b) = pb
                        && bytes[i + j] != *b
                    {
                        ok = false;
                        break;
                    }
                }
                if ok {
                    matches.push(format!("{:#x}", seg_start + offset as u64 + i as u64));
                }
            }

            if remaining <= chunk_size {
                break;
            }
            offset += chunk_size;
        }

        if matches.len() >= max_results {
            break;
        }
    }

    Ok(json!({
        "pattern": pattern,
        "matches": matches,
        "count": matches.len()
    }))
}

pub fn handle_search_text(
    idb: &Option<IDB>,
    text: &str,
    max_results: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let mut matches = Vec::new();
    for addr in db.find_text_iter(text) {
        matches.push(format!("{:#x}", addr));
        if matches.len() >= max_results {
            break;
        }
    }
    Ok(json!({ "matches": matches, "count": matches.len() }))
}

pub fn handle_search_imm(
    idb: &Option<IDB>,
    imm: u64,
    max_results: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let imm32 = imm as u32;
    let mut matches = Vec::new();
    for addr in db.find_imm_iter(imm32) {
        matches.push(format!("{:#x}", addr));
        if matches.len() >= max_results {
            break;
        }
    }
    Ok(json!({ "matches": matches, "count": matches.len() }))
}

pub fn handle_find_insns(
    idb: &Option<IDB>,
    patterns: &[String],
    max_results: usize,
    case_insensitive: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    if patterns.is_empty() {
        return Err(ToolError::InvalidParams("empty patterns".to_string()));
    }

    let patterns_norm: Vec<String> = if case_insensitive {
        patterns.iter().map(|p| p.to_ascii_lowercase()).collect()
    } else {
        patterns.to_vec()
    };
    let mut matches = Vec::new();

    for (_id, seg) in db.segments() {
        let seg_end = seg.end_address();
        let mut addr = seg.start_address();

        while addr < seg_end && matches.len() < max_results {
            if let Some(line) = generate_disasm_line(db, addr) {
                let (mnemonic, _operands, clean_line) = split_disasm_line(&line);
                if !mnemonic.is_empty() {
                    let mnemonic_cmp = if case_insensitive {
                        mnemonic.to_ascii_lowercase()
                    } else {
                        mnemonic.clone()
                    };
                    let line_cmp = if case_insensitive {
                        clean_line.to_ascii_lowercase()
                    } else {
                        clean_line.clone()
                    };
                    let first_pat = &patterns_norm[0];
                    let first_match = if first_pat.contains(' ') || first_pat.contains(',') {
                        line_cmp.contains(first_pat)
                    } else {
                        mnemonic_cmp.contains(first_pat)
                    };

                    if first_match {
                        if patterns_norm.len() == 1 {
                            matches.push(json!({
                                "address": format!("{:#x}", addr),
                                "mnemonic": mnemonic,
                                "line": clean_line
                            }));
                        } else {
                            let mut seq_addrs = vec![addr];
                            let mut current = addr;
                            let mut ok = true;
                            for pat in patterns_norm.iter().skip(1) {
                                let next = match next_addr(db, current) {
                                    Some(next) if next < seg_end => next,
                                    _ => {
                                        ok = false;
                                        break;
                                    }
                                };
                                let next_line = match generate_disasm_line(db, next) {
                                    Some(line) => line,
                                    None => {
                                        ok = false;
                                        break;
                                    }
                                };
                                let (next_mnemonic, _next_operands, next_clean) =
                                    split_disasm_line(&next_line);
                                if next_mnemonic.is_empty() {
                                    ok = false;
                                    break;
                                }
                                let next_mnemonic_cmp = if case_insensitive {
                                    next_mnemonic.to_ascii_lowercase()
                                } else {
                                    next_mnemonic.clone()
                                };
                                let next_line_cmp = if case_insensitive {
                                    next_clean.to_ascii_lowercase()
                                } else {
                                    next_clean.clone()
                                };
                                let pat_match = if pat.contains(' ') || pat.contains(',') {
                                    next_line_cmp.contains(pat)
                                } else {
                                    next_mnemonic_cmp.contains(pat)
                                };
                                if !pat_match {
                                    ok = false;
                                    break;
                                }
                                seq_addrs.push(next);
                                current = next;
                            }
                            if ok {
                                matches.push(json!({
                                    "address": format!("{:#x}", addr),
                                    "mnemonic": mnemonic,
                                    "line": clean_line,
                                    "sequence": seq_addrs.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>()
                                }));
                            }
                        }
                    }
                }
            }

            match next_addr(db, addr) {
                Some(next) if next > addr => addr = next,
                _ => break,
            }
        }

        if matches.len() >= max_results {
            break;
        }
    }

    Ok(json!({
        "patterns": patterns,
        "case_insensitive": case_insensitive,
        "matches": matches,
        "count": matches.len()
    }))
}

pub fn handle_find_insn_operands(
    idb: &Option<IDB>,
    patterns: &[String],
    max_results: usize,
    case_insensitive: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    if patterns.is_empty() {
        return Err(ToolError::InvalidParams("empty patterns".to_string()));
    }

    let patterns_norm: Vec<String> = if case_insensitive {
        patterns.iter().map(|p| p.to_ascii_lowercase()).collect()
    } else {
        patterns.to_vec()
    };
    let mut matches = Vec::new();

    for (_id, seg) in db.segments() {
        let seg_end = seg.end_address();
        let mut addr = seg.start_address();

        while addr < seg_end && matches.len() < max_results {
            if let Some(line) = generate_disasm_line(db, addr) {
                let (mnemonic, operands, clean_line) = split_disasm_line(&line);
                if !mnemonic.is_empty() {
                    let operands_cmp = if case_insensitive {
                        operands.to_ascii_lowercase()
                    } else {
                        operands.clone()
                    };
                    if patterns_norm
                        .iter()
                        .any(|pat| matches_pattern(&operands_cmp, pat, false))
                    {
                        matches.push(json!({
                            "address": format!("{:#x}", addr),
                            "mnemonic": mnemonic,
                            "operands": operands,
                            "line": clean_line
                        }));
                    }
                }
            }

            match next_addr(db, addr) {
                Some(next) if next > addr => addr = next,
                _ => break,
            }
        }

        if matches.len() >= max_results {
            break;
        }
    }

    Ok(json!({
        "patterns": patterns,
        "case_insensitive": case_insensitive,
        "matches": matches,
        "count": matches.len()
    }))
}
