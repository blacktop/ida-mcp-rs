//! Struct/UDT handlers.

use crate::error::ToolError;
use crate::ida::handlers::hex_encode;
use crate::ida::types::{
    StructInfo, StructListResult, StructMemberInfo, StructMemberValue, StructReadResult,
    StructSummary, XRefInfo, XrefsToFieldResult,
};
use idalib::xref::XRefQuery;
use idalib::IDB;

/// Find a struct by name in the database.
fn find_struct_by_name(db: &IDB, name: &str) -> Option<idalib::udt::UdtInfo> {
    let query = name.trim();
    let query_lower = query.to_lowercase();
    let mut fuzzy_match = None;
    let mut fuzzy_count = 0usize;
    let limit = db.udt_ordinal_limit();
    for ordinal in 1..limit {
        // Use match/continue to skip non-struct ordinals (typedefs, enums, deleted types)
        // The ? operator would cause early return on first None, breaking the search
        let info = match db.udt_info(ordinal) {
            Some(info) => info,
            None => continue,
        };
        let info_name = info.name.as_str();
        let normalized = info_name
            .strip_prefix("struct ")
            .or_else(|| info_name.strip_prefix("union "))
            .unwrap_or(info_name);
        let query_normalized = query
            .strip_prefix("struct ")
            .or_else(|| query.strip_prefix("union "))
            .unwrap_or(query);
        if info_name == query || normalized == query || normalized == query_normalized {
            return Some(info);
        }
        if info.name.to_lowercase().contains(&query_lower) {
            fuzzy_match = Some(info);
            fuzzy_count += 1;
        }
    }
    if fuzzy_count == 1 {
        fuzzy_match
    } else {
        None
    }
}

pub fn handle_structs(
    idb: &Option<IDB>,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> Result<StructListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let filter_lower = filter.map(|f| f.to_lowercase());
    let mut total = 0usize;
    let mut structs = Vec::new();

    let ordinal_limit = db.udt_ordinal_limit();
    for ordinal in 1..ordinal_limit {
        let info = match db.udt_info(ordinal) {
            Some(info) => info,
            None => continue,
        };

        if let Some(f) = &filter_lower
            && !info.name.to_lowercase().contains(f)
        {
            continue;
        }

        total += 1;
        if total <= offset {
            continue;
        }
        if structs.len() >= limit {
            continue;
        }

        structs.push(StructSummary {
            ordinal: info.ordinal,
            name: info.name,
            size: info.size,
            is_union: info.is_union,
            member_count: info.member_count,
        });
    }

    let next_offset = if offset.saturating_add(structs.len()) < total {
        Some(offset.saturating_add(structs.len()))
    } else {
        None
    };

    Ok(StructListResult {
        structs,
        total,
        next_offset,
    })
}

pub fn handle_struct_info(
    idb: &Option<IDB>,
    ordinal: Option<u32>,
    name: Option<&str>,
) -> Result<StructInfo, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let info = match (ordinal, name) {
        (Some(ord), _) => db
            .udt_info(ord)
            .ok_or_else(|| ToolError::InvalidParams(format!("unknown struct ordinal: {ord}")))?,
        (None, Some(name)) => find_struct_by_name(db, name)
            .ok_or_else(|| ToolError::InvalidParams(format!("unknown struct name: {name}")))?,
        (None, None) => {
            return Err(ToolError::InvalidParams(
                "struct_info requires ordinal or name".to_string(),
            ));
        }
    };

    let mut members = Vec::new();
    for idx in 0..info.member_count {
        let member = match db.udt_member(info.ordinal, idx) {
            Some(member) => member,
            None => continue,
        };
        let offset = member.offset_bits / 8;
        let size = member.size_bits.div_ceil(8);
        members.push(StructMemberInfo {
            name: member.name,
            type_name: member.type_name,
            offset_bits: member.offset_bits,
            size_bits: member.size_bits,
            offset,
            size,
            is_bitfield: member.is_bitfield,
        });
    }

    Ok(StructInfo {
        ordinal: info.ordinal,
        name: info.name,
        size: info.size,
        is_union: info.is_union,
        member_count: info.member_count,
        members,
    })
}

pub fn handle_read_struct(
    idb: &Option<IDB>,
    addr: u64,
    ordinal: Option<u32>,
    name: Option<&str>,
) -> Result<StructReadResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let info = match (ordinal, name) {
        (Some(ord), _) => db
            .udt_info(ord)
            .ok_or_else(|| ToolError::InvalidParams(format!("unknown struct ordinal: {ord}")))?,
        (None, Some(name)) => find_struct_by_name(db, name)
            .ok_or_else(|| ToolError::InvalidParams(format!("unknown struct name: {name}")))?,
        (None, None) => {
            return Err(ToolError::InvalidParams(
                "read_struct requires ordinal or name".to_string(),
            ));
        }
    };

    let mut members = Vec::new();
    for idx in 0..info.member_count {
        let member = match db.udt_member(info.ordinal, idx) {
            Some(member) => member,
            None => continue,
        };
        let offset = member.offset_bits / 8;
        let size = member.size_bits.div_ceil(8);
        let read_len = usize::try_from(size).unwrap_or(0).min(0x10000);
        let bytes = if read_len == 0 {
            String::new()
        } else {
            hex_encode(&db.get_bytes(addr.saturating_add(offset), read_len))
        };

        members.push(StructMemberValue {
            name: member.name,
            type_name: member.type_name,
            offset_bits: member.offset_bits,
            size_bits: member.size_bits,
            offset,
            size,
            is_bitfield: member.is_bitfield,
            bytes,
        });
    }

    Ok(StructReadResult {
        address: format!("{:#x}", addr),
        ordinal: info.ordinal,
        name: info.name,
        size: info.size,
        members,
    })
}

pub fn handle_xrefs_to_field(
    idb: &Option<IDB>,
    ordinal: Option<u32>,
    name: Option<&str>,
    member_index: Option<u32>,
    member_name: Option<&str>,
    limit: usize,
) -> Result<XrefsToFieldResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let info = match (ordinal, name) {
        (Some(ord), _) => db
            .udt_info(ord)
            .ok_or_else(|| ToolError::InvalidParams(format!("unknown struct ordinal: {ord}")))?,
        (None, Some(name)) => find_struct_by_name(db, name)
            .ok_or_else(|| ToolError::InvalidParams(format!("unknown struct name: {name}")))?,
        (None, None) => {
            return Err(ToolError::InvalidParams(
                "xrefs_to_field requires struct ordinal or name".to_string(),
            ));
        }
    };

    let member_idx = match (member_index, member_name) {
        (Some(idx), _) => idx,
        (None, Some(name)) => {
            let mut found = None;
            for idx in 0..info.member_count {
                if let Some(member) = db.udt_member(info.ordinal, idx)
                    && member.name == name
                {
                    found = Some(idx);
                    break;
                }
            }
            found.ok_or_else(|| {
                ToolError::InvalidParams(format!(
                    "unknown struct member name: {name} in {}",
                    info.name
                ))
            })?
        }
        (None, None) => {
            return Err(ToolError::InvalidParams(
                "xrefs_to_field requires member index or name".to_string(),
            ));
        }
    };

    if member_idx >= info.member_count {
        return Err(ToolError::InvalidParams(format!(
            "member index out of range: {member_idx} (member_count={})",
            info.member_count
        )));
    }

    let member = db
        .udt_member(info.ordinal, member_idx)
        .ok_or_else(|| ToolError::InvalidParams("failed to load struct member".to_string()))?;

    let tid = db
        .udt_member_tid(info.ordinal, member_idx)
        .ok_or_else(|| ToolError::InvalidParams("struct member has no TID".to_string()))?;

    let mut xrefs = Vec::new();
    let mut current = db.first_xref_to(tid, XRefQuery::TID);
    let mut truncated = false;
    while let Some(xref) = current {
        if xrefs.len() >= limit {
            truncated = true;
            break;
        }
        xrefs.push(XRefInfo {
            from: format!("{:#x}", xref.from()),
            to: format!("{:#x}", xref.to()),
            r#type: format!("{:?}", xref.type_()),
            is_code: xref.is_code(),
        });
        current = xref.next_to();
    }

    Ok(XrefsToFieldResult {
        struct_ordinal: info.ordinal,
        struct_name: info.name,
        member_index: member_idx,
        member_name: member.name,
        member_type: member.type_name,
        member_offset_bits: member.offset_bits,
        member_size_bits: member.size_bits,
        tid: format!("{:#x}", tid),
        xrefs,
        truncated,
    })
}
