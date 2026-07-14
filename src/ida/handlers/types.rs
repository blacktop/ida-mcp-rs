//! Type handlers (local types).

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use crate::ida::types::{
    ApplyTypeResult, DeclareTypeResult, DeclareTypesResult, FrameInfo, FrameMemberInfo, FrameRange,
    GuessTypeResult, LocalTypeInfo, LocalTypeListResult, StackVarResult,
};
use idalib::IDB;

pub fn handle_local_types(
    idb: &Option<IDB>,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> Result<LocalTypeListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let filter_lower = filter.map(|f| f.to_lowercase());
    let mut total = 0usize;
    let mut types = Vec::new();

    let ordinal_limit = db.udt_ordinal_limit();
    for ordinal in 1..ordinal_limit {
        let info = match db.local_type_info(ordinal) {
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
        if types.len() >= limit {
            continue;
        }

        types.push(LocalTypeInfo {
            ordinal: info.ordinal,
            name: info.name,
            decl: info.decl,
            kind: info.kind,
        });
    }

    let next_offset = if offset.saturating_add(types.len()) < total {
        Some(offset.saturating_add(types.len()))
    } else {
        None
    };

    Ok(LocalTypeListResult {
        types,
        total,
        next_offset,
    })
}

pub fn handle_stack_frame(idb: &Option<IDB>, addr: u64) -> Result<FrameInfo, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let info = db
        .frame_info(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;

    let mut members = Vec::new();
    for idx in 0..info.member_count {
        let member = match db.frame_member(addr, idx) {
            Some(member) => member,
            None => continue,
        };
        let offset = member.offset_bits / 8;
        let size = member.size_bits.div_ceil(8);
        members.push(FrameMemberInfo {
            name: member.name,
            type_name: member.type_name,
            offset_bits: member.offset_bits,
            size_bits: member.size_bits,
            offset,
            size,
            is_bitfield: member.is_bitfield,
            part: member.part,
        });
    }

    Ok(FrameInfo {
        address: format!("{:#x}", addr),
        frame_size: info.frame_size,
        ret_size: info.ret_size,
        frsize: info.frsize,
        frregs: info.frregs,
        argsize: info.argsize,
        fpd: info.fpd,
        args_range: FrameRange {
            start: format!("{:#x}", info.args_start),
            end: format!("{:#x}", info.args_end),
        },
        retaddr_range: FrameRange {
            start: format!("{:#x}", info.retaddr_start),
            end: format!("{:#x}", info.retaddr_end),
        },
        savregs_range: FrameRange {
            start: format!("{:#x}", info.savregs_start),
            end: format!("{:#x}", info.savregs_end),
        },
        locals_range: FrameRange {
            start: format!("{:#x}", info.locals_start),
            end: format!("{:#x}", info.locals_end),
        },
        member_count: info.member_count,
        members,
    })
}

pub fn handle_declare_type(
    idb: &Option<IDB>,
    decl: &str,
    relaxed: bool,
    replace: bool,
    multi: bool,
) -> Result<serde_json::Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    if multi {
        let errors = db.declare_types(decl, relaxed);
        return Ok(serde_json::to_value(DeclareTypesResult { errors })
            .unwrap_or_else(|_| serde_json::json!({ "errors": errors })));
    }

    let result = db.declare_type(decl, relaxed, replace);
    Ok(serde_json::to_value(DeclareTypeResult {
        code: result.code,
        name: result.name,
        decl: result.decl,
        kind: result.kind,
        replaced: replace,
    })
    .unwrap_or_else(|_| serde_json::json!({ "code": result.code })))
}

#[allow(clippy::too_many_arguments)]
pub fn handle_apply_types(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    stack_offset: Option<i64>,
    stack_name: Option<&str>,
    decl: Option<&str>,
    type_name: Option<&str>,
    relaxed: bool,
    delay: bool,
    strict: bool,
) -> Result<serde_json::Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    if stack_offset.is_some() || stack_name.is_some() {
        let func_addr = resolve_address(idb, addr, name, offset)?;
        let decl = decl.ok_or_else(|| {
            ToolError::InvalidParams("apply_types for stack var requires decl".to_string())
        })?;
        let use_offset = stack_offset.is_some();
        let stack_off = stack_offset.unwrap_or(0);
        let result = db.set_stack_var_type(
            func_addr, stack_name, stack_off, use_offset, decl, relaxed, strict,
        );
        let status = if result.code == 0 { "ok" } else { "error" };
        let out = StackVarResult {
            function: format!("{:#x}", func_addr),
            name: result.name,
            offset: result.offset,
            code: result.code,
            status: status.to_string(),
        };
        return Ok(serde_json::to_value(out)
            .unwrap_or_else(|_| serde_json::json!({ "code": result.code })));
    }

    let address = resolve_address(idb, addr, name, offset)?;
    let (applied, source) = if let Some(decl) = decl {
        (
            db.apply_decl_type(address, decl, relaxed, delay, strict),
            "decl",
        )
    } else if let Some(type_name) = type_name {
        (db.apply_named_type(address, type_name), "named")
    } else {
        return Err(ToolError::InvalidParams(
            "apply_types requires decl or type_name".to_string(),
        ));
    };

    Ok(serde_json::to_value(ApplyTypeResult {
        address: format!("{:#x}", address),
        applied,
        source: source.to_string(),
    })
    .unwrap_or_else(|_| serde_json::json!({ "applied": applied })))
}

pub fn handle_infer_types(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
) -> Result<GuessTypeResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let address = resolve_address(idb, addr, name, offset)?;
    let guessed = db.guess_type(address);
    let status = match guessed.code {
        0 => "failed",
        1 => "trivial",
        2 => "ok",
        _ => "unknown",
    };
    Ok(GuessTypeResult {
        address: format!("{:#x}", address),
        code: guessed.code,
        status: status.to_string(),
        decl: guessed.decl,
        kind: guessed.kind,
    })
}

pub fn handle_declare_stack(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    var_name: Option<&str>,
    decl: &str,
    relaxed: bool,
) -> Result<StackVarResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let func_addr = resolve_address(idb, addr, name, 0)?;
    let result = db.define_stack_var(func_addr, var_name, offset, decl, relaxed);
    let status = if result.code == 0 { "ok" } else { "error" };
    Ok(StackVarResult {
        function: format!("{:#x}", func_addr),
        name: result.name,
        offset: result.offset,
        code: result.code,
        status: status.to_string(),
    })
}

pub fn handle_delete_stack(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: Option<i64>,
    var_name: Option<&str>,
) -> Result<StackVarResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    if offset.is_none() && var_name.is_none() {
        return Err(ToolError::InvalidParams(
            "delete_stack requires offset or name".to_string(),
        ));
    }
    let func_addr = resolve_address(idb, addr, name, 0)?;
    let use_offset = offset.is_some();
    let off = offset.unwrap_or(0);
    let result = db.delete_stack_var(func_addr, var_name, off, use_offset);
    let status = if result.code == 0 { "ok" } else { "error" };
    Ok(StackVarResult {
        function: format!("{:#x}", func_addr),
        name: result.name,
        offset: result.offset,
        code: result.code,
        status: status.to_string(),
    })
}
