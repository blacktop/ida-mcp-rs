//! Import, export, and entrypoint handlers.

use crate::error::ToolError;
use crate::ida::types::{ExportInfo, ImportInfo};
use idalib::IDB;
use std::collections::HashSet;

pub fn handle_imports(
    idb: &Option<IDB>,
    offset: usize,
    limit: usize,
) -> Result<Vec<ImportInfo>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    // Imports are names in external segments
    let mut imports = Vec::new();
    let mut count = 0;

    for name in db.names().iter() {
        // Check if this is in an external segment
        if let Some(seg) = db.segment_at(name.address()) {
            if seg.r#type().is_extern() || seg.r#type().is_import() {
                if count < offset {
                    count += 1;
                    continue;
                }

                if imports.len() >= limit {
                    break;
                }

                imports.push(ImportInfo {
                    address: format!("{:#x}", name.address()),
                    name: name.name().to_string(),
                    ordinal: count,
                });
                count += 1;
            }
        }
    }

    Ok(imports)
}

pub fn handle_exports(
    idb: &Option<IDB>,
    offset: usize,
    limit: usize,
) -> Result<Vec<ExportInfo>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut exports = Vec::new();
    let mut count = 0;

    for name in db.names().iter() {
        if count < offset {
            count += 1;
            continue;
        }

        if exports.len() >= limit {
            break;
        }

        exports.push(ExportInfo {
            address: format!("{:#x}", name.address()),
            name: name.name().to_string(),
            is_public: name.is_public(),
        });
        count += 1;
    }

    Ok(exports)
}

pub fn handle_entrypoints(idb: &Option<IDB>) -> Result<Vec<String>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    // idalib's EntryPointIter has a bug: index is not incremented on success,
    // causing infinite iteration. Break as soon as a duplicate address is seen.
    let mut seen = HashSet::new();
    let mut entrypoints = Vec::new();
    for addr in db.entries() {
        if !seen.insert(addr) {
            break;
        }
        entrypoints.push(format!("{:#x}", addr));
    }

    Ok(entrypoints)
}
