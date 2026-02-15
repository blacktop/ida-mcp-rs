//! Database open/close handlers.

use crate::error::ToolError;
use crate::expand_path;
use crate::ida::handlers::analysis::build_analysis_status;
use crate::ida::lock::{
    acquire_mcp_lock, clean_stale_mcp_lock, detect_db_lock, release_mcp_lock_file,
};
use crate::ida::types::{DbInfo, DebugInfoLoad};
use idalib::{IDBOpenOptions, IDB};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Build `DbInfo` from an open IDB.
fn build_db_info(db: &IDB, path: &str, debug_info: Option<DebugInfoLoad>) -> DbInfo {
    let meta = db.meta();
    DbInfo {
        path: path.to_string(),
        file_type: format!("{:?}", meta.filetype()),
        processor: db.processor().long_name(),
        bits: if meta.is_64bit() {
            64
        } else if meta.is_32bit_exactly() {
            32
        } else {
            16
        },
        function_count: db.function_count(),
        debug_info,
        analysis_status: build_analysis_status(db),
    }
}

// Helper functions for debug info paths

fn dsym_expected_path_for_binary(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?;
    let mut dsym = OsString::from(path.as_os_str());
    dsym.push(".dSYM");
    let dsym_root = PathBuf::from(dsym);
    let dwarf_path = dsym_root
        .join("Contents")
        .join("Resources")
        .join("DWARF")
        .join(file_name);
    Some(dwarf_path)
}

fn dsym_path_for_binary(path: &Path) -> Option<PathBuf> {
    dsym_expected_path_for_binary(path).filter(|p| p.exists())
}

fn unpacked_id0_path(path: &Path) -> Option<PathBuf> {
    let ext = path.extension().and_then(|e| e.to_str())?;
    if ext == "i64" || ext == "idb" {
        let mut id0 = path.to_path_buf();
        id0.set_extension("id0");
        return Some(id0);
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub fn handle_open(
    idb: &mut Option<IDB>,
    lock_file: &mut Option<File>,
    lock_path: &mut Option<PathBuf>,
    path: &str,
    load_debug_info: bool,
    debug_info_path: Option<&str>,
    debug_info_verbose: bool,
    force: bool,
    file_type: Option<&str>,
    auto_analyse: bool,
    extra_args: &[String],
) -> Result<DbInfo, ToolError> {
    let expanded = expand_path(path);

    // Check if a database is already open
    if let Some(db) = idb.as_ref() {
        let current_path = db.path();
        if current_path == expanded {
            // Same database - return its info instead of reopening
            info!(path = %expanded.display(), "Database already open, returning existing info");
            return Ok(build_db_info(db, &current_path.display().to_string(), None));
        } else {
            // Different database - tell them to close first
            return Err(ToolError::DatabaseAlreadyOpen(
                current_path.display().to_string(),
            ));
        }
    }

    // Check file exists
    if !expanded.exists() {
        return Err(ToolError::InvalidPath(format!(
            "File not found: {}",
            expanded.display()
        )));
    }

    // Determine if this is an IDA database or a raw binary
    let ext = expanded
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_idb = ext == "i64" || ext == "idb" || ext == "id0";

    let mut raw_out_path = None;
    let mut dsym_path = None;
    let mut should_load_dsym = false;
    if !is_idb {
        let out_path = expanded.with_extension("i64");
        should_load_dsym = !out_path.exists();
        if should_load_dsym {
            dsym_path = dsym_path_for_binary(&expanded);
        }
        raw_out_path = Some(out_path);
    }

    // If force is enabled, try to clean up stale lock files from crashed sessions
    if force {
        if let Some(stale) = clean_stale_mcp_lock(&expanded) {
            info!(
                path = %stale.path.display(),
                pid = stale.pid,
                reason = %stale.reason,
                "Cleaned up stale lock file"
            );
        }
    }

    // Acquire MCP lock file (to detect other ida-mcp instances)
    let mcp_lock = acquire_mcp_lock(&expanded)?;

    // Open database
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();
    let path_display = expanded.display().to_string();
    let ticker = std::thread::spawn(move || {
        let start = Instant::now();
        loop {
            std::thread::sleep(Duration::from_secs(10));
            if done_clone.load(Ordering::Relaxed) {
                break;
            }
            info!(
                path = %path_display,
                elapsed = start.elapsed().as_secs(),
                "Still opening database..."
            );
        }
    });

    let open_start = Instant::now();
    let mut opened_path = expanded.clone();
    let db = if is_idb {
        // Open existing IDA database (no auto-analysis needed, but save=true to pack on close)
        let mut db = IDB::open_with(&expanded, false, true);
        if db.is_err() {
            if let Some(id0_path) = unpacked_id0_path(&expanded) {
                if id0_path.exists() {
                    info!(path = %id0_path.display(), "Falling back to unpacked ID0 database");
                    opened_path = id0_path.clone();
                    db = IDB::open_with(&id0_path, false, true);
                }
            }
        }
        db
    } else {
        // Raw binary - open with auto-analysis and save to .i64
        let out_path = raw_out_path
            .as_ref()
            .expect("raw binary should have out path");
        info!(
            "Opening raw binary with auto-analysis (idb_out={})",
            out_path.display()
        );
        opened_path = out_path.clone();
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(auto_analyse);
        if let Some(ft) = file_type {
            info!(file_type = ft, "Using file type selector (-T flag)");
            opts.file_type(ft);
        }
        for arg in extra_args {
            opts.arg(arg);
        }
        opts.idb(out_path).save(true).open(&expanded)
    };
    done.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    let db = match db {
        Ok(db) => db,
        Err(e) => {
            release_mcp_lock_file(mcp_lock);
            if let Some(lock_msg) = detect_db_lock(&expanded, &e) {
                return Err(ToolError::DatabaseLocked(lock_msg));
            }
            return Err(ToolError::OpenFailed(format!(
                "{}: {}",
                opened_path.display(),
                e
            )));
        }
    };

    let mut debug_info = None;
    if load_debug_info {
        let mut resolved = None;
        if let Some(path) = debug_info_path {
            resolved = Some(PathBuf::from(path));
        } else {
            let mut base = expanded.clone();
            if is_idb {
                if let Some(ext) = base.extension().and_then(|e| e.to_str()) {
                    if ext.eq_ignore_ascii_case("i64") || ext.eq_ignore_ascii_case("idb") {
                        base.set_extension("");
                    }
                }
            }
            if let Some(candidate) = dsym_expected_path_for_binary(&base) {
                resolved = Some(candidate);
            }
        }

        if let Some(path) = resolved {
            if !path.exists() {
                debug_info = Some(DebugInfoLoad {
                    path: path.display().to_string(),
                    loaded: false,
                    error: Some("debug info not found".to_string()),
                });
            } else {
                match db.load_debug_info(&path, debug_info_verbose) {
                    Ok(loaded) => {
                        if loaded {
                            info!(path = %path.display(), "Debug info loaded");
                            debug_info = Some(DebugInfoLoad {
                                path: path.display().to_string(),
                                loaded,
                                error: None,
                            });
                        } else {
                            warn!(path = %path.display(), "Debug info load returned false");
                            debug_info = Some(DebugInfoLoad {
                                path: path.display().to_string(),
                                loaded,
                                error: Some("load returned false".to_string()),
                            });
                        }
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "Debug info load error");
                        debug_info = Some(DebugInfoLoad {
                            path: path.display().to_string(),
                            loaded: false,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }
    } else if !is_idb && should_load_dsym {
        if let Some(path) = dsym_path.as_ref() {
            info!(path = %path.display(), "Loading dSYM debug info");
            match db.load_debug_info(path, false) {
                Ok(true) => info!(path = %path.display(), "dSYM debug info loaded"),
                Ok(false) => warn!(path = %path.display(), "dSYM debug info load failed"),
                Err(e) => warn!(path = %path.display(), error = %e, "dSYM debug info load error"),
            }
        }
    }

    let path_str = opened_path.display().to_string();
    let info = build_db_info(&db, &path_str, debug_info);
    info!(
        "IDA open success: type={} proc={} bits={} functions={} elapsed={}s",
        info.file_type,
        info.processor,
        info.bits,
        info.function_count,
        open_start.elapsed().as_secs()
    );

    let (lf, lp) = mcp_lock.into_parts();
    *lock_file = Some(lf);
    *lock_path = Some(lp);
    *idb = Some(db);
    Ok(info)
}

pub fn handle_load_debug_info(
    idb: &Option<IDB>,
    path: Option<&str>,
    verbose: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let resolved = if let Some(path) = path {
        PathBuf::from(path)
    } else {
        let mut base = db.path().to_path_buf();
        if let Some(ext) = base.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("i64") || ext.eq_ignore_ascii_case("idb") {
                base.set_extension("");
            }
        }
        dsym_path_for_binary(&base)
            .ok_or_else(|| ToolError::InvalidPath("No sibling .dSYM found".to_string()))?
    };

    if !resolved.exists() {
        return Err(ToolError::InvalidPath(format!(
            "File not found: {}",
            resolved.display()
        )));
    }

    let loaded = db.load_debug_info(&resolved, verbose)?;
    Ok(json!({
        "path": resolved.display().to_string(),
        "loaded": loaded,
    }))
}
