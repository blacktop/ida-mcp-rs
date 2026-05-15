//! Database open/close handlers.

use crate::error::ToolError;
use crate::expand_path;
use crate::ida::handlers::analysis::build_analysis_status;
use crate::ida::lock::{
    acquire_mcp_lock, clean_stale_mcp_lock, detect_db_lock, release_mcp_lock_file,
};
use crate::ida::observability::{
    emit_progress, ensure_not_cancelled, ProgressHeartbeat, ProgressSender, OPEN_IDB_PROGRESS_TOTAL,
};
use crate::ida::types::{DbInfo, DebugInfoLoad};
use idalib::{IDBOpenOptions, IDB};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
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
    if ext.eq_ignore_ascii_case("i64") || ext.eq_ignore_ascii_case("idb") {
        let mut id0 = path.to_path_buf();
        id0.set_extension("id0");
        return Some(id0);
    }
    None
}

fn idb_path_for_raw_binary(path: &Path) -> PathBuf {
    let mut raw_idb = OsString::from(path.as_os_str());
    raw_idb.push(".i64");
    PathBuf::from(raw_idb)
}

fn base_input_path_for_database(path: &Path) -> PathBuf {
    let mut base = path.to_path_buf();
    if let Some(ext) = base.extension().and_then(|e| e.to_str()) {
        if ext.eq_ignore_ascii_case("i64")
            || ext.eq_ignore_ascii_case("idb")
            || ext.eq_ignore_ascii_case("id0")
        {
            base.set_extension("");
        }
    }
    base
}

fn database_paths_match(current: &Path, requested: &Path) -> bool {
    current == requested
        || unpacked_id0_path(current).as_deref() == Some(requested)
        || unpacked_id0_path(requested).as_deref() == Some(current)
}

fn init_database_args(extra_args: &[String]) -> Vec<String> {
    let mut args = Vec::new();

    if !extra_args.iter().any(|arg| arg == "-A") {
        args.push("-A".to_string());
    }

    args.extend(extra_args.iter().cloned());
    args
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
    progress_tx: Option<ProgressSender>,
    cancel: Option<CancellationToken>,
) -> Result<DbInfo, ToolError> {
    let expanded = expand_path(path);
    ensure_not_cancelled(cancel.as_ref())?;

    // Check if a database is already open
    if let Some(db) = idb.as_ref() {
        let current_path = db.path();
        if database_paths_match(current_path, &expanded) {
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
        let out_path = idb_path_for_raw_binary(&expanded);
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
    let path_display = expanded.display().to_string();
    let (ticker_stop_tx, ticker_stop_rx) = mpsc::channel();
    let ticker = std::thread::spawn(move || {
        let start = Instant::now();
        loop {
            match ticker_stop_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    info!(
                        path = %path_display,
                        elapsed = start.elapsed().as_secs(),
                        "Still opening database..."
                    );
                }
            }
        }
    });

    let open_start = Instant::now();
    let mut opened_path = expanded.clone();
    let init_args = init_database_args(extra_args);
    let open_message = if is_idb {
        "Opening existing IDA database"
    } else if auto_analyse {
        "Opening raw binary and waiting for initial auto-analysis"
    } else {
        "Opening raw binary"
    };
    let _opening_heartbeat = ProgressHeartbeat::start(
        progress_tx.clone(),
        "opening",
        1.0,
        2.8,
        Some(OPEN_IDB_PROGRESS_TOTAL),
        open_message,
    );
    let db = if is_idb {
        // Open existing IDA database (no auto-analysis needed, but save=true to pack on close)
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(false).save(true);
        for arg in &init_args {
            opts.arg(arg);
        }
        let mut db = opts.open(&expanded);
        if db.is_err() {
            if let Some(id0_path) = unpacked_id0_path(&expanded) {
                if id0_path.exists() {
                    info!(path = %id0_path.display(), "Falling back to unpacked ID0 database");
                    opened_path = id0_path.clone();
                    let mut opts = IDBOpenOptions::new();
                    opts.auto_analyse(false).save(true);
                    for arg in &init_args {
                        opts.arg(arg);
                    }
                    db = opts.open(&id0_path);
                }
            }
        }
        db
    } else {
        // Raw binary - open with auto-analysis and save to .i64
        let Some(out_path) = raw_out_path.as_ref() else {
            return Err(ToolError::OpenFailed(
                "raw binary output path was not initialized".to_string(),
            ));
        };
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
        for arg in &init_args {
            opts.arg(arg);
        }
        opts.idb(out_path).save(true).open(&expanded)
    };
    let _ = ticker_stop_tx.send(());
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
    ensure_not_cancelled(cancel.as_ref())?;
    if !is_idb && auto_analyse {
        emit_progress(
            progress_tx.as_ref(),
            "analyzing",
            2.0,
            Some(OPEN_IDB_PROGRESS_TOTAL),
            "Raw binary open finished; collecting post-open analysis state",
        );
    }

    let mut debug_info = None;
    if load_debug_info {
        emit_progress(
            progress_tx.as_ref(),
            "loading_debug_info",
            3.0,
            Some(OPEN_IDB_PROGRESS_TOTAL),
            "Loading requested debug information",
        );
        ensure_not_cancelled(cancel.as_ref())?;
        let mut resolved = None;
        if let Some(path) = debug_info_path {
            resolved = Some(PathBuf::from(path));
        } else {
            let base = if is_idb {
                base_input_path_for_database(&expanded)
            } else {
                expanded.clone()
            };
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
            emit_progress(
                progress_tx.as_ref(),
                "loading_debug_info",
                3.0,
                Some(OPEN_IDB_PROGRESS_TOTAL),
                "Loading sibling dSYM debug information",
            );
            ensure_not_cancelled(cancel.as_ref())?;
            info!(path = %path.display(), "Loading dSYM debug info");
            match db.load_debug_info(path, false) {
                Ok(true) => info!(path = %path.display(), "dSYM debug info loaded"),
                Ok(false) => warn!(path = %path.display(), "dSYM debug info load failed"),
                Err(e) => warn!(path = %path.display(), error = %e, "dSYM debug info load error"),
            }
        }
    }
    ensure_not_cancelled(cancel.as_ref())?;

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
        let base = base_input_path_for_database(db.path());
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::ida::handlers::database::{
        base_input_path_for_database, database_paths_match, idb_path_for_raw_binary,
        init_database_args,
    };

    #[test]
    fn init_database_args_preserves_user_args() {
        let args = init_database_args(&["-Sscript.py".to_string(), "-Tpe".to_string()]);
        assert!(args.iter().any(|arg| arg == "-Sscript.py"));
        assert!(args.iter().any(|arg| arg == "-Tpe"));
    }

    #[test]
    fn database_paths_match_treats_packed_and_unpacked_as_same_database() {
        let packed = Path::new("/tmp/sample.i64");
        let unpacked = Path::new("/tmp/sample.id0");
        let legacy = Path::new("/tmp/sample.idb");
        let packed_upper = Path::new("/tmp/sample.I64");

        assert!(database_paths_match(packed, unpacked));
        assert!(database_paths_match(unpacked, packed));
        assert!(database_paths_match(legacy, unpacked));
        assert!(database_paths_match(unpacked, legacy));
        assert!(database_paths_match(packed_upper, unpacked));
        assert!(!database_paths_match(packed, legacy));
    }

    #[test]
    fn idb_path_for_raw_binary_appends_i64_to_full_path() {
        assert_eq!(
            idb_path_for_raw_binary(Path::new("/tmp/sample")),
            Path::new("/tmp/sample.i64")
        );
        assert_eq!(
            idb_path_for_raw_binary(Path::new("/tmp/com.apple.driver.AppleDAPF")),
            Path::new("/tmp/com.apple.driver.AppleDAPF.i64")
        );
        assert_eq!(
            idb_path_for_raw_binary(Path::new("/tmp/kernelcache.release.iphone")),
            Path::new("/tmp/kernelcache.release.iphone.i64")
        );
    }

    #[test]
    fn base_input_path_for_database_strips_supported_database_extensions() {
        assert_eq!(
            base_input_path_for_database(Path::new("/tmp/sample.i64")),
            Path::new("/tmp/sample")
        );
        assert_eq!(
            base_input_path_for_database(Path::new("/tmp/sample.idb")),
            Path::new("/tmp/sample")
        );
        assert_eq!(
            base_input_path_for_database(Path::new("/tmp/sample.id0")),
            Path::new("/tmp/sample")
        );
        assert_eq!(
            base_input_path_for_database(Path::new("/tmp/sample.bin")),
            Path::new("/tmp/sample.bin")
        );
    }

    #[test]
    fn init_database_args_injects_non_interactive_flag_once() {
        let args = init_database_args(&[]);
        assert_eq!(args, vec!["-A".to_string()]);

        let args = init_database_args(&["-A".to_string(), "-Tpe".to_string()]);
        assert_eq!(args.iter().filter(|arg| arg.as_str() == "-A").count(), 1);
    }
}
