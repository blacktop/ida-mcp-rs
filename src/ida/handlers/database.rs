//! Database open/close handlers.

use crate::error::ToolError;
use crate::expand_path;
use crate::ida::handlers::analysis::build_analysis_status;
use crate::ida::lock::{
    acquire_mcp_lock, clean_stale_mcp_lock, detect_db_lock, release_mcp_lock_file, McpLock,
};
use crate::ida::observability::{
    emit_progress, ensure_not_cancelled, ProgressHeartbeat, ProgressSender, OPEN_IDB_PROGRESS_TOTAL,
};
use crate::ida::types::{DbInfo, DebugInfoLoad, RawBinaryTarget};
use idalib::{IDBOpenOptions, IDB};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Build `DbInfo` from an open IDB.
fn database_bitness(db: &IDB) -> u32 {
    let meta = db.meta();
    if meta.is_64bit() {
        64
    } else if meta.is_32bit_exactly() {
        32
    } else {
        16
    }
}

fn build_db_info(db: &IDB, path: &str, debug_info: Option<DebugInfoLoad>) -> DbInfo {
    let meta = db.meta();
    DbInfo {
        path: path.to_string(),
        file_type: format!("{:?}", meta.filetype()),
        processor: db.processor().long_name(),
        bits: database_bitness(db),
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

fn existing_idb_for_raw_binary(path: &Path) -> Option<PathBuf> {
    let idb_path = idb_path_for_raw_binary(path);
    ida_database_output_exists(&idb_path).then_some(idb_path)
}

fn existing_idb_for_raw_open(path: &Path, explicit_idb_out: Option<&Path>) -> Option<PathBuf> {
    if let Some(explicit_idb_out) = explicit_idb_out {
        ida_database_output_exists(explicit_idb_out).then_some(explicit_idb_out.to_path_buf())
    } else {
        existing_idb_for_raw_binary(path)
    }
}

fn database_artifact_paths(output: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![output.to_path_buf()];
    for extension in ["id0", "id1", "id2", "nam", "til"] {
        let mut candidate = output.to_path_buf();
        candidate.set_extension(extension);
        candidates.push(candidate);
    }
    candidates
}

fn ida_database_output_exists(output: &Path) -> bool {
    output.exists()
        || unpacked_id0_path(output)
            .as_deref()
            .is_some_and(Path::exists)
}

fn has_ida_database_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let ext = ext.to_ascii_lowercase();
            ext == "i64" || ext == "idb" || ext == "id0"
        })
        .unwrap_or(false)
}

fn raw_input_matches_generated_database(raw: &Path, database: &Path) -> bool {
    !has_ida_database_extension(raw) && idb_path_for_raw_binary(raw) == database
}

fn base_input_path_for_database(path: &Path) -> PathBuf {
    let mut base = path.to_path_buf();
    if let Some(ext) = base.extension().and_then(|e| e.to_str())
        && (ext.eq_ignore_ascii_case("i64")
            || ext.eq_ignore_ascii_case("idb")
            || ext.eq_ignore_ascii_case("id0"))
    {
        base.set_extension("");
    }
    base
}

fn database_paths_match(current: &Path, requested: &Path) -> bool {
    current == requested
        || unpacked_id0_path(current).as_deref() == Some(requested)
        || unpacked_id0_path(requested).as_deref() == Some(current)
        || raw_input_matches_generated_database(requested, current)
        || raw_input_matches_generated_database(current, requested)
}

fn non_empty_trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn init_database_args(extra_args: &[String]) -> Vec<String> {
    let mut args = Vec::new();

    if !extra_args.iter().any(|arg| arg == "-A") {
        args.push("-A".to_string());
    }

    args.extend(extra_args.iter().cloned());
    args
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingRawIdbAction {
    Reuse,
    Rebuild,
}

fn existing_raw_idb_action(
    rebuild: bool,
    recorded_hash: &[u8; 32],
    input_hash: &[u8; 32],
    recorded_path_matches: bool,
) -> Option<ExistingRawIdbAction> {
    let recorded_hash_available = recorded_hash.iter().any(|byte| *byte != 0);
    let hash_matches = recorded_hash_available && recorded_hash == input_hash;

    if !rebuild && hash_matches {
        Some(ExistingRawIdbAction::Reuse)
    } else if rebuild && (hash_matches || recorded_path_matches) {
        Some(ExistingRawIdbAction::Rebuild)
    } else {
        None
    }
}

fn sha256_file(path: &Path) -> Result<[u8; 32], ToolError> {
    let mut file = File::open(path).map_err(|error| {
        ToolError::OpenFailed(format!(
            "failed to read input for SHA-256 verification ({}): {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            ToolError::OpenFailed(format!(
                "failed while hashing input ({}): {error}",
                path.display()
            ))
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn recorded_input_path_matches(input: &Path, recorded: &str) -> bool {
    // IDA's get_input_file_path/getinf_buf length may include the trailing C
    // terminator. Treat it as transport padding, never as part of the path.
    let recorded =
        recorded.trim_matches(|character: char| character == '\0' || character.is_whitespace());
    !recorded.is_empty() && paths_refer_to_same_file(input, &expand_path(recorded))
}

fn validate_raw_idb_output(input: &Path, output: &Path) -> Result<(), ToolError> {
    let valid_extension = output
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("i64") || extension.eq_ignore_ascii_case("idb")
        });
    if !valid_extension {
        return Err(ToolError::InvalidParams(format!(
            "idb_out must end in .i64 or .idb: {}",
            output.display()
        )));
    }
    if paths_refer_to_same_file(input, output) {
        return Err(ToolError::InvalidParams(
            "idb_out must not refer to the raw input file".to_string(),
        ));
    }
    if output.exists() && !output.is_file() {
        return Err(ToolError::InvalidPath(format!(
            "idb_out is not a file: {}",
            output.display()
        )));
    }
    if let Some(id0) = unpacked_id0_path(output)
        && id0.exists()
        && !id0.is_file()
    {
        return Err(ToolError::InvalidPath(format!(
            "unpacked idb_out artifact is not a file: {}",
            id0.display()
        )));
    }
    if !ida_database_output_exists(output)
        && let Some(orphan) = database_artifact_paths(output)
            .into_iter()
            .skip(1)
            .find(|candidate| candidate.exists())
    {
        return Err(ToolError::InvalidParams(format!(
            "idb_out has an orphaned pre-existing database artifact ({}); choose another output path or remove the artifact after verifying it",
            orphan.display()
        )));
    }

    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(parent).map_err(|error| {
        ToolError::InvalidPath(format!(
            "idb_out parent is unavailable ({}): {error}",
            parent.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ToolError::InvalidPath(format!(
            "idb_out parent is not a directory: {}",
            parent.display()
        )));
    }
    if metadata.permissions().readonly() {
        return Err(ToolError::InvalidPath(format!(
            "idb_out parent is read-only: {}",
            parent.display()
        )));
    }
    Ok(())
}

fn open_existing_idb(
    path: &Path,
    init_args: &[String],
    save: bool,
) -> Result<(IDB, PathBuf), idalib::IDAError> {
    let mut opened_path = path.to_path_buf();
    let mut opts = IDBOpenOptions::new();
    opts.auto_analyse(false).save(save);
    for arg in init_args {
        opts.arg(arg);
    }
    let mut database = opts.open(path);
    if database.is_err()
        && let Some(id0_path) = unpacked_id0_path(path)
        && id0_path.exists()
    {
        info!(path = %id0_path.display(), "Falling back to unpacked ID0 database");
        opened_path = id0_path.clone();
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(false).save(save);
        for arg in init_args {
            opts.arg(arg);
        }
        database = opts.open(&id0_path);
    }
    database.map(|database| (database, opened_path))
}

fn remove_new_database_artifacts(output: &Path) {
    for candidate in database_artifact_paths(output) {
        match fs::remove_file(&candidate) {
            Ok(()) => info!(path = %candidate.display(), "Removed partial IDA database artifact"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!(
                path = %candidate.display(),
                error = %error,
                "Failed to remove partial IDA database artifact"
            ),
        }
    }
}

fn cleanup_failed_open(db: IDB, mcp_lock: McpLock, output: &Path, remove_artifacts: bool) {
    drop(db);
    release_mcp_lock_file(mcp_lock);
    if remove_artifacts {
        remove_new_database_artifacts(output);
    }
}

fn configure_raw_bitness(db: &mut IDB, bitness: idalib::segment::Bitness) -> Result<(), ToolError> {
    db.meta_mut().set_app_bitness(bitness);
    for (_, mut segment) in db.segments() {
        if !segment.set_bitness(bitness) {
            return Err(ToolError::OpenFailed(format!(
                "failed to set {}-bit addressing for segment at {:#x}",
                bitness.bits(),
                segment.start_address()
            )));
        }
    }

    let actual = database_bitness(db);
    if actual != bitness.bits() {
        return Err(ToolError::OpenFailed(format!(
            "IDA reported {actual}-bit after requesting {}-bit raw input mode",
            bitness.bits()
        )));
    }
    Ok(())
}

fn configure_raw_entry_point(db: &mut IDB, entry_point: u64) -> Result<(), ToolError> {
    if db.segment_at(entry_point).is_none() {
        return Err(ToolError::OpenFailed(format!(
            "raw entry point {entry_point:#x} is outside every loaded segment"
        )));
    }

    if db.meta().start_address() != Some(entry_point)
        && !db.meta_mut().set_start_address(entry_point)
    {
        return Err(ToolError::OpenFailed(format!(
            "IDA refused raw entry point {entry_point:#x}"
        )));
    }
    if db.meta().start_address() != Some(entry_point) {
        return Err(ToolError::OpenFailed(format!(
            "IDA did not retain requested raw entry point {entry_point:#x}"
        )));
    }
    Ok(())
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
    rebuild: bool,
    file_type: Option<&str>,
    auto_analyse: bool,
    raw_target: &RawBinaryTarget,
    extra_args: &[String],
    idb_out: Option<&str>,
    progress_tx: Option<ProgressSender>,
    cancel: Option<CancellationToken>,
) -> Result<DbInfo, ToolError> {
    let expanded = expand_path(path);
    let debug_info_path = non_empty_trimmed(debug_info_path);
    let file_type = non_empty_trimmed(file_type);
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
    if is_idb && !raw_target.is_empty() {
        return Err(ToolError::InvalidParams(
            "processor, bitness, base_address, and entry_point apply only to a newly-created raw-input database"
                .to_string(),
        ));
    }
    if let Some(base_address) = raw_target.base_address
        && base_address % 16 != 0
    {
        return Err(ToolError::InvalidParams(format!(
            "raw base address {base_address:#x} must be 16-byte aligned"
        )));
    }

    let mut raw_out_path = None;
    let mut existing_raw_idb_candidate = None;
    let mut dsym_path = None;
    let mut should_load_dsym = false;
    if !is_idb {
        let explicit_idb_out = idb_out.map(expand_path);
        let out_path = explicit_idb_out
            .clone()
            .unwrap_or_else(|| idb_path_for_raw_binary(&expanded));
        validate_raw_idb_output(&expanded, &out_path)?;
        let generated_idb_path = existing_idb_for_raw_open(&expanded, explicit_idb_out.as_deref());
        let generated_exists = generated_idb_path.is_some();
        if generated_exists && !rebuild && !raw_target.is_empty() {
            return Err(ToolError::InvalidParams(
                "raw target options cannot change an existing database; set rebuild=true to recreate it"
                    .to_string(),
            ));
        }
        existing_raw_idb_candidate = generated_idb_path;
        should_load_dsym = !generated_exists;
        if should_load_dsym {
            dsym_path = dsym_path_for_binary(&expanded);
        }
        raw_out_path = Some(out_path);
    }

    let lock_target_path = raw_out_path.as_ref().unwrap_or(&expanded);

    // If force is enabled, try to clean up stale lock files from crashed sessions.
    // Raw binaries lock the generated .i64 path so all sessions agree on the
    // effective database/output file even when the input has its own extension.
    if force {
        for candidate in [lock_target_path, &expanded] {
            if let Some(stale) = clean_stale_mcp_lock(candidate) {
                info!(
                    path = %stale.path.display(),
                    pid = stale.pid,
                    reason = %stale.reason,
                    "Cleaned up stale lock file"
                );
            }
        }
    }

    // Acquire MCP lock file (to detect other ida-mcp instances)
    let mcp_lock = acquire_mcp_lock(lock_target_path)?;

    let init_args = init_database_args(extra_args);
    let mut existing_raw_idb_path = None;
    if let Some(candidate_path) = existing_raw_idb_candidate.as_ref() {
        let (candidate, _) = match open_existing_idb(candidate_path, &init_args, false) {
            Ok(candidate) => candidate,
            Err(error) => {
                release_mcp_lock_file(mcp_lock);
                return Err(ToolError::OpenFailed(format!(
                    "refusing to reuse or overwrite {} because its input provenance could not be read: {error}",
                    candidate_path.display()
                )));
            }
        };
        let recorded_hash = candidate.meta().input_file_sha256();
        let recorded_path = candidate.meta().input_file_path();
        drop(candidate);
        if let Err(error) = ensure_not_cancelled(cancel.as_ref()) {
            release_mcp_lock_file(mcp_lock);
            return Err(error);
        }
        let input_hash = match sha256_file(&expanded) {
            Ok(hash) => hash,
            Err(error) => {
                release_mcp_lock_file(mcp_lock);
                return Err(error);
            }
        };
        let path_matches = recorded_input_path_matches(&expanded, &recorded_path);

        match existing_raw_idb_action(rebuild, &recorded_hash, &input_hash, path_matches) {
            Some(ExistingRawIdbAction::Reuse) => {
                info!(
                    input = %expanded.display(),
                    idb = %candidate_path.display(),
                    auto_analyse,
                    "Reusing SHA-256-verified IDA database for raw input"
                );
                existing_raw_idb_path = Some(candidate_path.clone());
            }
            Some(ExistingRawIdbAction::Rebuild) => {
                warn!(
                    input = %expanded.display(),
                    idb = %candidate_path.display(),
                    hash_matches = recorded_hash.iter().any(|byte| *byte != 0)
                        && recorded_hash == input_hash,
                    recorded_path_matches = path_matches,
                    "Rebuilding raw input and overwriting provenance-matched IDA database"
                );
            }
            None => {
                release_mcp_lock_file(mcp_lock);
                let recorded_hash_available = recorded_hash.iter().any(|byte| *byte != 0);
                let message = if !rebuild && path_matches {
                    if recorded_hash_available {
                        format!(
                            "{} was created from this input path, but its recorded SHA-256 does not match the current file; retry with rebuild=true to replace stale analysis",
                            candidate_path.display()
                        )
                    } else {
                        format!(
                            "{} has no recorded input SHA-256 and cannot be reused automatically; retry with rebuild=true to replace it because its recorded input path matches",
                            candidate_path.display()
                        )
                    }
                } else {
                    format!(
                        "refusing to {} {} because it is not provenance-matched to {}; choose a different idb_out or remove the candidate after verifying it",
                        if rebuild { "overwrite" } else { "reuse" },
                        candidate_path.display(),
                        expanded.display()
                    )
                };
                return Err(ToolError::InvalidParams(message));
            }
        }
    }

    // A newly-created raw database owns its output artifacts, including a
    // rebuild that replaces an existing provenance-matched database. If that
    // operation fails, leaving its partially-written output behind would make
    // a later call treat an incomplete database as reusable. Reopening a
    // verified existing database does not take ownership of its artifacts.
    let created_raw_database = !is_idb && existing_raw_idb_path.is_none();

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
    let open_existing_database = is_idb || existing_raw_idb_path.is_some();
    let open_message = if open_existing_database {
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
    let db_path_to_open = existing_raw_idb_path.as_ref().unwrap_or(&expanded);
    let (db, opened_path) = if open_existing_database {
        // Open existing IDA database (no auto-analysis needed, but save=true to pack on close)
        match open_existing_idb(db_path_to_open, &init_args, true) {
            Ok((database, opened_path)) => (Ok(database), opened_path),
            Err(error) => (Err(error), db_path_to_open.clone()),
        }
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
        let opened_path = out_path.clone();
        let mut opts = IDBOpenOptions::new();
        // Defer analysis until typed metadata that the raw loader may ignore
        // has been applied and verified on the newly-created database.
        opts.auto_analyse(
            auto_analyse && raw_target.bitness.is_none() && raw_target.entry_point.is_none(),
        );
        if let Some(ft) = file_type {
            info!(file_type = ft, "Using file type selector (-T flag)");
            opts.file_type(ft);
        }
        if let Some(processor) = raw_target.processor.as_deref() {
            opts.processor(processor);
        }
        if let Some(base_address) = raw_target.base_address
            && let Err(error) = opts.base_address(base_address)
        {
            release_mcp_lock_file(mcp_lock);
            return Err(ToolError::InvalidParams(error.to_string()));
        }
        if let Some(entry_point) = raw_target.entry_point {
            opts.entry_point(entry_point);
        }
        for arg in &init_args {
            opts.arg(arg);
        }
        let db = opts.idb(out_path).save(true).open(&expanded);
        (db, opened_path)
    };
    let _ = ticker_stop_tx.send(());
    let _ = ticker.join();
    let mut db = match db {
        Ok(db) => db,
        Err(e) => {
            release_mcp_lock_file(mcp_lock);
            if created_raw_database {
                remove_new_database_artifacts(&opened_path);
            }
            if let Some(lock_msg) =
                detect_db_lock(&opened_path, &e).or_else(|| detect_db_lock(&expanded, &e))
            {
                return Err(ToolError::DatabaseLocked(lock_msg));
            }
            return Err(ToolError::OpenFailed(format!(
                "{}: {}",
                opened_path.display(),
                e
            )));
        }
    };
    if let Some(bitness) = raw_target.bitness
        && let Err(error) = configure_raw_bitness(&mut db, bitness)
    {
        cleanup_failed_open(db, mcp_lock, &opened_path, created_raw_database);
        return Err(error);
    }
    if let Some(entry_point) = raw_target.entry_point
        && let Err(error) = configure_raw_entry_point(&mut db, entry_point)
    {
        cleanup_failed_open(db, mcp_lock, &opened_path, created_raw_database);
        return Err(error);
    }
    if auto_analyse
        && (raw_target.bitness.is_some() || raw_target.entry_point.is_some())
        && !db.auto_wait()
    {
        cleanup_failed_open(db, mcp_lock, &opened_path, created_raw_database);
        return Err(ToolError::OpenFailed(
            "IDA auto-analysis did not complete after raw target configuration".to_string(),
        ));
    }
    if let Err(error) = ensure_not_cancelled(cancel.as_ref()) {
        cleanup_failed_open(db, mcp_lock, &opened_path, created_raw_database);
        return Err(error);
    }
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
        if let Err(error) = ensure_not_cancelled(cancel.as_ref()) {
            cleanup_failed_open(db, mcp_lock, &opened_path, created_raw_database);
            return Err(error);
        }
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
    } else if !is_idb
        && should_load_dsym
        && let Some(path) = dsym_path.as_ref()
    {
        emit_progress(
            progress_tx.as_ref(),
            "loading_debug_info",
            3.0,
            Some(OPEN_IDB_PROGRESS_TOTAL),
            "Loading sibling dSYM debug information",
        );
        if let Err(error) = ensure_not_cancelled(cancel.as_ref()) {
            cleanup_failed_open(db, mcp_lock, &opened_path, created_raw_database);
            return Err(error);
        }
        info!(path = %path.display(), "Loading dSYM debug info");
        match db.load_debug_info(path, false) {
            Ok(true) => info!(path = %path.display(), "dSYM debug info loaded"),
            Ok(false) => warn!(path = %path.display(), "dSYM debug info load failed"),
            Err(e) => warn!(path = %path.display(), error = %e, "dSYM debug info load error"),
        }
    }
    if let Err(error) = ensure_not_cancelled(cancel.as_ref()) {
        cleanup_failed_open(db, mcp_lock, &opened_path, created_raw_database);
        return Err(error);
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
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::ida::handlers::database::{
        base_input_path_for_database, database_paths_match, existing_idb_for_raw_binary,
        existing_idb_for_raw_open, existing_raw_idb_action, has_ida_database_extension,
        idb_path_for_raw_binary, init_database_args, non_empty_trimmed,
        recorded_input_path_matches, sha256_file, validate_raw_idb_output, ExistingRawIdbAction,
    };

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("ida-mcp-{label}-{unique}"))
    }

    #[test]
    fn empty_optional_open_strings_are_ignored() {
        assert_eq!(non_empty_trimmed(None), None);
        assert_eq!(non_empty_trimmed(Some("")), None);
        assert_eq!(non_empty_trimmed(Some("  \t  ")), None);
        assert_eq!(non_empty_trimmed(Some(" pe ")), Some("pe"));
    }

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
    fn database_paths_match_treats_raw_input_and_generated_i64_as_same_database() {
        let raw = Path::new("/tmp/testA.exe");
        let generated = Path::new("/tmp/testA.exe.i64");
        let replaced_extension = Path::new("/tmp/testA.i64");

        assert!(database_paths_match(generated, raw));
        assert!(database_paths_match(raw, generated));
        assert!(!database_paths_match(raw, replaced_extension));
    }

    #[test]
    fn has_ida_database_extension_only_matches_real_database_extensions() {
        assert!(has_ida_database_extension(Path::new("/tmp/a.i64")));
        assert!(has_ida_database_extension(Path::new("/tmp/a.IDB")));
        assert!(!has_ida_database_extension(Path::new("/tmp/a.exe")));
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
    fn existing_idb_for_raw_binary_detects_generated_database_without_replacing_extension() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ida-mcp-test-{unique}"));
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("testA.exe");
        let generated = dir.join("testA.exe.i64");
        let replaced_extension = dir.join("testA.i64");

        fs::write(&raw, b"raw").expect("write raw");
        fs::write(&replaced_extension, b"wrong idb").expect("write replaced-extension idb");

        assert_eq!(existing_idb_for_raw_binary(&raw), None);

        fs::write(&generated, b"generated idb").expect("write generated idb");
        assert_eq!(existing_idb_for_raw_binary(&raw), Some(generated));
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn explicit_idb_out_does_not_reuse_default_generated_database() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ida-mcp-test-{unique}"));
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("dyld_shared_cache_arm64e");
        let generated = dir.join("dyld_shared_cache_arm64e.i64");
        let explicit = dir.join("explicit-output.i64");

        fs::write(&raw, b"raw").expect("write raw");
        fs::write(&generated, b"default generated idb").expect("write generated idb");

        assert_eq!(existing_idb_for_raw_open(&raw, Some(&explicit)), None);

        fs::write(&explicit, b"explicit generated idb").expect("write explicit idb");
        assert_eq!(
            existing_idb_for_raw_open(&raw, Some(&explicit)),
            Some(explicit)
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn explicit_idb_out_detects_an_unpacked_database() {
        let dir = temp_dir("unpacked-explicit-idb-out");
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("sample.bin");
        let explicit = dir.join("explicit.i64");
        let unpacked = dir.join("explicit.id0");
        fs::write(&raw, b"raw").expect("write raw");
        fs::write(&unpacked, b"unpacked database").expect("write unpacked database");

        assert_eq!(
            existing_idb_for_raw_open(&raw, Some(&explicit)),
            Some(explicit)
        );

        fs::remove_dir_all(&dir).expect("remove temp dir");
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

    #[test]
    fn existing_raw_idb_requires_hash_match_for_reuse() {
        let input_hash = [0x11; 32];
        let other_hash = [0x22; 32];
        let missing_hash = [0; 32];

        assert_eq!(
            existing_raw_idb_action(false, &input_hash, &input_hash, false),
            Some(ExistingRawIdbAction::Reuse)
        );
        assert_eq!(
            existing_raw_idb_action(false, &other_hash, &input_hash, true),
            None,
            "recorded path alone must not authorize automatic reuse"
        );
        assert_eq!(
            existing_raw_idb_action(false, &missing_hash, &input_hash, true),
            None,
            "missing IDA hashes must never authorize automatic reuse"
        );
    }

    #[test]
    fn rebuild_only_overwrites_provenance_matched_database() {
        let input_hash = [0x11; 32];
        let other_hash = [0x22; 32];
        let missing_hash = [0; 32];

        assert_eq!(
            existing_raw_idb_action(true, &input_hash, &input_hash, false),
            Some(ExistingRawIdbAction::Rebuild)
        );
        assert_eq!(
            existing_raw_idb_action(true, &other_hash, &input_hash, true),
            Some(ExistingRawIdbAction::Rebuild),
            "a recorded input-path match authorizes rebuilding changed input"
        );
        assert_eq!(
            existing_raw_idb_action(true, &missing_hash, &input_hash, true),
            Some(ExistingRawIdbAction::Rebuild)
        );
        assert_eq!(
            existing_raw_idb_action(true, &other_hash, &input_hash, false),
            None
        );
    }

    #[test]
    fn recorded_input_path_ignores_a_trailing_c_terminator() {
        let dir = temp_dir("recorded-input-path-c-terminator");
        fs::create_dir(&dir).expect("create temp dir");
        let input = dir.join("sample.bin");
        fs::write(&input, b"sample").expect("write input");
        let recorded = format!("{}\0", input.display());
        assert!(recorded_input_path_matches(&input, &recorded));
        fs::remove_dir_all(dir).expect("remove temp dir");
    }

    #[test]
    fn raw_idb_output_requires_safe_database_path() {
        let dir = temp_dir("validate-idb-out");
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("sample.bin");
        fs::write(&raw, b"raw").expect("write raw");

        assert!(validate_raw_idb_output(&raw, &dir.join("sample.i64")).is_ok());
        assert!(validate_raw_idb_output(&raw, &dir.join("sample.IDB")).is_ok());
        assert!(validate_raw_idb_output(&raw, &raw).is_err());
        assert!(validate_raw_idb_output(&raw, &dir.join("sample.txt")).is_err());
        assert!(validate_raw_idb_output(&raw, &dir.join("missing").join("sample.i64")).is_err());

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn raw_idb_output_rejects_orphaned_sidecars() {
        let dir = temp_dir("orphaned-idb-out");
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("sample.bin");
        let output = dir.join("sample.i64");
        fs::write(&raw, b"raw").expect("write raw");
        fs::write(dir.join("sample.nam"), b"pre-existing").expect("write orphaned sidecar");

        let error = validate_raw_idb_output(&raw, &output)
            .expect_err("orphaned IDA sidecar must reject a new output");
        assert!(error.to_string().contains("orphaned pre-existing"));

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn input_hash_is_streamed_as_sha256() {
        let dir = temp_dir("sha256-input");
        fs::create_dir(&dir).expect("create temp dir");
        let input = dir.join("sample.bin");
        fs::write(&input, b"abc").expect("write input");

        assert_eq!(
            sha256_file(&input).expect("hash input"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }
}
