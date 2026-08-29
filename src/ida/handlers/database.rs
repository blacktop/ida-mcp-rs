//! Database open/close handlers.
//!
//! # Provenance closure
//!
//! Every path that reuses (or overwrites) an existing on-disk artifact must
//! verify content identity or carry a documented exemption. A new reuse path
//! extends this table — with its verification or its exemption — before it
//! ships; "the file exists" is never sufficient identity on its own.
//!
//! | reuse path | identity check |
//! |---|---|
//! | raw input → explicit `idb_out` | recorded input SHA-256 vs streamed hash (`existing_raw_idb_action`) |
//! | raw input → default `<input>.i64` sibling | same hash verification, same code path |
//! | `rebuild=true` replacement | hash or recorded-input-path match required; unrelated/corrupt outputs refused |
//! | idempotent retry of an open raw-input database | output identity + recorded input path + freshly streamed SHA-256 (`open_database_matches_raw_request`) |
//! | pooled raw open forcibly retired before response | pre-open artifact snapshot + exact killed-worker output-lock reclaim (`RawOpenArtifactCleanup`) |
//! | direct `.i64`/`.idb`/`.id0` open | exemption: the database itself is the requested object; there is no separate input to verify against |
//! | unpacked `.id0` fallback for a missing packed path | same exemption as direct opens (`open_existing_idb`) |
//! | DSC managed temp cache | cache filename keyed by the DSC header UUID; inputs without a trustworthy UUID are rejected (`dsc_content_identity` in `server::mod`) |
//! | DSC sibling `.i64` next to the cache | exemption: user-managed artifact beside their own file; delete it to force a reload (documented in `open_dsc` reuse-order comment) |
//! | `debug_open_module` output | standalone image or DSC primary opened through `open_idb` with explicit `idb_out`, so the raw-input hash verification above applies |

use crate::error::ToolError;
use crate::expand_path;
use crate::ida::handlers::analysis::build_analysis_status;
use crate::ida::lock::{
    acquire_mcp_lock, clean_stale_mcp_lock, detect_db_lock, reclaim_killed_worker_mcp_lock,
    release_mcp_lock_file, McpLock,
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
pub(crate) fn database_bitness(db: &IDB) -> u32 {
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

pub(crate) fn database_path_for_open_request(path: &str, idb_out: Option<&str>) -> PathBuf {
    let input = expand_path(path);
    if has_ida_database_extension(&input) {
        input
    } else {
        idb_out
            .map(expand_path)
            .unwrap_or_else(|| idb_path_for_raw_binary(&input))
    }
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

pub(crate) fn ida_database_output_exists(output: &Path) -> bool {
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

fn sha256_reader(
    reader: &mut impl Read,
    path: &Path,
    cancel: Option<&CancellationToken>,
) -> Result<[u8; 32], ToolError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        ensure_not_cancelled(cancel)?;
        let count = reader.read(&mut buffer).map_err(|error| {
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
    ensure_not_cancelled(cancel)?;

    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

fn sha256_file(path: &Path, cancel: Option<&CancellationToken>) -> Result<[u8; 32], ToolError> {
    let mut file = File::open(path).map_err(|error| {
        ToolError::OpenFailed(format!(
            "failed to read input for SHA-256 verification ({}): {error}",
            path.display()
        ))
    })?;
    sha256_reader(&mut file, path, cancel)
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
    let recorded = recorded.trim_end_matches('\0');
    !recorded.is_empty() && paths_refer_to_same_file(input, &expand_path(recorded))
}

/// Check the path half of a raw-input retry against the database that is
/// already open. Content identity is deliberately checked separately below:
/// path equality alone must never authorize stale-analysis reuse.
fn open_database_path_matches_raw_request(
    current_path: &Path,
    requested_input: &Path,
    requested_output: Option<&Path>,
    recorded_input: &str,
) -> bool {
    if has_ida_database_extension(requested_input) {
        return false;
    }
    let output_matches = match requested_output {
        Some(requested_output) => {
            // IDA may hold the requested packed output open in unpacked form,
            // so the retry's `.i64`/`.idb` also matches its `.id0` sibling.
            paths_refer_to_same_file(current_path, requested_output)
                || unpacked_id0_path(requested_output).as_deref() == Some(current_path)
        }
        None => database_paths_match(current_path, requested_input),
    };
    output_matches && recorded_input_path_matches(requested_input, recorded_input)
}

/// Prove the full identity of an idempotent raw-input open.
///
/// Both default-output and explicit-`idb_out` retries flow through this one
/// boundary. The output path and recorded source path establish which
/// database is being addressed; a freshly streamed SHA-256 establishes that
/// the currently-open analysis still belongs to the current input bytes.
fn open_database_matches_raw_request(
    database_input_path: &Path,
    effective_database_path: Option<&Path>,
    requested_input: &Path,
    requested_output: Option<&Path>,
    recorded_input: &str,
    recorded_hash: &[u8; 32],
    cancel: Option<&CancellationToken>,
) -> Result<bool, ToolError> {
    let current_path = effective_database_path.unwrap_or(database_input_path);
    if !open_database_path_matches_raw_request(
        current_path,
        requested_input,
        requested_output,
        recorded_input,
    ) || recorded_hash.iter().all(|byte| *byte == 0)
    {
        return Ok(false);
    }

    Ok(sha256_file(requested_input, cancel)? == *recorded_hash)
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

/// Pre-open identity of one database artifact.
///
/// A `rebuild=true` open intends to replace an existing provenance-matched
/// database, so failure cleanup cannot simply delete every artifact path: an
/// open that fails *before* IDA writes anything (missing input, license
/// refusal) would otherwise destroy the user's analyzed database that this
/// call never touched. Comparing against this snapshot removes only what the
/// call actually created or modified.
struct ArtifactSnapshot {
    path: PathBuf,
    before: Option<(u64, Option<std::time::SystemTime>)>,
}

pub(crate) struct RawOpenArtifactCleanup {
    output: PathBuf,
    artifacts: Vec<ArtifactSnapshot>,
}

const WORKER_LOCK_RECLAIM_ATTEMPTS: usize = 20;
const WORKER_LOCK_RECLAIM_BACKOFF: Duration = Duration::from_millis(25);

impl RawOpenArtifactCleanup {
    pub(crate) fn for_request(path: &str, idb_out: Option<&str>, rebuild: bool) -> Option<Self> {
        let input = expand_path(path);
        if has_ida_database_extension(&input) {
            return None;
        }
        let output = database_path_for_open_request(path, idb_out);
        if !rebuild && ida_database_output_exists(&output) {
            return None;
        }
        Some(Self {
            artifacts: snapshot_database_artifacts(&output),
            output,
        })
    }

    pub(crate) async fn cleanup_after_worker_loss(self, worker_pid: Option<u32>) {
        for attempt in 0..WORKER_LOCK_RECLAIM_ATTEMPTS {
            if let Some(mcp_lock) = reclaim_killed_worker_mcp_lock(&self.output, worker_pid) {
                remove_new_database_artifacts(&self.artifacts);
                release_mcp_lock_file(mcp_lock);
                return;
            }
            if attempt + 1 < WORKER_LOCK_RECLAIM_ATTEMPTS {
                tokio::time::sleep(WORKER_LOCK_RECLAIM_BACKOFF).await;
            }
        }
        warn!(
            path = %self.output.display(),
            ?worker_pid,
            "Skipped partial open cleanup because the killed worker's output lock could not be reclaimed"
        );
    }
}

fn artifact_identity(path: &Path) -> Option<(u64, Option<std::time::SystemTime>)> {
    let metadata = fs::metadata(path).ok()?;
    Some((metadata.len(), metadata.modified().ok()))
}

fn snapshot_database_artifacts(output: &Path) -> Vec<ArtifactSnapshot> {
    database_artifact_paths(output)
        .into_iter()
        .map(|path| ArtifactSnapshot {
            before: artifact_identity(&path),
            path,
        })
        .collect()
}

fn remove_new_database_artifacts(artifacts: &[ArtifactSnapshot]) {
    for artifact in artifacts {
        let now = artifact_identity(&artifact.path);
        let touched_by_this_call = match (&artifact.before, &now) {
            // Nothing is there now: nothing to clean up.
            (_, None) => false,
            // Created by this call.
            (None, Some(_)) => true,
            // Rewritten by this call.
            (Some(before), Some(now)) => before != now,
        };
        if !touched_by_this_call {
            continue;
        }
        match fs::remove_file(&artifact.path) {
            Ok(()) => {
                info!(path = %artifact.path.display(), "Removed partial IDA database artifact")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!(
                path = %artifact.path.display(),
                error = %error,
                "Failed to remove partial IDA database artifact"
            ),
        }
    }
}

fn cleanup_open_artifacts_before_unlock(mcp_lock: McpLock, artifacts: Option<&[ArtifactSnapshot]>) {
    if let Some(artifacts) = artifacts {
        remove_new_database_artifacts(artifacts);
    }
    release_mcp_lock_file(mcp_lock);
}

fn cleanup_failed_open(db: IDB, mcp_lock: McpLock, artifacts: Option<&[ArtifactSnapshot]>) {
    drop(db);
    cleanup_open_artifacts_before_unlock(mcp_lock, artifacts);
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

fn normalized_raw_entry_point(raw_target: &RawBinaryTarget) -> Option<(u64, bool)> {
    let entry_point = raw_target.entry_point?;
    let arm = raw_target
        .processor
        .as_deref()
        .and_then(|processor| processor.split(':').next())
        .is_some_and(|family| family.eq_ignore_ascii_case("arm"));
    let thumb = arm && entry_point & 1 == 1;
    Some((if thumb { entry_point & !1 } else { entry_point }, thumb))
}

fn configure_raw_entry_point(db: &mut IDB, entry_point: u64, thumb: bool) -> Result<(), ToolError> {
    if db.segment_at(entry_point).is_none() {
        return Err(ToolError::OpenFailed(format!(
            "raw entry point {entry_point:#x} is outside every loaded segment"
        )));
    }

    if thumb {
        let mut processor = db.processor();
        if !processor.is_thumb_at(entry_point) && !processor.set_thumb_at(entry_point, true) {
            return Err(ToolError::OpenFailed(format!(
                "IDA refused Thumb state at raw entry point {entry_point:#x}"
            )));
        }
        if !processor.is_thumb_at(entry_point) {
            return Err(ToolError::OpenFailed(format!(
                "IDA did not retain Thumb state at raw entry point {entry_point:#x}"
            )));
        }
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

fn materialize_raw_entry_point(
    db: &mut IDB,
    entry_point: u64,
    thumb: bool,
) -> Result<(), ToolError> {
    if !thumb {
        return Ok(());
    }

    let restored_thumb = {
        let mut processor = db.processor();
        let was_thumb = processor.is_thumb_at(entry_point);
        if !was_thumb && !processor.set_thumb_at(entry_point, true) {
            return Err(ToolError::OpenFailed(format!(
                "IDA refused Thumb state at raw entry point {entry_point:#x} after analysis"
            )));
        }
        if !processor.is_thumb_at(entry_point) {
            return Err(ToolError::OpenFailed(format!(
                "IDA did not retain Thumb state at raw entry point {entry_point:#x} after analysis"
            )));
        }
        !was_thumb
    };

    if (restored_thumb || !db.flags_at(entry_point).is_code()) && !db.recreate_insn_at(entry_point)
    {
        return Err(ToolError::OpenFailed(format!(
            "IDA could not create code at raw entry point {entry_point:#x}"
        )));
    }
    if !db.flags_at(entry_point).is_code() {
        return Err(ToolError::OpenFailed(format!(
            "IDA did not retain code at raw entry point {entry_point:#x}"
        )));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn handle_open(
    idb: &mut Option<IDB>,
    effective_database_path: Option<&Path>,
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
    let is_idb = has_ida_database_extension(&expanded);
    let raw_entry_point = normalized_raw_entry_point(raw_target);

    if is_idb && (idb_out.is_some() || !raw_target.is_empty()) {
        return Err(ToolError::InvalidParams(
            "processor, bitness, base_address, entry_point, and idb_out apply only to a raw input"
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
    if idb.is_some() && !raw_target.is_empty() {
        return Err(ToolError::InvalidParams(
            "raw target options only apply while creating a database; close the open database before retrying with processor, bitness, base_address, or entry_point"
                .to_string(),
        ));
    }

    // Check if a database is already open
    if let Some(db) = idb.as_ref() {
        let database_input_path = db.path();
        let current_path = effective_database_path.unwrap_or(database_input_path);
        let requested_output = idb_out.map(expand_path);
        let same_database = if is_idb {
            database_paths_match(current_path, &expanded)
        } else {
            let meta = db.meta();
            open_database_matches_raw_request(
                database_input_path,
                effective_database_path,
                &expanded,
                requested_output.as_deref(),
                &meta.input_file_path(),
                &meta.input_file_sha256(),
                cancel.as_ref(),
            )?
        };
        if same_database {
            // Same database and, for raw inputs, same current bytes: return
            // its info instead of reopening.
            info!(path = %expanded.display(), "Database already open, returning existing info");
            return Ok(build_db_info(db, &current_path.display().to_string(), None));
        }
        // Different database - tell them to close first
        return Err(ToolError::DatabaseAlreadyOpen(
            current_path.display().to_string(),
        ));
    }

    // Check file exists
    // A packed database can legitimately be absent while its unpacked `.id0`
    // form exists. `open_existing_idb` already knows how to fall back to that
    // path, so keep the fallback reachable from direct `.i64`/`.idb` opens.
    if !ida_database_output_exists(&expanded) {
        return Err(ToolError::InvalidPath(format!(
            "File not found: {}",
            expanded.display()
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
    let mut existing_raw_idb = None;
    if let Some(candidate_path) = existing_raw_idb_candidate.as_ref() {
        let (mut candidate, opened_candidate_path) = match open_existing_idb(
            candidate_path,
            &init_args,
            false,
        ) {
            Ok(candidate) => candidate,
            Err(error) => {
                release_mcp_lock_file(mcp_lock);
                if let Some(lock_message) = detect_db_lock(candidate_path, &error) {
                    return Err(ToolError::DatabaseLocked(lock_message));
                }
                return Err(ToolError::OpenFailed(format!(
                    "refusing to reuse or overwrite {} because its input provenance could not be read: {error}",
                    candidate_path.display()
                )));
            }
        };
        let recorded_hash = candidate.meta().input_file_sha256();
        let recorded_path = candidate.meta().input_file_path();
        if let Err(error) = ensure_not_cancelled(cancel.as_ref()) {
            drop(candidate);
            release_mcp_lock_file(mcp_lock);
            return Err(error);
        }
        let input_hash = match sha256_file(&expanded, cancel.as_ref()) {
            Ok(hash) => hash,
            Err(error) => {
                drop(candidate);
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
                candidate.save_on_close(true);
                existing_raw_idb = Some((candidate, opened_candidate_path));
            }
            Some(ExistingRawIdbAction::Rebuild) => {
                drop(candidate);
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
                drop(candidate);
                release_mcp_lock_file(mcp_lock);
                let recorded_hash_available = recorded_hash.iter().any(|byte| *byte != 0);
                let message = if !rebuild && path_matches {
                    if recorded_hash_available {
                        format!(
                            "{} was created from this input path, but its recorded SHA-256 does not match the current file; open that database path directly to preserve its analysis, choose a different idb_out, or retry with rebuild=true to replace stale analysis",
                            candidate_path.display()
                        )
                    } else {
                        format!(
                            "{} has no recorded input SHA-256 and cannot be reused automatically; open that database path directly to preserve its analysis, choose a different idb_out, or retry with rebuild=true to replace it because its recorded input path matches",
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
    let created_raw_database = !is_idb && existing_raw_idb.is_none();
    // Snapshot before IDA can write: cleanup removes only what this call
    // creates or rewrites, so a rebuild that fails before touching the
    // output leaves the existing database intact.
    let owned_artifacts = raw_out_path
        .as_deref()
        .filter(|_| created_raw_database)
        .map(snapshot_database_artifacts);

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
    let open_existing_database = is_idb || existing_raw_idb.is_some();
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
    let (db, opened_path) = if let Some((database, opened_path)) = existing_raw_idb.take() {
        (Ok(database), opened_path)
    } else if is_idb {
        // Open existing IDA database (no auto-analysis needed, but save=true to pack on close)
        match open_existing_idb(&expanded, &init_args, true) {
            Ok((database, opened_path)) => (Ok(database), opened_path),
            Err(error) => (Err(error), expanded.clone()),
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
        if let Some((entry_point, _)) = raw_entry_point {
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
            cleanup_open_artifacts_before_unlock(mcp_lock, owned_artifacts.as_deref());
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
        cleanup_failed_open(db, mcp_lock, owned_artifacts.as_deref());
        return Err(error);
    }
    if let Some((entry_point, thumb)) = raw_entry_point
        && let Err(error) = configure_raw_entry_point(&mut db, entry_point, thumb)
    {
        cleanup_failed_open(db, mcp_lock, owned_artifacts.as_deref());
        return Err(error);
    }
    if auto_analyse
        && (raw_target.bitness.is_some() || raw_target.entry_point.is_some())
        && !db.auto_wait()
    {
        cleanup_failed_open(db, mcp_lock, owned_artifacts.as_deref());
        return Err(ToolError::OpenFailed(
            "IDA auto-analysis did not complete after raw target configuration".to_string(),
        ));
    }
    if let Some((entry_point, thumb)) = raw_entry_point
        && let Err(error) = materialize_raw_entry_point(&mut db, entry_point, thumb)
    {
        cleanup_failed_open(db, mcp_lock, owned_artifacts.as_deref());
        return Err(error);
    }
    if let Err(error) = ensure_not_cancelled(cancel.as_ref()) {
        cleanup_failed_open(db, mcp_lock, owned_artifacts.as_deref());
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
            cleanup_failed_open(db, mcp_lock, owned_artifacts.as_deref());
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
            cleanup_failed_open(db, mcp_lock, owned_artifacts.as_deref());
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
        cleanup_failed_open(db, mcp_lock, owned_artifacts.as_deref());
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
        io::{Cursor, Read},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::error::ToolError;
    use crate::ida::handlers::database::{
        base_input_path_for_database, database_paths_match, existing_idb_for_raw_binary,
        existing_idb_for_raw_open, existing_raw_idb_action, has_ida_database_extension,
        idb_path_for_raw_binary, init_database_args, non_empty_trimmed, normalized_raw_entry_point,
        open_database_matches_raw_request, open_database_path_matches_raw_request,
        recorded_input_path_matches, remove_new_database_artifacts, sha256_file, sha256_reader,
        snapshot_database_artifacts, validate_raw_idb_output, ExistingRawIdbAction,
        RawOpenArtifactCleanup,
    };
    use crate::ida::lock::acquire_mcp_lock;
    use crate::ida::types::RawBinaryTarget;
    use tokio_util::sync::CancellationToken;

    struct CancelAfterFirstRead {
        inner: Cursor<Vec<u8>>,
        cancel: CancellationToken,
        reads: usize,
    }

    impl Read for CancelAfterFirstRead {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.inner.read(buffer)?;
            self.reads += 1;
            if count > 0 && self.reads == 1 {
                self.cancel.cancel();
            }
            Ok(count)
        }
    }

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
    fn arm_thumb_entry_point_is_normalized_without_affecting_other_processors() {
        let thumb = RawBinaryTarget {
            processor: Some("arm:ARMv7-M".to_string()),
            bitness: Some(idalib::segment::Bitness::Bits32),
            base_address: Some(0x0800_0000),
            entry_point: Some(0x0800_0101),
        };
        assert_eq!(
            normalized_raw_entry_point(&thumb),
            Some((0x0800_0100, true))
        );

        let non_arm = RawBinaryTarget {
            processor: Some("metapc:80386p".to_string()),
            entry_point: Some(0x1001),
            ..RawBinaryTarget::default()
        };
        assert_eq!(normalized_raw_entry_point(&non_arm), Some((0x1001, false)));
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
    fn recorded_input_path_preserves_filename_whitespace() {
        let dir = temp_dir("recorded-input-path-whitespace");
        fs::create_dir(&dir).expect("create temp dir");
        let spaced = dir.join(" sample.bin ");
        let trimmed = dir.join("sample.bin");
        fs::write(&spaced, b"spaced").expect("write spaced input");
        fs::write(&trimmed, b"trimmed").expect("write trimmed input");
        let recorded = format!("{}\0", spaced.display());

        assert!(recorded_input_path_matches(&spaced, &recorded));
        assert!(!recorded_input_path_matches(&trimmed, &recorded));

        fs::remove_dir_all(dir).expect("remove temp dir");
    }

    /// A rebuild that fails before IDA writes anything must leave the
    /// existing database intact: cleanup removes only artifacts this call
    /// created or rewrote.
    #[test]
    fn failed_open_cleanup_preserves_an_untouched_existing_database() {
        let dir = temp_dir("cleanup-preserves-existing");
        fs::create_dir(&dir).expect("create temp dir");
        let output = dir.join("firmware.i64");
        fs::write(&output, b"existing analyzed database").expect("write existing database");
        let sidecar = dir.join("firmware.id1");
        fs::write(&sidecar, b"existing sidecar").expect("write sidecar");

        // Snapshot, then fail without touching anything.
        let artifacts = snapshot_database_artifacts(&output);
        remove_new_database_artifacts(&artifacts);
        assert!(
            output.exists(),
            "an untouched database must survive cleanup"
        );
        assert!(
            sidecar.exists(),
            "an untouched sidecar must survive cleanup"
        );

        // Snapshot, then partially write: the rewritten artifacts go away.
        let artifacts = snapshot_database_artifacts(&output);
        fs::write(&output, b"partial rebuild output").expect("rewrite output");
        let fresh = dir.join("firmware.id0");
        fs::write(&fresh, b"new artifact").expect("write new artifact");
        remove_new_database_artifacts(&artifacts);
        assert!(!output.exists(), "a rewritten output must be removed");
        assert!(!fresh.exists(), "a newly created artifact must be removed");
        assert!(sidecar.exists(), "an untouched sidecar must still survive");

        fs::remove_dir_all(dir).expect("remove temp dir");
    }

    #[tokio::test]
    async fn killed_raw_open_cleanup_removes_only_artifacts_owned_by_its_lock() {
        let dir = temp_dir("killed-open-cleanup");
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("firmware.bin");
        let output = dir.join("firmware.i64");
        fs::write(&raw, b"raw").expect("write raw input");
        let cleanup = RawOpenArtifactCleanup::for_request(
            &raw.display().to_string(),
            Some(&output.display().to_string()),
            false,
        )
        .expect("new raw output owns its artifacts");

        let lock = acquire_mcp_lock(&output).expect("acquire simulated worker lock");
        let (lock_file, lock_path) = lock.into_parts();
        drop(lock_file);
        let partial = dir.join("firmware.id0");
        fs::write(&partial, b"partial").expect("write partial artifact");

        cleanup
            .cleanup_after_worker_loss(Some(std::process::id()))
            .await;

        assert!(
            !partial.exists(),
            "the killed open's partial ID0 must be removed"
        );
        assert!(
            !lock_path.exists(),
            "the reclaimed worker lock must be released"
        );
        fs::remove_dir_all(dir).expect("remove temp dir");
    }

    #[tokio::test]
    async fn killed_raw_open_cleanup_refuses_a_different_lock_owner() {
        let dir = temp_dir("killed-open-lock-owner");
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("firmware.bin");
        let output = dir.join("firmware.i64");
        fs::write(&raw, b"raw").expect("write raw input");
        let cleanup = RawOpenArtifactCleanup::for_request(
            &raw.display().to_string(),
            Some(&output.display().to_string()),
            false,
        )
        .expect("new raw output owns its artifacts");

        let lock = acquire_mcp_lock(&output).expect("acquire another owner's lock");
        let (lock_file, lock_path) = lock.into_parts();
        drop(lock_file);
        let partial = dir.join("firmware.id0");
        fs::write(&partial, b"other owner's artifact").expect("write owned artifact");

        cleanup
            .cleanup_after_worker_loss(Some(std::process::id().saturating_add(1)))
            .await;

        assert!(
            partial.exists(),
            "cleanup must not touch another owner's artifact"
        );
        fs::remove_file(lock_path).expect("remove simulated lock");
        fs::remove_dir_all(dir).expect("remove temp dir");
    }

    #[test]
    fn raw_retry_path_matches_only_same_input_and_output() {
        let dir = temp_dir("explicit-output-retry");
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("firmware.bin");
        fs::write(&raw, b"raw").expect("write raw input");
        let output = dir.join("custom.i64");
        let recorded = format!("{}\0", raw.display());

        assert!(open_database_path_matches_raw_request(
            &output,
            &raw,
            Some(&output),
            &recorded
        ));
        // No idb_out on the retry: only the default identity rules apply.
        assert!(!open_database_path_matches_raw_request(
            &output, &raw, None, &recorded
        ));
        // A direct database open never matches through idb_out.
        assert!(!open_database_path_matches_raw_request(
            &output,
            &dir.join("firmware.i64"),
            Some(&output),
            &recorded
        ));
        // Same output requested for a different raw input stays a conflict.
        let other = dir.join("other.bin");
        fs::write(&other, b"other").expect("write other input");
        assert!(!open_database_path_matches_raw_request(
            &output,
            &other,
            Some(&output),
            &recorded
        ));
        // A different output path is a different database.
        assert!(!open_database_path_matches_raw_request(
            &output,
            &raw,
            Some(&dir.join("elsewhere.i64")),
            &recorded
        ));
        // An explicit output makes that output the request identity. Do not
        // silently return a default sibling that happens to be open.
        assert!(!open_database_path_matches_raw_request(
            &dir.join("firmware.bin.i64"),
            &raw,
            Some(&output),
            &recorded
        ));
        assert!(database_paths_match(&dir.join("firmware.bin.i64"), &raw));
        // The requested packed output also matches its open unpacked form.
        assert!(open_database_path_matches_raw_request(
            &dir.join("custom.id0"),
            &raw,
            Some(&output),
            &recorded
        ));
        assert!(!open_database_path_matches_raw_request(
            &dir.join("elsewhere.id0"),
            &raw,
            Some(&output),
            &recorded
        ));

        fs::remove_dir_all(dir).expect("remove temp dir");
    }

    #[test]
    fn raw_retry_revalidates_content_for_default_and_explicit_outputs() {
        let dir = temp_dir("raw-retry-content");
        fs::create_dir(&dir).expect("create temp dir");
        let raw = dir.join("firmware.bin");
        let default_output = dir.join("firmware.bin.i64");
        let explicit_output = dir.join("custom.i64");
        fs::write(&raw, b"first firmware").expect("write raw input");
        let recorded_hash = sha256_file(&raw, None).expect("hash original input");
        let recorded_path = raw.display().to_string();

        assert!(open_database_matches_raw_request(
            &raw,
            Some(&default_output),
            &raw,
            None,
            &recorded_path,
            &recorded_hash,
            None,
        )
        .expect("verify default output retry"));
        assert!(open_database_matches_raw_request(
            &raw,
            Some(&explicit_output),
            &raw,
            Some(&explicit_output),
            &recorded_path,
            &recorded_hash,
            None,
        )
        .expect("verify explicit output retry"));
        assert!(!open_database_matches_raw_request(
            &raw,
            None,
            &raw,
            Some(&explicit_output),
            &recorded_path,
            &recorded_hash,
            None,
        )
        .expect("the raw IDB input path is not the effective explicit output"));

        fs::write(&raw, b"second firmware").expect("replace raw input");
        assert!(!open_database_matches_raw_request(
            &raw,
            Some(&default_output),
            &raw,
            None,
            &recorded_path,
            &recorded_hash,
            None,
        )
        .expect("reject stale default output"));
        assert!(!open_database_matches_raw_request(
            &raw,
            Some(&explicit_output),
            &raw,
            Some(&explicit_output),
            &recorded_path,
            &recorded_hash,
            None,
        )
        .expect("reject stale explicit output"));

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
            sha256_file(&input, None).expect("hash input"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn input_hash_stops_between_reads_after_cancellation() {
        let cancel = CancellationToken::new();
        let mut reader = CancelAfterFirstRead {
            inner: Cursor::new(vec![0u8; 128 * 1024]),
            cancel: cancel.clone(),
            reads: 0,
        };

        let error = sha256_reader(&mut reader, Path::new("large-input.bin"), Some(&cancel))
            .expect_err("hashing must stop after cancellation");

        assert!(matches!(error, ToolError::Cancelled(_)));
        assert_eq!(reader.reads, 1, "no read may begin after cancellation");
    }
}
