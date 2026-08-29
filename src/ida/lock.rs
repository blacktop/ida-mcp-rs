//! MCP lock file helpers to prevent concurrent database access.

use crate::error::ToolError;
use idalib::IDAError;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, Write};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Lock file for an open IDA database to prevent concurrent access.
pub(crate) struct McpLock {
    file: File,
    path: PathBuf,
    /// Set to true when ownership is transferred to caller, preventing Drop cleanup
    transferred: bool,
}

impl McpLock {
    /// Transfer ownership of the lock file and path to the caller.
    /// After this call, Drop will not clean up the lock file.
    pub fn into_parts(mut self) -> (File, PathBuf) {
        self.transferred = true;
        // Use ManuallyDrop to prevent Drop from running, then extract fields
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: We set transferred=true above, so Drop won't do cleanup.
        // We're extracting fields from ManuallyDrop which won't run Drop.
        // Each field is read exactly once and we never access `this` again.
        let file = unsafe { std::ptr::read(&this.file) };
        let path = unsafe { std::ptr::read(&this.path) };
        (file, path)
    }
}

impl Drop for McpLock {
    fn drop(&mut self) {
        if !self.transferred && lock_path_names_file(&self.file, &self.path) {
            // Lock was not transferred to caller (e.g., panic occurred) - clean up
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Acquire an MCP lock file for the given database path.
pub(crate) fn acquire_mcp_lock(db_path: &Path) -> Result<McpLock, ToolError> {
    let mut lock_path = db_path.to_path_buf();
    lock_path.set_extension("imcp");

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| ToolError::OpenFailed(format!("{}: {}", lock_path.display(), e)))?;

    if let Err(pid) = try_lock_file(&file) {
        let mut msg = format!("{}", lock_path.display());
        if pid > 0 {
            msg = format!("{} (locked by pid {})", lock_path.display(), pid);
        }
        return Err(ToolError::DatabaseLocked(msg));
    }

    let pid = std::process::id();
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string());

    let info = format!(
        "pid={}\nhost={}\nexe={}\nopened_at={}\n",
        pid, host, exe, now
    );
    let _ = file.set_len(0);
    let _ = file.seek(std::io::SeekFrom::Start(0));
    let _ = file.write_all(info.as_bytes());
    let _ = file.flush();

    Ok(McpLock {
        file,
        path: lock_path,
        transferred: false,
    })
}

/// Reclaim the unlocked MCP lock file left by a worker the pool killed.
///
/// Cleanup callers must hold this lock while removing partial database
/// artifacts. Requiring the recorded worker PID prevents a delayed cleanup
/// from deleting files after another process has claimed the output.
pub(crate) fn reclaim_killed_worker_mcp_lock(
    db_path: &Path,
    worker_pid: Option<u32>,
) -> Option<McpLock> {
    let worker_pid = worker_pid?;
    let mut lock_path = db_path.to_path_buf();
    lock_path.set_extension("imcp");

    reclaim_mcp_lock_path(&lock_path, Some(worker_pid))
}

fn reclaim_mcp_lock_path(lock_path: &Path, expected_pid: Option<u32>) -> Option<McpLock> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .ok()?;
    if try_lock_file(&file).is_err() {
        return None;
    }
    let recorded_pid = read_lock_file_pid_from_file(&file);
    if recorded_pid != expected_pid || !lock_path_names_file(&file, lock_path) {
        return None;
    }

    Some(McpLock {
        file,
        path: lock_path.to_path_buf(),
        transferred: false,
    })
}

/// Release an MCP lock using mutable references to the file and path options.
pub(crate) fn release_mcp_lock(lock_file: &mut Option<File>, lock_path: &mut Option<PathBuf>) {
    let file = lock_file.take();
    let path = lock_path.take();
    if let (Some(file), Some(path)) = (file, path)
        && lock_path_names_file(&file, &path)
    {
        let _ = std::fs::remove_file(path);
    }
}

/// Release an MCP lock file directly.
pub(crate) fn release_mcp_lock_file(lock: McpLock) {
    let _ = remove_mcp_lock_file(lock);
}

fn remove_mcp_lock_file(lock: McpLock) -> Result<PathBuf, (PathBuf, std::io::Error)> {
    let path_is_owned = lock_path_names_file(&lock.file, &lock.path);
    let (_file, path) = lock.into_parts();
    if !path_is_owned {
        let error = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "MCP lock path no longer names the locked file",
        );
        return Err((path, error));
    }
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(path),
        Err(error) => Err((path, error)),
    }
}

/// Remove a lock file that still belongs to a worker process the pool killed.
pub(crate) fn remove_mcp_lock_for_pid(db_path: &Path, pid: Option<u32>) {
    let Some(pid) = pid else {
        return;
    };

    let Some(lock) = reclaim_killed_worker_mcp_lock(db_path, Some(pid)) else {
        return;
    };
    let lock_path = lock.path.clone();

    match remove_mcp_lock_file(lock) {
        Ok(_) => info!(
            path = %lock_path.display(),
            pid,
            "removed killed worker MCP lock file"
        ),
        Err((_, error)) => warn!(
            path = %lock_path.display(),
            pid,
            %error,
            "failed to remove killed worker MCP lock file"
        ),
    }
}

/// Information about a stale lock that was cleaned up.
#[derive(Debug)]
pub struct StaleLockInfo {
    pub path: PathBuf,
    pub pid: u32,
    pub reason: String,
}

/// Clean up stale MCP lock files for a database path.
/// Returns information about any stale locks that were removed.
pub(crate) fn clean_stale_mcp_lock(db_path: &Path) -> Option<StaleLockInfo> {
    let mut lock_path = db_path.to_path_buf();
    lock_path.set_extension("imcp");

    if !lock_path.exists() {
        return None;
    }

    // Try to read the lock file to get the PID
    let pid = match read_lock_file_pid(&lock_path) {
        Some(pid) => pid,
        None => {
            // Can't read PID, but file exists - try to acquire lock to check if stale
            if let Some(lock) = reclaim_mcp_lock_path(&lock_path, None) {
                return match remove_mcp_lock_file(lock) {
                    Ok(_) => {
                        info!(path = %lock_path.display(), "Removed stale lock file (no valid PID, no fcntl lock)");
                        Some(StaleLockInfo {
                            path: lock_path,
                            pid: 0,
                            reason: "no valid PID and no fcntl lock held".to_string(),
                        })
                    }
                    Err((_, error)) => {
                        warn!(path = %lock_path.display(), %error, "Failed to remove stale lock file");
                        None
                    }
                };
            }
            return None;
        }
    };

    // Check if the process is still running
    if is_process_running(pid) {
        // Process is still alive - lock is valid
        return None;
    }

    // Process is dead - this is a stale lock
    info!(
        path = %lock_path.display(),
        pid = pid,
        "Found stale lock file from dead process"
    );

    // Re-check the recorded owner while holding the advisory lock, then keep
    // that lock held through unlink so another worker cannot claim this path
    // between ownership validation and removal.
    let lock = reclaim_mcp_lock_path(&lock_path, Some(pid))?;
    if let Err((_, error)) = remove_mcp_lock_file(lock) {
        warn!(path = %lock_path.display(), %error, "Failed to remove stale lock file");
        return None;
    }

    info!(path = %lock_path.display(), pid = pid, "Removed stale lock file");
    Some(StaleLockInfo {
        path: lock_path,
        pid,
        reason: format!("process {} is no longer running", pid),
    })
}

/// Read the PID from a lock file.
fn read_lock_file_pid(lock_path: &Path) -> Option<u32> {
    let file = File::open(lock_path).ok()?;
    read_lock_file_pid_from_file(&file)
}

fn read_lock_file_pid_from_file(file: &File) -> Option<u32> {
    // POSIX process locks are released when *any* descriptor for the same
    // inode is closed. Read through the descriptor that owns the lock: a
    // cloned or freshly-opened descriptor would silently unlock cleanup when
    // it went out of scope.
    let mut reader = BufReader::new(file);
    reader.seek(std::io::SeekFrom::Start(0)).ok()?;

    for line in reader.lines().map_while(Result::ok) {
        if let Some(pid_str) = line.strip_prefix("pid=") {
            return pid_str.trim().parse().ok();
        }
    }
    None
}

#[cfg(unix)]
fn lock_path_names_file(file: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(file_metadata) = file.metadata() else {
        return false;
    };
    let Ok(path_metadata) = std::fs::metadata(path) else {
        return false;
    };
    file_metadata.dev() == path_metadata.dev() && file_metadata.ino() == path_metadata.ino()
}

#[cfg(windows)]
fn lock_path_names_file(file: &File, path: &Path) -> bool {
    let Ok(path_file) = File::open(path) else {
        return false;
    };
    windows_file_identity(file)
        .zip(windows_file_identity(&path_file))
        .is_some_and(|(locked_identity, path_identity)| locked_identity == path_identity)
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> Option<(u32, u64)> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: `file` keeps the OS handle valid for this call, and
    // GetFileInformationByHandle initializes the output structure on success.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) != 0 };
    if !succeeded {
        return None;
    }
    // SAFETY: the successful call above initialized the entire structure.
    let info = unsafe { info.assume_init() };
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Some((info.dwVolumeSerialNumber, index))
}

#[cfg(not(any(unix, windows)))]
fn lock_path_names_file(_file: &File, _path: &Path) -> bool {
    false
}

/// Check if a process with the given PID is still running.
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    // Send signal 0 to check if process exists
    // SAFETY: kill with signal 0 is safe - it doesn't actually send a signal,
    // just checks if the process exists and we have permission to signal it.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    // If kill returns -1, check errno
    // ESRCH means no such process
    // EPERM means process exists but we don't have permission (still running)
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno == libc::EPERM
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    // On non-Unix platforms, assume process might be running
    // This is conservative - won't clean up locks that might be stale
    true
}

/// Detect if a database file is locked by another process.
/// Returns a descriptive message if locked, None otherwise.
pub(crate) fn detect_db_lock(path: &Path, _err: &IDAError) -> Option<String> {
    let mut candidates = Vec::new();
    candidates.push(path.to_path_buf());

    if let Some(ext) = path.extension().and_then(|e| e.to_str())
        && (ext == "i64" || ext == "idb" || ext == "id0")
    {
        if ext == "id0" {
            let mut i64_path = path.to_path_buf();
            i64_path.set_extension("i64");
            candidates.push(i64_path);
        }

        let mut id0 = path.to_path_buf();
        id0.set_extension("id0");
        candidates.push(id0);

        let mut id1 = path.to_path_buf();
        id1.set_extension("id1");
        candidates.push(id1);

        let mut nam = path.to_path_buf();
        nam.set_extension("nam");
        candidates.push(nam);
    }

    let mut imcp = path.to_path_buf();
    imcp.set_extension("imcp");
    candidates.push(imcp);

    for candidate in candidates {
        if !candidate.exists() {
            continue;
        }
        if let Some(pid) = locked_by_pid(&candidate) {
            if pid == 0 {
                return Some(format!(
                    "{} (locked by another process)",
                    candidate.display()
                ));
            }
            return Some(format!("{} (locked by pid {})", candidate.display(), pid));
        }
    }

    None
}

// Platform-specific file locking implementation

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // F_WRLCK is i32 on Linux, i16 on macOS
fn try_lock_file(file: &File) -> Result<(), u32> {
    use std::os::unix::io::AsRawFd;

    let mut fl = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };

    // SAFETY: `file` is a valid open File, so `as_raw_fd()` returns a valid descriptor.
    // `fl` is properly initialized per POSIX flock requirements. The descriptor remains
    // valid for the duration of this call since we hold a reference to `file`.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &mut fl) };
    if rc == -1 {
        return Err(locked_by_pid_from_fd(file).unwrap_or(0));
    }
    Ok(())
}

#[cfg(not(unix))]
fn try_lock_file(file: &File) -> Result<(), u32> {
    file.try_lock().map_err(|_| 0)
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // F_WRLCK/F_UNLCK is i32 on Linux, i16 on macOS
fn locked_by_pid(path: &Path) -> Option<u32> {
    use std::os::unix::io::AsRawFd;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .or_else(|_| std::fs::OpenOptions::new().read(true).open(path))
        .ok()?;

    let mut fl = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };

    // SAFETY: `file` is a valid open File, so `as_raw_fd()` returns a valid descriptor.
    // `fl` is properly initialized per POSIX flock requirements. The descriptor remains
    // valid for the duration of this call since we hold a reference to `file`.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut fl) };
    if rc == -1 {
        return None;
    }
    if fl.l_type == libc::F_UNLCK as i16 {
        None
    } else {
        Some(fl.l_pid as u32)
    }
}

#[cfg(not(unix))]
fn locked_by_pid(path: &Path) -> Option<u32> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .or_else(|_| std::fs::OpenOptions::new().read(true).open(path))
        .ok()?;

    if try_lock_file(&file).is_ok() {
        return None;
    }

    read_lock_file_pid(path).or(Some(0))
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // F_WRLCK/F_UNLCK is i32 on Linux, i16 on macOS
fn locked_by_pid_from_fd(file: &File) -> Option<u32> {
    use std::os::unix::io::AsRawFd;

    let mut fl = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    // SAFETY: `file` is a valid open File, so `as_raw_fd()` returns a valid descriptor.
    // `fl` is properly initialized per POSIX flock requirements. The descriptor remains
    // valid for the duration of this call since we hold a reference to `file`.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut fl) };
    if rc == -1 {
        return None;
    }
    if fl.l_type == libc::F_UNLCK as i16 {
        None
    } else {
        Some(fl.l_pid as u32)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use crate::ida::lock::{reclaim_mcp_lock_path, try_lock_file};
    use std::fs::{self, OpenOptions};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    const LOCK_PROBE_PATH: &str = "IDA_MCP_LOCK_PROBE_PATH";

    #[test]
    fn mcp_lock_probe_subprocess() {
        let Some(path) = std::env::var_os(LOCK_PROBE_PATH) else {
            return;
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("probe should open the parent's lock file");
        assert!(
            try_lock_file(&file).is_err(),
            "another process acquired the reclaimed lock"
        );
    }

    #[test]
    fn reclaimed_lock_remains_held_after_owner_validation() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should follow the Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ida-mcp-lock-{}-{unique}.imcp", std::process::id()));
        let recorded_pid = 424_242;
        fs::write(&path, format!("pid={recorded_pid}\n"))
            .expect("test should create its lock file");

        let lock = reclaim_mcp_lock_path(&path, Some(recorded_pid))
            .expect("test should reclaim the unlocked file");
        let output = Command::new(std::env::current_exe().expect("test binary should be known"))
            .arg("mcp_lock_probe_subprocess")
            .arg("--nocapture")
            .env(LOCK_PROBE_PATH, &path)
            .output()
            .expect("lock probe subprocess should run");

        assert!(
            output.status.success(),
            "lock probe failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        drop(lock);
        assert!(
            !path.exists(),
            "dropping the reclaimed lock should unlink it"
        );
    }
}

#[cfg(all(test, any(unix, windows)))]
mod identity_cleanup_tests {
    use crate::ida::lock::{lock_path_names_file, release_mcp_lock, remove_mcp_lock_file, McpLock};
    use std::fs::{self, File, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn replaced_lock(name: &str) -> (File, PathBuf, PathBuf) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should follow the Unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ida-mcp-lock-replacement-{}-{name}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("create test directory");
        let path = dir.join("database.imcp");
        let moved = dir.join("previous.imcp");
        fs::write(&path, b"pid=1\n").expect("create original lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open original lock");
        assert!(lock_path_names_file(&file, &path));
        fs::rename(&path, &moved).expect("move original lock while its handle is open");
        fs::write(&path, b"pid=2\n").expect("create replacement lock");
        assert!(!lock_path_names_file(&file, &path));
        (file, path, moved)
    }

    fn assert_replacement_survived(path: &Path, moved: &Path) {
        assert_eq!(
            fs::read(path).expect("replacement lock should remain"),
            b"pid=2\n"
        );
        let dir = path.parent().expect("test lock should have a parent");
        fs::remove_file(moved).expect("remove moved original lock");
        fs::remove_file(path).expect("remove replacement lock");
        fs::remove_dir(dir).expect("remove test directory");
    }

    #[test]
    fn every_lock_release_path_preserves_a_replacement_owner() {
        let (file, path, moved) = replaced_lock("drop");
        drop(McpLock {
            file,
            path: path.clone(),
            transferred: false,
        });
        assert_replacement_survived(&path, &moved);

        let (file, path, moved) = replaced_lock("remove");
        let result = remove_mcp_lock_file(McpLock {
            file,
            path: path.clone(),
            transferred: false,
        });
        assert!(result.is_err(), "replacement identity must fail closed");
        assert_replacement_survived(&path, &moved);

        let (file, path, moved) = replaced_lock("release");
        let mut file = Some(file);
        let mut lock_path = Some(path.clone());
        release_mcp_lock(&mut file, &mut lock_path);
        assert!(file.is_none());
        assert!(lock_path.is_none());
        assert_replacement_survived(&path, &moved);
    }
}
