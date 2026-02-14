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
        if !self.transferred {
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
        .truncate(true)
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

/// Release an MCP lock using mutable references to the file and path options.
pub(crate) fn release_mcp_lock(lock_file: &mut Option<File>, lock_path: &mut Option<PathBuf>) {
    if let Some(path) = lock_path.take() {
        let _ = std::fs::remove_file(path);
    }
    *lock_file = None;
}

/// Release an MCP lock file directly.
pub(crate) fn release_mcp_lock_file(lock: McpLock) {
    let (_file, path) = lock.into_parts();
    let _ = std::fs::remove_file(path);
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
            if let Ok(file) = OpenOptions::new().read(true).write(true).open(&lock_path) {
                if try_lock_file(&file).is_ok() {
                    // We got the lock - file was stale (no process holding fcntl lock)
                    drop(file);
                    if std::fs::remove_file(&lock_path).is_ok() {
                        info!(path = %lock_path.display(), "Removed stale lock file (no valid PID, no fcntl lock)");
                        return Some(StaleLockInfo {
                            path: lock_path,
                            pid: 0,
                            reason: "no valid PID and no fcntl lock held".to_string(),
                        });
                    }
                }
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

    // Remove the stale lock file
    if let Err(e) = std::fs::remove_file(&lock_path) {
        warn!(
            path = %lock_path.display(),
            error = %e,
            "Failed to remove stale lock file"
        );
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
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        if let Some(pid_str) = line.strip_prefix("pid=") {
            return pid_str.trim().parse().ok();
        }
    }
    None
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

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if ext == "i64" || ext == "idb" || ext == "id0" {
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
fn try_lock_file(_file: &File) -> Result<(), u32> {
    Ok(())
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
fn locked_by_pid(_path: &Path) -> Option<u32> {
    None
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
