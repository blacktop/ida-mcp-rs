//! Process-local Windows registry isolation for the embedded IDA runtime.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::process;
use std::ptr::{null, null_mut};

use tracing::{info, warn};
use uuid::Uuid;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_ITEMS,
    ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCopyTreeW, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegEnumKeyExW,
    RegOverridePredefKey, HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_OPTION_NON_VOLATILE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};

const IDA_REGISTRY_PATH: &str = r"Software\Hex-Rays\IDA";
const ISOLATION_ROOT: &str = r"Software\blacktop\ida-mcp\RegistryIsolation";
const MAX_REGISTRY_KEY_NAME_LEN: usize = 255;

fn wide_null(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn registry_error(operation: &str, status: u32) -> String {
    format!("{operation} failed with Windows registry status {status}")
}

struct RegistryKey(HKEY);

impl RegistryKey {
    fn create(parent: HKEY, path: &str) -> Result<Self, String> {
        let path = wide_null(path);
        let mut key = null_mut();
        // SAFETY: all pointers are either null optional parameters or valid for
        // the duration of the call, and `key` receives an owned registry handle.
        let status = unsafe {
            RegCreateKeyExW(
                parent,
                path.as_ptr(),
                0,
                null(),
                // RegCopyTreeW creates ordinary child keys and Windows rejects
                // those beneath a volatile parent with ERROR_CHILD_MUST_BE_VOLATILE.
                // The guard explicitly deletes this unique subtree on drop.
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                null(),
                &mut key,
                null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(registry_error("creating isolated registry key", status));
        }
        Ok(Self(key))
    }
}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is an owned handle returned by RegCreateKeyExW.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is an owned handle returned by OpenProcess.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotOwner {
    Process(u32),
    Unknown,
}

fn snapshot_name(pid: u32, id: Uuid) -> String {
    format!("{pid}-{id}")
}

fn snapshot_owner(name: &str) -> SnapshotOwner {
    let Some((pid, id)) = name.split_once('-') else {
        return SnapshotOwner::Unknown;
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return SnapshotOwner::Unknown;
    };
    if Uuid::parse_str(id).is_err() {
        return SnapshotOwner::Unknown;
    }
    SnapshotOwner::Process(pid)
}

fn process_is_running(pid: u32) -> bool {
    // SAFETY: OpenProcess does not borrow caller-owned memory. Failure with
    // ERROR_INVALID_PARAMETER means the PID does not exist; other failures
    // are treated as live so access restrictions cannot cause unsafe reaping.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    let handle = ProcessHandle(handle);

    // SAFETY: `handle.0` is valid for the duration of this non-blocking wait.
    let status = unsafe { WaitForSingleObject(handle.0, 0) };
    match status {
        WAIT_OBJECT_0 => false,
        WAIT_TIMEOUT => true,
        _ => {
            warn!(
                pid,
                status, "Could not determine registry snapshot owner state; preserving it"
            );
            true
        }
    }
}

fn snapshot_should_be_reaped(name: &str, is_process_running: impl FnOnce(u32) -> bool) -> bool {
    match snapshot_owner(name) {
        SnapshotOwner::Process(pid) => !is_process_running(pid),
        SnapshotOwner::Unknown => false,
    }
}

fn delete_registry_tree(parent: HKEY, path: &str) -> bool {
    let path_wide = wide_null(path);
    // SAFETY: `parent` is valid and `path_wide` is a terminated UTF-16 string.
    let tree_status = unsafe { RegDeleteTreeW(parent, path_wide.as_ptr()) };
    if tree_status != ERROR_SUCCESS && tree_status != ERROR_FILE_NOT_FOUND {
        warn!(
            path,
            status = tree_status,
            "Failed to clear temporary IDA registry tree"
        );
        return false;
    }

    // RegDeleteTreeW recursively clears the tree but can leave the named root.
    let key_status = unsafe { RegDeleteKeyW(parent, path_wide.as_ptr()) };
    if key_status != ERROR_SUCCESS && key_status != ERROR_FILE_NOT_FOUND {
        warn!(
            path,
            status = key_status,
            "Failed to remove temporary IDA registry key"
        );
        return false;
    }
    true
}

fn reap_stale_snapshots(root: &RegistryKey) {
    let mut index = 0;
    loop {
        let mut name = [0u16; MAX_REGISTRY_KEY_NAME_LEN + 1];
        let mut name_len = name.len() as u32;
        // SAFETY: `root.0` is valid, the writable name buffer has the declared
        // capacity, and all optional output pointers are null.
        let status = unsafe {
            RegEnumKeyExW(
                root.0,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS {
            warn!(status, "Failed to enumerate stale IDA registry snapshots");
            break;
        }

        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        if snapshot_should_be_reaped(&name, process_is_running)
            && delete_registry_tree(root.0, &name)
        {
            info!(snapshot = %name, "Removed stale IDA registry snapshot");
            continue;
        }
        index += 1;
    }
}

pub(crate) struct IsolatedWindowsRegistry {
    root: RegistryKey,
    path: String,
    active: bool,
}

impl IsolatedWindowsRegistry {
    pub(crate) fn prepare() -> Result<Self, String> {
        let isolation_root = RegistryKey::create(HKEY_CURRENT_USER, ISOLATION_ROOT)?;
        reap_stale_snapshots(&isolation_root);

        let name = snapshot_name(process::id(), Uuid::new_v4());
        let path = format!(r"{ISOLATION_ROOT}\{name}");
        let root = RegistryKey::create(isolation_root.0, &name)?;
        drop(isolation_root);
        let mut isolated = Self {
            root,
            path,
            active: false,
        };
        let ida = RegistryKey::create(isolated.root.0, IDA_REGISTRY_PATH)?;
        let source = wide_null(IDA_REGISTRY_PATH);

        // Copy the user's IDA settings into the private tree so the embedded
        // runtime keeps its normal configuration. A first-run profile has no
        // source key and can safely start from an empty tree.
        // SAFETY: both handles are valid and `source` is a terminated UTF-16 string.
        let copy_status = unsafe { RegCopyTreeW(HKEY_CURRENT_USER, source.as_ptr(), ida.0) };
        if copy_status != ERROR_SUCCESS && copy_status != ERROR_FILE_NOT_FOUND {
            return Err(registry_error(
                "copying IDA registry settings into the isolated tree",
                copy_status,
            ));
        }
        drop(ida);

        // SAFETY: `isolated.root.0` is an open non-predefined key. Windows
        // retains its own reference while the per-process override is active.
        let override_status = unsafe { RegOverridePredefKey(HKEY_CURRENT_USER, isolated.root.0) };
        if override_status != ERROR_SUCCESS {
            return Err(registry_error(
                "enabling process-local IDA registry isolation",
                override_status,
            ));
        }

        isolated.active = true;
        info!("Using process-local Windows registry for the IDA headless runtime");
        Ok(isolated)
    }
}

impl Drop for IsolatedWindowsRegistry {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: a null replacement restores the predefined key mapping.
            let status = unsafe { RegOverridePredefKey(HKEY_CURRENT_USER, null_mut()) };
            if status != ERROR_SUCCESS {
                warn!(
                    status,
                    "Failed to restore the default HKEY_CURRENT_USER mapping"
                );
            }
            self.active = false;
        }

        let root = std::mem::replace(&mut self.root, RegistryKey(null_mut()));
        drop(root);

        delete_registry_tree(HKEY_CURRENT_USER, &self.path);
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::ida::registry_isolation::{
        snapshot_name, snapshot_owner, snapshot_should_be_reaped, SnapshotOwner,
    };

    #[test]
    fn snapshot_owner_round_trips_pid_and_uuid() {
        let id = Uuid::parse_str("4f593156-5425-4e8c-a866-b4db4df5972f")
            .expect("fixture UUID should parse");
        let name = snapshot_name(4242, id);

        assert_eq!(snapshot_owner(&name), SnapshotOwner::Process(4242));
    }

    #[test]
    fn stale_snapshot_decision_preserves_live_and_unknown_owners() {
        let id = Uuid::parse_str("4f593156-5425-4e8c-a866-b4db4df5972f")
            .expect("fixture UUID should parse");
        let name = snapshot_name(4242, id);

        assert!(!snapshot_should_be_reaped(&name, |pid| pid == 4242));
        assert!(snapshot_should_be_reaped(&name, |_| false));
        assert!(!snapshot_should_be_reaped(
            "legacy-or-user-created-key",
            |_| false
        ));
    }
}
