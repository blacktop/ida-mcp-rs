use crate::error::ToolError;
use crate::ida::observability::ensure_not_cancelled;
use idalib::IDB;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

unsafe extern "C" {
    fn ida_mcp_set_cancelled();
    fn ida_mcp_clear_cancelled();
}

struct CancelFlagGuard;

impl CancelFlagGuard {
    fn new() -> Self {
        unsafe { ida_mcp_clear_cancelled() };
        Self
    }
}

impl Drop for CancelFlagGuard {
    fn drop(&mut self) {
        unsafe { ida_mcp_clear_cancelled() };
    }
}

pub(crate) fn cancellable_auto_wait(
    db: &mut IDB,
    cancel: Option<&CancellationToken>,
) -> Result<bool, ToolError> {
    ensure_not_cancelled(cancel)?;
    let _flag_guard = CancelFlagGuard::new();
    let watcher_done = Arc::new(AtomicBool::new(false));
    let watcher = cancel.cloned().map(|cancel| {
        let watcher_done = Arc::clone(&watcher_done);
        std::thread::spawn(move || {
            while !watcher_done.load(Ordering::Acquire) {
                if cancel.is_cancelled() {
                    unsafe { ida_mcp_set_cancelled() };
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        })
    });

    let completed = db.auto_wait();
    watcher_done.store(true, Ordering::Release);
    if let Some(watcher) = watcher {
        let _ = watcher.join();
    }
    ensure_not_cancelled(cancel)?;
    if !completed {
        return Err(ToolError::Cancelled(
            "IDA auto-analysis was cancelled".to_string(),
        ));
    }
    Ok(true)
}
