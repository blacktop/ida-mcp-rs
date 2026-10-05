//! Crash isolation for IDA SDK FFI calls.
//!
//! The Hex-Rays decompiler and certain IDA SDK mutation ops can segfault.
//! This module catches SIGSEGV/SIGBUS via sigsetjmp/siglongjmp and
//! converts them to errors instead of killing the server process.
//!
//! # Safety
//!
//! After a caught crash, C++ destructors for in-flight objects were skipped
//! and heap corruption is possible, so the database state can no longer be
//! trusted. [`CrashGuard`] remembers the crash; the worker loop then discards
//! the database without saving, and a pool parent retires the child process.

use crate::error::ToolError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(unix)]
unsafe extern "C" {
    fn crash_guard_call(
        func: extern "C" fn(*mut std::ffi::c_void),
        ctx: *mut std::ffi::c_void,
    ) -> std::ffi::c_int;
}

/// Tells the MCP server thread that the IDA thread caught an SDK crash, so a
/// child worker can report it to its parent out of band.
#[derive(Clone, Debug, Default)]
pub struct SdkCrashSignal(Arc<AtomicBool>);

impl SdkCrashSignal {
    fn raise(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether a crash was caught since the last call.
    pub fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

/// Runs IDA SDK calls with crash isolation and remembers a caught crash.
#[derive(Default)]
pub struct CrashGuard {
    crashed_operation: std::cell::RefCell<Option<String>>,
    signal: SdkCrashSignal,
}

impl CrashGuard {
    pub fn new(signal: SdkCrashSignal) -> Self {
        Self {
            crashed_operation: std::cell::RefCell::default(),
            signal,
        }
    }

    /// Run `f` with one-shot crash isolation.
    pub fn run<T, F: FnOnce() -> Result<T, ToolError>>(
        &self,
        operation: &str,
        f: F,
    ) -> Result<T, ToolError> {
        let result = guarded(operation, f);
        if let Err(ToolError::SdkCrashed(_)) = &result {
            self.crashed_operation.replace(Some(operation.to_string()));
            self.signal.raise();
        }
        result
    }

    /// The operation that crashed since the last call, if any.
    pub fn take_crashed(&self) -> Option<String> {
        self.crashed_operation.take()
    }
}

fn guarded<T, F: FnOnce() -> Result<T, ToolError>>(operation: &str, f: F) -> Result<T, ToolError> {
    #[cfg(unix)]
    {
        unix_guard(operation, f)
    }
    #[cfg(not(unix))]
    {
        let _ = operation;
        f()
    }
}

#[cfg(unix)]
fn unix_guard<T, F: FnOnce() -> Result<T, ToolError>>(
    operation: &str,
    f: F,
) -> Result<T, ToolError> {
    use std::ffi::c_void;

    struct Context<T, F: FnOnce() -> Result<T, ToolError>> {
        f: Option<F>,
        result: Option<Result<T, ToolError>>,
    }

    extern "C" fn trampoline<T, F: FnOnce() -> Result<T, ToolError>>(ctx: *mut c_void) {
        let ctx = unsafe { &mut *(ctx.cast::<Context<T, F>>()) };
        if let Some(f) = ctx.f.take() {
            ctx.result = Some(f());
        }
    }

    let mut ctx = Context {
        f: Some(f),
        result: None,
    };

    let sig = unsafe {
        crash_guard_call(
            trampoline::<T, F>,
            std::ptr::from_mut(&mut ctx).cast::<c_void>(),
        )
    };

    if sig == 0 {
        ctx.result.unwrap_or_else(|| {
            Err(ToolError::IdaError(format!(
                "{operation}: callback did not produce a result"
            )))
        })
    } else {
        tracing::error!(
            operation,
            signal = sig,
            "IDA SDK crashed (signal {sig} caught). Server survived."
        );
        Err(ToolError::SdkCrashed(format!(
            "{operation} crashed inside the IDA SDK (signal {sig}). The database state can \
             no longer be trusted, so it is closed without saving and changes since the \
             last save_idb are lost. Call open_idb again."
        )))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use crate::crash_guard::{CrashGuard, SdkCrashSignal};
    use crate::error::ToolError;

    unsafe extern "C" {
        fn raise(signal: std::ffi::c_int) -> std::ffi::c_int;
    }

    const SIGSEGV: std::ffi::c_int = 11;

    /// One test, in sequence: the guard swaps the process-wide SIGSEGV
    /// disposition, which only the IDA thread does in production, so two
    /// guards on parallel test threads would race.
    #[test]
    fn only_a_caught_signal_marks_a_crash_and_it_is_reported_once() {
        let signal = SdkCrashSignal::default();
        let guard = CrashGuard::new(signal.clone());

        assert_eq!(guard.run("ok", || Ok(7)).ok(), Some(7));
        let failed: Result<(), ToolError> = guard.run("fail", || Err(ToolError::Busy));
        assert!(matches!(failed, Err(ToolError::Busy)));
        assert_eq!(guard.take_crashed(), None);
        assert!(!signal.take());

        let result: Result<(), ToolError> = guard.run("handle_decompile", || {
            // SAFETY: raising a signal on the current thread has no memory
            // preconditions; the guard's handler is installed for this call.
            unsafe { raise(SIGSEGV) };
            Ok(())
        });
        let Err(ToolError::SdkCrashed(message)) = result else {
            panic!("a caught SIGSEGV must surface as SdkCrashed");
        };
        assert!(message.contains("handle_decompile"));
        assert!(message.contains("signal 11"));
        assert_eq!(guard.take_crashed().as_deref(), Some("handle_decompile"));
        assert_eq!(guard.take_crashed(), None);
        assert!(signal.take());
        assert!(!signal.take());
    }
}
