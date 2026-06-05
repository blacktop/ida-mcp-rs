//! Crash isolation for IDA SDK FFI calls.
//!
//! The Hex-Rays decompiler and certain IDA SDK mutation ops can segfault.
//! This module catches SIGSEGV/SIGBUS via sigsetjmp/siglongjmp and
//! converts them to errors instead of killing the server process.
//!
//! # Safety
//!
//! After a caught crash, C++ destructors for in-flight objects were skipped.
//! The IDA worker continues processing — this works in practice because
//! IDA's allocator is resilient, but heap corruption is possible.

use crate::error::ToolError;

#[cfg(unix)]
unsafe extern "C" {
    unsafe fn crash_guard_call(
        func: extern "C" fn(*mut std::ffi::c_void),
        ctx: *mut std::ffi::c_void,
    ) -> std::ffi::c_int;
}

/// Run `f` with one-shot crash isolation.
pub fn crash_guarded<T, F: FnOnce() -> Result<T, ToolError>>(
    operation: &str,
    f: F,
) -> Result<T, ToolError> {
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
        Err(ToolError::IdaError(format!(
            "{operation} crashed in IDA SDK (signal {sig}). \
             The database may still be usable — try other operations. \
             This is a bug in the IDA SDK, not in ida-mcp."
        )))
    }
}
