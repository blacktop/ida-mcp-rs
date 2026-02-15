//! IDA Pro integration module.
//!
//! This module provides a headless IDA Pro interface via the idalib crate.
//! It uses a channel-based worker pattern to ensure IDA operations run on the main thread
//! (IDA types are not thread-safe).

pub mod handlers;
pub mod lock;
mod loop_impl;
pub mod request;
pub mod types;
pub mod worker;

pub use loop_impl::run_ida_loop;
pub use request::IdaRequest;
pub use types::*;
pub use worker::IdaWorker;
