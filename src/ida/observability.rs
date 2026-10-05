//! Foreground operation observability helpers for the IDA worker.

use crate::error::ToolError;
use serde::Serialize;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc as tokio_mpsc;
use tokio_util::sync::CancellationToken;

/// Total progress units for `open_idb`.
pub const OPEN_IDB_PROGRESS_TOTAL: f64 = 4.0;
/// Total progress units for single-phase foreground operations.
pub const SINGLE_PHASE_PROGRESS_TOTAL: f64 = 1.0;
const HEARTBEAT_INTERVAL_SECS: u64 = 10;
const HEARTBEAT_PROGRESS_STEP: f64 = 0.05;

pub type ProgressSender = tokio_mpsc::UnboundedSender<ProgressUpdate>;
pub type ProgressReceiver = tokio_mpsc::UnboundedReceiver<ProgressUpdate>;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProgressUpdate {
    pub phase: &'static str,
    pub message: String,
    pub progress: f64,
    pub total: Option<f64>,
}

impl ProgressUpdate {
    pub fn new(
        phase: &'static str,
        message: impl Into<String>,
        progress: f64,
        total: Option<f64>,
    ) -> Self {
        Self {
            phase,
            message: message.into(),
            progress,
            total,
        }
    }
}

pub fn emit_progress(
    progress_tx: Option<&ProgressSender>,
    phase: &'static str,
    progress: f64,
    total: Option<f64>,
    message: impl Into<String>,
) {
    if let Some(tx) = progress_tx {
        let _ = tx.send(ProgressUpdate::new(phase, message, progress, total));
    }
}

pub fn ensure_not_cancelled(cancel: Option<&CancellationToken>) -> Result<(), ToolError> {
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        return Err(ToolError::Cancelled(
            "Operation cancelled by client".to_string(),
        ));
    }
    Ok(())
}

/// Emits periodic progress heartbeats from a helper thread while a blocking IDA
/// call is in-flight so MCP clients keep receiving updates.
pub struct ProgressHeartbeat {
    stop_tx: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl ProgressHeartbeat {
    pub fn start(
        progress_tx: Option<ProgressSender>,
        phase: &'static str,
        start_progress: f64,
        max_progress: f64,
        total: Option<f64>,
        message: impl Into<String>,
    ) -> Self {
        let Some(tx) = progress_tx else {
            return Self {
                stop_tx: None,
                handle: None,
            };
        };

        let message = message.into();
        let (stop_tx, stop_rx) = mpsc::channel();
        let phase_total = total;
        let initial_message = message.clone();
        let handle = std::thread::spawn(move || {
            emit_progress(
                Some(&tx),
                phase,
                start_progress,
                phase_total,
                initial_message,
            );

            let mut next_progress = start_progress;
            let mut elapsed_secs = 0u64;
            loop {
                match stop_rx.recv_timeout(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // A crash that skipped this heartbeat's destructor
                        // never signals stop; the closed channel does.
                        if tx.is_closed() {
                            break;
                        }
                        elapsed_secs += HEARTBEAT_INTERVAL_SECS;
                        next_progress = (next_progress + HEARTBEAT_PROGRESS_STEP).min(max_progress);
                        emit_progress(
                            Some(&tx),
                            phase,
                            next_progress,
                            phase_total,
                            format!("{message} ({elapsed_secs}s elapsed)"),
                        );
                    }
                }
            }
        });

        Self {
            stop_tx: Some(stop_tx),
            handle: Some(handle),
        }
    }
}

impl Drop for ProgressHeartbeat {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
