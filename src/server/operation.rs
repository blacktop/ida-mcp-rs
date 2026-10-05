//! Foreground operation history for MCP-visible observability.

use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const RECENT_EVENT_CAP: usize = 20;
const MAX_RECENT_LIMIT: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationSnapshot {
    pub op_id: String,
    pub tool: String,
    pub target_summary: String,
    pub phase: String,
    pub status: OperationStatus,
    pub message: String,
    pub started_at_ms: u64,
    pub last_update_ms: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationEvent {
    pub op_id: String,
    pub tool: String,
    pub target_summary: String,
    pub phase: String,
    pub status: OperationStatus,
    pub message: String,
    pub timestamp_ms: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecentOperations {
    pub active_operation: Option<OperationSnapshot>,
    pub recent_events: Vec<OperationEvent>,
}

#[derive(Clone)]
pub struct OperationRegistry {
    inner: Arc<Mutex<OperationRegistryInner>>,
}

struct OperationRegistryInner {
    active_op_id: Option<String>,
    current: HashMap<String, OperationState>,
    events: VecDeque<OperationEvent>,
}

struct OperationState {
    op_id: String,
    tool: String,
    target_summary: String,
    phase: String,
    status: OperationStatus,
    message: String,
    started_at: Instant,
    started_at_ms: u64,
    last_update_ms: u64,
}

impl OperationState {
    fn snapshot(&self) -> OperationSnapshot {
        OperationSnapshot {
            op_id: self.op_id.clone(),
            tool: self.tool.clone(),
            target_summary: self.target_summary.clone(),
            phase: self.phase.clone(),
            status: self.status,
            message: self.message.clone(),
            started_at_ms: self.started_at_ms,
            last_update_ms: self.last_update_ms,
            elapsed_ms: self.started_at.elapsed().as_millis() as u64,
        }
    }

    fn event(&self) -> OperationEvent {
        OperationEvent {
            op_id: self.op_id.clone(),
            tool: self.tool.clone(),
            target_summary: self.target_summary.clone(),
            phase: self.phase.clone(),
            status: self.status,
            message: self.message.clone(),
            timestamp_ms: self.last_update_ms,
            elapsed_ms: self.started_at.elapsed().as_millis() as u64,
        }
    }
}

impl Default for OperationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(OperationRegistryInner {
                active_op_id: None,
                current: HashMap::new(),
                events: VecDeque::with_capacity(RECENT_EVENT_CAP),
            })),
        }
    }

    pub fn start(&self, op_id: String, tool: &str, target_summary: String) {
        let mut inner = self.lock_inner();
        let now_ms = now_ms();
        let state = OperationState {
            op_id: op_id.clone(),
            tool: tool.to_string(),
            target_summary,
            phase: "queued".to_string(),
            status: OperationStatus::Queued,
            message: "Queued for IDA worker execution".to_string(),
            started_at: Instant::now(),
            started_at_ms: now_ms,
            last_update_ms: now_ms,
        };
        push_event(&mut inner.events, state.event());
        inner.active_op_id = Some(op_id.clone());
        inner.current.insert(op_id, state);
    }

    pub fn record_progress(
        &self,
        op_id: &str,
        phase: &str,
        message: impl Into<String>,
    ) -> Option<OperationSnapshot> {
        let mut inner = self.lock_inner();
        let (snapshot, event) = {
            let state = inner.current.get_mut(op_id)?;
            state.phase = phase.to_string();
            state.status = if phase == "queued" {
                OperationStatus::Queued
            } else {
                OperationStatus::Running
            };
            state.message = message.into();
            state.last_update_ms = now_ms();
            (state.snapshot(), state.event())
        };
        inner.active_op_id = Some(op_id.to_string());
        push_event(&mut inner.events, event);
        Some(snapshot)
    }

    pub fn snapshot(&self, op_id: &str) -> Option<OperationSnapshot> {
        let inner = self.lock_inner();
        inner.current.get(op_id).map(OperationState::snapshot)
    }

    pub fn finish_completed(
        &self,
        op_id: &str,
        message: impl Into<String>,
    ) -> Option<OperationSnapshot> {
        self.finish(op_id, OperationStatus::Completed, message)
    }

    pub fn finish_failed(
        &self,
        op_id: &str,
        message: impl Into<String>,
    ) -> Option<OperationSnapshot> {
        self.finish(op_id, OperationStatus::Failed, message)
    }

    pub fn finish_timed_out(
        &self,
        op_id: &str,
        message: impl Into<String>,
    ) -> Option<OperationSnapshot> {
        self.finish(op_id, OperationStatus::TimedOut, message)
    }

    pub fn finish_cancelled(
        &self,
        op_id: &str,
        message: impl Into<String>,
    ) -> Option<OperationSnapshot> {
        self.finish(op_id, OperationStatus::Cancelled, message)
    }

    pub fn recent(&self, limit: Option<usize>) -> RecentOperations {
        let inner = self.lock_inner();
        let active_operation = inner
            .active_op_id
            .as_ref()
            .and_then(|op_id| inner.current.get(op_id))
            .map(OperationState::snapshot);
        let limit = limit.unwrap_or(RECENT_EVENT_CAP).clamp(1, MAX_RECENT_LIMIT);
        let recent_events = inner.events.iter().rev().take(limit).cloned().collect();
        RecentOperations {
            active_operation,
            recent_events,
        }
    }

    fn finish(
        &self,
        op_id: &str,
        status: OperationStatus,
        message: impl Into<String>,
    ) -> Option<OperationSnapshot> {
        let mut inner = self.lock_inner();
        let mut state = inner.current.remove(op_id)?;
        state.status = status;
        state.message = message.into();
        state.last_update_ms = now_ms();
        if state.phase == "queued" {
            state.phase = match status {
                OperationStatus::Completed => "completed",
                OperationStatus::Failed => "failed",
                OperationStatus::TimedOut => "timed_out",
                OperationStatus::Cancelled => "cancelled",
                OperationStatus::Queued | OperationStatus::Running => state.phase.as_str(),
            }
            .to_string();
        }
        if inner.active_op_id.as_deref() == Some(op_id) {
            inner.active_op_id = None;
        }
        let snapshot = state.snapshot();
        push_event(&mut inner.events, state.event());
        Some(snapshot)
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, OperationRegistryInner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

pub fn next_operation_id(counter: &AtomicU64) -> String {
    let now = now_ms();
    let nonce = counter.fetch_add(1, Ordering::Relaxed);
    format!("fg-{now:016x}-{nonce:08x}")
}

fn push_event(events: &mut VecDeque<OperationEvent>, event: OperationEvent) {
    if events.len() == RECENT_EVENT_CAP {
        events.pop_front();
    }
    events.push_back(event);
}

fn now_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as u64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use crate::server::operation::{next_operation_id, OperationRegistry, OperationStatus};

    #[test]
    fn recent_events_are_capped_and_ordered_newest_first() {
        let registry = OperationRegistry::new();
        let counter = AtomicU64::new(0);
        for index in 0..25 {
            let op_id = next_operation_id(&counter);
            registry.start(op_id.clone(), "run_script", format!("script-{index}"));
            registry.record_progress(&op_id, "executing", format!("progress-{index}"));
            registry.finish_completed(&op_id, format!("done-{index}"));
        }

        let recent = registry.recent(None);
        assert_eq!(recent.active_operation, None);
        assert_eq!(recent.recent_events.len(), 20);
        assert_eq!(recent.recent_events[0].message, "done-24");
        assert_eq!(recent.recent_events[19].message, "progress-18");
    }

    #[test]
    fn active_operation_tracks_latest_progress() {
        let registry = OperationRegistry::new();
        let counter = AtomicU64::new(0);
        let op_id = next_operation_id(&counter);
        registry.start(op_id.clone(), "open_idb", "/tmp/sample.i64".to_string());
        registry.record_progress(&op_id, "opening", "Opening database");

        let recent = registry.recent(Some(5));
        let active = recent.active_operation.expect("active operation");
        assert_eq!(active.op_id, op_id);
        assert_eq!(active.phase, "opening");
        assert_eq!(active.status, OperationStatus::Running);
    }

    #[test]
    fn recent_operations_shape_serializes_expected_keys() {
        let registry = OperationRegistry::new();
        let counter = AtomicU64::new(0);
        let op_id = next_operation_id(&counter);
        registry.start(
            op_id.clone(),
            "analyze_funcs",
            "current database".to_string(),
        );
        registry.finish_timed_out(&op_id, "Timed out");

        let value = serde_json::to_value(registry.recent(Some(3))).expect("serialize recent ops");
        assert!(value.get("active_operation").is_some());
        assert!(value.get("recent_events").is_some());
        assert_eq!(value["recent_events"][0]["status"], "timed_out");
    }
}
