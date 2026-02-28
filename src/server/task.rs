//! Lightweight in-process task registry for background operations.
//!
//! Serves two consumers:
//! - The custom `task_status` MCP tool (universal fallback for all clients)
//! - The native MCP Tasks protocol (SEP-1686) via `ServerHandler` methods

use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::task::JoinHandle;

pub const TERMINAL_TASK_CAP: usize = 256;
/// `ttl` value exposed via MCP task metadata.
/// `0` communicates there is no minimum retention guarantee.
pub const TASK_RETENTION_TTL_MS: u64 = 0;

/// Task status in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Snapshot of a background task's state (cloneable, no handles).
#[derive(Debug, Clone)]
pub struct TaskState {
    pub id: String,
    pub status: TaskStatus,
    pub message: String,
    pub result: Option<Value>,
    pub created_at: Instant,
    pub updated_at: Instant,
    /// ISO-8601 creation timestamp for the MCP protocol.
    pub created_at_iso: String,
    /// ISO-8601 timestamp for the most recent state/message update.
    pub updated_at_iso: String,
    /// Deduplication key (e.g. the output .i64 path).
    pub key: Option<String>,
}

/// Internal entry that owns the abort handle.
struct TaskEntry {
    state: TaskState,
    handle: Option<JoinHandle<()>>,
}

/// Thread-safe registry of background tasks.
#[derive(Clone)]
pub struct TaskRegistry {
    inner: Arc<Mutex<HashMap<String, TaskEntry>>>,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl TaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a task with a deduplication key. If a running task with
    /// the same key already exists, returns `Err(existing_task_id)`.
    pub fn create_keyed(&self, key: &str, message: &str) -> Result<String, String> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(existing_id) = entries
            .values()
            .find(|entry| {
                entry.state.status == TaskStatus::Running && entry.state.key.as_deref() == Some(key)
            })
            .map(|entry| entry.state.id.clone())
        {
            return Err(existing_id);
        }

        let id = next_task_id("dsc");
        let (now, created) = now_with_iso();
        let state = TaskState {
            id: id.clone(),
            status: TaskStatus::Running,
            message: message.to_string(),
            result: None,
            created_at: now,
            updated_at: now,
            created_at_iso: created.clone(),
            updated_at_iso: created,
            key: Some(key.to_string()),
        };
        entries.insert(
            id.clone(),
            TaskEntry {
                state,
                handle: None,
            },
        );
        prune_terminal_tasks(&mut entries);
        Ok(id)
    }

    /// Create a completed task with a precomputed result payload.
    ///
    /// Used for inline task-mode calls that complete immediately but still
    /// need to be retrievable via tasks/get and tasks/result.
    pub fn create_completed(&self, message: &str, result: Value) -> String {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = next_task_id("task");
        let (now, created) = now_with_iso();
        let state = TaskState {
            id: id.clone(),
            status: TaskStatus::Completed,
            message: message.to_string(),
            result: Some(result),
            created_at: now,
            updated_at: now,
            created_at_iso: created.clone(),
            updated_at_iso: created,
            key: None,
        };
        entries.insert(
            id.clone(),
            TaskEntry {
                state,
                handle: None,
            },
        );
        prune_terminal_tasks(&mut entries);
        id
    }

    /// Store the `JoinHandle` for a task so it can be cancelled.
    pub fn set_handle(&self, id: &str, handle: JoinHandle<()>) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.handle = Some(handle);
        }
    }

    /// Get a cloneable snapshot of a task's current state.
    pub fn get(&self, id: &str) -> Option<TaskState> {
        let entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        entries.get(id).map(|e| e.state.clone())
    }

    /// List all tasks (snapshots only).
    pub fn list_all(&self) -> Vec<TaskState> {
        let entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        entries.values().map(|e| e.state.clone()).collect()
    }

    /// Update the progress message on a running task.
    pub fn update_message(&self, id: &str, message: &str) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.message = message.to_string();
            refresh_updated(&mut entry.state);
        }
    }

    /// Mark a task as completed with a JSON result.
    pub fn complete(&self, id: &str, result: Value) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.status = TaskStatus::Completed;
            entry.state.message = "Completed".to_string();
            entry.state.result = Some(result);
            refresh_updated(&mut entry.state);
            entry.handle = None;
        }
        prune_terminal_tasks(&mut entries);
    }

    /// Mark a task as failed with an error message.
    pub fn fail(&self, id: &str, error: &str) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.status = TaskStatus::Failed;
            entry.state.message = error.to_string();
            refresh_updated(&mut entry.state);
            entry.handle = None;
        }
        prune_terminal_tasks(&mut entries);
    }

    /// Cancel a running task. Returns `true` if the task was running
    /// and has been aborted.
    pub fn cancel(&self, id: &str) -> bool {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            if entry.state.status == TaskStatus::Running {
                if let Some(handle) = entry.handle.take() {
                    handle.abort();
                }
                entry.state.status = TaskStatus::Cancelled;
                entry.state.message = "Cancelled by client".to_string();
                refresh_updated(&mut entry.state);
                prune_terminal_tasks(&mut entries);
                return true;
            }
        }
        false
    }
}

fn now_with_iso() -> (Instant, String) {
    (Instant::now(), iso_now())
}

fn refresh_updated(state: &mut TaskState) {
    let (updated_at, updated_at_iso) = now_with_iso();
    state.updated_at = updated_at;
    state.updated_at_iso = updated_at_iso;
}

fn prune_terminal_tasks(entries: &mut HashMap<String, TaskEntry>) {
    let terminal_ids: Vec<_> = entries
        .iter()
        .filter_map(|(id, entry)| {
            (entry.state.status != TaskStatus::Running)
                .then_some((id.clone(), entry.state.updated_at))
        })
        .collect();

    if terminal_ids.len() <= TERMINAL_TASK_CAP {
        return;
    }

    let mut ordered = terminal_ids;
    ordered.sort_by_key(|(_, updated_at)| *updated_at);
    let remove_count = ordered.len() - TERMINAL_TASK_CAP;

    for (id, _) in ordered.into_iter().take(remove_count) {
        entries.remove(&id);
    }
}

/// Generate a unique task ID using an atomic counter and prefix.
fn next_task_id(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

/// ISO-8601 timestamp for the current time (UTC).
pub fn iso_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Manual UTC formatting to avoid adding chrono dependency.
    // Good enough for task timestamps.
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since epoch to Y-M-D (simplified leap year handling)
    let (year, month, day) = epoch_days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's date library
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use crate::server::task::{TaskRegistry, TaskStatus, TERMINAL_TASK_CAP};
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn create_and_get() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("test-key", "Starting")
            .expect("should succeed");
        assert!(id.starts_with("dsc-"));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Running);
        assert_eq!(state.message, "Starting");
        assert!(state.result.is_none());
        assert!(!state.created_at_iso.is_empty());
    }

    #[test]
    fn update_message() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("k1", "Phase 1")
            .expect("should succeed");
        registry.update_message(&id, "Phase 2");
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.message, "Phase 2");
    }

    #[test]
    fn complete_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("k2", "Working")
            .expect("should succeed");
        let result = json!({"db": "opened"});
        registry.complete(&id, result.clone());
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Completed);
        assert_eq!(state.result, Some(result));
    }

    #[test]
    fn fail_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("k3", "Working")
            .expect("should succeed");
        registry.fail(&id, "idat exited with code 4");
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Failed);
        assert_eq!(state.message, "idat exited with code 4");
    }

    #[test]
    fn get_nonexistent() {
        let registry = TaskRegistry::new();
        assert!(registry.get("dsc-nope").is_none());
    }

    #[test]
    fn keyed_dedup_prevents_duplicate() {
        let registry = TaskRegistry::new();
        let id1 = registry
            .create_keyed("/path/to/dsc.i64", "First")
            .expect("first should succeed");
        let dup = registry.create_keyed("/path/to/dsc.i64", "Second");
        assert_eq!(dup, Err(id1.clone()));

        // After completing, a new task with the same key can be created.
        registry.complete(&id1, json!({}));
        let id2 = registry
            .create_keyed("/path/to/dsc.i64", "Third")
            .expect("should succeed after first completed");
        assert_ne!(id1, id2);
    }

    #[test]
    fn cancel_running_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("k4", "Working")
            .expect("should succeed");
        assert!(registry.cancel(&id));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Cancelled);

        // Cancelling again returns false.
        assert!(!registry.cancel(&id));
    }

    #[test]
    fn list_all_tasks() {
        let registry = TaskRegistry::new();
        let _ = registry.create_keyed("a", "Task A");
        let _ = registry.create_keyed("b", "Task B");
        assert_eq!(registry.list_all().len(), 2);
    }

    #[test]
    fn iso_timestamp_format() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("ts", "Timestamp test")
            .expect("should succeed");
        let state = registry.get(&id).expect("task should exist");
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert!(
            state.created_at_iso.len() == 20,
            "unexpected ISO length: {}",
            state.created_at_iso
        );
        assert!(state.created_at_iso.ends_with('Z'));
    }

    #[test]
    fn create_completed_uses_task_prefix() {
        let registry = TaskRegistry::new();
        let id = registry.create_completed("Done", json!({"ok": true}));
        assert!(id.starts_with("task-"));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Completed);
    }

    #[test]
    fn inline_completed_tasks_are_capped() {
        let registry = TaskRegistry::new();
        for _ in 0..(TERMINAL_TASK_CAP + 20) {
            let _ = registry.create_completed("Done", json!({"ok": true}));
        }

        let tasks = registry.list_all();
        let inline_terminal_count = tasks
            .iter()
            .filter(|t| t.key.is_none() && t.status != TaskStatus::Running)
            .count();
        assert_eq!(inline_terminal_count, TERMINAL_TASK_CAP);
    }

    #[test]
    fn keyed_terminal_tasks_are_capped() {
        let registry = TaskRegistry::new();
        for i in 0..(TERMINAL_TASK_CAP + 20) {
            let key = format!("key-{i}");
            let id = registry
                .create_keyed(&key, "Working")
                .expect("should create keyed task");
            registry.complete(&id, json!({"ok": true}));
        }

        let tasks = registry.list_all();
        let keyed_terminal_count = tasks
            .iter()
            .filter(|t| t.key.is_some() && t.status != TaskStatus::Running)
            .count();
        assert_eq!(keyed_terminal_count, TERMINAL_TASK_CAP);
    }

    #[test]
    fn recently_completed_task_not_immediately_evicted() {
        let registry = TaskRegistry::new();
        let long_running_id = registry
            .create_keyed("long-running", "Working")
            .expect("should create long-running task");

        for i in 0..TERMINAL_TASK_CAP {
            let _ = registry.create_completed("Done", json!({"idx": i}));
        }

        std::thread::sleep(Duration::from_millis(2));
        registry.complete(&long_running_id, json!({"ok": true}));

        assert!(
            registry.get(&long_running_id).is_some(),
            "newly completed task should remain retrievable after pruning"
        );
        let terminal_count = registry
            .list_all()
            .iter()
            .filter(|t| t.status != TaskStatus::Running)
            .count();
        assert_eq!(terminal_count, TERMINAL_TASK_CAP);
    }
}
