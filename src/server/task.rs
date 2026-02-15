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
    /// ISO-8601 creation timestamp for the MCP protocol.
    pub created_at_iso: String,
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

        for entry in entries.values() {
            if entry.state.status == TaskStatus::Running {
                if let Some(existing_key) = &entry.state.key {
                    if existing_key == key {
                        return Err(entry.state.id.clone());
                    }
                }
            }
        }

        let id = next_task_id();
        let state = TaskState {
            id: id.clone(),
            status: TaskStatus::Running,
            message: message.to_string(),
            result: None,
            created_at: Instant::now(),
            created_at_iso: iso_now(),
            key: Some(key.to_string()),
        };
        entries.insert(
            id.clone(),
            TaskEntry {
                state,
                handle: None,
            },
        );
        Ok(id)
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
        }
    }

    /// Mark a task as completed with a JSON result.
    pub fn complete(&self, id: &str, result: Value) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.status = TaskStatus::Completed;
            entry.state.message = "Completed".to_string();
            entry.state.result = Some(result);
            entry.handle = None;
        }
    }

    /// Mark a task as failed with an error message.
    pub fn fail(&self, id: &str, error: &str) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.state.status = TaskStatus::Failed;
            entry.state.message = error.to_string();
            entry.handle = None;
        }
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
                return true;
            }
        }
        false
    }
}

/// Generate a unique task ID using an atomic counter.
fn next_task_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("dsc-{n}")
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
    use crate::server::task::{TaskRegistry, TaskStatus};
    use serde_json::json;

    #[test]
    fn create_and_get() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed("test-key", "Starting")
            .expect("should succeed");
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
}
