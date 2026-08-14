//! Lightweight in-process task registry for background operations.
//!
//! Serves two consumers:
//! - The custom `task_status` MCP tool (universal fallback for all clients)
//! - The native MCP Tasks extension (SEP-2663) via `ServerHandler` methods

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

/// Protocol TTL advertised from task creation (SEP-2663 `ttlMs`). Terminal
/// entries are pruned this long after their last transition; running tasks are
/// never pruned. A result normally outlives completion by the full TTL, but is
/// reclaimed earlier if it is the oldest terminal entry when the registry hits
/// [`MAX_TASK_REGISTRY_ENTRIES`].
pub const TASK_RETENTION_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Hard bound for all retained tasks, including running tasks.
///
/// Terminal entries normally remain available for the full advertised TTL, but
/// admission takes priority over retention: reaching this bound reclaims the
/// least recently updated terminal entries rather than rejecting new work, so
/// a run of completed tasks cannot strand background work for the whole TTL.
/// New work is rejected only when every slot is held by a running task.
pub const MAX_TASK_REGISTRY_ENTRIES: usize = 256;

/// Identity allowed to observe and control a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOwner {
    /// A stateful legacy HTTP/SSE or stdio MCP session.
    Session(Arc<str>),
    /// Sessionless MCP 2026 requests, which have no stable session identity.
    Runtime,
}

/// Failure to admit a background task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskCreateError {
    /// The same legacy session already has matching work in progress.
    AlreadyRunning(String),
    /// Matching work exists, but its bearer task ID must remain private.
    ExistingTaskIdIsPrivate,
    /// Every slot in the bounded registry is held by a running task, so there
    /// is nothing reclaimable to make room for another.
    CapacityExceeded { max_entries: usize },
}

/// Task status in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Result of attempting to settle a task after its operation returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskSettlement {
    Completed,
    Failed,
    Cancelled,
    Unchanged,
}

/// Atomic decision made at the final successful-result boundary. A pending
/// cancellation remains non-terminal so the caller can clean up resources
/// before publishing `cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCompletionDecision {
    Completed,
    CancellationPending,
    Unchanged,
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

/// Internal entry that owns a task's cancellation token.
///
/// Deliberately does not retain the spawned `JoinHandle`: aborting it cannot
/// interrupt an operation blocked in a native IDA call, since a tokio abort
/// only lands at an await point. Cancellation is cooperative, via the token.
struct TaskEntry {
    owner: TaskOwner,
    state: TaskState,
    cancel_token: Option<CancellationToken>,
    cancel_requested: Option<String>,
}

impl TaskEntry {
    fn new(owner: TaskOwner, state: TaskState) -> Self {
        Self {
            owner,
            state,
            cancel_token: None,
            cancel_requested: None,
        }
    }

    fn set_cancel_token(&mut self, cancel_token: Option<CancellationToken>) {
        if self.cancel_requested.is_some()
            && let Some(cancel_token) = cancel_token.as_ref()
        {
            cancel_token.cancel();
        }
        self.cancel_token = cancel_token;
    }

    fn clear_runtime(&mut self) {
        self.cancel_token = None;
    }

    fn complete(&mut self, result: Value) -> TaskSettlement {
        if self.state.status != TaskStatus::Running {
            return TaskSettlement::Unchanged;
        }
        if let Some(message) = self.cancel_requested.take() {
            self.transition_cancelled(&message);
            return TaskSettlement::Cancelled;
        }

        self.state.status = TaskStatus::Completed;
        self.state.message = "Completed".to_string();
        self.state.result = Some(result);
        refresh_updated(&mut self.state);
        self.clear_runtime();
        TaskSettlement::Completed
    }

    fn fail(&mut self, error: &str) -> TaskSettlement {
        if self.state.status != TaskStatus::Running {
            return TaskSettlement::Unchanged;
        }
        if let Some(message) = self.cancel_requested.take() {
            self.transition_cancelled(&message);
            return TaskSettlement::Cancelled;
        }

        self.state.status = TaskStatus::Failed;
        self.state.message = error.to_string();
        refresh_updated(&mut self.state);
        self.clear_runtime();
        TaskSettlement::Failed
    }

    fn fail_after_cleanup_error(&mut self, error: &str) -> TaskSettlement {
        if self.state.status != TaskStatus::Running {
            return TaskSettlement::Unchanged;
        }

        self.cancel_requested = None;
        self.state.status = TaskStatus::Failed;
        self.state.message = error.to_string();
        refresh_updated(&mut self.state);
        self.clear_runtime();
        TaskSettlement::Failed
    }

    fn request_cancel(&mut self, message: &str) -> bool {
        if self.state.status != TaskStatus::Running || self.cancel_requested.is_some() {
            return false;
        }

        if let Some(cancel_token) = self.cancel_token.as_ref() {
            cancel_token.cancel();
        }
        self.cancel_requested = Some(message.to_string());
        self.state.message = format!("{message}; waiting for the operation to settle");
        refresh_updated(&mut self.state);
        true
    }

    fn transition_cancelled(&mut self, message: &str) {
        self.clear_runtime();
        self.cancel_requested = None;
        self.state.status = TaskStatus::Cancelled;
        self.state.message = message.to_string();
        refresh_updated(&mut self.state);
    }

    fn finish_cancelled(&mut self, message: &str) -> bool {
        if self.state.status != TaskStatus::Running {
            return false;
        }

        self.transition_cancelled(message);
        true
    }

    fn update_message(&mut self, message: &str) {
        if self.state.status == TaskStatus::Running && self.cancel_requested.is_none() {
            self.state.message = message.to_string();
            refresh_updated(&mut self.state);
        }
    }
}

/// Thread-safe registry of background tasks.
#[derive(Clone, Default)]
pub struct TaskRegistry {
    inner: Arc<Mutex<HashMap<String, TaskEntry>>>,
}

impl TaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a task with a deduplication key. A legacy session requesting
    /// matching work that it owns receives the existing task ID. All other
    /// matches remain private and block duplicate work. In particular,
    /// sessionless clients share [`TaskOwner::Runtime`], so Runtime matches
    /// never disclose the existing bearer ID.
    /// `prefix` is used in the generated task id (e.g. "dsc", "analyze").
    pub fn create_keyed(
        &self,
        owner: &TaskOwner,
        prefix: &str,
        key: &str,
        message: &str,
    ) -> Result<String, TaskCreateError> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);

        if let Some(existing) = entries.values().find(|entry| {
            entry.state.status == TaskStatus::Running && entry.state.key.as_deref() == Some(key)
        }) {
            return if matches!(owner, TaskOwner::Session(_)) && &existing.owner == owner {
                Err(TaskCreateError::AlreadyRunning(existing.state.id.clone()))
            } else {
                Err(TaskCreateError::ExistingTaskIdIsPrivate)
            };
        }

        reclaim_capacity_for_admission(&mut entries);
        if entries.len() >= MAX_TASK_REGISTRY_ENTRIES {
            return Err(TaskCreateError::CapacityExceeded {
                max_entries: MAX_TASK_REGISTRY_ENTRIES,
            });
        }

        let id = next_task_id(prefix);
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
        entries.insert(id.clone(), TaskEntry::new(owner.clone(), state));
        Ok(id)
    }

    /// Test fixture: create a terminal task with a precomputed result payload
    /// without going through the create/complete lifecycle.
    #[cfg(test)]
    pub fn create_completed(
        &self,
        owner: &TaskOwner,
        message: &str,
        result: Value,
    ) -> Result<String, TaskCreateError> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);
        reclaim_capacity_for_admission(&mut entries);
        if entries.len() >= MAX_TASK_REGISTRY_ENTRIES {
            return Err(TaskCreateError::CapacityExceeded {
                max_entries: MAX_TASK_REGISTRY_ENTRIES,
            });
        }
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
        entries.insert(id.clone(), TaskEntry::new(owner.clone(), state));
        Ok(id)
    }

    /// Store the cancellation token for a task.
    ///
    /// Cancels immediately when cancellation was requested before the spawned
    /// operation got far enough to register its token.
    pub fn set_cancel_token(&self, id: &str, cancel_token: CancellationToken) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.set_cancel_token(Some(cancel_token));
        }
    }

    /// Get a cloneable snapshot of a task's current state.
    pub fn get(&self, id: &str) -> Option<TaskState> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);
        entries.get(id).map(|e| e.state.clone())
    }

    /// Get a task only when it belongs to the requesting owner. Unknown and
    /// unauthorized IDs deliberately have the same result.
    pub fn get_for_owner(&self, owner: &TaskOwner, id: &str) -> Option<TaskState> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);
        entries
            .get(id)
            .filter(|entry| &entry.owner == owner)
            .map(|entry| entry.state.clone())
    }

    /// Test fixture: list all tasks (snapshots only). Production code resolves
    /// tasks by ID; SEP-2663 dropped `tasks/list`.
    #[cfg(test)]
    pub fn list_all(&self) -> Vec<TaskState> {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        prune_terminal_tasks(&mut entries);
        entries.values().map(|e| e.state.clone()).collect()
    }

    /// Update the progress message on a running task.
    pub fn update_message(&self, id: &str, message: &str) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.get_mut(id) {
            entry.update_message(message);
        }
    }

    /// Mark a task as completed with a JSON result.
    pub fn complete(&self, id: &str, result: Value) -> TaskSettlement {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let settlement = match entries.get_mut(id) {
            Some(entry) => entry.complete(result),
            None => TaskSettlement::Unchanged,
        };
        if settlement != TaskSettlement::Unchanged {
            prune_terminal_tasks(&mut entries);
        }
        settlement
    }

    /// Settle a successful operation, publishing cancellation instead when
    /// its lifetime token was cancelled before the registry transition.
    pub fn complete_with_cancel_token(
        &self,
        id: &str,
        result: Value,
        cancel_token: &CancellationToken,
        cancel_message: &str,
    ) -> TaskSettlement {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let settlement = match entries.get_mut(id) {
            Some(entry) if cancel_token.is_cancelled() => {
                if entry.finish_cancelled(cancel_message) {
                    TaskSettlement::Cancelled
                } else {
                    TaskSettlement::Unchanged
                }
            }
            Some(entry) => entry.complete(result),
            None => TaskSettlement::Unchanged,
        };
        if settlement != TaskSettlement::Unchanged {
            prune_terminal_tasks(&mut entries);
        }
        settlement
    }

    /// Complete atomically unless cancellation has already won. Unlike
    /// [`Self::complete_with_cancel_token`], this leaves cancellation pending
    /// so resource cleanup can finish before a terminal state is visible.
    pub fn complete_or_defer_cancellation(
        &self,
        id: &str,
        result: Value,
        cancel_token: &CancellationToken,
    ) -> TaskCompletionDecision {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let decision = match entries.get_mut(id) {
            Some(entry) if entry.state.status != TaskStatus::Running => {
                TaskCompletionDecision::Unchanged
            }
            Some(entry) if cancel_token.is_cancelled() || entry.cancel_requested.is_some() => {
                TaskCompletionDecision::CancellationPending
            }
            Some(entry) => match entry.complete(result) {
                TaskSettlement::Completed => TaskCompletionDecision::Completed,
                TaskSettlement::Failed | TaskSettlement::Cancelled | TaskSettlement::Unchanged => {
                    TaskCompletionDecision::Unchanged
                }
            },
            None => TaskCompletionDecision::Unchanged,
        };
        if decision == TaskCompletionDecision::Completed {
            prune_terminal_tasks(&mut entries);
        }
        decision
    }

    /// Mark a task as failed with an error message.
    pub fn fail(&self, id: &str, error: &str) -> TaskSettlement {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let settlement = match entries.get_mut(id) {
            Some(entry) => entry.fail(error),
            None => TaskSettlement::Unchanged,
        };
        if settlement != TaskSettlement::Unchanged {
            prune_terminal_tasks(&mut entries);
        }
        settlement
    }

    /// Publish a cleanup failure even when cancellation was requested. A task
    /// must not claim clean cancellation when its owned resource could not be
    /// closed or proven replaced.
    pub fn fail_after_cleanup_error(&self, id: &str, error: &str) -> TaskSettlement {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let settlement = match entries.get_mut(id) {
            Some(entry) => entry.fail_after_cleanup_error(error),
            None => TaskSettlement::Unchanged,
        };
        if settlement != TaskSettlement::Unchanged {
            prune_terminal_tasks(&mut entries);
        }
        settlement
    }

    /// Request cancellation only when the task belongs to the owner.
    pub fn cancel_for_owner(&self, owner: &TaskOwner, id: &str) -> bool {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cancelled = entries
            .get_mut(id)
            .filter(|entry| &entry.owner == owner)
            .is_some_and(|entry| entry.request_cancel("Cancelled by client"));
        if cancelled {
            prune_terminal_tasks(&mut entries);
        }
        cancelled
    }

    pub fn finish_cancelled(&self, id: &str, message: &str) -> bool {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cancelled = match entries.get_mut(id) {
            Some(entry) => entry.finish_cancelled(message),
            None => false,
        };
        if cancelled {
            prune_terminal_tasks(&mut entries);
        }
        cancelled
    }

    /// Request cancellation for every running task. Returns the number of new
    /// cancellation requests; tasks remain running until their work settles.
    pub fn cancel_all_running(&self, message: &str) -> usize {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cancelled = entries.values_mut().fold(0, |count, entry| {
            count + usize::from(entry.request_cancel(message))
        });

        if cancelled > 0 {
            prune_terminal_tasks(&mut entries);
        }

        cancelled
    }
}

/// Generate a task ID with a cryptographically random UUIDv4 component.
///
/// The ID is a bearer capability, not just a name: sessionless MCP 2026
/// clients all share [`TaskOwner::Runtime`], so the ID is the only thing
/// separating one client's task (and its result, which can carry a
/// `close_token`) from another's. It must be unguessable — a client that
/// knows its own ID must not be able to derive any other. Full per-task
/// randomness also keeps IDs from different registries (pooled HTTP
/// sessions, worker processes) from colliding, so a stale ID fails lookup
/// instead of resolving to another task.
fn next_task_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
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
    let retention = std::time::Duration::from_millis(TASK_RETENTION_TTL_MS);
    let now = Instant::now();
    // Measure from `updated_at` (refreshed on the terminal transition), not
    // `created_at`: a task that ran longer than the TTL must stay retrievable
    // after it completes, not vanish in the same call that stored its result.
    entries.retain(|_, entry| {
        entry.state.status == TaskStatus::Running
            || now.saturating_duration_since(entry.state.updated_at) < retention
    });
}

/// Make room for one new task, reclaiming the least recently updated terminal
/// entries when the registry is at capacity.
///
/// The TTL sweep alone lets completed tasks accumulate to the cap well inside
/// the retention window; admission then fails for every new background task
/// even though none are running, and stays failed until the oldest entry ages
/// out. Reclaiming instead means a caller can always make progress while any
/// entry is still reclaimable.
///
/// Deliberately *not* part of [`prune_terminal_tasks`]: that runs on read paths
/// too (`get`, `list_all`), and a read must never discard a result the caller
/// did not ask to drop.
///
/// Running entries are never reclaimed — they hold their slot legitimately, so
/// a registry saturated with in-flight work still reports `CapacityExceeded`.
fn reclaim_capacity_for_admission(entries: &mut HashMap<String, TaskEntry>) {
    if entries.len() < MAX_TASK_REGISTRY_ENTRIES {
        return;
    }

    let mut terminal = Vec::new();
    for (id, entry) in entries.iter() {
        if entry.state.status != TaskStatus::Running {
            terminal.push((entry.state.updated_at, id.clone()));
        }
    }
    terminal.sort_unstable();

    // Free one slot beyond the cap so the caller that triggered this prune can
    // be admitted.
    let excess = entries.len() - MAX_TASK_REGISTRY_ENTRIES + 1;
    for (_, id) in terminal.into_iter().take(excess) {
        entries.remove(&id);
    }
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
    use crate::server::task::{
        TaskCompletionDecision, TaskCreateError, TaskOwner, TaskRegistry, TaskSettlement,
        TaskStatus, MAX_TASK_REGISTRY_ENTRIES, TASK_RETENTION_TTL_MS,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    const OWNER: TaskOwner = TaskOwner::Runtime;

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Returns `false` when the platform cannot represent an Instant that far
    /// in the past (Windows Instants start at boot), letting callers skip.
    fn age_task_past_retention(registry: &TaskRegistry, id: &str) -> bool {
        let Some(past) =
            Instant::now().checked_sub(Duration::from_millis(TASK_RETENTION_TTL_MS + 1))
        else {
            return false;
        };
        let mut entries = registry.inner.lock().unwrap_or_else(|e| e.into_inner());
        let task = entries.get_mut(id).expect("task should exist before aging");
        task.state.created_at = past;
        task.state.updated_at = past;
        true
    }

    #[test]
    fn create_and_get() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "dsc", "test-key", "Starting")
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
            .create_keyed(&OWNER, "t", "k1", "Phase 1")
            .expect("should succeed");
        registry.update_message(&id, "Phase 2");
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.message, "Phase 2");
    }

    #[test]
    fn complete_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k2", "Working")
            .expect("should succeed");
        let result = json!({"db": "opened"});
        assert_eq!(
            registry.complete(&id, result.clone()),
            TaskSettlement::Completed
        );
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Completed);
        assert_eq!(state.result, Some(result));
    }

    #[test]
    fn fail_task() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k3", "Working")
            .expect("should succeed");
        assert_eq!(
            registry.fail(&id, "idat exited with code 4"),
            TaskSettlement::Failed
        );
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
    fn runtime_keyed_dedup_keeps_existing_id_private() {
        let registry = TaskRegistry::new();
        let id1 = registry
            .create_keyed(&OWNER, "dsc", "/path/to/dsc.i64", "First")
            .expect("first should succeed");
        let dup = registry.create_keyed(&OWNER, "dsc", "/path/to/dsc.i64", "Second");
        assert_eq!(dup, Err(TaskCreateError::ExistingTaskIdIsPrivate));

        // After completing, a new task with the same key can be created.
        registry.complete(&id1, json!({}));
        let id2 = registry
            .create_keyed(&OWNER, "dsc", "/path/to/dsc.i64", "Third")
            .expect("should succeed after first completed");
        assert_ne!(id1, id2);
    }

    #[test]
    fn task_ownership_isolates_dedup_lookup_and_cancellation() {
        let registry = TaskRegistry::new();
        let owner_a = TaskOwner::Session(Arc::from("session-a"));
        let owner_b = TaskOwner::Session(Arc::from("session-b"));
        let id = registry
            .create_keyed(&owner_a, "dsc", "/path/to/shared.dsc", "Opening")
            .expect("first owner should create the task");

        assert_eq!(
            registry.create_keyed(&owner_a, "dsc", "/path/to/shared.dsc", "Opening again"),
            Err(TaskCreateError::AlreadyRunning(id.clone()))
        );
        assert_eq!(
            registry.create_keyed(&owner_b, "dsc", "/path/to/shared.dsc", "Other owner"),
            Err(TaskCreateError::ExistingTaskIdIsPrivate)
        );
        assert!(registry.get_for_owner(&owner_b, &id).is_none());
        assert!(!registry.cancel_for_owner(&owner_b, &id));
        assert_eq!(
            registry
                .get_for_owner(&owner_a, &id)
                .expect("owner should still see its task")
                .status,
            TaskStatus::Running
        );

        registry.complete(&id, json!({"close_token": "owner-a-secret"}));
        assert!(registry.get_for_owner(&owner_b, &id).is_none());
        assert_eq!(
            registry
                .get_for_owner(&owner_a, &id)
                .and_then(|task| task.result),
            Some(json!({"close_token": "owner-a-secret"}))
        );
    }

    #[test]
    fn cancellation_request_remains_running_until_work_settles() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k4", "Working")
            .expect("should succeed");
        assert!(registry.cancel_for_owner(&OWNER, &id));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Running);
        assert!(state
            .message
            .contains("waiting for the operation to settle"));

        // A repeated request is acknowledged by the protocol handler but does
        // not signal the operation twice.
        assert!(!registry.cancel_for_owner(&OWNER, &id));

        assert_eq!(
            registry.complete(&id, json!({"late_result": true})),
            TaskSettlement::Cancelled
        );
        let state = registry.get(&id).expect("task should remain retained");
        assert_eq!(state.status, TaskStatus::Cancelled);
        assert_eq!(state.message, "Cancelled by client");
        assert!(state.result.is_none());
    }

    #[test]
    fn final_completion_defers_terminal_cancellation_for_cleanup() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "dsc", "late-cancel", "Working")
            .expect("should create task");
        let cancel_token = CancellationToken::new();

        assert!(registry.cancel_for_owner(&OWNER, &id));
        assert_eq!(
            registry.complete_or_defer_cancellation(
                &id,
                json!({"close_token": "must-not-publish"}),
                &cancel_token,
            ),
            TaskCompletionDecision::CancellationPending
        );
        let pending = registry.get(&id).expect("task should remain visible");
        assert_eq!(pending.status, TaskStatus::Running);
        assert!(pending.result.is_none());

        assert!(registry.finish_cancelled(&id, "database closed"));
        assert_eq!(
            registry
                .get(&id)
                .expect("task should remain retained")
                .status,
            TaskStatus::Cancelled
        );
    }

    #[test]
    fn cancellation_cleanup_failure_is_not_reported_as_clean_cancel() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "dsc", "cleanup-failed", "Working")
            .expect("should create task");
        assert!(registry.cancel_for_owner(&OWNER, &id));

        assert_eq!(
            registry.fail_after_cleanup_error(&id, "conditional close failed"),
            TaskSettlement::Failed
        );
        let failed = registry.get(&id).expect("task should remain retained");
        assert_eq!(failed.status, TaskStatus::Failed);
        assert_eq!(failed.message, "conditional close failed");
    }

    #[test]
    fn terminal_tasks_ignore_late_complete_or_fail_updates() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "late", "Working")
            .expect("should succeed");

        assert!(registry.cancel_for_owner(&OWNER, &id));
        assert_eq!(
            registry.complete(&id, json!({"ok": true})),
            TaskSettlement::Cancelled
        );
        assert_eq!(
            registry.fail(&id, "late failure"),
            TaskSettlement::Unchanged
        );

        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Cancelled);
        assert_eq!(state.message, "Cancelled by client");
        assert!(state.result.is_none());
    }

    #[tokio::test]
    async fn cancel_running_task_signals_cancellation_token() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "k-cancel", "Working")
            .expect("should succeed");
        let cancel_token = CancellationToken::new();
        let observed = cancel_token.clone();
        let wrapper_dropped = Arc::new(AtomicBool::new(false));
        let wrapper_drop_flag = wrapper_dropped.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        // Held to the end of the test: dropping a `JoinHandle` only detaches
        // the task, so the wrapper stays alive either way, but binding it keeps
        // the intent explicit.
        let _handle = tokio::spawn(async move {
            let _drop_flag = DropFlag(wrapper_drop_flag);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("wrapper should start");
        registry.set_cancel_token(&id, cancel_token);

        assert!(registry.cancel_for_owner(&OWNER, &id));
        assert!(observed.is_cancelled());
        tokio::task::yield_now().await;
        assert!(
            !wrapper_dropped.load(Ordering::SeqCst),
            "requesting cancellation must not abort the wrapper"
        );
        assert_eq!(
            registry.get(&id).expect("task should exist").status,
            TaskStatus::Running
        );
    }

    #[test]
    fn cancelled_lifetime_token_wins_at_operation_settlement() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "lifetime-cancel", "Working")
            .expect("should succeed");
        let cancel_token = CancellationToken::new();
        cancel_token.cancel();

        assert_eq!(
            registry.complete_with_cancel_token(
                &id,
                json!({"late_result": true}),
                &cancel_token,
                "Cancelled after connection closed",
            ),
            TaskSettlement::Cancelled
        );
        let state = registry.get(&id).expect("task should remain retained");
        assert_eq!(state.status, TaskStatus::Cancelled);
        assert_eq!(state.message, "Cancelled after connection closed");
        assert!(state.result.is_none());
    }

    #[tokio::test]
    async fn cancel_all_running_cancels_tokens_and_preserves_terminal_tasks() {
        let registry = TaskRegistry::new();
        let id1 = registry
            .create_keyed(&OWNER, "t", "k-all-1", "Working 1")
            .expect("should succeed");
        let id2 = registry
            .create_keyed(&OWNER, "t", "k-all-2", "Working 2")
            .expect("should succeed");
        let completed = registry
            .create_completed(&OWNER, "Done", json!({"ok": true}))
            .expect("should create completed task");

        let cancel_token1 = CancellationToken::new();
        let cancel_token2 = CancellationToken::new();
        let observed1 = cancel_token1.clone();
        let observed2 = cancel_token2.clone();
        let _handle1 = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        let _handle2 = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        registry.set_cancel_token(&id1, cancel_token1);
        registry.set_cancel_token(&id2, cancel_token2);

        assert_eq!(registry.cancel_all_running("Cancelled by shutdown"), 2);
        assert!(observed1.is_cancelled());
        assert!(observed2.is_cancelled());

        let state1 = registry.get(&id1).expect("task should exist");
        let state2 = registry.get(&id2).expect("task should exist");
        let completed_state = registry.get(&completed).expect("task should exist");
        assert_eq!(state1.status, TaskStatus::Running);
        assert_eq!(state2.status, TaskStatus::Running);
        assert_eq!(completed_state.status, TaskStatus::Completed);
        assert_eq!(registry.cancel_all_running("again"), 0);

        assert_eq!(
            registry.complete(&id1, json!({"ok": true})),
            TaskSettlement::Cancelled
        );
        assert_eq!(
            registry.fail(&id2, "worker settled with an error"),
            TaskSettlement::Cancelled
        );
        assert_eq!(
            registry.get(&id1).expect("task should exist").message,
            "Cancelled by shutdown"
        );
        assert_eq!(
            registry.get(&id2).expect("task should exist").status,
            TaskStatus::Cancelled
        );
    }

    #[test]
    fn list_all_tasks() {
        let registry = TaskRegistry::new();
        let _ = registry.create_keyed(&OWNER, "t", "a", "Task A");
        let _ = registry.create_keyed(&OWNER, "t", "b", "Task B");
        assert_eq!(registry.list_all().len(), 2);
    }

    #[test]
    fn iso_timestamp_format() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "ts", "Timestamp test")
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
        let id = registry
            .create_completed(&OWNER, "Done", json!({"ok": true}))
            .expect("should create completed task");
        assert!(id.starts_with("task-"));
        let state = registry.get(&id).expect("task should exist");
        assert_eq!(state.status, TaskStatus::Completed);
    }

    #[test]
    fn task_admission_reclaims_the_oldest_terminal_result_at_capacity() {
        let registry = TaskRegistry::new();
        let mut ids = Vec::with_capacity(MAX_TASK_REGISTRY_ENTRIES);
        for _ in 0..MAX_TASK_REGISTRY_ENTRIES {
            ids.push(
                registry
                    .create_completed(&OWNER, "Done", json!({"ok": true}))
                    .expect("entries within the bound should be admitted"),
            );
        }
        assert_eq!(registry.list_all().len(), MAX_TASK_REGISTRY_ENTRIES);

        // A registry saturated with *terminal* entries must still admit work.
        // Rejecting here would strand every later open_dsc / background
        // analyze_funcs for the whole retention window with nothing running.
        let admitted = registry
            .create_completed(&OWNER, "Admitted", json!({"ok": true}))
            .expect("capacity must be reclaimed from the oldest terminal entry");

        assert_eq!(registry.list_all().len(), MAX_TASK_REGISTRY_ENTRIES);
        assert!(registry.get(&admitted).is_some());
        assert!(
            registry.get(&ids[0]).is_none(),
            "the least recently updated terminal entry should be reclaimed"
        );
        assert!(
            ids[1..].iter().all(|id| registry.get(id).is_some()),
            "reclaiming must take only as many entries as admission needs"
        );
    }

    #[test]
    fn capacity_reclaim_never_evicts_running_tasks() {
        let registry = TaskRegistry::new();
        let mut running = Vec::with_capacity(MAX_TASK_REGISTRY_ENTRIES);
        for index in 0..MAX_TASK_REGISTRY_ENTRIES {
            running.push(
                registry
                    .create_keyed(&OWNER, "t", &format!("k-{index}"), "Working")
                    .expect("entries within the bound should be admitted"),
            );
        }

        assert_eq!(
            registry.create_keyed(&OWNER, "t", "k-overflow", "Working"),
            Err(TaskCreateError::CapacityExceeded {
                max_entries: MAX_TASK_REGISTRY_ENTRIES
            }),
            "in-flight work holds its slot; admission still fails when nothing is reclaimable"
        );
        assert!(
            running.iter().all(|id| registry.get(id).is_some()),
            "running tasks must never be reclaimed"
        );
    }

    #[test]
    fn expired_terminal_task_frees_admission_capacity() {
        let registry = TaskRegistry::new();
        let mut first_id = None;
        for index in 0..MAX_TASK_REGISTRY_ENTRIES {
            let id = registry
                .create_completed(&OWNER, "Done", json!({"index": index}))
                .expect("entries within the bound should be admitted");
            first_id.get_or_insert(id);
        }
        let first_id = first_id.expect("registry bound should be non-zero");
        if !age_task_past_retention(&registry, &first_id) {
            return;
        }

        let replacement = registry
            .create_completed(&OWNER, "Replacement", json!({"ok": true}))
            .expect("expired terminal task should free capacity");
        assert!(registry.get(&first_id).is_none());
        assert!(registry.get(&replacement).is_some());
        assert_eq!(registry.list_all().len(), MAX_TASK_REGISTRY_ENTRIES);
    }

    #[test]
    fn expired_terminal_tasks_are_pruned() {
        let registry = TaskRegistry::new();
        let expired_id = registry
            .create_completed(&OWNER, "Expired", json!({"ok": true}))
            .expect("should create expired fixture");
        let retained_id = registry
            .create_completed(&OWNER, "Retained", json!({"ok": true}))
            .expect("should create retained fixture");

        if !age_task_past_retention(&registry, &expired_id) {
            return;
        }

        assert!(registry.get(&expired_id).is_none());
        assert!(registry.get(&retained_id).is_some());
    }

    #[test]
    fn running_tasks_are_not_pruned_after_retention_ttl() {
        let registry = TaskRegistry::new();
        let running_id = registry
            .create_keyed(&OWNER, "t", "long-running", "Working")
            .expect("should create long-running task");

        if !age_task_past_retention(&registry, &running_id) {
            return;
        }

        assert!(registry.get(&running_id).is_some());
    }

    #[test]
    fn task_completing_after_ttl_remains_retrievable() {
        let registry = TaskRegistry::new();
        let id = registry
            .create_keyed(&OWNER, "t", "slow", "Working")
            .expect("should create task");

        if !age_task_past_retention(&registry, &id) {
            return;
        }
        registry.complete(&id, json!({"ok": true}));

        assert!(
            registry.get(&id).is_some(),
            "a task older than the TTL must survive its own completion"
        );
    }

    #[test]
    fn task_ids_do_not_collide_across_registries() {
        let first = TaskRegistry::new();
        let second = TaskRegistry::new();
        let a = first
            .create_keyed(&OWNER, "dsc", "same-key", "Working")
            .expect("should create task");
        let b = second
            .create_keyed(&OWNER, "dsc", "same-key", "Working")
            .expect("should create task");

        assert_ne!(a, b);
        assert!(second.get(&a).is_none(), "stale IDs must not resolve");
    }

    /// Task IDs are bearer capabilities under the shared sessionless Runtime
    /// owner: each must carry full per-task randomness, never a shared
    /// registry tag plus a guessable counter.
    #[test]
    fn task_ids_are_individually_random_within_one_registry() {
        let registry = TaskRegistry::new();
        let a = registry
            .create_keyed(&OWNER, "dsc", "key-a", "Working")
            .expect("should create task");
        let b = registry
            .create_keyed(&OWNER, "dsc", "key-b", "Working")
            .expect("should create task");

        let random_component = |id: &str| {
            id.strip_prefix("dsc-")
                .expect("task id should start with its prefix")
                .to_string()
        };
        let (a, b) = (random_component(&a), random_component(&b));
        assert_eq!(a.len(), 32, "expected a full 128-bit hex component: {a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b, "sibling tasks must not share a derivable component");
    }
}
