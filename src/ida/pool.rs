//! Multi-process worker pool for HTTP sessions.

use crate::error::ToolError;
use crate::ida::handlers::database::{database_path_for_open_request, RawOpenArtifactCleanup};
use crate::ida::handlers::debugger::DEBUGGER_TEARDOWN_TIMEOUT_SECS;
use crate::ida::lock::remove_mcp_lock_for_pid;
use crate::ida::observability::ProgressSender;
use crate::ida::remote;
use crate::ida::types::*;
use crate::ida::worker::{
    debugger_response_timeout_secs, CLOSE_SEND_TIMEOUT_SECS, DEBUG_MODULES_TIMEOUT_SECS,
    MAX_TIMEOUT_SECS,
};
use futures_util::future::join_all;
use rmcp::handler::client::ClientHandler;
use rmcp::model::{CallToolResult, ClientInfo, JsonObject};
use rmcp::service::{Peer, RoleClient, RunningService};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::ServiceExt;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard, Weak};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const CHILD_SERVICE_CLOSE_TIMEOUT_SECS: u64 = 5;
pub(crate) const CHILD_TIMEOUT_GRACE_SECS: u64 = 10;
// A close_idb RPC can spend its enqueue and debugger teardown budgets before
// packing the database and sending its response. Its parent watchdog must
// leave the same post-child grace as every other pooled operation.
const MIN_CHILD_CLOSE_RPC_TIMEOUT_SECS: u64 =
    CLOSE_SEND_TIMEOUT_SECS + DEBUGGER_TEARDOWN_TIMEOUT_SECS as u64 + CHILD_TIMEOUT_GRACE_SECS;

#[derive(Debug, Clone)]
pub struct WorkerPoolConfig {
    pub max_workers: usize,
    pub min_workers: usize,
    pub worker_idle_timeout: Duration,
    pub worker_op_timeout: Duration,
    pub exe_path: PathBuf,
    /// Process-wide CLI arguments forwarded to worker processes.
    pub worker_args: Vec<OsString>,
}

/// Public tool-filter environment variables. Filtering is enforced by the
/// parent HTTP server; private child workers must keep lifecycle/internal
/// tools such as `close_idb` and `analyze_funcs` available for the parent,
/// so these are stripped from the child environment.
const CHILD_FILTER_ENV_VARS: &[&str] = &[
    "IDA_MCP_TOOLSETS",
    "IDA_MCP_TOOLS",
    "IDA_MCP_EXCLUDE_TOOLS",
    "IDA_MCP_READ_ONLY",
];

#[derive(Clone)]
pub struct WorkerPool {
    inner: Arc<Mutex<PoolInner>>,
    config: Arc<WorkerPoolConfig>,
}

struct PoolInner {
    children: Vec<Arc<ChildSlot>>,
    spawning: HashSet<usize>,
    next_id: usize,
}

pub struct ChildSlot {
    id: usize,
    child: Mutex<PooledChild>,
    call_lock: Mutex<()>,
}

struct PooledChild {
    service: Option<RunningService<RoleClient, ParentClientHandler>>,
    peer: Peer<RoleClient>,
    pid: Option<u32>,
    stderr_task: JoinHandle<()>,
    state: ChildState,
    spawned_at: Instant,
    last_used: Instant,
    idb_path: Option<PathBuf>,
    pending_open_artifacts: Option<RawOpenArtifactCleanup>,
}

impl PooledChild {
    /// Whether this child's MCP transport is gone. A missing service is
    /// treated as closed: the child can no longer serve any call.
    fn transport_closed(&self) -> bool {
        self.service
            .as_ref()
            .is_none_or(|service| service.is_transport_closed())
    }
}

struct DeadWorker {
    service: Option<RunningService<RoleClient, ParentClientHandler>>,
    pid: Option<u32>,
    age_secs: u64,
    idb_path: Option<PathBuf>,
    pending_open_artifacts: Option<RawOpenArtifactCleanup>,
}

struct OpenDispatch {
    database_path: PathBuf,
    artifacts: Option<RawOpenArtifactCleanup>,
}

impl OpenDispatch {
    fn for_request(path: &str, idb_out: Option<&str>, rebuild: bool) -> Self {
        Self {
            database_path: database_path_for_open_request(path, idb_out),
            artifacts: RawOpenArtifactCleanup::for_request(path, idb_out, rebuild),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChildState {
    Idle,
    Leased { session_id: String },
    Closing,
    Dead,
}

#[derive(Clone)]
pub struct PooledWorkerHandle {
    pool: WorkerPool,
    slot: Arc<ChildSlot>,
    session_id: String,
    worker_id: usize,
}

#[derive(Clone)]
struct ParentClientHandler;

impl ClientHandler for ParentClientHandler {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::default()
    }
}

#[derive(Clone, Copy)]
enum WorkerRetireReason {
    Release,
    Call { tool: &'static str },
}

impl WorkerRetireReason {
    fn warn_missing_runtime(self, worker_id: usize, session_id: &str) {
        match self {
            Self::Release => {
                // This should only happen after the runtime is gone; there is
                // no safe async executor left to retire the worker.
                warn!(
                    worker_id,
                    session_id = %session_id,
                    "release cleanup was dropped outside a Tokio runtime; worker may remain unreleased"
                );
            }
            Self::Call { tool } => {
                warn!(
                    worker_id,
                    session_id = %session_id,
                    tool,
                    "pooled worker call was dropped outside a Tokio runtime; worker may remain leased"
                );
            }
        }
    }

    fn warn_retiring_worker(self, worker_id: usize, session_id: &str) {
        match self {
            Self::Release => {
                warn!(
                    worker_id,
                    session_id = %session_id,
                    "release cleanup was dropped before worker release completed; retiring worker"
                );
            }
            Self::Call { tool } => {
                warn!(
                    worker_id,
                    session_id = %session_id,
                    tool,
                    "pooled worker call was dropped before completion; retiring worker"
                );
            }
        }
    }
}

struct WorkerRetireGuard {
    pool: WorkerPool,
    slot: Arc<ChildSlot>,
    worker_id: usize,
    session_id: String,
    reason: WorkerRetireReason,
    runtime: Option<Handle>,
    armed: bool,
}

struct SpawnReservation {
    pool: WorkerPool,
    worker_id: usize,
    runtime: Option<Handle>,
    cleanup_slot: Option<Arc<ChildSlot>>,
    armed: bool,
}

impl WorkerRetireGuard {
    fn release(pool: WorkerPool, slot: Arc<ChildSlot>, handle: &PooledWorkerHandle) -> Self {
        Self {
            pool,
            slot,
            worker_id: handle.worker_id,
            session_id: handle.session_id.clone(),
            reason: WorkerRetireReason::Release,
            runtime: Handle::try_current().ok(),
            armed: true,
        }
    }

    fn call(handle: &PooledWorkerHandle, tool: &'static str) -> Self {
        Self {
            pool: handle.pool.clone(),
            slot: handle.slot.clone(),
            worker_id: handle.worker_id,
            session_id: handle.session_id.clone(),
            reason: WorkerRetireReason::Call { tool },
            runtime: Handle::try_current().ok(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorkerRetireGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let pool = self.pool.clone();
        let slot = self.slot.clone();
        let worker_id = self.worker_id;
        let session_id = self.session_id.clone();
        let reason = self.reason;
        let runtime = self.runtime.clone().or_else(|| Handle::try_current().ok());
        let Some(runtime) = runtime else {
            reason.warn_missing_runtime(worker_id, &session_id);
            return;
        };

        runtime.spawn(async move {
            reason.warn_retiring_worker(worker_id, &session_id);
            pool.mark_dead(&slot).await;
        });
    }
}

impl SpawnReservation {
    fn new(pool: WorkerPool, worker_id: usize) -> Self {
        Self {
            pool,
            worker_id,
            runtime: Handle::try_current().ok(),
            cleanup_slot: None,
            armed: true,
        }
    }

    fn worker_id(&self) -> usize {
        self.worker_id
    }

    async fn finish(mut self, slot: Option<Arc<ChildSlot>>) {
        self.cleanup_slot = slot.clone();
        self.pool
            .finish_spawn_reservation(self.worker_id, slot)
            .await;
        self.cleanup_slot = None;
        self.armed = false;
    }
}

impl Drop for SpawnReservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let pool = self.pool.clone();
        let worker_id = self.worker_id;
        let cleanup_slot = self.cleanup_slot.take();
        let runtime = self.runtime.clone().or_else(|| Handle::try_current().ok());
        let Some(runtime) = runtime else {
            warn!(
                worker_id,
                "spawn reservation was dropped outside a Tokio runtime; capacity may remain reserved"
            );
            return;
        };

        runtime.spawn(async move {
            warn!(
                worker_id,
                "spawn reservation was dropped before worker installation completed"
            );
            pool.finish_spawn_reservation(worker_id, None).await;
            if let Some(slot) = cleanup_slot {
                pool.mark_dead(&slot).await;
            }
        });
    }
}

impl WorkerPool {
    pub fn new(config: WorkerPoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PoolInner {
                children: Vec::new(),
                spawning: HashSet::new(),
                next_id: 0,
            })),
            config: Arc::new(config),
        }
    }

    pub async fn warm_min(&self) -> Result<(), ToolError> {
        let min = self.config.min_workers.min(self.config.max_workers);
        for _ in 0..min {
            let reservation = self.reserve_spawn_slot().await;
            self.spawn_reserved_slot(reservation, ChildState::Idle)
                .await?;
        }
        Ok(())
    }

    pub async fn lease(&self, session_id: &str) -> Result<PooledWorkerHandle, ToolError> {
        let session_id = session_id.to_string();
        let reservation = {
            let mut inner = self.inner.lock().await;
            let mut active = inner.spawning.len();
            let mut dead_ids = Vec::new();

            for slot in &inner.children {
                let mut child = slot.child.lock().await;
                if child.state == ChildState::Dead {
                    dead_ids.push(slot.id);
                    continue;
                }
                active += 1;
                if child.state == ChildState::Idle {
                    child.state = ChildState::Leased {
                        session_id: session_id.clone(),
                    };
                    child.last_used = Instant::now();
                    info!(
                        worker_id = slot.id,
                        session_id = %session_id,
                        "leased idle IDA child worker"
                    );
                    return Ok(PooledWorkerHandle {
                        pool: self.clone(),
                        slot: slot.clone(),
                        session_id,
                        worker_id: slot.id,
                    });
                }
            }

            if !dead_ids.is_empty() {
                inner.children.retain(|slot| !dead_ids.contains(&slot.id));
            }

            if active >= self.config.max_workers {
                return Err(ToolError::PoolExhausted {
                    active,
                    max: self.config.max_workers,
                });
            }

            self.reserve_spawn_slot_locked(&mut inner)
        };

        let id = reservation.worker_id();
        let slot = self
            .spawn_reserved_slot(
                reservation,
                ChildState::Leased {
                    session_id: session_id.clone(),
                },
            )
            .await?;
        info!(
            worker_id = id,
            session_id = %session_id,
            "spawned leased IDA child worker"
        );
        Ok(PooledWorkerHandle {
            pool: self.clone(),
            slot,
            session_id,
            worker_id: id,
        })
    }

    async fn spawn_reserved_slot(
        &self,
        reservation: SpawnReservation,
        initial_state: ChildState,
    ) -> Result<Arc<ChildSlot>, ToolError> {
        let id = reservation.worker_id();
        match self.spawn_slot(id, initial_state).await {
            Ok(slot) => {
                reservation.finish(Some(slot.clone())).await;
                Ok(slot)
            }
            Err(err) => {
                reservation.finish(None).await;
                Err(err)
            }
        }
    }

    async fn reserve_spawn_slot(&self) -> SpawnReservation {
        let mut inner = self.inner.lock().await;
        self.reserve_spawn_slot_locked(&mut inner)
    }

    fn reserve_spawn_slot_locked(&self, inner: &mut PoolInner) -> SpawnReservation {
        let id = inner.next_id;
        inner.next_id += 1;
        inner.spawning.insert(id);
        SpawnReservation::new(self.clone(), id)
    }

    async fn finish_spawn_reservation(&self, worker_id: usize, slot: Option<Arc<ChildSlot>>) {
        let mut inner = self.inner.lock().await;
        inner.spawning.remove(&worker_id);
        if let Some(slot) = slot {
            inner.children.push(slot);
        }
    }

    fn worker_command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.config.exe_path);
        cmd.args(&self.config.worker_args);
        cmd.arg("worker");
        for var in CHILD_FILTER_ENV_VARS {
            cmd.env_remove(var);
        }
        cmd.kill_on_drop(true);
        cmd
    }

    async fn spawn_slot(
        &self,
        id: usize,
        initial_state: ChildState,
    ) -> Result<Arc<ChildSlot>, ToolError> {
        let cmd = self.worker_command();

        let (transport, stderr) = TokioChildProcess::builder(cmd)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                ToolError::RemoteProtocol(format!("failed to spawn worker {id}: {err}"))
            })?;
        let pid = transport.id();
        let stderr_task = spawn_stderr_relay(id, stderr);
        let handler = ParentClientHandler;
        let service = handler.serve(transport).await.map_err(|err| {
            ToolError::RemoteProtocol(format!("failed to initialize worker {id}: {err}"))
        })?;
        let peer = service.peer().clone();
        Ok(Arc::new(ChildSlot {
            id,
            child: Mutex::new(PooledChild {
                service: Some(service),
                peer,
                pid,
                stderr_task,
                state: initial_state,
                spawned_at: Instant::now(),
                last_used: Instant::now(),
                idb_path: None,
                pending_open_artifacts: None,
            }),
            call_lock: Mutex::new(()),
        }))
    }

    pub async fn release(&self, handle: PooledWorkerHandle) -> Result<(), ToolError> {
        let result = self.release_inner(&handle).await;
        if self.slot_is_idle(&handle.slot).await {
            self.schedule_idle_reap(handle.slot.clone());
        }
        result
    }

    async fn slot_is_idle(&self, slot: &Arc<ChildSlot>) -> bool {
        let child = slot.child.lock().await;
        child.state == ChildState::Idle
    }

    async fn release_inner(&self, handle: &PooledWorkerHandle) -> Result<(), ToolError> {
        let mut release_guard =
            WorkerRetireGuard::release(self.clone(), handle.slot.clone(), handle);
        let _call_guard = handle.slot.call_lock.lock().await;
        let peer = {
            let mut child = handle.slot.child.lock().await;
            if child.state == ChildState::Dead {
                release_guard.disarm();
                return Ok(());
            }
            child.state = ChildState::Closing;
            child.peer.clone()
        };

        let args = remote::json_object(json!({}))?;
        let close_timeout = self.close_rpc_timeout();
        let close =
            tokio::time::timeout(close_timeout, remote::call_tool(&peer, "close_idb", args)).await;

        let close_error = match close {
            Ok(Ok(result)) if result.is_error != Some(true) => None,
            Ok(Ok(result)) => remote::result_error(&result, "close_idb"),
            Ok(Err(err)) => Some(err),
            Err(_) => Some(ToolError::Timeout(close_timeout.as_secs())),
        };

        let close_error = match close_error {
            Some(err) if release_error_retires_worker(&err) => {
                warn!(
                    worker_id = handle.worker_id,
                    session_id = %handle.session_id,
                    error = %err,
                    "retiring IDA child worker after close_idb transport failure"
                );
                self.mark_dead(&handle.slot).await;
                release_guard.disarm();
                return Err(err);
            }
            other => other,
        };

        let mut child = handle.slot.child.lock().await;
        if child.state == ChildState::Dead {
            release_guard.disarm();
            if let Some(err) = close_error {
                return Err(err);
            }
            return Ok(());
        }
        child.state = ChildState::Idle;
        child.last_used = Instant::now();
        child.idb_path = None;
        child.pending_open_artifacts = None;
        release_guard.disarm();
        info!(
            worker_id = handle.worker_id,
            session_id = %handle.session_id,
            "released IDA child worker"
        );

        if let Some(err) = close_error {
            warn!(
                worker_id = handle.worker_id,
                session_id = %handle.session_id,
                error = %err,
                "child close_idb reported a non-retiring error during release; slot was reset idle"
            );
        }
        Ok(())
    }

    fn schedule_idle_reap(&self, slot: Arc<ChildSlot>) {
        let pool = self.clone();
        tokio::spawn(async move {
            let timeout = pool.config.worker_idle_timeout;
            if timeout.is_zero() {
                return;
            }
            let sleep_started = Instant::now();
            tokio::time::sleep(timeout).await;

            pool.mark_stale_idle_dead(&slot, sleep_started).await;
        });
    }

    pub async fn mark_dead(&self, slot: &Arc<ChildSlot>) {
        self.mark_dead_inner(slot, true).await;
    }

    async fn mark_dead_without_replacement(&self, slot: &Arc<ChildSlot>) {
        self.mark_dead_inner(slot, false).await;
    }

    async fn mark_dead_inner(&self, slot: &Arc<ChildSlot>, replenish: bool) {
        let dead = self.take_dead_worker(slot).await;
        self.forget_slot(slot.id).await;
        if let Some(dead) = dead {
            Self::finish_dead_worker(slot.id, dead).await;
        }
        if replenish {
            self.ensure_min_workers().await;
        }
    }

    async fn mark_stale_idle_dead(&self, slot: &Arc<ChildSlot>, sleep_started: Instant) {
        let Some(dead) = self
            .take_stale_idle_worker_if_above_min(slot, sleep_started)
            .await
        else {
            return;
        };
        info!(worker_id = slot.id, "reaping idle IDA child worker");
        self.forget_slot(slot.id).await;
        Self::finish_dead_worker(slot.id, dead).await;
    }

    async fn forget_slot(&self, worker_id: usize) {
        let mut inner = self.inner.lock().await;
        inner.children.retain(|slot| slot.id != worker_id);
    }

    async fn take_dead_worker(&self, slot: &Arc<ChildSlot>) -> Option<DeadWorker> {
        let mut child = slot.child.lock().await;
        if child.state == ChildState::Dead {
            return None;
        }
        Some(Self::take_dead_worker_locked(&mut child))
    }

    async fn take_stale_idle_worker_if_above_min(
        &self,
        slot: &Arc<ChildSlot>,
        sleep_started: Instant,
    ) -> Option<DeadWorker> {
        let inner = self.inner.lock().await;
        let mut live_count = inner.spawning.len();
        for child_slot in &inner.children {
            let child = child_slot.child.lock().await;
            if child.state != ChildState::Dead {
                live_count += 1;
            }
        }
        if live_count <= self.config.min_workers {
            return None;
        }

        let mut child = slot.child.lock().await;
        if child.state != ChildState::Idle || child.last_used > sleep_started {
            return None;
        }
        Some(Self::take_dead_worker_locked(&mut child))
    }

    fn take_dead_worker_locked(child: &mut PooledChild) -> DeadWorker {
        child.state = ChildState::Dead;
        let idb_path = child.idb_path.take();
        let pending_open_artifacts = child.pending_open_artifacts.take();
        let pid = child.pid;
        let age_secs = child.spawned_at.elapsed().as_secs();
        let service = child.service.take();
        child.stderr_task.abort();
        DeadWorker {
            service,
            pid,
            age_secs,
            idb_path,
            pending_open_artifacts,
        }
    }

    async fn finish_dead_worker(worker_id: usize, mut dead: DeadWorker) {
        if let Some(mut service) = dead.service.take() {
            let _ = service
                .close_with_timeout(Duration::from_secs(CHILD_SERVICE_CLOSE_TIMEOUT_SECS))
                .await;
        }
        if let Some(artifacts) = dead.pending_open_artifacts.take() {
            artifacts.cleanup_after_worker_loss(dead.pid).await;
        }
        if let Some(idb_path) = dead.idb_path.as_ref() {
            remove_mcp_lock_for_pid(idb_path, dead.pid);
        }
        warn!(
            worker_id,
            ?dead.pid,
            age_secs = dead.age_secs,
            "marked IDA child worker dead"
        );
    }

    async fn ensure_min_workers(&self) {
        let min_workers = self.config.min_workers.min(self.config.max_workers);
        if min_workers == 0 {
            return;
        }

        loop {
            let reservation = {
                let mut inner = self.inner.lock().await;
                let live_or_reserved = inner.spawning.len() + inner.children.len();
                if live_or_reserved >= min_workers || live_or_reserved >= self.config.max_workers {
                    return;
                }
                self.reserve_spawn_slot_locked(&mut inner)
            };

            let worker_id = reservation.worker_id();
            if let Err(err) = self
                .spawn_reserved_slot(reservation, ChildState::Idle)
                .await
            {
                warn!(worker_id, error = %err, "failed to replenish minimum pooled worker");
                return;
            }
        }
    }

    pub async fn shutdown_all(&self) {
        let slots = {
            let inner = self.inner.lock().await;
            inner.children.clone()
        };
        join_all(slots.into_iter().map(|slot| {
            let pool = self.clone();
            async move {
                pool.mark_dead_without_replacement(&slot).await;
            }
        }))
        .await;
    }

    #[cfg(test)]
    async fn live_or_reserved_count(&self) -> usize {
        let inner = self.inner.lock().await;
        let mut count = inner.spawning.len();
        for slot in &inner.children {
            let child = slot.child.lock().await;
            if child.state != ChildState::Dead {
                count += 1;
            }
        }
        count
    }

    /// Add parent response/retirement grace to a child-side deadline, then
    /// honor the operator's process-safety hard cap.
    fn worker_op_timeout(&self, requested: Option<u64>) -> Duration {
        let configured = self.config.worker_op_timeout;
        requested
            .map(|seconds| {
                seconds
                    .min(MAX_TIMEOUT_SECS)
                    .saturating_add(CHILD_TIMEOUT_GRACE_SECS)
            })
            .map(Duration::from_secs)
            .map(|requested| requested.min(configured))
            .unwrap_or(configured)
    }

    /// Closing owns process and database cleanup, so its watchdog cannot be
    /// configured below the child's bounded enqueue and debugger-teardown
    /// phases. Longer configured operation timeouts remain available for
    /// packing large databases.
    fn close_rpc_timeout(&self) -> Duration {
        self.config
            .worker_op_timeout
            .max(Duration::from_secs(MIN_CHILD_CLOSE_RPC_TIMEOUT_SECS))
    }
}

impl PooledWorkerHandle {
    pub fn worker_id(&self) -> usize {
        self.worker_id
    }

    async fn call_tool(
        &self,
        tool: &'static str,
        args: JsonObject,
        timeout: Duration,
        cancel: Option<CancellationToken>,
        mut open_dispatch: Option<OpenDispatch>,
    ) -> Result<CallToolResult, ToolError> {
        let _call_guard = self.slot.call_lock.lock().await;
        let tracks_open = open_dispatch.is_some();
        let mut previous_idb_path = None;
        let peer = {
            let mut child = self.slot.child.lock().await;
            match &child.state {
                ChildState::Leased { session_id } if session_id == &self.session_id => {
                    if let Some(open_dispatch) = open_dispatch.take() {
                        previous_idb_path = child.idb_path.replace(open_dispatch.database_path);
                        child.pending_open_artifacts = open_dispatch.artifacts;
                    }
                    child.peer.clone()
                }
                ChildState::Dead => {
                    return Err(ToolError::WorkerCrashed {
                        worker_id: self.worker_id,
                        last_op: tool.to_string(),
                    });
                }
                other => {
                    return Err(ToolError::RemoteProtocol(format!(
                        "worker {} is not leased to session {} (state: {other:?})",
                        self.worker_id, self.session_id
                    )));
                }
            }
        };

        let request = remote::call_tool(&peer, tool, args);
        tokio::pin!(request);
        let mut retire_guard = WorkerRetireGuard::call(self, tool);

        let result = if let Some(cancel) = cancel {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    self.pool.mark_dead(&self.slot).await;
                    retire_guard.disarm();
                    return Err(ToolError::Cancelled(format!(
                        "cancelled {tool}; killed worker {}",
                        self.worker_id
                    )));
                }
                result = tokio::time::timeout(timeout, &mut request) => result,
            }
        } else {
            tokio::time::timeout(timeout, &mut request).await
        };

        match result {
            Ok(Ok(result)) => {
                if tracks_open
                    && let Some(err) = remote::result_error(&result, tool)
                    && unsettled_open_error_retires_worker(&err)
                {
                    // A timeout/cancellation response bounds the caller's
                    // wait, not the native IDA open. Keep the pre-dispatch
                    // artifact snapshot attached while retirement settles
                    // the child and cleans only this generation's output.
                    self.pool.mark_dead(&self.slot).await;
                    retire_guard.disarm();
                    return Err(err);
                }
                if tracks_open {
                    let mut child = self.slot.child.lock().await;
                    child.pending_open_artifacts = None;
                    if result.is_error == Some(true) {
                        child.idb_path = previous_idb_path;
                    }
                }
                retire_guard.disarm();
                Ok(result)
            }
            Ok(Err(err)) => {
                self.pool.mark_dead(&self.slot).await;
                retire_guard.disarm();
                Err(ToolError::WorkerCrashed {
                    worker_id: self.worker_id,
                    last_op: format!("{tool}: {err}"),
                })
            }
            Err(_) => {
                self.pool.mark_dead(&self.slot).await;
                retire_guard.disarm();
                Err(ToolError::TimeoutDetailed(format!(
                    "{tool} exceeded worker operation timeout of {} seconds; killed worker {}",
                    timeout.as_secs(),
                    self.worker_id
                )))
            }
        }
    }
}

pub struct WorkspaceDatabase {
    pool: WorkerPool,
    session_id: String,
    handle: Arc<Mutex<Option<PooledDatabaseLease>>>,
    next_database_generation: AtomicU64,
    runtime: Option<Handle>,
}

/// Routes opaque database IDs to pooled worker leases.
///
/// # Lifecycle invariants
///
/// The workspace registry, the worker pool, and the debugger runtime are
/// three interacting state machines. Every transition one of them makes must
/// preserve these invariants; a change that adds a transition (a new
/// retirement path, pin, or lease state) must say which invariant covers it
/// or add one — with a test — rather than rely on review to notice the gap.
///
/// - **I1 — pin is lease state:** the debug pin is a field of
///   [`PooledDatabaseLease`], so it structurally cannot outlive the worker or
///   database generation that produced it, and it is applied only by
///   `WorkspaceDatabase::set_debug_pin_for_lease`, which re-checks the
///   dispatching (worker, generation) pair under the lease mutex — a stale
///   start completion pins nothing and its success-shaped result is replaced
///   with [`crate::error::ToolError::DebuggerSessionLost`], never reported as
///   a live session. The reaper reads pins via `try_lock`
///   (`lease_reap_decision`), treating contention as busy — no
///   cross-atomic memory-ordering contract. A healthy pin clears only through
///   successful `debug_stop` or database close; a pinned lease whose worker
///   transport closed out of band is terminal loss, so the reaper clears the
///   lease and retires the slot. External target exit without another
///   debugger call remains a documented limitation; tests
///   `debug_pin_cannot_exist_without_its_lease` and
///   `debug_start_pins_whenever_worker_retains_ownership`.
/// - **I2 — pins block reaping:** an entry with active calls, task pins, or a
///   debug pin is never idle-reaped. Enforced by the [`workspace_reaper`]
///   filter; test `workspace_idle_reaper_respects_every_lifetime_guard`.
///   Guard release publishes the refreshed idle timestamp *before*
///   decrementing its counter ([`WorkspaceLease`]/[`WorkspacePin`] `Drop`),
///   so a call outliving the TTL can never expose a zero guard count beside
///   a stale timestamp to a reaper pass in progress; test
///   `guard_release_refreshes_idle_time_before_dropping_its_count`.
/// - **I3 — close removes exactly the closable:** `close_idb` removes an
///   entry unless a keyed background open for it is still running, so a
///   pending open is protected while a terminal lease-less entry stays
///   removable. Enforced by `workspace_close_should_remove_entry` +
///   `TaskRegistry::has_running_workspace_open`; test
///   `workspace_close_retains_entry_while_background_open_is_running`.
/// - **I4 — retained session pins:** every debugger start that leaves the
///   child owning a live process pins the entry, including error and
///   `user_action_required` results. Enforced by `debug_start` over the
///   explicit `session_retained` /
///   [`crate::error::ToolError::DebuggerStartRetained`] signals.
/// - **I5 — stop unpins:** a debug stop that ends ownership (including the
///   already-exited `NoProcess` escape) clears the session and the pin.
/// - **I6 — retirement is cancellation-safe:** worker retirement completes
///   even if the awaiting future is dropped. Enforced by
///   [`WorkerRetireGuard`].
/// - **I7 — retirement is operation-scoped:** only hard transport failures
///   retire a worker, plus debugger-op timeouts, which permanently wedge the
///   child's serial loop. Enforced by `child_tool_error_retires_worker`; test
///   `child_tool_error_retire_decision_is_operation_specific`.
/// - **I8 — generations gate stale calls:** a call bound to a database
///   generation can never reach a reopened database. Enforced by
///   [`WorkspaceDatabase::required_handle_for_generation`], atomically with
///   handle acquisition.
/// - **I9 — health is not retention:** worker transport liveness is probed
///   independently of the workspace idle timeout. A zero timeout disables
///   only healthy idle eviction; it never disables dead-worker retirement or
///   terminal handle removal. Enforced by [`workspace_reaper`]; the strict
///   debugger oracle kills a pooled worker under a zero-TTL registry, and
///   `workspace_zero_ttl_still_reaps_terminal_no_lease_handles` covers the
///   lease-less terminal state while preserving active and pinned handles.
/// - **I10 — watchdogs enclose child deadlines:** debugger response waits add
///   worker-local grace after the SDK event timeout, and the pooled watchdog
///   adds parent grace after that. `close_idb` likewise adds parent grace after
///   its bounded enqueue and debugger teardown phases. The configured
///   operation watchdog is an explicit operator hard cap. Enforced by
///   `debugger_timeout_layers_are_strictly_nested`.
/// - **I11 — open intent is transactional:** an open publishes its effective
///   output and owned-artifact snapshot before child dispatch. Success commits
///   the path, an application error restores the previous path, and forced
///   retirement cleans only artifacts protected by the killed worker's exact
///   output lock. Enforced by `open_dispatch_tracks_the_effective_output_before_child_dispatch`,
///   the database artifact-cleanup tests, and `test-pool-second-open`.
///   Timeout, cancellation, and closed-worker error responses do not prove
///   the native open settled: they retire the child with its artifact
///   snapshot intact. Enforced by `unsettled_open_errors_require_retirement`
///   and `test-pool-open-timeout`.
#[derive(Clone)]
pub struct WorkspaceRegistry {
    inner: Arc<WorkspaceRegistryInner>,
}

struct WorkspaceRegistryInner {
    pool: WorkerPool,
    entries: StdMutex<HashMap<String, Arc<WorkspaceRegistryEntry>>>,
    idle_timeout: Duration,
}

struct WorkspaceRegistryEntry {
    database: Arc<WorkspaceDatabase>,
    last_used: StdMutex<Instant>,
    active_calls: AtomicUsize,
    pins: AtomicUsize,
    legacy: bool,
}

pub struct WorkspaceLease {
    database_id: String,
    entry: Arc<WorkspaceRegistryEntry>,
}

pub struct WorkspacePin {
    entry: Arc<WorkspaceRegistryEntry>,
}

pub struct LegacySessionBinding {
    registry: WorkspaceRegistry,
    database_id: String,
    database: Arc<WorkspaceDatabase>,
}

#[derive(Clone)]
pub enum PooledDatabaseBinding {
    Legacy(Arc<LegacySessionBinding>),
    Workspace(Arc<WorkspaceDatabase>),
}

#[derive(Clone)]
struct PooledDatabaseLease {
    handle: PooledWorkerHandle,
    generation: DatabaseGeneration,
    /// Invariant I1: the debug pin lives inside the lease it protects, so it
    /// structurally cannot outlive the worker or database generation that
    /// produced it — releasing or replacing the lease erases the pin with it.
    /// It is applied only through [`WorkspaceDatabase::set_debug_pin_for_lease`],
    /// which re-checks the dispatching (worker, generation) pair under this
    /// same mutex.
    debug_pinned: bool,
}

/// A child-tool outcome plus the lease that served it, kept even for failed
/// calls so debugger completions can bind pin decisions to their ownership.
struct DispatchedCall {
    result: Result<CallToolResult, ToolError>,
    lease: Option<(usize, DatabaseGeneration)>,
}

/// Worker binding of one workspace database, as seen by `list_databases`.
enum LeaseSnapshot {
    /// A worker is bound to a completed database open.
    Bound { path: PathBuf, debug_pinned: bool },
    /// No worker is bound: the database is allocated but not yet open, or
    /// its worker was lost.
    NoWorker,
    /// The lease is locked by an in-flight operation.
    Busy,
}

/// One row of `list_databases`: enough to re-address a handle after a lost
/// response or a stateless HTTP reconnect, and nothing internal.
pub struct WorkspaceDatabaseSummary {
    pub database_id: String,
    pub path: Option<String>,
    pub state: &'static str,
    pub idle_seconds: u64,
    pub active_calls: usize,
    pub pinned: bool,
    pub debug_pinned: bool,
}

/// Outcome of the reaper's lease-health probe for one workspace entry.
enum LeaseReapDecision {
    /// No worker lease is installed.
    NoLease,
    /// The worker transport is healthy and no debugger pin blocks eviction.
    HealthyUnpinned,
    /// The worker transport is healthy and a debugger pin blocks idle
    /// eviction.
    HealthyPinned,
    /// A lease or slot mutex was contended: the database is mid-operation.
    Busy,
    /// A lease whose worker transport closed out of band. The lease has been
    /// cleared; the caller retires the returned slot.
    DeadWorker(Arc<ChildSlot>),
}

#[derive(Clone, Copy)]
enum WorkspaceReapReason {
    Idle,
    Terminal,
}

/// Report the loss of a worker that was hosting a live debugger session.
///
/// Any server-initiated retirement of a debug-pinned lease — a timed-out
/// lifecycle operation, a crashed child, a dropped transport — ends ida-mcp's
/// control of that session without ending the debuggee: the worker never runs
/// `DebuggerRuntime::drop`, so its debug-server helper is reparented rather
/// than terminated. A start timeout can create the same orphan before the
/// lease is pinned. A bare timeout or transport error would hide either case,
/// so the error names it. Non-debugger losses keep their original error.
fn debugger_worker_loss_error(tool: &str, error: ToolError, debug_pinned: bool) -> ToolError {
    let uncertain_start = matches!(tool, "debug_launch" | "debug_attach")
        && matches!(
            &error,
            ToolError::Timeout(_) | ToolError::TimeoutDetailed(_)
        );
    if !debug_pinned && !uncertain_start {
        return error;
    }
    if uncertain_start && !debug_pinned {
        return ToolError::DebuggerSessionLost(format!(
            "{tool} timed out and its worker was retired ({error}); ida-mcp cannot determine \
             whether the debugger started before the timeout, and the target process may still \
             be running — check for a stray debuggee before retrying {tool}"
        ));
    }
    ToolError::DebuggerSessionLost(format!(
        "{tool} lost the worker hosting this database's debugger session ({error}); ida-mcp no \
         longer controls that session and the target process may still be running — check for a \
         stray debuggee, then reopen the database to start a new session"
    ))
}

/// Whether a debugger start left the child owning a live process: a `ready`
/// result, a `user_action_required` result whose process survived, or the
/// dedicated retained-start error all report it explicitly.
fn debug_start_retains_session(result: &Result<Value, ToolError>) -> bool {
    match result {
        Ok(value) => value
            .get("session_retained")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        Err(ToolError::DebuggerStartRetained(_)) => true,
        Err(_) => false,
    }
}

impl WorkspaceRegistry {
    fn with_inner(pool: WorkerPool, idle_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(WorkspaceRegistryInner {
                pool,
                entries: StdMutex::new(HashMap::new()),
                idle_timeout,
            }),
        }
    }

    pub fn new(pool: WorkerPool, idle_timeout: Duration) -> Self {
        let registry = Self::with_inner(pool, idle_timeout);
        registry.spawn_reaper();
        registry
    }

    /// Registry for legacy pooled HTTP sessions. Every entry is a legacy
    /// binding, and the reaper considers only non-legacy leases, so spawning
    /// one would tick every second for the life of the server and never find
    /// a candidate.
    pub fn new_legacy(pool: WorkerPool) -> Self {
        Self::with_inner(pool, Duration::ZERO)
    }

    fn entries(&self) -> StdMutexGuard<'_, HashMap<String, Arc<WorkspaceRegistryEntry>>> {
        match self.inner.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => {
                warn!("workspace registry mutex was poisoned; recovering its entries");
                poisoned.into_inner()
            }
        }
    }

    fn new_entry(&self, owner_id: String, legacy: bool) -> Arc<WorkspaceRegistryEntry> {
        Arc::new(WorkspaceRegistryEntry {
            database: Arc::new(WorkspaceDatabase::new(self.inner.pool.clone(), owner_id)),
            last_used: StdMutex::new(Instant::now()),
            active_calls: AtomicUsize::new(0),
            pins: AtomicUsize::new(0),
            legacy,
        })
    }

    pub fn allocate_database(&self) -> WorkspaceLease {
        let database_id = uuid::Uuid::new_v4().to_string();
        let entry = self.new_entry(format!("workspace:{database_id}"), false);
        entry.active_calls.store(1, Ordering::Relaxed);
        self.entries().insert(database_id.clone(), entry.clone());
        WorkspaceLease { database_id, entry }
    }

    pub fn runtime_database(&self) -> Arc<WorkspaceDatabase> {
        Arc::new(WorkspaceDatabase::new(
            self.inner.pool.clone(),
            "workspace-runtime".to_string(),
        ))
    }

    pub fn acquire(&self, database_id: &str) -> Option<WorkspaceLease> {
        let entry = {
            let entries = self.entries();
            let entry = entries.get(database_id).cloned()?;
            // Protect the entry before releasing the registry lock so the
            // idle reaper cannot remove it between lookup and acquisition.
            entry.active_calls.fetch_add(1, Ordering::Relaxed);
            entry
        };
        entry.touch();
        Some(WorkspaceLease {
            database_id: database_id.to_string(),
            entry,
        })
    }

    pub fn bind_legacy(&self, session_id: String) -> LegacySessionBinding {
        let database_id = format!("legacy:{}", uuid::Uuid::new_v4());
        let entry = self.new_entry(session_id, true);
        let database = entry.database.clone();
        self.entries().insert(database_id.clone(), entry);
        LegacySessionBinding {
            registry: self.clone(),
            database_id,
            database,
        }
    }

    pub fn remove(&self, database_id: &str) -> Option<Arc<WorkspaceDatabase>> {
        self.entries()
            .remove(database_id)
            .map(|entry| entry.database.clone())
    }

    pub fn pin(&self, database_id: &str) -> Option<WorkspacePin> {
        let entry = {
            let entries = self.entries();
            let entry = entries.get(database_id).cloned()?;
            // See `acquire`: pinning and lookup are one reaper-visible state
            // transition, not two independently scheduled operations.
            entry.pins.fetch_add(1, Ordering::Relaxed);
            entry
        };
        entry.touch();
        Some(WorkspacePin { entry })
    }

    /// Snapshot every workspace database handle for discovery. Legacy
    /// session bindings are internal routing state and never listed. The
    /// registry lock is released before probing worker state so one busy
    /// database cannot stall the listing.
    pub fn list_databases(&self) -> Vec<WorkspaceDatabaseSummary> {
        let entries = {
            let entries = self.entries();
            let mut collected = Vec::with_capacity(entries.len());
            for (database_id, entry) in entries.iter() {
                if !entry.legacy {
                    collected.push((database_id.clone(), entry.clone()));
                }
            }
            collected
        };
        let mut summaries = Vec::with_capacity(entries.len());
        for (database_id, entry) in entries {
            let active_calls = entry.active_calls.load(Ordering::Relaxed);
            let (path, state, debug_pinned) = match entry.database.lease_snapshot() {
                LeaseSnapshot::Bound { path, debug_pinned } => (
                    Some(path.display().to_string()),
                    if active_calls > 0 { "busy" } else { "open" },
                    debug_pinned,
                ),
                LeaseSnapshot::NoWorker => (None, "no_worker", false),
                LeaseSnapshot::Busy => (None, "busy", false),
            };
            summaries.push(WorkspaceDatabaseSummary {
                database_id,
                path,
                state,
                idle_seconds: entry.idle_for().as_secs(),
                active_calls,
                pinned: entry.pins.load(Ordering::Relaxed) > 0,
                debug_pinned,
            });
        }
        summaries.sort_by(|left, right| left.database_id.cmp(&right.database_id));
        summaries
    }

    pub async fn close_database(&self, database_id: &str) -> Result<(), ToolError> {
        let database = self.remove(database_id).ok_or_else(|| {
            ToolError::InvalidParams(format!("unknown database_id: {database_id}"))
        })?;
        database.close().await
    }

    pub async fn shutdown(&self) {
        let databases = {
            let mut entries = self.entries();
            entries
                .drain()
                .map(|(_, entry)| entry.database.clone())
                .collect::<Vec<_>>()
        };
        // Each close is a child RPC with a teardown-timeout floor; closing
        // them sequentially would make shutdown scale with database count.
        join_all(databases.into_iter().map(|database| async move {
            let _ = database.close().await;
        }))
        .await;
    }

    fn spawn_reaper(&self) {
        let Ok(runtime) = Handle::try_current() else {
            return;
        };
        let weak = Arc::downgrade(&self.inner);
        let interval = if self.inner.idle_timeout.is_zero() {
            Duration::from_secs(1)
        } else {
            self.inner
                .idle_timeout
                .checked_div(2)
                .unwrap_or(Duration::from_secs(1))
                .clamp(Duration::from_secs(1), Duration::from_secs(30))
        };
        runtime.spawn(async move {
            workspace_reaper(weak, interval).await;
        });
    }
}

/// Unguarded workspace leases, which are the reaper's health candidates.
/// Healthy idle eviction is a later policy decision; transport liveness must
/// still run when idle eviction is disabled (I9).
fn collect_reap_candidates(
    inner: &WorkspaceRegistryInner,
) -> Vec<(String, Arc<WorkspaceRegistryEntry>)> {
    let entries = match inner.entries.lock() {
        Ok(entries) => entries,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut candidates = Vec::new();
    for (id, entry) in entries.iter() {
        if !entry.legacy
            && entry.active_calls.load(Ordering::Relaxed) == 0
            && entry.pins.load(Ordering::Relaxed) == 0
        {
            candidates.push((id.clone(), entry.clone()));
        }
    }
    candidates
}

/// Probe transport health outside the registry lock. Dead workers and
/// lease-less handles are terminal regardless of TTL; healthy unpinned
/// entries are eligible only under the idle policy.
async fn probe_reap_candidates(
    inner: &WorkspaceRegistryInner,
    candidates: Vec<(String, Arc<WorkspaceRegistryEntry>)>,
) -> Vec<(String, WorkspaceReapReason)> {
    let mut reapable = Vec::new();
    for (database_id, entry) in candidates {
        match entry.database.lease_reap_decision().await {
            LeaseReapDecision::NoLease => {
                reapable.push((database_id, WorkspaceReapReason::Terminal));
            }
            LeaseReapDecision::HealthyUnpinned => {
                if !inner.idle_timeout.is_zero() && entry.idle_for() >= inner.idle_timeout {
                    reapable.push((database_id, WorkspaceReapReason::Idle));
                }
            }
            LeaseReapDecision::HealthyPinned | LeaseReapDecision::Busy => {}
            LeaseReapDecision::DeadWorker(slot) => {
                warn!(
                    database_id,
                    "workspace worker exited out of band; clearing its lease"
                );
                inner.pool.mark_dead(&slot).await;
                reapable.push((database_id, WorkspaceReapReason::Terminal));
            }
        }
    }
    reapable
}

/// Re-verify under the registry lock before removal: a call that arrived
/// while probing raised `active_calls` or refreshed idle time, and any
/// freshly-set pin implies such a call.
fn take_expired_entries(
    inner: &WorkspaceRegistryInner,
    reapable: Vec<(String, WorkspaceReapReason)>,
) -> Vec<(String, Arc<WorkspaceDatabase>, WorkspaceReapReason)> {
    let mut entries = match inner.entries.lock() {
        Ok(entries) => entries,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut expired = Vec::new();
    for (database_id, reason) in reapable {
        let still_reapable = entries.get(&database_id).is_some_and(|entry| {
            !entry.legacy
                && entry.active_calls.load(Ordering::Relaxed) == 0
                && entry.pins.load(Ordering::Relaxed) == 0
                && match reason {
                    WorkspaceReapReason::Idle => {
                        !inner.idle_timeout.is_zero() && entry.idle_for() >= inner.idle_timeout
                    }
                    WorkspaceReapReason::Terminal => entry.database.lease_is_absent(),
                }
        });
        if still_reapable && let Some(entry) = entries.remove(&database_id) {
            expired.push((database_id, entry.database.clone(), reason));
        }
    }
    expired
}

async fn workspace_reaper(inner: Weak<WorkspaceRegistryInner>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let Some(inner) = Weak::upgrade(&inner) else {
            break;
        };
        let candidates = collect_reap_candidates(&inner);
        let reapable = probe_reap_candidates(&inner, candidates).await;
        for (database_id, database, reason) in take_expired_entries(&inner, reapable) {
            match reason {
                WorkspaceReapReason::Idle => {
                    info!(database_id, "reaping idle workspace database");
                }
                WorkspaceReapReason::Terminal => {
                    info!(database_id, "removing terminal workspace database");
                }
            }
            let _ = database.close().await;
        }
    }
}

impl WorkspaceRegistryEntry {
    fn touch(&self) {
        let mut last_used = match self.last_used.lock() {
            Ok(last_used) => last_used,
            Err(poisoned) => poisoned.into_inner(),
        };
        *last_used = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        let last_used = match self.last_used.lock() {
            Ok(last_used) => last_used,
            Err(poisoned) => poisoned.into_inner(),
        };
        last_used.elapsed()
    }
}

impl WorkspaceLease {
    pub fn database_id(&self) -> &str {
        &self.database_id
    }

    pub fn database(&self) -> Arc<WorkspaceDatabase> {
        self.entry.database.clone()
    }
}

impl Drop for WorkspaceLease {
    fn drop(&mut self) {
        // Publish the fresh idle timestamp before releasing the guard
        // (invariant I2). A call outliving the TTL would otherwise expose a
        // zero guard count alongside its stale timestamp, and a reaper pass
        // landing in that window would reap a database that was in use one
        // instant earlier.
        self.entry.touch();
        self.entry.active_calls.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for WorkspacePin {
    fn drop(&mut self) {
        // Same ordering rule as WorkspaceLease: timestamp first, then guard.
        self.entry.touch();
        self.entry.pins.fetch_sub(1, Ordering::Relaxed);
    }
}

impl std::ops::Deref for LegacySessionBinding {
    type Target = WorkspaceDatabase;

    fn deref(&self) -> &Self::Target {
        &self.database
    }
}

impl std::ops::Deref for PooledDatabaseBinding {
    type Target = WorkspaceDatabase;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Legacy(binding) => binding,
            Self::Workspace(database) => database,
        }
    }
}

impl Drop for LegacySessionBinding {
    fn drop(&mut self) {
        let _ = self.registry.remove(&self.database_id);
    }
}

impl WorkspaceDatabase {
    pub fn new(pool: WorkerPool, session_id: String) -> Self {
        Self {
            pool,
            session_id,
            handle: Arc::new(Mutex::new(None)),
            next_database_generation: AtomicU64::new(0),
            runtime: Handle::try_current().ok(),
        }
    }

    /// Apply a debug-pin decision produced by a debugger call dispatched on
    /// `lease` (worker id, database generation). The pin mutates only while
    /// that exact lease is still installed, so a completion whose worker was
    /// lost or whose database was replaced applies nothing (invariant I1).
    async fn set_debug_pin_for_lease(
        &self,
        lease: (usize, DatabaseGeneration),
        pinned: bool,
    ) -> bool {
        let mut guard = self.handle.lock().await;
        let Some(current) = guard.as_mut() else {
            return false;
        };
        if current.handle.worker_id != lease.0 || current.generation != lease.1 {
            return false;
        }
        current.debug_pinned = pinned;
        true
    }

    /// Read-only snapshot of this database's worker binding for
    /// `list_databases`. Uses `try_lock` throughout: a database mid-call
    /// reports `busy` rather than blocking a discovery request behind a
    /// long-running analysis.
    fn lease_snapshot(&self) -> LeaseSnapshot {
        let Ok(guard) = self.handle.try_lock() else {
            return LeaseSnapshot::Busy;
        };
        let Some(lease) = guard.as_ref() else {
            return LeaseSnapshot::NoWorker;
        };
        // `call_lock` covers the complete remote operation, including
        // background opens whose registry-level active-call guard has already
        // been released. Holding it also prevents a call from starting while
        // the child state below is being classified.
        let Ok(_call_guard) = lease.handle.slot.call_lock.try_lock() else {
            return LeaseSnapshot::Busy;
        };
        // Contention is reported as busy rather than as a bound worker with
        // an unknown path: `open` with `path: null` would misdescribe a
        // database that is simply mid-call.
        let Ok(child) = lease.handle.slot.child.try_lock() else {
            return LeaseSnapshot::Busy;
        };
        // A closed transport means the worker is gone even though the lease
        // survives until a dispatch or the reaper clears it. Reporting it as
        // `open` would advertise a handle no call can serve.
        if child.transport_closed() {
            return LeaseSnapshot::NoWorker;
        }
        // The worker lease is installed before open_idb starts, while the
        // path is published only after that call succeeds. The narrow
        // post-call handoff must remain busy rather than claiming an open
        // database without an addressable path.
        let Some(path) = child.idb_path.clone() else {
            return LeaseSnapshot::Busy;
        };
        LeaseSnapshot::Bound {
            path,
            debug_pinned: lease.debug_pinned,
        }
    }

    /// Reaper-side lease-health and debug-pin gate. Contended state reads as busy so the
    /// reaper never blocks behind an in-flight call, and no cross-atomic
    /// ordering contract is needed. A pinned lease whose worker transport
    /// already closed is reported as terminal worker loss: without this probe
    /// an out-of-band child exit would leave the pinned lease installed
    /// forever, because only dispatch paths clear handles (invariants I1/I2).
    ///
    /// Worker liveness is the only signal available here. IDA's
    /// `debugger_process_state` is a cached getter, so a target killed
    /// outside ida-mcp keeps reporting its last state until some call drains
    /// the pending debug event; asking for it from the reaper cannot prove
    /// the target exited. A session whose target dies externally therefore
    /// stays pinned until `debug_stop`, `close_idb`, or worker loss — a
    /// documented limitation, not silent cleanup.
    async fn lease_reap_decision(&self) -> LeaseReapDecision {
        let Ok(mut guard) = self.handle.try_lock() else {
            return LeaseReapDecision::Busy;
        };
        let Some(lease) = guard.as_ref() else {
            return LeaseReapDecision::NoLease;
        };
        let Ok(child) = lease.handle.slot.child.try_lock() else {
            return LeaseReapDecision::Busy;
        };
        let worker_unavailable = child.state == ChildState::Dead || child.transport_closed();
        drop(child);
        if !worker_unavailable {
            return if lease.debug_pinned {
                LeaseReapDecision::HealthyPinned
            } else {
                LeaseReapDecision::HealthyUnpinned
            };
        }
        let Some(lease) = guard.take() else {
            return LeaseReapDecision::NoLease;
        };
        LeaseReapDecision::DeadWorker(lease.handle.slot)
    }

    /// Re-verify that terminal worker loss did not race a new open that
    /// installed a replacement lease.
    fn lease_is_absent(&self) -> bool {
        self.handle.try_lock().is_ok_and(|lease| lease.is_none())
    }

    fn next_database_generation(&self) -> Result<DatabaseGeneration, ToolError> {
        let previous = self
            .next_database_generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                ToolError::IdaError("database generation counter exhausted".to_string())
            })?;
        previous
            .checked_add(1)
            .map(DatabaseGeneration)
            .ok_or_else(|| ToolError::IdaError("database generation counter exhausted".to_string()))
    }

    async fn lease_for_open(
        &self,
    ) -> Result<(PooledWorkerHandle, DatabaseGeneration, bool), ToolError> {
        let mut guard = self.handle.lock().await;
        if let Some(lease) = guard.as_ref() {
            return Ok((lease.handle.clone(), lease.generation, false));
        }
        let generation = self.next_database_generation()?;
        let handle = self.pool.lease(&self.session_id).await?;
        *guard = Some(PooledDatabaseLease {
            handle: handle.clone(),
            generation,
            debug_pinned: false,
        });
        Ok((handle, generation, true))
    }

    /// Resolve the leased worker, optionally only while `expected_generation`
    /// is still this session's database lifetime.
    ///
    /// The generation comparison and the handle clone happen under one lock
    /// acquisition: a `close_idb` that replaces the lease either loses the race
    /// (we dispatch against the database we opened) or wins it (we refuse). A
    /// caller that checked separately could be redirected onto the new lease.
    async fn required_handle_for_generation(
        &self,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<(PooledWorkerHandle, DatabaseGeneration), ToolError> {
        let guard = self.handle.lock().await;
        let lease = guard.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
        require_lease_generation(lease.generation, expected_generation)?;
        Ok((lease.handle.clone(), lease.generation))
    }

    async fn take_handle(&self) -> Option<PooledDatabaseLease> {
        self.handle.lock().await.take()
    }

    async fn release_current_handle(&self) {
        if let Some(lease) = self.take_handle().await {
            let _ = self.pool.release(lease.handle).await;
        }
    }

    /// Unbind a lost worker. Returns whether the cleared lease held a debug
    /// pin, so the caller can report a live debugger session ending with its
    /// worker instead of a bare transport error.
    async fn clear_handle_if_worker(&self, worker_id: usize) -> bool {
        let mut guard = self.handle.lock().await;
        if guard
            .as_ref()
            .is_some_and(|lease| lease.handle.worker_id == worker_id)
        {
            // The debug pin lives inside the lease, so dropping the lease
            // erases it structurally (invariant I1) — no separate cleanup.
            let debug_pinned = guard.as_ref().is_some_and(|lease| lease.debug_pinned);
            *guard = None;
            return debug_pinned;
        }
        false
    }

    /// Call a child tool, optionally bound to one database lifetime (see
    /// [`Self::required_handle_for_generation`]).
    async fn call_result_for_generation(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<CallToolResult, ToolError> {
        self.dispatch_result_for_generation(tool, args, timeout_secs, cancel, expected_generation)
            .await
            .result
    }

    /// Like [`Self::call_result_for_generation`], but also reports which
    /// lease (worker id, database generation) served the call — even when the
    /// call itself failed — so debugger completions can bind their pin
    /// decision to the exact ownership that produced them (invariant I1).
    async fn dispatch_result_for_generation(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
        expected_generation: Option<DatabaseGeneration>,
    ) -> DispatchedCall {
        let (handle, generation) = match self
            .required_handle_for_generation(expected_generation)
            .await
        {
            Ok(dispatched) => dispatched,
            Err(err) => {
                return DispatchedCall {
                    result: Err(err),
                    lease: None,
                };
            }
        };
        let lease = Some((handle.worker_id, generation));
        let args = match remote::json_object(args) {
            Ok(args) => args,
            Err(err) => {
                return DispatchedCall {
                    result: Err(err),
                    lease,
                };
            }
        };
        let timeout = self.pool.worker_op_timeout(timeout_secs);
        let result = match handle.call_tool(tool, args, timeout, cancel, None).await {
            Ok(result) => {
                if let Some(err) = remote::result_error(&result, tool) {
                    if child_tool_error_retires_worker(tool, &err) {
                        let mut retire_guard = WorkerRetireGuard::call(&handle, tool);
                        let debug_pinned = self.clear_handle_if_worker(handle.worker_id).await;
                        self.pool.mark_dead(&handle.slot).await;
                        retire_guard.disarm();
                        Err(debugger_worker_loss_error(tool, err, debug_pinned))
                    } else {
                        Err(err)
                    }
                } else {
                    Ok(result)
                }
            }
            Err(err) => {
                let debug_pinned = self.clear_handle_if_worker(handle.worker_id).await;
                Err(debugger_worker_loss_error(tool, err, debug_pinned))
            }
        };
        DispatchedCall { result, lease }
    }

    async fn call_json<T: DeserializeOwned>(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<T, ToolError> {
        self.call_json_for_generation(tool, args, timeout_secs, cancel, None)
            .await
    }

    async fn call_json_for_generation<T: DeserializeOwned>(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<T, ToolError> {
        let result = self
            .call_result_for_generation(tool, args, timeout_secs, cancel, expected_generation)
            .await?;
        remote::parse_json(result, tool)
    }

    async fn call_value(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        self.call_value_for_generation(tool, args, timeout_secs, cancel, None)
            .await
    }

    async fn call_value_for_generation(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<Value, ToolError> {
        let result = self
            .call_result_for_generation(tool, args, timeout_secs, cancel, expected_generation)
            .await?;
        remote::parse_value(result, tool)
    }

    async fn call_json_field<T: DeserializeOwned>(
        &self,
        tool: &'static str,
        args: Value,
        field: &'static str,
        timeout_secs: Option<u64>,
    ) -> Result<T, ToolError> {
        self.call_json_field_for_generation(tool, args, field, timeout_secs, None)
            .await
    }

    async fn call_json_field_for_generation<T: DeserializeOwned>(
        &self,
        tool: &'static str,
        args: Value,
        field: &'static str,
        timeout_secs: Option<u64>,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<T, ToolError> {
        let value = self
            .call_value_for_generation(tool, args, timeout_secs, None, expected_generation)
            .await?;
        let Some(field_value) = value.get(field).cloned() else {
            return Err(ToolError::RemoteProtocol(format!(
                "child tool {tool} response did not contain `{field}`"
            )));
        };
        serde_json::from_value(field_value).map_err(|err| {
            ToolError::RemoteProtocol(format!("invalid {tool}.{field} response: {err}"))
        })
    }

    async fn call_text(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<String, ToolError> {
        let result = self
            .call_result_for_generation(tool, args, timeout_secs, cancel, None)
            .await?;
        remote::result_text(&result, tool)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_observed(
        &self,
        path: &str,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        rebuild: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        raw_target: RawBinaryTarget,
        extra_args: Vec<String>,
        idb_out: Option<String>,
        timeout_secs: Option<u64>,
        _progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<DbInfo, ToolError> {
        self.open_observed_with_generation(
            path,
            load_debug_info,
            debug_info_path,
            debug_info_verbose,
            force,
            rebuild,
            file_type,
            auto_analyse,
            raw_target,
            extra_args,
            idb_out,
            timeout_secs,
            _progress_tx,
            cancel,
        )
        .await
        .map(|opened| opened.info)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_observed_with_generation(
        &self,
        path: &str,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        rebuild: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        raw_target: RawBinaryTarget,
        extra_args: Vec<String>,
        idb_out: Option<String>,
        timeout_secs: Option<u64>,
        _progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<OpenedDatabase, ToolError> {
        let (handle, generation, fresh_lease) = self.lease_for_open().await?;
        let timeout = self.pool.worker_op_timeout(timeout_secs);
        let open_dispatch = OpenDispatch::for_request(path, idb_out.as_deref(), rebuild);
        let result = handle
            .call_tool(
                "open_idb",
                remote::json_object(open_idb_child_args(
                    path,
                    load_debug_info,
                    debug_info_path,
                    debug_info_verbose,
                    force,
                    rebuild,
                    file_type,
                    auto_analyse,
                    raw_target,
                    extra_args,
                    idb_out,
                    timeout_secs,
                ))?,
                timeout,
                cancel,
                Some(open_dispatch),
            )
            .await;

        match result.and_then(|result| remote::parse_json::<DbInfo>(result, "open_idb")) {
            Ok(info) => {
                let mut child = handle.slot.child.lock().await;
                child.idb_path = Some(PathBuf::from(&info.path));
                Ok(OpenedDatabase { info, generation })
            }
            Err(err) => {
                if open_error_releases_lease(fresh_lease, &err) {
                    self.release_current_handle().await;
                }
                Err(err)
            }
        }
    }

    pub async fn close(&self) -> Result<(), ToolError> {
        let Some(lease) = self.take_handle().await else {
            return Err(ToolError::NoDatabaseOpen);
        };
        self.pool.release(lease.handle).await
    }

    pub(crate) async fn close_if_generation(
        &self,
        generation: DatabaseGeneration,
    ) -> Result<ConditionalCloseResult, ToolError> {
        let lease = {
            let mut guard = self.handle.lock().await;
            if guard
                .as_ref()
                .is_none_or(|lease| lease.generation != generation)
            {
                return Ok(ConditionalCloseResult::NotCurrent);
            }
            guard.take()
        };
        let Some(lease) = lease else {
            return Ok(ConditionalCloseResult::NotCurrent);
        };
        self.pool.release(lease.handle).await?;
        Ok(ConditionalCloseResult::Closed)
    }

    pub async fn load_debug_info(
        &self,
        path: Option<String>,
        verbose: bool,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "load_debug_info",
            json!({ "path": path, "verbose": verbose }),
            None,
            None,
        )
        .await
    }

    pub async fn debug_launch(
        &self,
        path: &str,
        arguments: Option<String>,
        start_directory: Option<String>,
        timeout_seconds: u32,
    ) -> Result<Value, ToolError> {
        self.debug_start(
            "debug_launch",
            json!({
                "path": path,
                "arguments": arguments,
                "start_directory": start_directory,
                "timeout_secs": timeout_seconds,
            }),
            timeout_seconds,
        )
        .await
    }

    pub async fn debug_attach(&self, pid: u32, timeout_seconds: u32) -> Result<Value, ToolError> {
        self.debug_start(
            "debug_attach",
            json!({ "pid": pid, "timeout_secs": timeout_seconds }),
            timeout_seconds,
        )
        .await
    }

    /// Dispatch a debugger start and pin this database while the child owns a
    /// live process. The pin is applied against the exact lease that served
    /// the call, so a completion that raced worker loss or a database
    /// replacement pins nothing (invariant I1) — the session it reports died
    /// with its worker.
    async fn debug_start(
        &self,
        tool: &'static str,
        args: Value,
        timeout_seconds: u32,
    ) -> Result<Value, ToolError> {
        let dispatched = self
            .dispatch_result_for_generation(
                tool,
                args,
                Some(debugger_response_timeout_secs(timeout_seconds)),
                None,
                None,
            )
            .await;
        let result = dispatched
            .result
            .and_then(|result| remote::parse_value(result, tool));
        if debug_start_retains_session(&result) {
            let pinned = match dispatched.lease {
                Some(lease) => self.set_debug_pin_for_lease(lease, true).await,
                None => false,
            };
            if !pinned {
                // The session this result reports died with its worker before
                // it could be tracked. Returning the original success-shaped
                // result would tell the client it owns a live session, so the
                // outcome is replaced with the truth.
                warn!(
                    session_id = %self.session_id,
                    tool,
                    "retained debugger session lost its lease before pinning; \
                     reporting the session as lost"
                );
                // Do not claim the debuggee ended. A worker killed outside
                // its own control (SIGKILL, crash) never runs
                // DebuggerRuntime::drop, so its debug-server helper is
                // reparented rather than terminated and can keep the target
                // process alive.
                return Err(ToolError::DebuggerSessionLost(format!(
                    "{tool} started a debugger session, but its worker was lost before the \
                     session could be tracked; ida-mcp no longer controls that session and the \
                     target process may still be running — check for a stray debuggee before \
                     retrying {tool}"
                )));
            }
        }
        result
    }

    pub async fn debug_modules(&self) -> Result<Value, ToolError> {
        self.call_value(
            "debug_modules",
            json!({}),
            Some(DEBUG_MODULES_TIMEOUT_SECS),
            None,
        )
        .await
    }

    pub async fn debug_stop(
        &self,
        action: DebugStopAction,
        timeout_seconds: u32,
    ) -> Result<Value, ToolError> {
        let dispatched = self
            .dispatch_result_for_generation(
                "debug_stop",
                json!({ "action": action.as_str(), "timeout_secs": timeout_seconds }),
                Some(debugger_response_timeout_secs(timeout_seconds)),
                None,
                None,
            )
            .await;
        let result = dispatched
            .result
            .and_then(|result| remote::parse_value(result, "debug_stop"));
        // A successful stop ended ownership for the lease that served it; a
        // failed stop keeps the session (and its pin) fail-closed. A stale
        // lease needs no clearing — its pin died with it.
        if result.is_ok()
            && let Some(lease) = dispatched.lease
        {
            let _ = self.set_debug_pin_for_lease(lease, false).await;
        }
        result
    }

    pub async fn analysis_status(&self) -> Result<AnalysisStatus, ToolError> {
        self.analysis_status_for_generation(None).await
    }

    pub(crate) async fn analysis_status_for_generation(
        &self,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<AnalysisStatus, ToolError> {
        self.call_json_for_generation(
            "analysis_status",
            json!({}),
            None,
            None,
            expected_generation,
        )
        .await
    }

    pub async fn dsc_load_image(
        &self,
        module: &str,
        timeout_secs: Option<u64>,
    ) -> Result<DscImageInfo, ToolError> {
        self.dsc_load_image_for_generation(module, timeout_secs, None)
            .await
    }

    pub(crate) async fn dsc_load_image_for_generation(
        &self,
        module: &str,
        timeout_secs: Option<u64>,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<DscImageInfo, ToolError> {
        self.call_json_field_for_generation(
            "dsc_add_dylib",
            json!({ "module": module, "timeout_secs": timeout_secs }),
            "image",
            timeout_secs,
            expected_generation,
        )
        .await
    }

    pub async fn dsc_load_region(
        &self,
        addr: u64,
        timeout_secs: Option<u64>,
    ) -> Result<DscRegionInfo, ToolError> {
        self.call_json_field(
            "dsc_add_region",
            json!({ "address": remote::hex_addr(addr), "timeout_secs": timeout_secs }),
            "region",
            timeout_secs,
        )
        .await
    }

    pub async fn list_functions(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<FunctionListResult, ToolError> {
        self.call_json(
            "list_functions",
            json!({ "offset": offset, "limit": limit, "filter": filter, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn resolve_function(&self, name: &str) -> Result<FunctionInfo, ToolError> {
        self.call_json("resolve_function", json!({ "name": name }), None, None)
            .await
    }

    pub async fn disasm_by_name(&self, name: &str, count: usize) -> Result<String, ToolError> {
        self.call_text(
            "disasm_by_name",
            json!({ "name": name, "count": count }),
            None,
            None,
        )
        .await
    }

    pub async fn disasm(&self, addr: u64, count: usize) -> Result<String, ToolError> {
        self.call_text(
            "disasm",
            json!({ "address": remote::hex_addr(addr), "count": count }),
            None,
            None,
        )
        .await
    }

    pub async fn render_range(
        &self,
        start: u64,
        end: u64,
        max_lines: usize,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "render_range",
            json!({ "start": remote::hex_addr(start), "end": remote::hex_addr(end), "max_lines": max_lines }),
            None,
            None,
        )
        .await
    }

    pub async fn decompile(&self, addr: u64) -> Result<String, ToolError> {
        self.call_text(
            "decompile",
            json!({ "address": remote::hex_addr(addr) }),
            None,
            None,
        )
        .await
    }

    pub async fn segments(&self) -> Result<Vec<SegmentInfo>, ToolError> {
        self.call_json("segments", json!({}), None, None).await
    }

    pub async fn strings(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError> {
        self.call_json(
            "strings",
            json!({ "offset": offset, "limit": limit, "filter": filter, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn local_types(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<LocalTypeListResult, ToolError> {
        self.call_json(
            "local_types",
            json!({ "offset": offset, "limit": limit, "filter": filter, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn declare_type(
        &self,
        decl: String,
        relaxed: bool,
        replace: bool,
        multi: bool,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "declare_type",
            json!({ "decl": decl, "relaxed": relaxed, "replace": replace, "multi": multi }),
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn apply_types(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        stack_offset: Option<i64>,
        stack_name: Option<String>,
        decl: Option<String>,
        type_name: Option<String>,
        relaxed: bool,
        delay: bool,
        strict: bool,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "apply_types",
            json!({
                "address": remote::opt_hex_addr(addr),
                "target_name": name,
                "offset": offset,
                "stack_offset": stack_offset,
                "stack_name": stack_name,
                "decl": decl,
                "type_name": type_name,
                "relaxed": relaxed,
                "delay": delay,
                "strict": strict,
            }),
            None,
            None,
        )
        .await
    }

    pub async fn infer_types(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<GuessTypeResult, ToolError> {
        self.call_json(
            "infer_types",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset }),
            None,
            None,
        )
        .await
    }

    pub async fn addr_info(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<AddressInfo, ToolError> {
        self.call_json(
            "addr_info",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset }),
            None,
            None,
        )
        .await
    }

    pub async fn function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<FunctionRangeInfo, ToolError> {
        self.call_json(
            "function_at",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset }),
            None,
            None,
        )
        .await
    }

    pub async fn disasm_function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        count: usize,
    ) -> Result<String, ToolError> {
        self.call_text(
            "disasm_function_at",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset, "count": count }),
            None,
            None,
        )
        .await
    }

    pub async fn declare_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        var_name: Option<String>,
        decl: String,
        relaxed: bool,
    ) -> Result<StackVarResult, ToolError> {
        self.call_json(
            "declare_stack",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset, "var_name": var_name, "decl": decl, "relaxed": relaxed }),
            None,
            None,
        )
        .await
    }

    pub async fn delete_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: Option<i64>,
        var_name: Option<String>,
    ) -> Result<StackVarResult, ToolError> {
        self.call_json(
            "delete_stack",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset, "var_name": var_name }),
            None,
            None,
        )
        .await
    }

    pub async fn stack_frame(&self, addr: u64) -> Result<FrameInfo, ToolError> {
        self.call_json(
            "stack_frame",
            json!({ "address": remote::hex_addr(addr) }),
            None,
            None,
        )
        .await
    }

    pub async fn structs(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<String>,
        timeout_secs: Option<u64>,
    ) -> Result<StructListResult, ToolError> {
        self.call_json(
            "structs",
            json!({ "offset": offset, "limit": limit, "filter": filter, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn struct_info(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructInfo, ToolError> {
        self.call_json(
            "struct_info",
            json!({ "ordinal": ordinal, "name": name }),
            None,
            None,
        )
        .await
    }

    pub async fn read_struct(
        &self,
        addr: u64,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructReadResult, ToolError> {
        self.call_json(
            "read_struct",
            json!({ "address": remote::hex_addr(addr), "ordinal": ordinal, "name": name }),
            None,
            None,
        )
        .await
    }

    pub async fn xrefs_to(
        &self,
        addr: u64,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<XRefListResult, ToolError> {
        self.call_json(
            "xrefs_to",
            json!({
                "address": remote::hex_addr(addr),
                "offset": offset,
                "limit": limit,
                "timeout_secs": timeout_secs,
            }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn xrefs_from(
        &self,
        addr: u64,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<XRefListResult, ToolError> {
        self.call_json(
            "xrefs_from",
            json!({
                "address": remote::hex_addr(addr),
                "offset": offset,
                "limit": limit,
                "timeout_secs": timeout_secs,
            }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn xrefs_to_field(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
        member_index: Option<u32>,
        member_name: Option<String>,
        limit: usize,
    ) -> Result<XrefsToFieldResult, ToolError> {
        self.call_json(
            "xrefs_to_field",
            json!({ "ordinal": ordinal, "name": name, "member_index": member_index, "member_name": member_name, "limit": limit }),
            None,
            None,
        )
        .await
    }

    pub async fn imports(&self, offset: usize, limit: usize) -> Result<Vec<ImportInfo>, ToolError> {
        self.call_json(
            "imports",
            json!({ "offset": offset, "limit": limit }),
            None,
            None,
        )
        .await
    }

    pub async fn exports(&self, offset: usize, limit: usize) -> Result<Vec<ExportInfo>, ToolError> {
        self.call_json(
            "exports",
            json!({ "offset": offset, "limit": limit }),
            None,
            None,
        )
        .await
    }

    pub async fn entrypoints(&self) -> Result<Vec<String>, ToolError> {
        self.call_json("entrypoints", json!({}), None, None).await
    }

    pub async fn lumina_lookup(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "lumina_lookup",
            json!({
                "address": remote::opt_hex_addr(addr),
                "target_name": name,
                "offset": offset,
                "timeout_secs": timeout_secs,
            }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn lumina_apply(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        force: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "lumina_apply",
            lumina_apply_child_args(addr, name, offset, force),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn get_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        size: usize,
    ) -> Result<BytesResult, ToolError> {
        self.call_json(
            "get_bytes",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset, "size": size }),
            None,
            None,
        )
        .await
    }

    pub async fn list_patches(
        &self,
        start: Option<u64>,
        end: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "list_patches",
            json!({
                "start": remote::opt_hex_addr(start),
                "end": remote::opt_hex_addr(end),
                "offset": offset,
                "limit": limit,
            }),
            None,
            None,
        )
        .await
    }

    pub async fn set_comments(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        comment: String,
        repeatable: bool,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "set_comments",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset, "comment": comment, "repeatable": repeatable }),
            None,
            None,
        )
        .await
    }

    pub async fn rename(
        &self,
        addr: Option<u64>,
        current_name: Option<String>,
        new_name: String,
        flags: i32,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "rename",
            json!({ "address": remote::opt_hex_addr(addr), "current_name": current_name, "name": new_name, "flags": flags }),
            None,
            None,
        )
        .await
    }

    pub async fn patch_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        bytes: Vec<u8>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "patch",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset, "bytes": bytes }),
            None,
            None,
        )
        .await
    }

    pub async fn patch_asm(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        line: String,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "patch_asm",
            json!({ "address": remote::opt_hex_addr(addr), "target_name": name, "offset": offset, "line": line }),
            None,
            None,
        )
        .await
    }

    pub async fn basic_blocks(&self, addr: u64) -> Result<Vec<BasicBlockInfo>, ToolError> {
        self.call_json(
            "basic_blocks",
            json!({ "address": remote::hex_addr(addr) }),
            None,
            None,
        )
        .await
    }

    pub async fn callees(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
        self.call_json(
            "callees",
            json!({ "address": remote::hex_addr(addr) }),
            None,
            None,
        )
        .await
    }

    pub async fn callers(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
        self.call_json(
            "callers",
            json!({ "address": remote::hex_addr(addr) }),
            None,
            None,
        )
        .await
    }

    pub async fn idb_meta(&self) -> Result<Value, ToolError> {
        self.call_value("idb_meta", json!({}), None, None).await
    }

    pub async fn lookup_funcs(&self, queries: Vec<String>) -> Result<Value, ToolError> {
        self.call_value("lookup_funcs", json!({ "queries": queries }), None, None)
            .await
    }

    pub async fn list_globals(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "list_globals",
            json!({ "query": query, "offset": offset, "limit": limit, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn analyze_strings(
        &self,
        query: Option<String>,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "analyze_strings",
            json!({ "query": query, "offset": offset, "limit": limit, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn find_string(
        &self,
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError> {
        self.call_json(
            "find_string",
            json!({ "query": query, "exact": exact, "case_insensitive": case_insensitive, "offset": offset, "limit": limit, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn xrefs_to_string(
        &self,
        query: String,
        exact: bool,
        case_insensitive: bool,
        offset: usize,
        limit: usize,
        max_xrefs: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringXrefsResult, ToolError> {
        self.call_json(
            "xrefs_to_string",
            json!({ "query": query, "exact": exact, "case_insensitive": case_insensitive, "offset": offset, "limit": limit, "max_xrefs": max_xrefs, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn analyze_funcs(&self, timeout_secs: Option<u64>) -> Result<Value, ToolError> {
        self.call_value(
            "analyze_funcs",
            json!({ "background": false, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn analyze_funcs_observed(
        &self,
        _progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "analyze_funcs",
            analyze_funcs_child_args(timeout_secs, false),
            timeout_secs,
            cancel,
        )
        .await
    }

    pub async fn analyze_funcs_unbounded_observed(
        &self,
        _progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "analyze_funcs",
            analyze_funcs_child_args(None, true),
            None,
            cancel,
        )
        .await
    }

    pub async fn find_bytes(
        &self,
        pattern: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let value = self
            .call_value(
                "find_bytes",
                find_bytes_child_args(pattern, max_results, timeout_secs),
                timeout_secs,
                None,
            )
            .await?;
        extract_first_matches(value, "find_bytes")
    }

    pub async fn search_text(
        &self,
        text: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.search_one(text, "text", max_results, timeout_secs)
            .await
    }

    pub async fn search_imm(
        &self,
        imm: u64,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.search_one(format!("0x{imm:x}"), "imm", max_results, timeout_secs)
            .await
    }

    async fn search_one(
        &self,
        target: String,
        kind: &str,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let value = self
            .call_value(
                "search",
                search_child_args(target, kind, max_results, timeout_secs),
                timeout_secs,
                None,
            )
            .await?;
        extract_first_matches(value, "search")
    }

    pub async fn find_insns(
        &self,
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "find_insns",
            json!({ "patterns": patterns, "limit": max_results, "case_insensitive": case_insensitive, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn find_insn_operands(
        &self,
        patterns: Vec<String>,
        max_results: usize,
        case_insensitive: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "find_insn_operands",
            json!({ "patterns": patterns, "limit": max_results, "case_insensitive": case_insensitive, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn read_int(&self, addr: u64, size: usize) -> Result<Value, ToolError> {
        let tool = match size {
            1 => "get_u8",
            2 => "get_u16",
            4 => "get_u32",
            8 => "get_u64",
            _ => {
                return Err(ToolError::InvalidParams(format!(
                    "unsupported integer size: {size}"
                )));
            }
        };
        self.call_value(
            tool,
            json!({ "address": remote::hex_addr(addr) }),
            None,
            None,
        )
        .await
    }

    pub async fn get_string(&self, addr: u64, max_len: usize) -> Result<Value, ToolError> {
        self.call_value(
            "get_string",
            json!({ "address": remote::hex_addr(addr), "max_len": max_len }),
            None,
            None,
        )
        .await
    }

    pub async fn get_global_value(&self, query: String) -> Result<Value, ToolError> {
        self.call_value("get_global_value", json!({ "query": query }), None, None)
            .await
    }

    pub async fn find_paths(
        &self,
        start: u64,
        end: u64,
        max_paths: usize,
        max_depth: usize,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "find_paths",
            json!({ "start": remote::hex_addr(start), "end": remote::hex_addr(end), "max_paths": max_paths, "max_depth": max_depth }),
            None,
            None,
        )
        .await
    }

    pub async fn callgraph(
        &self,
        addr: u64,
        direction: CallGraphDirection,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "callgraph",
            json!({ "roots": remote::hex_addr(addr), "direction": direction.as_str(), "max_depth": max_depth, "max_nodes": max_nodes }),
            None,
            None,
        )
        .await
    }

    pub async fn xref_matrix(&self, addrs: Vec<u64>) -> Result<Value, ToolError> {
        let addrs = addrs.into_iter().map(remote::hex_addr).collect::<Vec<_>>();
        self.call_value("xref_matrix", json!({ "addrs": addrs }), None, None)
            .await
    }

    pub async fn export_funcs(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<FunctionListResult, ToolError> {
        self.call_json(
            "export_funcs",
            json!({ "offset": offset, "limit": limit, "format": "json" }),
            None,
            None,
        )
        .await
    }

    pub async fn run_script(
        &self,
        code: &str,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "run_script",
            json!({ "code": code, "timeout_secs": timeout_secs }),
            timeout_secs,
            None,
        )
        .await
    }

    pub async fn run_script_observed(
        &self,
        code: &str,
        _progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "run_script",
            run_script_child_args(code, timeout_secs),
            timeout_secs,
            cancel,
        )
        .await
    }

    pub async fn pseudocode_at(
        &self,
        addr: u64,
        end_addr: Option<u64>,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "pseudocode_at",
            json!({ "address": remote::hex_addr(addr), "end_address": end_addr.map(|addr| format!("0x{addr:x}")) }),
            None,
            None,
        )
        .await
    }
}

impl Drop for WorkspaceDatabase {
    fn drop(&mut self) {
        let pool = self.pool.clone();
        let handle_slot = self.handle.clone();
        let runtime = Handle::try_current().ok().or_else(|| self.runtime.clone());
        let Some(runtime) = runtime else {
            warn!(
                session_id = %self.session_id,
                "pooled session dropped outside a Tokio runtime; worker lease may remain active"
            );
            return;
        };
        runtime.spawn(async move {
            let Some(lease) = handle_slot.lock().await.take() else {
                return;
            };
            let _ = pool.release(lease.handle).await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn open_idb_child_args(
    path: &str,
    load_debug_info: bool,
    debug_info_path: Option<String>,
    debug_info_verbose: bool,
    force: bool,
    rebuild: bool,
    file_type: Option<String>,
    auto_analyse: bool,
    raw_target: RawBinaryTarget,
    extra_args: Vec<String>,
    idb_out: Option<String>,
    timeout_secs: Option<u64>,
) -> Value {
    json!({
        "path": path,
        "load_debug_info": load_debug_info,
        "debug_info_path": debug_info_path,
        "debug_info_verbose": debug_info_verbose,
        "force": force,
        "rebuild": rebuild,
        "file_type": file_type,
        "auto_analyse": auto_analyse,
        "processor": raw_target.processor,
        "bitness": raw_target.bitness.map(idalib::segment::Bitness::bits),
        "base_address": raw_target.base_address.map(remote::hex_addr),
        "entry_point": raw_target.entry_point.map(remote::hex_addr),
        "_worker_extra_args": extra_args,
        "_worker_idb_out": idb_out,
        "timeout_secs": timeout_secs,
    })
}

fn analyze_funcs_child_args(timeout_secs: Option<u64>, worker_no_timeout: bool) -> Value {
    json!({
        "background": false,
        "timeout_secs": timeout_secs,
        "_worker_no_timeout": worker_no_timeout,
    })
}

fn run_script_child_args(code: &str, timeout_secs: Option<u64>) -> Value {
    json!({ "code": code, "timeout_secs": timeout_secs })
}

fn lumina_apply_child_args(
    addr: Option<u64>,
    name: Option<String>,
    offset: i64,
    force: bool,
) -> Value {
    json!({
        "address": remote::opt_hex_addr(addr),
        "target_name": name,
        "offset": offset,
        "force": force,
        // The child must not report a timeout while IDA is still mutating its
        // database. The parent watchdog owns timeout enforcement and kills the
        // child before returning a timeout to the caller.
        "timeout_secs": null,
    })
}

fn find_bytes_child_args(pattern: String, max_results: usize, timeout_secs: Option<u64>) -> Value {
    json!({
        "patterns": [pattern],
        "limit": max_results.min(10000),
        "offset": 0,
        "timeout_secs": timeout_secs,
        "_worker_max_results": max_results,
    })
}

fn search_child_args(
    target: String,
    kind: &str,
    max_results: usize,
    timeout_secs: Option<u64>,
) -> Value {
    json!({
        "targets": [target],
        "kind": kind,
        "limit": max_results.min(10000),
        "offset": 0,
        "timeout_secs": timeout_secs,
        "_worker_max_results": max_results,
    })
}

fn extract_first_matches(value: Value, tool: &'static str) -> Result<Value, ToolError> {
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ToolError::RemoteProtocol(format!("{tool} response did not include results"))
        })?;

    if results.len() > 1 {
        debug!(
            tool,
            result_sets = results.len(),
            "pooled worker response included multiple result sets; using the first"
        );
    }

    let Some(first) = results.first() else {
        return Ok(json!({ "matches": [] }));
    };
    if let Some(error) = first.get("error").and_then(Value::as_str) {
        return Err(ToolError::IdaError(error.to_string()));
    }

    let matches = first.get("matches").cloned().ok_or_else(|| {
        ToolError::RemoteProtocol(format!(
            "{tool} response did not include results[0].matches or results[0].error"
        ))
    })?;
    Ok(json!({ "matches": matches }))
}

/// Decide whether an operation bound to `expected` may run against the lease
/// currently held at `current`.
///
/// `None` opts out, for foreground tools that legitimately target whatever
/// database the session has open. `Some` binds the operation to one database
/// lifetime so a close/reopen refuses it instead of redirecting it onto the
/// new lease. The caller evaluates this while holding the lease lock, so the
/// decision cannot be invalidated between here and dispatch.
fn require_lease_generation(
    current: DatabaseGeneration,
    expected: Option<DatabaseGeneration>,
) -> Result<(), ToolError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if current == expected {
        return Ok(());
    }
    warn!(
        expected_generation = expected.0,
        current_generation = current.0,
        "Refusing a pooled operation bound to a replaced database generation"
    );
    Err(ToolError::DatabaseReplaced)
}

fn release_error_retires_worker(err: &ToolError) -> bool {
    matches!(
        err,
        ToolError::Timeout(_)
            | ToolError::TimeoutDetailed(_)
            | ToolError::Cancelled(_)
            | ToolError::DebuggerTeardown(_)
            | ToolError::WorkerCrashed { .. }
            | ToolError::RemoteProtocol(_)
            | ToolError::WorkerClosed
    )
}

fn child_tool_error_retires_worker(tool: &str, err: &ToolError) -> bool {
    if matches!(
        err,
        ToolError::WorkerClosed | ToolError::WorkerCrashed { .. } | ToolError::RemoteProtocol(_)
    ) {
        return true;
    }

    matches!(
        tool,
        "debug_launch" | "debug_attach" | "debug_modules" | "debug_stop"
    ) && matches!(err, ToolError::Timeout(_) | ToolError::TimeoutDetailed(_))
}

fn unsettled_open_error_retires_worker(err: &ToolError) -> bool {
    matches!(
        err,
        ToolError::Timeout(_)
            | ToolError::TimeoutDetailed(_)
            | ToolError::Cancelled(_)
            | ToolError::WorkerClosed
    )
}

fn open_error_releases_lease(fresh_lease: bool, err: &ToolError) -> bool {
    fresh_lease
        || matches!(
            err,
            ToolError::Timeout(_)
                | ToolError::TimeoutDetailed(_)
                | ToolError::Cancelled(_)
                | ToolError::WorkerCrashed { .. }
                | ToolError::WorkerClosed
        )
}

const STDERR_CHUNK_BYTES: usize = 4096;
const STDERR_LINE_LIMIT_BYTES: usize = 16 * 1024;

fn spawn_stderr_relay(
    worker_id: usize,
    stderr: Option<tokio::process::ChildStderr>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Some(mut stderr) = stderr else {
            return;
        };
        let mut chunk = [0_u8; STDERR_CHUNK_BYTES];
        let mut pending = Vec::new();

        loop {
            match stderr.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => drain_stderr_chunk(worker_id, &mut pending, &chunk[..n]),
                Err(err) => {
                    warn!(worker_id, error = %err, "failed to read child stderr");
                    break;
                }
            }
        }

        if !pending.is_empty() {
            log_stderr_line(worker_id, &pending);
        }
    })
}

fn drain_stderr_chunk(worker_id: usize, pending: &mut Vec<u8>, mut chunk: &[u8]) {
    while let Some(pos) = chunk.iter().position(|byte| *byte == b'\n') {
        pending.extend_from_slice(&chunk[..pos]);
        log_stderr_line(worker_id, pending);
        pending.clear();
        chunk = &chunk[pos + 1..];
    }

    pending.extend_from_slice(chunk);
    if pending.len() > STDERR_LINE_LIMIT_BYTES {
        let truncated = &pending[..STDERR_LINE_LIMIT_BYTES];
        let line = String::from_utf8_lossy(truncated);
        debug!(target: "ida_mcp::worker_stderr", worker_id, line = %line, truncated = true);
        pending.clear();
    }
}

fn log_stderr_line(worker_id: usize, line: &[u8]) {
    let line = String::from_utf8_lossy(line);
    debug!(target: "ida_mcp::worker_stderr", worker_id, line = %line);
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::handlers::debugger::DEBUGGER_TEARDOWN_TIMEOUT_SECS;
    use crate::ida::pool::{
        analyze_funcs_child_args, child_tool_error_retires_worker, debug_start_retains_session,
        debugger_worker_loss_error, extract_first_matches, find_bytes_child_args,
        lumina_apply_child_args, open_error_releases_lease, open_idb_child_args,
        release_error_retires_worker, require_lease_generation, run_script_child_args,
        search_child_args, unsettled_open_error_retires_worker, LeaseReapDecision, OpenDispatch,
        WorkerPool, WorkerPoolConfig, WorkspaceRegistry, CHILD_TIMEOUT_GRACE_SECS,
        MIN_CHILD_CLOSE_RPC_TIMEOUT_SECS,
    };
    use crate::ida::types::{ConditionalCloseResult, DatabaseGeneration, RawBinaryTarget};
    use crate::ida::worker::{
        debugger_response_timeout_secs, CLOSE_SEND_TIMEOUT_SECS, DEBUG_MODULES_TIMEOUT_SECS,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    fn test_pool(max_workers: usize) -> WorkerPool {
        WorkerPool::new(WorkerPoolConfig {
            max_workers,
            min_workers: 0,
            worker_idle_timeout: Duration::from_secs(300),
            worker_op_timeout: Duration::from_secs(600),
            exe_path: PathBuf::from("/does/not/spawn/in/this/test"),
            worker_args: Vec::new(),
        })
    }

    #[tokio::test]
    async fn workspace_and_legacy_bindings_share_one_registry_map() {
        let registry = WorkspaceRegistry::new(test_pool(4), Duration::ZERO);
        let first = registry.allocate_database();
        let second = registry.allocate_database();
        assert_ne!(first.database_id(), second.database_id());
        assert_eq!(registry.entries().len(), 2);

        let first_id = first.database_id().to_string();
        drop(first);
        let first_entry = registry
            .entries()
            .get(&first_id)
            .cloned()
            .expect("allocated database remains registered");
        assert_eq!(first_entry.active_calls.load(Ordering::Relaxed), 0);
        let acquired = registry
            .acquire(&first_id)
            .expect("database remains routed");
        assert_eq!(acquired.database_id(), first_id);
        assert_eq!(first_entry.active_calls.load(Ordering::Relaxed), 1);
        let pin = registry.pin(&first_id).expect("database can be pinned");
        assert_eq!(first_entry.pins.load(Ordering::Relaxed), 1);
        drop(pin);
        assert_eq!(first_entry.pins.load(Ordering::Relaxed), 0);
        drop(acquired);
        assert_eq!(first_entry.active_calls.load(Ordering::Relaxed), 0);

        let legacy = registry.bind_legacy("legacy-test".to_string());
        assert_eq!(registry.entries().len(), 3);
        drop(legacy);
        assert_eq!(registry.entries().len(), 2);

        assert!(registry.remove(&first_id).is_some());
        let second_id = second.database_id().to_string();
        drop(second);
        assert!(registry.remove(&second_id).is_some());
        assert!(registry.entries().is_empty());
        registry.shutdown().await;
    }

    #[tokio::test]
    async fn workspace_idle_reaper_respects_every_lifetime_guard() {
        let registry = WorkspaceRegistry::new(test_pool(4), Duration::from_millis(10));

        let idle = registry.allocate_database();
        let idle_id = idle.database_id().to_string();
        drop(idle);

        let active = registry.allocate_database();
        let active_id = active.database_id().to_string();

        let pinned = registry.allocate_database();
        let pinned_id = pinned.database_id().to_string();
        let pin = registry
            .pin(&pinned_id)
            .expect("allocated database can be pinned");
        drop(pinned);

        // A held handle mutex stands in for a live debugger dispatch: the
        // reaper's try_lock read must treat contention as pinned/busy.
        let debug_busy = registry.allocate_database();
        let debug_busy_id = debug_busy.database_id().to_string();
        let debug_busy_database = debug_busy.database();
        let debug_busy_guard = debug_busy_database.handle.lock().await;
        drop(debug_busy);

        let legacy = registry.bind_legacy("legacy-reaper-test".to_string());
        let legacy_id = legacy.database_id.clone();

        // The production reaper interval is clamped to one second. Waiting
        // past its first pass exercises the actual spawned lifecycle rather
        // than only restating its selection predicate in a helper test.
        tokio::time::sleep(Duration::from_millis(1_500)).await;

        {
            let entries = registry.entries();
            assert!(!entries.contains_key(&idle_id));
            assert!(entries.contains_key(&active_id));
            assert!(entries.contains_key(&pinned_id));
            assert!(entries.contains_key(&debug_busy_id));
            assert!(entries.contains_key(&legacy_id));
        }

        drop(active);
        drop(pin);
        drop(debug_busy_guard);
        drop(legacy);
        registry.shutdown().await;
    }

    #[tokio::test]
    async fn workspace_zero_ttl_still_reaps_terminal_no_lease_handles() {
        let registry = WorkspaceRegistry::new(test_pool(3), Duration::ZERO);

        let terminal = registry.allocate_database();
        let terminal_id = terminal.database_id().to_string();
        drop(terminal);

        let active = registry.allocate_database();
        let active_id = active.database_id().to_string();

        let pinned = registry.allocate_database();
        let pinned_id = pinned.database_id().to_string();
        let pin = registry
            .pin(&pinned_id)
            .expect("allocated database can be pinned");
        drop(pinned);

        tokio::time::sleep(Duration::from_millis(1_500)).await;

        {
            let entries = registry.entries();
            assert!(
                !entries.contains_key(&terminal_id),
                "zero TTL disables healthy idle eviction, not terminal cleanup"
            );
            assert!(entries.contains_key(&active_id));
            assert!(entries.contains_key(&pinned_id));
        }

        drop(active);
        drop(pin);
        registry.shutdown().await;
    }

    /// Lifecycle invariant I1: a debug pin exists only inside a worker lease,
    /// so it structurally cannot outlive the ownership that produced it. A
    /// pin decision from a dispatch whose lease is gone applies nothing, a
    /// lease-less database never reports a blocking pin, and a contended
    /// lease mutex reads as busy. The matching-lease apply path needs a live
    /// pooled worker and is covered by the debugger integration tests.
    #[tokio::test]
    async fn debug_pin_cannot_exist_without_its_lease() {
        let registry = WorkspaceRegistry::new(test_pool(2), Duration::from_secs(300));
        let lease = registry.allocate_database();
        let database = lease.database();

        // A completion for a lease that no longer exists applies nothing.
        assert!(
            !database
                .set_debug_pin_for_lease((7, DatabaseGeneration(1)), true)
                .await
        );
        let LeaseReapDecision::NoLease = database.lease_reap_decision().await else {
            panic!("a lease-less database must not report a blocking pin");
        };

        // Worker loss with no lease installed is a no-op, not a panic.
        database.clear_handle_if_worker(7).await;
        let LeaseReapDecision::NoLease = database.lease_reap_decision().await else {
            panic!("worker loss without a lease must leave the entry reapable");
        };

        // A contended lease mutex reads as busy rather than unpinned.
        let guard = database.handle.lock().await;
        let LeaseReapDecision::Busy = database.lease_reap_decision().await else {
            panic!("a contended lease mutex must read as busy");
        };
        drop(guard);

        drop(lease);
        registry.shutdown().await;
    }

    /// Lifecycle invariant I2: a guard release must never expose a zero
    /// guard count beside a stale idle timestamp, or a reaper pass landing in
    /// that window reaps a database that was in use an instant earlier. A
    /// concurrent sampler watches for that pair while long-idle leases are
    /// released; with the decrement ordered first it is observable, with the
    /// timestamp published first it cannot occur.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guard_release_refreshes_idle_time_before_dropping_its_count() {
        let registry = WorkspaceRegistry::new(test_pool(2), Duration::from_secs(300));
        let lease = registry.allocate_database();
        let database_id = lease.database_id().to_string();
        drop(lease);
        let entry = registry
            .entries()
            .get(&database_id)
            .cloned()
            .expect("allocated database remains registered");

        let stop = Arc::new(AtomicBool::new(false));
        let violations = Arc::new(AtomicUsize::new(0));
        let sampler = {
            let entry = entry.clone();
            let stop = stop.clone();
            let violations = violations.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // Read the timestamp and both counts as one snapshot,
                    // holding the lock `touch` uses. Sampling them as three
                    // independent loads would report torn states that never
                    // existed simultaneously.
                    let idle = {
                        let last_used = match entry.last_used.lock() {
                            Ok(last_used) => last_used,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        let idle = last_used.elapsed();
                        let guards = entry.active_calls.load(Ordering::Relaxed)
                            + entry.pins.load(Ordering::Relaxed);
                        (guards == 0).then_some(idle)
                    };
                    if idle.is_some_and(|idle| idle >= Duration::from_secs(30)) {
                        violations.fetch_add(1, Ordering::Relaxed);
                    }
                    std::hint::spin_loop();
                }
            })
        };

        let stale = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .expect("test clock supports a 60s offset");
        for _ in 0..5_000 {
            let held = registry.acquire(&database_id).expect("database is routed");
            match entry.last_used.lock() {
                Ok(mut last_used) => *last_used = stale,
                Err(poisoned) => *poisoned.into_inner() = stale,
            }
            drop(held);

            let pin = registry.pin(&database_id).expect("database can be pinned");
            match entry.last_used.lock() {
                Ok(mut last_used) => *last_used = stale,
                Err(poisoned) => *poisoned.into_inner() = stale,
            }
            drop(pin);
        }
        stop.store(true, Ordering::Relaxed);
        sampler.join().expect("sampler thread finishes");

        assert_eq!(
            violations.load(Ordering::Relaxed),
            0,
            "a released guard exposed a stale idle timestamp to a concurrent reaper"
        );
        registry.shutdown().await;
    }

    /// Every known or possible debugger-session loss must be reported
    /// truthfully — never as a bare timeout — without claiming the debuggee
    /// ended. Unrelated losses keep their original error.
    #[test]
    fn retiring_a_debugger_worker_reports_session_loss_truthfully() {
        let wedged = debugger_worker_loss_error(
            "debug_modules",
            ToolError::Timeout(DEBUG_MODULES_TIMEOUT_SECS),
            true,
        );
        let ToolError::DebuggerSessionLost(message) = &wedged else {
            panic!("a wedged debugger worker must report a lost session, got: {wedged}");
        };
        assert!(message.contains("debug_modules"));
        assert!(message.contains("may still be running"));
        assert!(!message.contains("ended with the worker"));

        let crashed = debugger_worker_loss_error(
            "debug_modules",
            ToolError::WorkerCrashed {
                worker_id: 3,
                last_op: "debug_modules".to_string(),
            },
            true,
        );
        assert!(matches!(crashed, ToolError::DebuggerSessionLost(_)));

        // No debugger session: the original error survives unchanged.
        let plain = debugger_worker_loss_error(
            "run_script",
            ToolError::Timeout(DEBUG_MODULES_TIMEOUT_SECS),
            false,
        );
        assert!(matches!(plain, ToolError::Timeout(_)));

        let uncertain_launch =
            debugger_worker_loss_error("debug_launch", ToolError::Timeout(5), false);
        let ToolError::DebuggerSessionLost(message) = uncertain_launch else {
            panic!("a timed-out debugger start must report possible target loss");
        };
        assert!(message.contains("cannot determine whether the debugger started"));
        assert!(message.contains("may still be running"));
    }

    /// Ownership signals that must pin: an explicit `session_retained`
    /// result or the dedicated retained-start error, and nothing else.
    #[test]
    fn debug_start_pins_whenever_worker_retains_ownership() {
        assert!(debug_start_retains_session(&Ok(json!({
            "status": "ready",
            "session_retained": true
        }))));
        assert!(debug_start_retains_session(&Ok(json!({
            "status": "user_action_required",
            "session_retained": true
        }))));
        assert!(!debug_start_retains_session(&Ok(json!({
            "status": "user_action_required",
            "session_retained": false
        }))));
        assert!(debug_start_retains_session(&Err(
            ToolError::DebuggerStartRetained("initial wait failed".to_string())
        )));
        assert!(!debug_start_retains_session(&Err(ToolError::IdaError(
            "start failed before process creation".to_string()
        ))));
    }

    #[test]
    fn pooled_child_workers_ignore_public_tool_filters() {
        let pool = test_pool(1);
        let cmd = pool.worker_command();
        let cleared: Vec<&str> = cmd
            .as_std()
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .filter_map(|(key, _)| key.to_str())
            .collect();

        for var in crate::ida::pool::CHILD_FILTER_ENV_VARS {
            assert!(
                cleared.contains(var),
                "pooled child workers must not inherit {var}; they need lifecycle tools"
            );
        }
    }

    #[test]
    fn explicit_child_timeout_gets_parent_watchdog_grace() {
        let pool = WorkerPool::new(WorkerPoolConfig {
            max_workers: 1,
            min_workers: 0,
            worker_idle_timeout: Duration::from_secs(300),
            worker_op_timeout: Duration::from_secs(1800),
            exe_path: PathBuf::from("/does/not/spawn/in/this/test"),
            worker_args: Vec::new(),
        });

        assert_eq!(pool.worker_op_timeout(Some(120)), Duration::from_secs(130));
        assert_eq!(pool.worker_op_timeout(Some(600)), Duration::from_secs(610));
        assert_eq!(
            pool.worker_op_timeout(Some(9999)),
            Duration::from_secs(610),
            "child foreground timeout is capped before adding parent grace"
        );
    }

    #[test]
    fn debugger_timeout_layers_are_strictly_nested() {
        let pool = test_pool(1);
        let sdk_timeout = 120;
        let child_timeout = debugger_response_timeout_secs(sdk_timeout);
        let parent_timeout = pool.worker_op_timeout(Some(child_timeout)).as_secs();

        assert!(u64::from(sdk_timeout) < child_timeout);
        assert!(child_timeout < parent_timeout);
        assert_eq!(
            MIN_CHILD_CLOSE_RPC_TIMEOUT_SECS,
            CLOSE_SEND_TIMEOUT_SECS
                + u64::from(DEBUGGER_TEARDOWN_TIMEOUT_SECS)
                + CHILD_TIMEOUT_GRACE_SECS
        );
        assert!(
            CLOSE_SEND_TIMEOUT_SECS + u64::from(DEBUGGER_TEARDOWN_TIMEOUT_SECS)
                < MIN_CHILD_CLOSE_RPC_TIMEOUT_SECS,
            "close_idb must leave time to pack the IDB and return after debugger teardown"
        );
        assert_eq!(
            pool.close_rpc_timeout(),
            pool.config.worker_op_timeout,
            "the configured operation budget should remain available for IDB packing"
        );

        let short_pool = WorkerPool::new(WorkerPoolConfig {
            worker_op_timeout: Duration::from_secs(1),
            ..pool.config.as_ref().clone()
        });
        assert_eq!(
            short_pool.close_rpc_timeout(),
            Duration::from_secs(MIN_CHILD_CLOSE_RPC_TIMEOUT_SECS),
            "configuration must not undercut the bounded child cleanup phases"
        );
    }

    #[test]
    fn pooled_observed_child_args_forward_timeouts_and_raw_target() {
        let raw_target = RawBinaryTarget {
            processor: Some("arm:ARMv7-M".to_string()),
            bitness: Some(idalib::segment::Bitness::Bits32),
            base_address: Some(0x0800_0000),
            entry_point: Some(0x0800_0100),
        };
        let open_args = open_idb_child_args(
            "/tmp/a",
            true,
            Some("/tmp/a.dSYM".to_string()),
            true,
            false,
            false,
            Some("pe".to_string()),
            true,
            raw_target,
            vec!["-A".to_string()],
            Some("/tmp/a.out.i64".to_string()),
            Some(600),
        );
        assert_eq!(open_args["timeout_secs"], json!(600));
        assert_eq!(open_args["rebuild"], json!(false));
        assert_eq!(open_args["processor"], json!("arm:ARMv7-M"));
        assert_eq!(open_args["bitness"], json!(32));
        assert_eq!(open_args["base_address"], json!("0x8000000"));
        assert_eq!(open_args["entry_point"], json!("0x8000100"));
        assert_eq!(open_args["_worker_idb_out"], json!("/tmp/a.out.i64"));

        let analyze_args = analyze_funcs_child_args(Some(600), false);
        assert_eq!(analyze_args["timeout_secs"], json!(600));
        assert_eq!(analyze_args["_worker_no_timeout"], json!(false));

        let background_analyze_args = analyze_funcs_child_args(None, true);
        assert!(background_analyze_args["timeout_secs"].is_null());
        assert_eq!(background_analyze_args["_worker_no_timeout"], json!(true));

        let script_args = run_script_child_args("print(1)", Some(30));
        assert_eq!(script_args["timeout_secs"], json!(30));
    }

    #[test]
    fn open_dispatch_tracks_the_effective_output_before_child_dispatch() {
        let dir =
            std::env::temp_dir().join(format!("ida-mcp-open-dispatch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create open dispatch fixture directory");
        let input = dir.join("firmware.bin");
        let output = dir.join("custom.i64");
        std::fs::write(&input, b"raw").expect("write raw input");

        let new_output = OpenDispatch::for_request(
            &input.display().to_string(),
            Some(&output.display().to_string()),
            false,
        );
        assert_eq!(new_output.database_path, output);
        assert!(
            new_output.artifacts.is_some(),
            "a new raw output needs forced-retirement cleanup"
        );

        std::fs::write(&output, b"existing database").expect("write existing output");
        let reuse = OpenDispatch::for_request(
            &input.display().to_string(),
            Some(&output.display().to_string()),
            false,
        );
        assert!(
            reuse.artifacts.is_none(),
            "verified reuse must not claim ownership of existing artifacts"
        );

        std::fs::remove_dir_all(dir).expect("remove open dispatch fixture directory");
    }

    #[test]
    fn pooled_lumina_apply_leaves_timeout_to_parent_watchdog() {
        let args = lumina_apply_child_args(Some(0x401000), Some("target".to_string()), 4, true);

        assert!(args["timeout_secs"].is_null());
        assert_eq!(args["address"], json!("0x401000"));
        assert_eq!(args["target_name"], json!("target"));
        assert_eq!(args["offset"], json!(4));
        assert_eq!(args["force"], json!(true));
    }

    #[test]
    fn pooled_search_child_args_preserve_single_terms_and_internal_limit() {
        let search_args = search_child_args("Hello, world".to_string(), "text", 11000, Some(30));
        assert_eq!(search_args["targets"], json!(["Hello, world"]));
        assert_eq!(search_args["limit"], json!(10000));
        assert_eq!(search_args["_worker_max_results"], json!(11000));

        let bytes_args = find_bytes_child_args("aa,bb".to_string(), 15000, None);
        assert_eq!(bytes_args["patterns"], json!(["aa,bb"]));
        assert_eq!(bytes_args["limit"], json!(10000));
        assert_eq!(bytes_args["_worker_max_results"], json!(15000));
    }

    #[test]
    fn extract_first_matches_preserves_child_pattern_error() {
        let err = extract_first_matches(
            json!({ "results": [{ "pattern": "", "error": "empty pattern" }] }),
            "find_bytes",
        )
        .expect_err("child pattern error must be surfaced");

        assert!(matches!(err, ToolError::IdaError(message) if message == "empty pattern"));
    }

    #[test]
    fn release_retire_decision_keeps_ida_tool_errors_reusable() {
        assert!(!release_error_retires_worker(&ToolError::IdaError(
            "No database is currently open".to_string()
        )));
    }

    #[test]
    fn child_tool_error_retire_decision_is_operation_specific() {
        assert!(!child_tool_error_retires_worker(
            "run_script",
            &ToolError::TimeoutDetailed("run_script timed out after 5 seconds".to_string())
        ));
        assert!(!child_tool_error_retires_worker(
            "run_script",
            &ToolError::Cancelled("run_script cancelled".to_string())
        ));
        for tool in [
            "debug_launch",
            "debug_attach",
            "debug_modules",
            "debug_stop",
        ] {
            assert!(child_tool_error_retires_worker(
                tool,
                &ToolError::Timeout(DEBUG_MODULES_TIMEOUT_SECS)
            ));
            assert!(child_tool_error_retires_worker(
                tool,
                &ToolError::TimeoutDetailed(format!("{tool} timed out"))
            ));
        }
        assert!(!child_tool_error_retires_worker(
            "debug_status",
            &ToolError::Timeout(5)
        ));
        assert!(child_tool_error_retires_worker(
            "run_script",
            &ToolError::WorkerClosed
        ));
    }

    #[test]
    fn release_retire_decision_retires_transport_failures() {
        assert!(release_error_retires_worker(&ToolError::RemoteProtocol(
            "transport closed".to_string()
        )));
        assert!(release_error_retires_worker(&ToolError::Timeout(5)));
        assert!(release_error_retires_worker(&ToolError::WorkerClosed));
        assert!(release_error_retires_worker(&ToolError::DebuggerTeardown(
            "terminal event missing".to_string()
        )));
    }

    #[test]
    fn open_failure_releases_fresh_lease() {
        assert!(open_error_releases_lease(
            true,
            &ToolError::IdaError("A database is already open".to_string())
        ));
    }

    #[test]
    fn open_failure_keeps_existing_lease_for_ida_errors() {
        assert!(!open_error_releases_lease(
            false,
            &ToolError::IdaError("A database is already open".to_string())
        ));
    }

    #[test]
    fn open_failure_releases_existing_lease_for_worker_crash() {
        assert!(open_error_releases_lease(
            false,
            &ToolError::WorkerCrashed {
                worker_id: 7,
                last_op: "open_idb".to_string(),
            }
        ));
    }

    #[tokio::test]
    async fn conditional_close_without_matching_pooled_generation_is_a_noop() {
        let state =
            crate::ida::pool::WorkspaceDatabase::new(test_pool(1), "generation-test".to_string());

        assert_eq!(
            state
                .close_if_generation(DatabaseGeneration(1))
                .await
                .expect("a missing generation should be a successful no-op"),
            ConditionalCloseResult::NotCurrent
        );
    }

    /// The close/reopen redirect: a background task holds the generation it
    /// opened, its session closes and reopens, and the task's next post-open
    /// call must be refused rather than resolved against the new lease.
    ///
    /// Every pooled post-open call resolves its worker through
    /// `required_handle_for_generation`, which applies this decision while
    /// holding the lease lock, so a concurrent close cannot slip between the
    /// check and the dispatch.
    #[test]
    fn post_open_call_is_refused_after_its_lease_is_replaced() {
        let opened = DatabaseGeneration(1);
        let after_reopen = DatabaseGeneration(2);

        // The task's own database: its remaining work proceeds.
        assert!(require_lease_generation(opened, Some(opened)).is_ok());

        // After a close/reopen the lease names a different database; the stale
        // task must be refused instead of silently mutating the new one.
        match require_lease_generation(after_reopen, Some(opened)) {
            Err(ToolError::DatabaseReplaced) => {}
            Err(other) => panic!("expected DatabaseReplaced, got {other}"),
            Ok(()) => panic!("a replaced lease must refuse the stale operation"),
        }

        // The session that owns the new database is unaffected.
        assert!(require_lease_generation(after_reopen, Some(after_reopen)).is_ok());

        // Foreground tools opt out and follow the current lease.
        assert!(require_lease_generation(after_reopen, None).is_ok());
    }

    #[tokio::test]
    async fn bound_call_reports_no_database_rather_than_a_redirect() {
        let state =
            crate::ida::pool::WorkspaceDatabase::new(test_pool(1), "redirect-test".to_string());

        assert!(matches!(
            state
                .required_handle_for_generation(Some(DatabaseGeneration(1)))
                .await,
            Err(ToolError::NoDatabaseOpen)
        ));
    }

    #[test]
    fn open_failure_releases_existing_lease_for_cancellation() {
        assert!(open_error_releases_lease(
            false,
            &ToolError::Cancelled("cancelled open_idb".to_string())
        ));
    }

    #[test]
    fn open_failure_releases_existing_lease_for_closed_worker() {
        assert!(open_error_releases_lease(false, &ToolError::WorkerClosed));
    }

    #[test]
    fn unsettled_open_errors_require_retirement() {
        for error in [
            ToolError::Timeout(5),
            ToolError::TimeoutDetailed("open_idb timed out".to_string()),
            ToolError::Cancelled("open_idb cancelled".to_string()),
            ToolError::WorkerClosed,
        ] {
            assert!(unsettled_open_error_retires_worker(&error));
        }
        assert!(!unsettled_open_error_retires_worker(
            &ToolError::InvalidParams("bad processor".to_string())
        ));
        assert!(!unsettled_open_error_retires_worker(&ToolError::IdaError(
            "unsupported input".to_string()
        )));
    }

    #[tokio::test]
    async fn spawn_reservation_counts_toward_pool_capacity() {
        let pool = test_pool(1);
        let reservation = pool.reserve_spawn_slot().await;

        assert_eq!(pool.live_or_reserved_count().await, 1);
        let err = match pool.lease("session-b").await {
            Ok(_) => panic!("lease should fail while the only slot is reserved"),
            Err(err) => err,
        };
        match err {
            ToolError::PoolExhausted { active, max } => {
                assert_eq!(active, 1);
                assert_eq!(max, 1);
            }
            other => panic!("unexpected lease error: {other}"),
        }

        reservation.finish(None).await;
        assert_eq!(pool.live_or_reserved_count().await, 0);
    }

    #[tokio::test]
    async fn dropped_spawn_reservation_releases_pool_capacity() {
        let pool = test_pool(1);
        let reservation = pool.reserve_spawn_slot().await;
        drop(reservation);

        for _ in 0..10 {
            if pool.live_or_reserved_count().await == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("dropped spawn reservation did not release capacity");
    }
}
