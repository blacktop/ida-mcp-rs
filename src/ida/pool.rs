//! Multi-process worker pool for HTTP sessions.

use crate::error::ToolError;
use crate::ida::observability::ProgressSender;
use crate::ida::remote;
use crate::ida::types::*;
use futures_util::future::join_all;
use rmcp::handler::client::ClientHandler;
use rmcp::model::{CallToolResult, ClientInfo, JsonObject, LoggingMessageNotificationParam};
use rmcp::service::{NotificationContext, Peer, RoleClient, RunningService};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::ServiceExt;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const CHILD_CLOSE_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct WorkerPoolConfig {
    pub max_workers: usize,
    pub min_workers: usize,
    pub worker_idle_timeout: Duration,
    pub worker_op_timeout: Duration,
    pub exe_path: PathBuf,
    pub filter_args: Vec<OsString>,
}

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
}

struct DeadWorker {
    service: Option<RunningService<RoleClient, ParentClientHandler>>,
    pid: Option<u32>,
    age_secs: u64,
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
struct ParentClientHandler {
    worker_id: usize,
}

impl ClientHandler for ParentClientHandler {
    async fn on_logging_message(
        &self,
        params: LoggingMessageNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        debug!(
            target: "ida_mcp::worker",
            worker_id = self.worker_id,
            level = ?params.level,
            logger = ?params.logger,
            data = ?params.data,
            "child worker log"
        );
    }

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

    async fn spawn_slot(
        &self,
        id: usize,
        initial_state: ChildState,
    ) -> Result<Arc<ChildSlot>, ToolError> {
        let mut cmd = tokio::process::Command::new(&self.config.exe_path);
        cmd.args(&self.config.filter_args);
        cmd.arg("worker");
        cmd.kill_on_drop(true);

        let (transport, stderr) = TokioChildProcess::builder(cmd)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                ToolError::RemoteProtocol(format!("failed to spawn worker {id}: {err}"))
            })?;
        let pid = transport.id();
        let stderr_task = spawn_stderr_relay(id, stderr);
        let handler = ParentClientHandler { worker_id: id };
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
            }),
            call_lock: Mutex::new(()),
        }))
    }

    pub async fn release(&self, handle: PooledWorkerHandle) -> Result<(), ToolError> {
        let result = self.release_inner(&handle).await;
        self.schedule_idle_reap(handle.slot.clone());
        result
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
        let close = tokio::time::timeout(
            Duration::from_secs(CHILD_CLOSE_TIMEOUT_SECS),
            remote::call_tool(&peer, "close_idb", args),
        )
        .await;

        let close_error = match close {
            Ok(Ok(result)) if result.is_error != Some(true) => None,
            Ok(Ok(result)) => remote::result_text(&result, "close_idb").err(),
            Ok(Err(err)) => Some(err),
            Err(_) => Some(ToolError::Timeout(CHILD_CLOSE_TIMEOUT_SECS)),
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
                "child close_idb reported an error during release"
            );
            return Err(err);
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
        let dead = self.take_dead_worker(slot).await;
        self.forget_slot(slot.id).await;
        if let Some(dead) = dead {
            Self::finish_dead_worker(slot.id, dead).await;
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
        child.idb_path = None;
        let pid = child.pid;
        let age_secs = child.spawned_at.elapsed().as_secs();
        let service = child.service.take();
        child.stderr_task.abort();
        DeadWorker {
            service,
            pid,
            age_secs,
        }
    }

    async fn finish_dead_worker(worker_id: usize, mut dead: DeadWorker) {
        if let Some(mut service) = dead.service.take() {
            let _ = service
                .close_with_timeout(Duration::from_secs(CHILD_CLOSE_TIMEOUT_SECS))
                .await;
        }
        warn!(
            worker_id,
            ?dead.pid,
            age_secs = dead.age_secs,
            "marked IDA child worker dead"
        );
    }

    pub async fn shutdown_all(&self) {
        let slots = {
            let inner = self.inner.lock().await;
            inner.children.clone()
        };
        join_all(slots.into_iter().map(|slot| {
            let pool = self.clone();
            async move {
                pool.mark_dead(&slot).await;
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

    fn worker_op_timeout(&self, requested: Option<u64>) -> Duration {
        let configured = self.config.worker_op_timeout;
        requested
            .map(Duration::from_secs)
            .map(|requested| requested.min(configured))
            .unwrap_or(configured)
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
    ) -> Result<CallToolResult, ToolError> {
        let _call_guard = self.slot.call_lock.lock().await;
        let peer = {
            let child = self.slot.child.lock().await;
            match &child.state {
                ChildState::Leased { session_id } if session_id == &self.session_id => {
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

pub struct PooledSessionState {
    pool: WorkerPool,
    session_id: String,
    handle: Arc<Mutex<Option<PooledWorkerHandle>>>,
    runtime: Option<Handle>,
}

impl PooledSessionState {
    pub fn new(pool: WorkerPool, session_id: String) -> Self {
        Self {
            pool,
            session_id,
            handle: Arc::new(Mutex::new(None)),
            runtime: Handle::try_current().ok(),
        }
    }

    async fn lease_for_open(&self) -> Result<(PooledWorkerHandle, bool), ToolError> {
        let mut guard = self.handle.lock().await;
        if let Some(handle) = guard.as_ref() {
            return Ok((handle.clone(), false));
        }
        let handle = self.pool.lease(&self.session_id).await?;
        *guard = Some(handle.clone());
        Ok((handle, true))
    }

    async fn required_handle(&self) -> Result<PooledWorkerHandle, ToolError> {
        let guard = self.handle.lock().await;
        guard.as_ref().cloned().ok_or(ToolError::NoDatabaseOpen)
    }

    async fn take_handle(&self) -> Option<PooledWorkerHandle> {
        self.handle.lock().await.take()
    }

    async fn release_current_handle(&self) {
        if let Some(handle) = self.take_handle().await {
            let _ = self.pool.release(handle).await;
        }
    }

    async fn clear_handle_if_worker(&self, worker_id: usize) {
        let mut guard = self.handle.lock().await;
        if guard
            .as_ref()
            .is_some_and(|handle| handle.worker_id == worker_id)
        {
            *guard = None;
        }
    }

    async fn call_result(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<CallToolResult, ToolError> {
        let handle = self.required_handle().await?;
        let timeout = self.pool.worker_op_timeout(timeout_secs);
        match handle
            .call_tool(tool, remote::json_object(args)?, timeout, cancel)
            .await
        {
            Ok(result) => Ok(result),
            Err(err) => {
                self.clear_handle_if_worker(handle.worker_id).await;
                Err(err)
            }
        }
    }

    async fn call_json<T: DeserializeOwned>(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<T, ToolError> {
        let result = self.call_result(tool, args, timeout_secs, cancel).await?;
        remote::parse_json(result, tool)
    }

    async fn call_value(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        let result = self.call_result(tool, args, timeout_secs, cancel).await?;
        remote::parse_value(result, tool)
    }

    async fn call_text(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<String, ToolError> {
        let result = self.call_result(tool, args, timeout_secs, cancel).await?;
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
        file_type: Option<String>,
        auto_analyse: bool,
        extra_args: Vec<String>,
        _progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<DbInfo, ToolError> {
        let (handle, fresh_lease) = self.lease_for_open().await?;
        let timeout = self.pool.worker_op_timeout(None);
        let result = handle
            .call_tool(
                "open_idb",
                remote::json_object(json!({
                    "path": path,
                    "load_debug_info": load_debug_info,
                    "debug_info_path": debug_info_path,
                    "debug_info_verbose": debug_info_verbose,
                    "force": force,
                    "file_type": file_type,
                    "auto_analyse": auto_analyse,
                    "extra_args": extra_args,
                }))?,
                timeout,
                cancel,
            )
            .await;

        match result.and_then(|result| remote::parse_json::<DbInfo>(result, "open_idb")) {
            Ok(info) => {
                let mut child = handle.slot.child.lock().await;
                child.idb_path = Some(PathBuf::from(&info.path));
                Ok(info)
            }
            Err(err) => {
                if open_error_releases_lease(fresh_lease, &err) {
                    self.release_current_handle().await;
                }
                Err(err)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        &self,
        path: &str,
        load_debug_info: bool,
        debug_info_path: Option<String>,
        debug_info_verbose: bool,
        force: bool,
        file_type: Option<String>,
        auto_analyse: bool,
        extra_args: Vec<String>,
    ) -> Result<DbInfo, ToolError> {
        self.open_observed(
            path,
            load_debug_info,
            debug_info_path,
            debug_info_verbose,
            force,
            file_type,
            auto_analyse,
            extra_args,
            None,
            None,
        )
        .await
    }

    pub async fn close(&self) -> Result<(), ToolError> {
        let Some(handle) = self.take_handle().await else {
            return Err(ToolError::NoDatabaseOpen);
        };
        self.pool.release(handle).await
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

    pub async fn analysis_status(&self) -> Result<AnalysisStatus, ToolError> {
        self.call_json("analysis_status", json!({}), None, None)
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

    pub async fn xrefs_to(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
        self.call_json(
            "xrefs_to",
            json!({ "address": remote::hex_addr(addr) }),
            None,
            None,
        )
        .await
    }

    pub async fn xrefs_from(&self, addr: u64) -> Result<Vec<XRefInfo>, ToolError> {
        self.call_json(
            "xrefs_from",
            json!({ "address": remote::hex_addr(addr) }),
            None,
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
    ) -> Result<Value, ToolError> {
        self.call_value(
            "analyze_funcs",
            json!({ "background": false }),
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
                json!({ "patterns": pattern, "limit": max_results, "offset": 0, "timeout_secs": timeout_secs }),
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
                json!({ "targets": target, "kind": kind, "limit": max_results, "offset": 0, "timeout_secs": timeout_secs }),
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
                )))
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
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Value, ToolError> {
        self.call_value(
            "callgraph",
            json!({ "roots": remote::hex_addr(addr), "max_depth": max_depth, "max_nodes": max_nodes }),
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
    ) -> Result<Value, ToolError> {
        self.call_value("run_script", json!({ "code": code }), None, cancel)
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

impl Drop for PooledSessionState {
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
            let Some(handle) = handle_slot.lock().await.take() else {
                return;
            };
            let _ = pool.release(handle).await;
        });
    }
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

    let matches = results
        .first()
        .and_then(|first| first.get("matches"))
        .cloned()
        .ok_or_else(|| {
            ToolError::RemoteProtocol(format!(
                "{tool} response did not include results[0].matches"
            ))
        })?;
    Ok(json!({ "matches": matches }))
}

fn release_error_retires_worker(err: &ToolError) -> bool {
    matches!(
        err,
        ToolError::Timeout(_)
            | ToolError::TimeoutDetailed(_)
            | ToolError::Cancelled(_)
            | ToolError::WorkerCrashed { .. }
            | ToolError::RemoteProtocol(_)
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

fn spawn_stderr_relay(
    worker_id: usize,
    stderr: Option<tokio::process::ChildStderr>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Some(stderr) = stderr else {
            return;
        };
        let mut lines = BufReader::new(stderr).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    debug!(target: "ida_mcp::worker_stderr", worker_id, %line);
                }
                Ok(None) => break,
                Err(err) => {
                    warn!(worker_id, error = %err, "failed to read child stderr");
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::pool::{
        open_error_releases_lease, release_error_retires_worker, WorkerPool, WorkerPoolConfig,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_pool(max_workers: usize) -> WorkerPool {
        WorkerPool::new(WorkerPoolConfig {
            max_workers,
            min_workers: 0,
            worker_idle_timeout: Duration::from_secs(300),
            worker_op_timeout: Duration::from_secs(600),
            exe_path: PathBuf::from("/does/not/spawn/in/this/test"),
            filter_args: Vec::new(),
        })
    }

    #[test]
    fn release_retire_decision_keeps_ida_tool_errors_reusable() {
        assert!(!release_error_retires_worker(&ToolError::IdaError(
            "No database is currently open".to_string()
        )));
    }

    #[test]
    fn release_retire_decision_retires_transport_failures() {
        assert!(release_error_retires_worker(&ToolError::RemoteProtocol(
            "transport closed".to_string()
        )));
        assert!(release_error_retires_worker(&ToolError::Timeout(5)));
        assert!(release_error_retires_worker(&ToolError::WorkerClosed));
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
