//! Subprocess tests for the supervisor; these fake workers do not load IDA.

use crate::error::ToolError;
use crate::ida::pool::{
    ChildState, DispatchProgress, OpenDispatch, WorkerPool, WorkerPoolConfig, WorkspaceDatabase,
};
use crate::ida::types::ConditionalCloseResult;
use crate::ida::worker::CloseAuthorization;
use rmcp::model::JsonObject;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("ida-mcp-startup-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create private fixture");
        Self { directory }
    }

    fn ready(&self) {
        std::fs::write(self.directory.join("ready"), b"").expect("release handshake");
    }

    fn pool(&self, startup_timeout: Duration) -> WorkerPool {
        // Record the PID only after receiving initialize. Withhold its response
        // until the test releases it, then behave like an idle MCP server.
        let script = r#"
IFS= read -r request || exit 1
printf '%s\n' "$$" > "$1/pid"
while [ ! -e "$1/ready" ]; do sleep 0.05; done
id=$(printf '%s\n' "$request" | sed -n 's/.*"id":\([^,}]*\).*/\1/p')
printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"startup-test","version":"1"}}}\n' "$id"
while IFS= read -r request; do
    case "$request" in
        *'"method":"tools/call"'*)
            printf '%s\n' "$request" >> "$1/requests"
            case "$request" in *'"name":"stall"'*) continue;; esac
            case "$request" in *'"name":"delay"'*) while [ ! -e "$1/release-call" ]; do sleep 0.05; done;; esac
            id=$(printf '%s\n' "$request" | sed -n 's/.*"id":\([^,}]*\).*/\1/p')
            printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[],"isError":false}}\n' "$id"
            ;;
    esac
done
"#;
        let mut pool = WorkerPool::new(WorkerPoolConfig {
            max_workers: 1,
            min_workers: 1,
            worker_idle_timeout: Duration::ZERO,
            worker_op_timeout: Duration::from_secs(60),
            exe_path: PathBuf::from("/bin/sh"),
            worker_args: vec![
                "-c".into(),
                script.into(),
                "startup-test".into(),
                self.directory.clone().into_os_string(),
            ],
        });
        pool.startup_timeout = startup_timeout;
        pool
    }

    async fn pid(&self) -> i32 {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(contents) = std::fs::read_to_string(self.directory.join("pid"))
                    && let Ok(pid) = contents.trim().parse::<i32>()
                {
                    assert!(pid > 0);
                    return pid;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fake worker received initialize")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn assert_process_exited(pid: i32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // SAFETY: pid is positive and signal 0 only queries process
            // existence; no memory or process state is modified.
            if unsafe { libc::kill(pid, 0) } != 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker process exited and was reaped");
}

#[tokio::test]
async fn implicit_close_ownership_cannot_outlive_its_database_generation() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let database = WorkspaceDatabase::new_shared_http(pool.clone());
    let (_, first, _) = database.lease_for_open().await.expect("first lease");
    let original = database
        .issue_close_token("owner-a", first)
        .await
        .expect("current generation")
        .expect("first owner");
    let denied = database.close_authorized("other", None, false).await;
    let Ok(CloseAuthorization::Denied { .. }) = denied else {
        panic!("non-owner close must be denied: {denied:?}");
    };
    database
        .close_if_generation(first)
        .await
        .expect("close first");
    let (_, second, _) = database.lease_for_open().await.expect("second lease");
    let replacement = database
        .issue_close_token("owner-b", second)
        .await
        .expect("current generation")
        .expect("replacement owner");
    assert_ne!(original.token, replacement.token);
    assert!(database.issue_close_token("owner-a", first).await.is_none());
    assert_eq!(
        database
            .close_if_generation(first)
            .await
            .expect("stale cleanup"),
        ConditionalCloseResult::NotCurrent
    );
    let stale = database
        .close_authorized("owner-a", Some(&original.token), false)
        .await;
    let Ok(CloseAuthorization::Denied { .. }) = stale else {
        panic!("stale token must be denied: {stale:?}");
    };
    let current = database.close_authorized("owner-b", None, false).await;
    let Ok(CloseAuthorization::Granted) = current else {
        panic!("current owner must close: {current:?}");
    };
    pool.shutdown_all().await;
}

#[tokio::test]
async fn stale_handle_cannot_reach_a_replacement_database_in_the_same_worker() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let database = WorkspaceDatabase::new_shared_http(pool.clone());
    let (original, first, _) = database.lease_for_open().await.expect("first lease");
    database
        .close_if_generation(first)
        .await
        .expect("close first");
    let (replacement, second, _) = database.lease_for_open().await.expect("replacement lease");
    assert_eq!(original.worker_id, replacement.worker_id);
    let requests = std::fs::read_to_string(fixture.directory.join("requests"))
        .expect("first close reached the worker");

    let result = original
        .call_tool(
            "stale_call",
            JsonObject::new(),
            Duration::from_secs(1),
            None,
            None,
            None,
        )
        .await;
    let Err(ToolError::DatabaseReplaced) = result else {
        panic!("stale lease must report replacement: {result:?}");
    };
    pool.release(original.clone()).await.expect("stale release");
    pool.mark_dead_for_lease(&original.slot, original.lease_id)
        .await;
    database
        .clear_handle_if_lease(original.worker_id, first)
        .await;
    assert_eq!(
        std::fs::read_to_string(fixture.directory.join("requests")).expect("worker requests"),
        requests,
        "stale work must not send an RPC to the replacement"
    );
    database
        .required_handle_for_generation(Some(second))
        .await
        .expect("replacement binding survives stale cleanup");
    replacement
        .call_tool(
            "replacement_call",
            JsonObject::new(),
            Duration::from_secs(1),
            None,
            None,
            None,
        )
        .await
        .expect("replacement remains usable");
    database.close().await.expect("close replacement");
    pool.shutdown_all().await;
}

#[tokio::test]
async fn immediate_reopen_waits_for_the_replacement_then_leases_it() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let first = pool.lease("first").await.expect("initial lease");
    let first_pid = fixture.pid().await;
    std::fs::remove_file(fixture.directory.join("ready")).expect("hold replacement handshake");
    std::fs::remove_file(fixture.directory.join("pid")).expect("clear initial PID");

    pool.mark_dead(&first.slot).await;
    let reopen = pool.lease("immediate-reopen");
    tokio::pin!(reopen);
    assert!(
        futures_util::poll!(reopen.as_mut()).is_pending(),
        "a starting replacement must not be reported as a leased worker"
    );
    assert_eq!(pool.live_or_reserved_count().await, 1);
    let replacement_pid = fixture.pid().await;
    assert_ne!(replacement_pid, first_pid);
    fixture.ready();
    let reopened = tokio::time::timeout(Duration::from_secs(2), &mut reopen)
        .await
        .expect("ready replacement wakes acquisition")
        .expect("immediate reopen succeeds without retrying");
    assert_eq!(
        reopened.slot.child.lock().await.pid,
        u32::try_from(replacement_pid).ok()
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(100), pool.lease("actually-full"))
            .await
            .expect("real exhaustion is prompt"),
        Err(ToolError::PoolExhausted { active: 1, max: 1 })
    ));
    pool.shutdown_all().await;
    assert_process_exited(first_pid).await;
    assert_process_exited(replacement_pid).await;
}

#[tokio::test]
async fn timed_out_replacement_releases_capacity_and_a_later_lease_recovers() {
    let fixture = Fixture::new();
    let pool = fixture.pool(Duration::from_secs(1));
    tokio::time::timeout(Duration::from_secs(1), pool.schedule_replenishment())
        .await
        .expect("retirement does not wait for replacement initialization");
    let first_pid = fixture.pid().await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while pool.live_or_reserved_count().await != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out startup releases its reservation");
    assert_process_exited(first_pid).await;

    fixture.ready();
    let handle = pool.lease("retry").await.expect("later startup succeeds");
    let second_pid = fixture.pid().await;
    assert_ne!(first_pid, second_pid);
    assert_eq!(pool.live_or_reserved_count().await, 1);
    drop(handle);
    pool.shutdown_all().await;
    assert_process_exited(second_pid).await;
}

#[tokio::test]
async fn shutdown_cancels_and_joins_a_stalled_replacement() {
    let fixture = Fixture::new();
    let pool = fixture.pool(Duration::from_secs(60));
    pool.schedule_replenishment().await;
    let pid = fixture.pid().await;
    let waiting_lease = pool.lease("waiting-during-shutdown");
    tokio::pin!(waiting_lease);
    assert!(futures_util::poll!(waiting_lease.as_mut()).is_pending());
    tokio::time::timeout(Duration::from_secs(2), pool.shutdown_all())
        .await
        .expect("shutdown cancels startup instead of waiting for its deadline");
    assert!(matches!(waiting_lease.await, Err(ToolError::WorkerClosed)));
    assert_process_exited(pid).await;
    fixture.ready();
    pool.schedule_replenishment().await;
    assert_eq!(pool.live_or_reserved_count().await, 0);
    assert!(matches!(
        pool.lease("closed").await,
        Err(ToolError::WorkerClosed)
    ));
    assert!(matches!(
        pool.warm_min().await,
        Err(ToolError::WorkerClosed)
    ));
}

#[tokio::test]
async fn failed_startup_wakes_acquisition_to_use_the_freed_capacity() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let failed_startup = pool.reserve_spawn_slot().await.expect("reserve worker");
    let lease = pool.lease("waiting-for-startup");
    tokio::pin!(lease);
    assert!(futures_util::poll!(lease.as_mut()).is_pending());
    failed_startup
        .finish(None)
        .await
        .expect("failed startup releases its reservation");
    let handle = tokio::time::timeout(Duration::from_secs(2), &mut lease)
        .await
        .expect("failure wakes acquisition")
        .expect("acquisition starts a fresh worker");
    let pid = fixture.pid().await;
    assert_eq!(handle.slot.child.lock().await.pid, u32::try_from(pid).ok());
    pool.shutdown_all().await;
    assert_process_exited(pid).await;
}

#[tokio::test]
async fn acquisition_timeout_cleans_up_its_own_stalled_startup() {
    let fixture = Fixture::new();
    let pool = fixture.pool(Duration::from_millis(200));
    let leasing_pool = pool.clone();
    let lease = tokio::spawn(async move { leasing_pool.lease("stalled-startup").await });
    let pid = fixture.pid().await;
    let result = tokio::time::timeout(Duration::from_secs(1), lease)
        .await
        .expect("acquisition has a deadline")
        .expect("acquisition task succeeds");
    assert!(matches!(
        result,
        Err(ToolError::NeverDispatched(_) | ToolError::RemoteProtocol(_))
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        while pool.live_or_reserved_count().await != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out acquisition releases its reservation");
    assert_process_exited(pid).await;
    pool.shutdown_all().await;
}

#[tokio::test]
async fn shutdown_rejects_a_worker_that_finished_handshaking_before_installation() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let reservation = pool.reserve_spawn_slot().await.expect("reserve worker");
    let slot = pool
        .spawn_slot(reservation.worker_id(), ChildState::Idle)
        .await
        .expect("worker handshake completes");
    let pid = fixture.pid().await;

    let shutdown_pool = pool.clone();
    let shutdown = tokio::spawn(async move { shutdown_pool.shutdown_all().await });
    pool.shutdown.cancelled().await;
    assert!(
        !shutdown.is_finished(),
        "shutdown waits for pending installation"
    );
    assert!(matches!(
        reservation.finish(Some(slot)).await,
        Err(ToolError::WorkerClosed)
    ));
    tokio::time::timeout(Duration::from_secs(7), shutdown)
        .await
        .expect("shutdown finishes")
        .expect("shutdown task succeeds");
    assert_eq!(pool.live_or_reserved_count().await, 0);
    assert_process_exited(pid).await;
}

#[tokio::test]
async fn cancellation_and_deadline_before_dispatch_preserve_the_worker() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let handle = pool.lease("healthy").await.expect("lease worker");
    let pid = fixture.pid().await;
    let original_path = fixture.directory.join("original.i64");
    let mut child = handle.slot.child.lock().await;
    child.idb_path = Some(original_path.clone());

    for cancelled in [true, false] {
        let cancel = CancellationToken::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let call = handle.call_tool(
            "open_idb",
            JsonObject::new(),
            if cancelled {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(25)
            },
            Some(cancel.clone()),
            Some(OpenDispatch {
                database_path: fixture.directory.join("never-opened.i64"),
                artifacts: None,
            }),
            Some(DispatchProgress::new(tx, "opening", "test dispatch")),
        );
        tokio::pin!(call);
        assert!(futures_util::poll!(call.as_mut()).is_pending());
        assert!(
            handle.slot.call_lock.try_lock().is_err(),
            "the request owns the call lock but has not acquired child state"
        );
        if cancelled {
            cancel.cancel();
        }
        let result = tokio::time::timeout(Duration::from_secs(1), &mut call)
            .await
            .expect("admission stays cancellable and bounded while child state is locked");
        assert!(matches!(result, Err(ToolError::NeverDispatched(_))));
        assert!(rx.try_recv().is_err(), "never advertised as dispatched");
        assert_eq!(child.idb_path.as_ref(), Some(&original_path));
        assert!(child.pending_open_artifacts.is_none());
        assert!(matches!(child.state, ChildState::Leased { .. }));
        assert!(!fixture.directory.join("requests").exists());
    }
    drop(child);

    handle
        .call_tool(
            "probe",
            JsonObject::new(),
            Duration::from_secs(1),
            None,
            None,
            None,
        )
        .await
        .expect("the original worker still serves requests");
    assert_eq!(fixture.pid().await, pid);
    pool.shutdown_all().await;
    assert_process_exited(pid).await;
}

#[tokio::test]
async fn cancellation_after_dispatch_retires_the_worker() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let handle = pool.lease("dispatched").await.expect("lease worker");
    let pid = fixture.pid().await;
    let cancel = CancellationToken::new();
    let call_cancel = cancel.clone();
    let call = tokio::spawn(async move {
        handle
            .call_tool(
                "stall",
                JsonObject::new(),
                Duration::from_secs(30),
                Some(call_cancel),
                None,
                None,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !fixture.directory.join("requests").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("child received the request");
    cancel.cancel();
    let result = tokio::time::timeout(Duration::from_secs(7), call)
        .await
        .expect("retirement returns")
        .expect("call task succeeds");
    assert!(matches!(result, Err(ToolError::WorkerRetired(_))));
    assert_process_exited(pid).await;
    pool.shutdown_all().await;
}

#[tokio::test]
async fn shared_call_survives_cancelled_and_dropped_waiters() {
    for drop_waiter in [false, true] {
        let fixture = Fixture::new();
        fixture.ready();
        let pool = fixture.pool(Duration::from_secs(3));
        let database = WorkspaceDatabase::new_shared_http(pool.clone());
        let (handle, _, _) = database.lease_for_open().await.expect("shared lease");
        let pid = fixture.pid().await;
        let cancel = CancellationToken::new();
        let call_cancel = cancel.clone();
        let caller = handle.clone();
        let call = tokio::spawn(async move {
            caller
                .call_tool(
                    "delay",
                    JsonObject::new(),
                    Duration::from_secs(3),
                    Some(call_cancel),
                    None,
                    None,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !fixture.directory.join("requests").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("child received the request");
        cancel.cancel();
        if drop_waiter {
            call.abort();
            assert!(call.await.expect_err("waiter was aborted").is_cancelled());
        } else {
            assert!(
                !call.is_finished(),
                "background cancellation waits for settlement"
            );
            std::fs::write(fixture.directory.join("release-call"), b"")
                .expect("finish native call");
            call.await
                .expect("waiter joined")
                .expect("native result survived cancellation");
        }
        std::fs::write(fixture.directory.join("release-call"), b"").expect("finish native call");
        handle
            .call_tool(
                "probe",
                JsonObject::new(),
                Duration::from_secs(2),
                None,
                None,
                None,
            )
            .await
            .expect("the shared worker survived");
        assert_eq!(fixture.pid().await, pid);
        pool.shutdown_all().await;
        assert_process_exited(pid).await;
    }
}

#[tokio::test]
async fn abandoned_shared_call_keeps_its_watchdog_and_can_reopen() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let database = WorkspaceDatabase::new_shared_http(pool.clone());
    let (handle, generation, _) = database.lease_for_open().await.expect("shared lease");
    let pid = fixture.pid().await;
    let call = tokio::spawn(async move {
        handle
            .call_tool(
                "stall",
                JsonObject::new(),
                Duration::from_millis(250),
                None,
                None,
                None,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !fixture.directory.join("requests").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("child received the request");
    call.abort();
    assert!(call.await.expect_err("waiter was aborted").is_cancelled());
    assert_process_exited(pid).await;
    let (_, replacement, fresh) = database
        .lease_for_open()
        .await
        .expect("reopen after watchdog");
    assert!(fresh);
    assert_ne!(generation, replacement);
    pool.shutdown_all().await;
}

#[tokio::test]
async fn shutdown_rejects_queued_calls_without_unbinding_the_database() {
    let fixture = Fixture::new();
    fixture.ready();
    let pool = fixture.pool(Duration::from_secs(3));
    let database = std::sync::Arc::new(WorkspaceDatabase::new_shared_http(pool.clone()));
    let (handle, generation, _) = database.lease_for_open().await.expect("shared lease");
    let busy = handle.slot.call_lock.lock().await;
    let caller = database.clone();
    let call = tokio::spawn(async move {
        caller
            .call_result_for_generation(
                "probe",
                serde_json::json!({}),
                None,
                None,
                Some(generation),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while handle.slot.queued.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("request queued");
    pool.begin_shutdown().await;
    let result = call.await.expect("queued call joined");
    let Err(ToolError::NeverDispatched(_)) = result else {
        panic!("shutdown must reject undispatched work: {result:?}");
    };
    database
        .required_handle_for_generation(Some(generation))
        .await
        .expect("database remains available for saving");
    drop(busy);
    database.close().await.expect("save during shutdown");
    pool.shutdown_all().await;
}
