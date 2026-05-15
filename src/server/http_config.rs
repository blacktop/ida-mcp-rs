//! Builds the rmcp Streamable HTTP transport configuration.

use futures_util::Stream;
use rmcp::model::ClientJsonRpcMessage;
use rmcp::transport::streamable_http_server::session::{
    local::{LocalSessionManager, LocalSessionManagerError},
    RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
};
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct HttpServerOptions {
    /// SSE keep-alive interval in seconds; `0` disables.
    pub sse_keep_alive_secs: u64,
    /// Run in stateless mode (POST only, no sessions).
    pub stateless: bool,
    /// Return `application/json` instead of SSE in stateless mode.
    pub json_response: bool,
}

fn session_manager_with_keep_alive(session_keep_alive_secs: u64) -> LocalSessionManager {
    let mut manager = LocalSessionManager::default();
    manager.session_config.keep_alive = if session_keep_alive_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(session_keep_alive_secs))
    };
    manager
}

/// Build an `Arc<LocalSessionManager>` with a session-inactivity timeout.
///
/// rmcp defaults to 5 minutes, which is too short for long-running IDA
/// analyses; when the timeout fires mid-call the session is killed and the
/// client's `Mcp-Session-Id` becomes invalid (issue #19).
///
/// `0` disables the timeout. rmcp's own docs warn this can leak zombie
/// sessions when HTTP connections drop silently (e.g. HTTP/2 `RST_STREAM`),
/// so prefer a generous positive value over disabling.
pub fn build_session_manager(session_keep_alive_secs: u64) -> Arc<LocalSessionManager> {
    Arc::new(session_manager_with_keep_alive(session_keep_alive_secs))
}

/// Build a pooled-mode session manager that closes abandoned HTTP sessions when
/// the client drops its standalone SSE stream without sending an explicit HTTP
/// DELETE. POST-only clients fall back to the session keep-alive timeout.
pub fn build_pooled_session_manager(
    session_keep_alive_secs: u64,
    disconnect_grace: Duration,
) -> Arc<PooledSessionManager> {
    let inner = Arc::new(session_manager_with_keep_alive(session_keep_alive_secs));
    Arc::new(PooledSessionManager::new(inner, disconnect_grace))
}

#[derive(Debug, Clone)]
pub struct PooledSessionManager {
    inner: Arc<LocalSessionManager>,
    disconnects: Arc<SessionDisconnectRegistry>,
}

impl PooledSessionManager {
    fn new(inner: Arc<LocalSessionManager>, disconnect_grace: Duration) -> Self {
        Self {
            inner: inner.clone(),
            disconnects: Arc::new(SessionDisconnectRegistry::new(inner, disconnect_grace)),
        }
    }
}

impl SessionManager for PooledSessionManager {
    type Error = LocalSessionManagerError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        self.inner.create_session().await
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<rmcp::model::ServerJsonRpcMessage, Self::Error> {
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.close_session(id).await?;
        self.disconnects.session_closed(id);
        Ok(())
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let stream = self.inner.create_stream(id, message).await?;
        let guard = self.disconnects.stream_opened(id);
        // A dropped POST response stream is not sufficient proof that the
        // session is gone; POST-only clients rely on the keep-alive timeout as
        // their final cleanup safety net.
        Ok(TrackedSessionStream::new(stream, guard, false))
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let stream = self.inner.create_standalone_stream(id).await?;
        let guard = self.disconnects.stream_opened(id);
        Ok(TrackedSessionStream::new(stream, guard, true))
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        // rmcp 1.7 local::EventId formats request-scoped streams as
        // "<index>/<request_id>" and standalone streams as "<index>".
        let close_on_drop = !last_event_id.contains('/');
        let stream = self.inner.resume(id, last_event_id).await?;
        let guard = self.disconnects.stream_opened(id);
        Ok(TrackedSessionStream::new(stream, guard, close_on_drop))
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        self.inner.restore_session(id).await
    }
}

#[derive(Debug)]
struct SessionDisconnectRegistry {
    inner: Arc<LocalSessionManager>,
    disconnect_grace: Duration,
    states: Mutex<HashMap<SessionId, SessionDisconnectState>>,
}

#[derive(Debug, Default)]
struct SessionDisconnectState {
    generation: u64,
    active_streams: usize,
    abandoned_generation: Option<u64>,
}

impl SessionDisconnectRegistry {
    fn new(inner: Arc<LocalSessionManager>, disconnect_grace: Duration) -> Self {
        Self {
            inner,
            disconnect_grace,
            states: Mutex::new(HashMap::new()),
        }
    }

    fn stream_opened(self: &Arc<Self>, session_id: &SessionId) -> SessionStreamGuard {
        let generation = match self.states.lock() {
            Ok(mut states) => {
                let state = states.entry(session_id.clone()).or_default();
                state.generation = state.generation.wrapping_add(1);
                state.active_streams = state.active_streams.saturating_add(1);
                state.abandoned_generation = None;
                state.generation
            }
            Err(err) => {
                tracing::warn!(error = %err, "pooled session disconnect state is poisoned");
                0
            }
        };
        SessionStreamGuard {
            registry: self.clone(),
            session_id: session_id.clone(),
            generation,
        }
    }

    fn session_closed(&self, session_id: &SessionId) {
        match self.states.lock() {
            Ok(mut states) => {
                states.remove(session_id);
            }
            Err(err) => {
                tracing::warn!(error = %err, "pooled session disconnect state is poisoned");
            }
        }
    }

    fn stream_closed(self: Arc<Self>, session_id: SessionId, generation: u64, abandoned: bool) {
        let close_generation = match self.states.lock() {
            Ok(mut states) => {
                let Some(state) = states.get_mut(&session_id) else {
                    return;
                };
                state.active_streams = state.active_streams.saturating_sub(1);
                if abandoned {
                    state.abandoned_generation = Some(generation);
                }
                if state.active_streams == 0 {
                    state.abandoned_generation
                } else {
                    None
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "pooled session disconnect state is poisoned");
                None
            }
        };
        let Some(close_generation) = close_generation else {
            return;
        };

        tokio::spawn(async move {
            if !self.disconnect_grace.is_zero() {
                tokio::time::sleep(self.disconnect_grace).await;
            }
            if !self.should_close(&session_id, close_generation) {
                return;
            }
            tracing::info!(
                session_id = session_id.as_ref(),
                "closing pooled HTTP session after client stream disconnect"
            );
            match self.inner.close_session(&session_id).await {
                Ok(()) => self.session_closed(&session_id),
                Err(err) => {
                    tracing::warn!(
                        session_id = session_id.as_ref(),
                        error = %err,
                        "failed to close pooled HTTP session after client stream disconnect"
                    );
                }
            }
        });
    }

    fn should_close(&self, session_id: &SessionId, generation: u64) -> bool {
        match self.states.lock() {
            Ok(states) => states.get(session_id).is_some_and(|state| {
                state.abandoned_generation == Some(generation) && state.active_streams == 0
            }),
            Err(err) => {
                tracing::warn!(error = %err, "pooled session disconnect state is poisoned");
                false
            }
        }
    }
}

struct SessionStreamGuard {
    registry: Arc<SessionDisconnectRegistry>,
    session_id: SessionId,
    generation: u64,
}

impl SessionStreamGuard {
    fn finish(self, abandoned: bool) {
        self.registry
            .stream_closed(self.session_id, self.generation, abandoned);
    }
}

struct TrackedSessionStream<S> {
    inner: Pin<Box<S>>,
    guard: Option<SessionStreamGuard>,
    close_on_drop: bool,
}

impl<S> TrackedSessionStream<S> {
    fn new(stream: S, guard: SessionStreamGuard, close_on_drop: bool) -> Self {
        Self {
            inner: Box::pin(stream),
            guard: Some(guard),
            close_on_drop,
        }
    }

    fn finish(&mut self, abandoned: bool) {
        if let Some(guard) = self.guard.take() {
            guard.finish(abandoned);
        }
    }
}

impl<S> Unpin for TrackedSessionStream<S> {}

impl<S> Stream for TrackedSessionStream<S>
where
    S: Stream<Item = ServerSseMessage>,
{
    type Item = ServerSseMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(None) => {
                this.finish(false);
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

impl<S> Drop for TrackedSessionStream<S> {
    fn drop(&mut self) {
        self.finish(self.close_on_drop);
    }
}

pub fn build_streamable_config(
    opts: HttpServerOptions,
    cancel: CancellationToken,
) -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_sse_keep_alive(if opts.sse_keep_alive_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(opts.sse_keep_alive_secs))
        })
        .with_sse_retry(None)
        .with_stateful_mode(!opts.stateless)
        .with_json_response(opts.json_response && opts.stateless)
        .with_cancellation_token(cancel)
        // Host validation is handled by HttpAccessService so the CLI can apply
        // bind-aware LAN rules and return actionable 403 messages.
        .with_allowed_hosts(Vec::<String>::new())
}

#[cfg(test)]
mod tests {
    use crate::server::http_config::{
        build_session_manager, build_streamable_config, HttpServerOptions,
        SessionDisconnectRegistry,
    };
    use rmcp::transport::streamable_http_server::session::{local::LocalSessionManager, SessionId};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    fn opts() -> HttpServerOptions {
        HttpServerOptions {
            sse_keep_alive_secs: 15,
            stateless: false,
            json_response: false,
        }
    }

    #[test]
    fn rmcp_host_check_is_disabled_for_outer_access_policy() {
        let config = build_streamable_config(opts(), CancellationToken::new());
        assert!(
            config.allowed_hosts.is_empty(),
            "HttpAccessService owns Host validation so rmcp's duplicate check stays disabled"
        );
    }

    #[test]
    fn json_response_only_enabled_in_stateless_mode() {
        let mut opts = opts();
        opts.json_response = true;

        let stateful = build_streamable_config(opts.clone(), CancellationToken::new());
        assert!(!stateful.json_response);

        opts.stateless = true;
        let stateless = build_streamable_config(opts, CancellationToken::new());
        assert!(stateless.json_response);
    }

    #[test]
    fn session_keep_alive_zero_disables_timeout() {
        let manager = build_session_manager(0);
        assert!(
            manager.session_config.keep_alive.is_none(),
            "0 must disable the rmcp session inactivity timeout"
        );
    }

    #[test]
    fn session_keep_alive_overrides_rmcp_default() {
        let manager = build_session_manager(1800);
        assert_eq!(
            manager.session_config.keep_alive,
            Some(Duration::from_secs(1800)),
            "explicit value must override rmcp's 300s default that killed long IDA calls"
        );
    }

    #[tokio::test]
    async fn pooled_disconnect_registry_closes_abandoned_stream_after_grace() {
        let registry = Arc::new(SessionDisconnectRegistry::new(
            Arc::new(LocalSessionManager::default()),
            Duration::ZERO,
        ));
        let session_id: SessionId = "session-a".to_string().into();

        let guard = registry.stream_opened(&session_id);
        guard.finish(true);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let states = registry.states.lock().unwrap();
        assert!(!states.contains_key(&session_id));
    }

    #[tokio::test]
    async fn pooled_disconnect_registry_reconnect_cancels_abandoned_close() {
        let registry = Arc::new(SessionDisconnectRegistry::new(
            Arc::new(LocalSessionManager::default()),
            Duration::from_millis(50),
        ));
        let session_id: SessionId = "session-b".to_string().into();

        let abandoned = registry.stream_opened(&session_id);
        abandoned.finish(true);
        let reconnected = registry.stream_opened(&session_id);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let states = registry.states.lock().unwrap();
        let state = states.get(&session_id).unwrap();
        assert_eq!(state.active_streams, 1);
        assert!(state.abandoned_generation.is_none());
        drop(states);

        reconnected.finish(false);
        let states = registry.states.lock().unwrap();
        let state = states.get(&session_id).unwrap();
        assert_eq!(state.active_streams, 0);
        assert!(state.abandoned_generation.is_none());
    }
}
