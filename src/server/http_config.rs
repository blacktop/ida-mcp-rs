//! Builds the rmcp Streamable HTTP transport configuration.

use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use std::sync::Arc;
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
    // rmcp 1.5 exposes no builder for SessionConfig; mutate the public field.
    let mut manager = LocalSessionManager::default();
    manager.session_config.keep_alive = if session_keep_alive_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(session_keep_alive_secs))
    };
    Arc::new(manager)
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
    };
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
}
