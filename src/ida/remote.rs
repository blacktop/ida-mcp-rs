//! Helpers for calling a child `ida-mcp worker` over MCP stdio.

use crate::error::{ToolError, DEBUGGER_START_RETAINED_PREFIX};
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResult, ClientRequest, JsonObject, ServerResult,
};
use rmcp::service::{Peer, PeerRequestOptions, RequestHandle, RoleClient, ServiceError};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub(crate) fn hex_addr(addr: u64) -> Value {
    Value::String(format!("0x{addr:x}"))
}

pub(crate) fn opt_hex_addr(addr: Option<u64>) -> Value {
    addr.map(hex_addr).unwrap_or(Value::Null)
}

pub(crate) fn json_object(value: Value) -> Result<JsonObject, ToolError> {
    match value {
        Value::Object(map) => Ok(map),
        other => Err(ToolError::RemoteProtocol(format!(
            "tool arguments must be a JSON object, got {other:?}"
        ))),
    }
}

const NOT_SUPPORTED_PREFIX: &str = "Not supported: ";

/// `_meta` key a child worker sets on a result when its IDA thread caught an
/// SDK crash while producing it. Result text is user-controlled (script
/// output, exception messages), so the parent retires on this key only.
const SDK_CRASHED_META_KEY: &str = "ida-mcp/sdk-crashed";

pub(crate) fn mark_sdk_crashed(result: &mut CallToolResult) {
    result
        .meta
        .get_or_insert_default()
        .0
        .insert(SDK_CRASHED_META_KEY.to_string(), Value::Bool(true));
}

/// The crash a child reported for `tool`, if it marked this result.
pub(crate) fn sdk_crash(result: &CallToolResult, tool: &str) -> Option<ToolError> {
    let marked = result
        .meta
        .as_ref()
        .and_then(|meta| meta.0.get(SDK_CRASHED_META_KEY))
        == Some(&Value::Bool(true));
    if !marked {
        return None;
    }
    let message = if result.is_error == Some(true) {
        result_error_message(result, tool)
    } else {
        format!(
            "{tool} crashed inside the IDA SDK. The database state can no longer be trusted, \
             so it is closed without saving and changes since the last save_idb are lost. \
             Call open_idb again."
        )
    };
    Some(ToolError::SdkCrashed(message))
}

pub(crate) fn strip_worker_metadata(value: &mut Value) {
    let Value::Object(map) = value else {
        return;
    };
    for key in [
        "session_id",
        "close_hint",
        "close_owner_session_id",
        "close_token",
        "close_token_reused",
        "close_recovery_hint",
    ] {
        map.remove(key);
    }
}

pub(crate) fn result_text(result: &CallToolResult, tool: &str) -> Result<String, ToolError> {
    if result.is_error == Some(true) {
        return Err(ToolError::IdaError(result_error_message(result, tool)));
    }

    let Some(text) = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.clone())
    else {
        return Err(ToolError::RemoteProtocol(format!(
            "child tool {tool} returned no text content"
        )));
    };

    if result.content.len() != 1 {
        return Err(ToolError::RemoteProtocol(format!(
            "child tool {tool} returned {} content items; expected 1",
            result.content.len()
        )));
    }

    Ok(text)
}

fn result_error_message(result: &CallToolResult, tool: &str) -> String {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.clone())
        .unwrap_or_else(|| format!("child tool {tool} returned an error"))
}

pub(crate) fn result_error(result: &CallToolResult, tool: &str) -> Option<ToolError> {
    if result.is_error != Some(true) {
        return None;
    }

    Some(classify_child_error(result_error_message(result, tool)))
}

fn classify_child_error(message: String) -> ToolError {
    if let Some(detail) = message.strip_prefix(DEBUGGER_START_RETAINED_PREFIX) {
        return ToolError::DebuggerStartRetained(detail.to_string());
    }
    // Callers downgrade NotSupported to a warning (open_dsc on an existing
    // database without the dscu service), so the type must survive the
    // child boundary. The prefix is NotSupported's own Display.
    if let Some(detail) = message.strip_prefix(NOT_SUPPORTED_PREFIX) {
        return ToolError::NotSupported(detail.to_string());
    }
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("worker channel closed") {
        return ToolError::WorkerClosed;
    }
    if lowered.contains("timed out after")
        || lowered.contains("operation timed out")
        || lowered.contains("exceeded worker operation timeout")
    {
        return ToolError::TimeoutDetailed(message);
    }
    if lowered.contains("cancelled") || lowered.contains("canceled") {
        return ToolError::Cancelled(message);
    }
    if lowered.contains("debugger teardown incomplete") {
        return ToolError::DebuggerTeardown(message);
    }
    ToolError::IdaError(message)
}

pub(crate) fn parse_json<T: DeserializeOwned>(
    result: CallToolResult,
    tool: &str,
) -> Result<T, ToolError> {
    if let Some(err) = result_error(&result, tool) {
        return Err(err);
    }

    if let Some(mut structured) = result.structured_content.clone() {
        strip_worker_metadata(&mut structured);
        return serde_json::from_value(structured).map_err(|err| {
            ToolError::RemoteProtocol(format!("failed to parse {tool} structured response: {err}"))
        });
    }

    let text = result_text(&result, tool)?;
    let mut value = serde_json::from_str::<Value>(&text).map_err(|err| {
        ToolError::RemoteProtocol(format!("failed to parse {tool} JSON response: {err}"))
    })?;
    strip_worker_metadata(&mut value);
    serde_json::from_value(value)
        .map_err(|err| ToolError::RemoteProtocol(format!("invalid {tool} response: {err}")))
}

pub(crate) fn parse_value(result: CallToolResult, tool: &str) -> Result<Value, ToolError> {
    if let Some(err) = result_error(&result, tool) {
        return Err(err);
    }

    if let Some(mut structured) = result.structured_content.clone() {
        strip_worker_metadata(&mut structured);
        return Ok(structured);
    }
    let text = result_text(&result, tool)?;
    let mut value = serde_json::from_str::<Value>(&text).map_err(|err| {
        ToolError::RemoteProtocol(format!("failed to parse {tool} JSON response: {err}"))
    })?;
    strip_worker_metadata(&mut value);
    Ok(value)
}

pub(crate) async fn call_tool(
    peer: &Peer<RoleClient>,
    tool: &'static str,
    args: JsonObject,
) -> Result<CallToolResult, ToolError> {
    let request = dispatch_tool(peer, tool, args).await?;
    tool_response(request, tool).await
}

/// Commit one request to rmcp's outbound queue. With no progress-timeout
/// options, rmcp's cancellable channel send is its last await before returning
/// this handle. Dropping this future before it returns cannot send the request.
pub(crate) async fn dispatch_tool(
    peer: &Peer<RoleClient>,
    tool: &'static str,
    args: JsonObject,
) -> Result<RequestHandle<RoleClient>, ToolError> {
    peer.send_cancellable_request(
        ClientRequest::CallToolRequest(CallToolRequest::new(
            CallToolRequestParams::new(tool).with_arguments(args),
        )),
        PeerRequestOptions::no_options(),
    )
    .await
    .map_err(|err| ToolError::RemoteProtocol(format!("{tool} call failed: {err}")))
}

pub(crate) async fn tool_response(
    request: RequestHandle<RoleClient>,
    tool: &'static str,
) -> Result<CallToolResult, ToolError> {
    match request
        .await_response()
        .await
        .map_err(|err| ToolError::RemoteProtocol(format!("{tool} call failed: {err}")))?
    {
        ServerResult::CallToolResult(result) => Ok(result),
        _ => Err(ToolError::RemoteProtocol(format!(
            "{tool} call failed: {}",
            ServiceError::UnexpectedResponse
        ))),
    }
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::remote::{mark_sdk_crashed, parse_json, parse_value, sdk_crash};
    use crate::ida::types::{MutationTarget, StackVarResult, TargetSelector};
    use rmcp::model::{CallToolResult, ContentBlock as Content};
    use serde_json::{json, Value};

    #[test]
    fn sdk_crash_is_read_from_the_marker_not_the_text() {
        let crash_text = "handle_run_script crashed inside the IDA SDK (signal 11).";

        // A script can produce the same words; without the marker that is an
        // ordinary tool error and the worker keeps its database.
        let lookalike = ToolError::IdaError(crash_text.to_string()).to_tool_result();
        assert!(sdk_crash(&lookalike, "run_script").is_none());
        let err = parse_value(lookalike, "run_script").expect_err("error stays an error");
        assert!(matches!(err, ToolError::IdaError(_)));

        let mut marked = ToolError::SdkCrashed(crash_text.to_string()).to_tool_result();
        mark_sdk_crashed(&mut marked);
        let err = sdk_crash(&marked, "run_script").expect("marked result is a crash");
        assert!(matches!(err, ToolError::SdkCrashed(message) if message == crash_text));
    }

    /// A child's NotSupported must reach the parent as NotSupported: open_dsc
    /// turns exactly that type into a warning instead of failing the open.
    #[test]
    fn not_supported_survives_the_child_boundary() {
        let child = ToolError::NotSupported("IDA dscu service is not available".to_string())
            .to_tool_result();
        let err = parse_value(child, "dsc_add_dylib").expect_err("stays an error");
        assert!(
            matches!(&err, ToolError::NotSupported(message) if message == "IDA dscu service is not available"),
            "{err:?}"
        );
    }

    /// Batch tools fold a per-item crash into a successful result; the marker
    /// must still surface it.
    #[test]
    fn sdk_crash_marker_is_honored_on_a_successful_result() {
        let mut batch = CallToolResult::success(vec![Content::text(
            r#"{"results":[{"error":"handle_find_bytes crashed"}]}"#,
        )]);
        assert!(sdk_crash(&batch, "find_bytes").is_none());
        mark_sdk_crashed(&mut batch);
        let err = sdk_crash(&batch, "find_bytes").expect("marked success is a crash");
        assert!(matches!(err, ToolError::SdkCrashed(message) if message.contains("find_bytes")));
    }

    /// Pooled and workspace parents decode a child's stack result into the
    /// typed struct; the target record must survive that round trip,
    /// including an unnamed (null) symbol.
    #[test]
    fn parse_json_keeps_mutation_target_in_stack_results() {
        for (selector, symbol) in [
            (TargetSelector::Name, Some("_main".to_string())),
            (TargetSelector::Address, None),
        ] {
            let child = StackVarResult {
                function: "0x100000460".to_string(),
                name: "var_8".to_string(),
                offset: -8,
                code: 0,
                status: "ok".to_string(),
                target: MutationTarget {
                    database: Some("/tmp/sample.i64".to_string()),
                    selector,
                    symbol,
                    base: "0x100000460".to_string(),
                    requested_address: "0x100000460".to_string(),
                    address: "0x100000460".to_string(),
                },
            };
            let text = serde_json::to_string_pretty(&child).expect("serialize child result");
            let result = CallToolResult::success(vec![Content::text(text)]);
            let parsed: StackVarResult = parse_json(result, "declare_stack").expect("decode");
            assert_eq!(parsed.target, child.target);
        }
    }

    #[test]
    fn parse_value_rejects_structured_error_results() {
        let result = CallToolResult::structured_error(json!({ "message": "bad idb" }));

        let err = parse_value(result, "open_idb").expect_err("structured error must fail");

        assert!(matches!(err, ToolError::IdaError(message) if message.contains("bad idb")));
    }

    #[test]
    fn parse_value_preserves_child_worker_closed_errors() {
        let result = CallToolResult::error(vec![Content::text("Worker channel closed")]);

        let err = parse_value(result, "close_idb").expect_err("worker closed must fail");

        assert!(matches!(err, ToolError::WorkerClosed));
    }

    #[test]
    fn parse_value_preserves_child_timeout_errors() {
        let result =
            CallToolResult::error(vec![Content::text("open_idb timed out after 600 seconds")]);

        let err = parse_value(result, "open_idb").expect_err("timeout must fail");

        assert!(
            matches!(err, ToolError::TimeoutDetailed(message) if message.contains("600 seconds"))
        );
    }

    #[test]
    fn parse_value_preserves_child_cancellation_errors() {
        let result = CallToolResult::error(vec![Content::text(
            "run_script was cancelled by the client",
        )]);

        let err = parse_value(result, "run_script").expect_err("cancellation must fail");

        assert!(matches!(err, ToolError::Cancelled(message) if message.contains("cancelled")));
    }

    #[test]
    fn parse_value_preserves_debugger_teardown_errors() {
        let result = CallToolResult::error(vec![Content::text(
            "Debugger teardown incomplete: timed out waiting for debugger teardown",
        )]);

        let err = parse_value(result, "close_idb").expect_err("teardown failure must fail");

        assert!(
            matches!(err, ToolError::DebuggerTeardown(message) if message.contains("timed out"))
        );
    }

    #[test]
    fn parse_value_preserves_retained_debugger_start_errors() {
        let result =
            ToolError::DebuggerStartRetained("initial wait cancelled".to_string()).to_tool_result();

        let err = parse_value(result, "debug_launch")
            .expect_err("retained debugger ownership must remain typed");

        assert!(
            matches!(err, ToolError::DebuggerStartRetained(message) if message.contains("cancelled"))
        );
    }

    #[test]
    fn parse_json_rejects_structured_error_results() {
        let mut result = CallToolResult::structured_error(json!({ "path": "/tmp/example.i64" }));
        result.content = vec![Content::text("child failed")];

        let err = parse_json::<Value>(result, "open_idb").expect_err("structured error must fail");

        assert!(matches!(err, ToolError::IdaError(message) if message == "child failed"));
    }
}
