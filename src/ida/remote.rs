//! Helpers for calling a child `ida-mcp worker` over MCP stdio.

use crate::error::ToolError;
use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject};
use rmcp::service::{Peer, RoleClient};
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

fn result_error(result: &CallToolResult, tool: &str) -> Option<ToolError> {
    if result.is_error != Some(true) {
        return None;
    }

    Some(ToolError::IdaError(result_error_message(result, tool)))
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
    peer.call_tool(CallToolRequestParams::new(tool).with_arguments(args))
        .await
        .map_err(|err| ToolError::RemoteProtocol(format!("{tool} call failed: {err}")))
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::remote::{parse_json, parse_value};
    use rmcp::model::{CallToolResult, Content};
    use serde_json::{json, Value};

    #[test]
    fn parse_value_rejects_structured_error_results() {
        let result = CallToolResult::structured_error(json!({ "message": "bad idb" }));

        let err = parse_value(result, "open_idb").expect_err("structured error must fail");

        assert!(matches!(err, ToolError::IdaError(message) if message.contains("bad idb")));
    }

    #[test]
    fn parse_json_rejects_structured_error_results() {
        let mut result = CallToolResult::structured_error(json!({ "path": "/tmp/example.i64" }));
        result.content = vec![Content::text("child failed")];

        let err = parse_json::<Value>(result, "open_idb").expect_err("structured error must fail");

        assert!(matches!(err, ToolError::IdaError(message) if message == "child failed"));
    }
}
