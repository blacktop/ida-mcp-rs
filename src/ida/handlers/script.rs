//! Script execution handler.

use crate::error::ToolError;
use crate::ida::observability::{
    emit_progress, ensure_not_cancelled, ProgressHeartbeat, ProgressSender,
    SINGLE_PHASE_PROGRESS_TOTAL,
};
use idalib::IDB;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

fn last_non_empty_line(text: &str) -> Option<&str> {
    text.lines().rev().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn classify_python_error(details: &str) -> Option<&'static str> {
    let lowered = details.to_ascii_lowercase();
    if lowered.contains("syntaxerror") || lowered.contains("invalid syntax") {
        return Some("SyntaxError");
    }
    if lowered.contains("nameerror") {
        return Some("NameError");
    }
    if lowered.contains("attributeerror") {
        return Some("AttributeError");
    }
    if lowered.contains("importerror") || lowered.contains("modulenotfounderror") {
        return Some("ImportError");
    }
    if lowered.contains("typeerror") {
        return Some("TypeError");
    }
    if lowered.contains("valueerror") {
        return Some("ValueError");
    }
    None
}

pub fn handle_run_script(
    idb: &Option<IDB>,
    code: &str,
    progress_tx: Option<ProgressSender>,
    cancel: Option<CancellationToken>,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    ensure_not_cancelled(cancel.as_ref())?;
    let _heartbeat = ProgressHeartbeat::start(
        progress_tx.clone(),
        "executing",
        0.0,
        0.95,
        Some(SINGLE_PHASE_PROGRESS_TOTAL),
        "Executing IDAPython script",
    );
    let output = db.run_python(code)?;
    ensure_not_cancelled(cancel.as_ref())?;
    let error_summary = output
        .error
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| last_non_empty_line(&output.stderr).map(str::to_string));
    let error_details = format!(
        "{}\n{}",
        error_summary.as_deref().unwrap_or_default(),
        output.stderr
    );
    let error_kind = classify_python_error(&error_details);

    let mut result = json!({
        "success": output.success,
        "stdout": output.stdout,
        "stderr": output.stderr,
    });
    if let Some(error) = &output.error {
        result["error"] = json!(error);
    } else if !output.success
        && let Some(summary) = &error_summary
    {
        result["error"] = json!(summary);
    }
    if let Some(summary) = &error_summary {
        result["error_summary"] = json!(summary);
    }
    if let Some(kind) = error_kind {
        result["error_kind"] = json!(kind);
    }
    emit_progress(
        progress_tx.as_ref(),
        "executing",
        0.95,
        Some(SINGLE_PHASE_PROGRESS_TOTAL),
        "Script execution finished; packaging result",
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::ida::handlers::script::{classify_python_error, last_non_empty_line};

    #[test]
    fn classifies_common_python_errors() {
        assert_eq!(
            classify_python_error("Traceback\nSyntaxError: invalid syntax"),
            Some("SyntaxError")
        );
        assert_eq!(
            classify_python_error("NameError: name 'foo' is not defined"),
            Some("NameError")
        );
        assert_eq!(
            classify_python_error("ModuleNotFoundError: No module named ida_bytes"),
            Some("ImportError")
        );
    }

    #[test]
    fn finds_last_non_empty_line() {
        assert_eq!(last_non_empty_line("a\n\nb  \n"), Some("b"));
        assert_eq!(last_non_empty_line(" \n\t\n"), None);
    }
}
