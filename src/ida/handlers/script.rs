//! Script execution handler.

use crate::error::ToolError;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_run_script(idb: &Option<IDB>, code: &str) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let output = db.run_python(code)?;
    let mut result = json!({
        "success": output.success,
        "stdout": output.stdout,
        "stderr": output.stderr,
    });
    if let Some(error) = &output.error {
        result["error"] = json!(error);
    }
    Ok(result)
}
