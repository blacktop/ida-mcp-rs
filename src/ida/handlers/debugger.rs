#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::Duration;

use idalib::debugger::DebuggerProcessState;
use idalib::meta::FileType;
use idalib::IDB;
use serde_json::{json, Value};
#[cfg(target_os = "macos")]
use tracing::{debug, warn};

use crate::error::ToolError;
use crate::ida::types::DebugStopAction;

const DEBUG_EVENT_TIMEOUT_MAX_SECS: u32 = 120;
pub(crate) const DEBUGGER_TEARDOWN_TIMEOUT_SECS: u32 = 5;

#[cfg(target_os = "macos")]
const MACOS_ARM64_DEBUGGER_HELPER: &str = "mac_server_arm";
#[cfg(target_os = "macos")]
const MACOS_X86_DEBUGGER_HELPER: &str = "mac_server";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugSessionKind {
    Launched,
    Attached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetArchitecture {
    Arm,
    Aarch64,
    X86,
    X86_64,
}

fn target_architecture(database: &IDB) -> Result<TargetArchitecture, ToolError> {
    let processor = database.processor();
    let family = processor.family();
    let is_64bit = database.meta().is_64bit();
    if family.is_arm() {
        Ok(if is_64bit {
            TargetArchitecture::Aarch64
        } else {
            TargetArchitecture::Arm
        })
    } else if family.is_386() {
        Ok(if is_64bit {
            TargetArchitecture::X86_64
        } else {
            TargetArchitecture::X86
        })
    } else {
        Err(ToolError::NotSupported(format!(
            "no debugger backend for target processor {}",
            processor.short_name()
        )))
    }
}

fn debugger_backend_for_target(
    file_type: FileType,
    architecture: TargetArchitecture,
) -> Result<&'static str, &'static str> {
    #[cfg(target_os = "macos")]
    {
        match (file_type, architecture) {
            (FileType::MACHO, TargetArchitecture::Aarch64) => Ok("arm_mac"),
            (FileType::MACHO, TargetArchitecture::X86 | TargetArchitecture::X86_64) => Ok("mac"),
            (FileType::MACHO, TargetArchitecture::Arm) => {
                Err("32-bit ARM Mach-O debugging is unsupported")
            }
            _ => Err("target is not a supported macOS executable"),
        }
    }

    #[cfg(target_os = "linux")]
    {
        match (file_type, architecture) {
            (FileType::ELF, TargetArchitecture::X86 | TargetArchitecture::X86_64) => Ok("linux"),
            (FileType::ELF, TargetArchitecture::Arm | TargetArchitecture::Aarch64) => {
                Err("the ARM Linux debugger is remote-only and remote configuration is not exposed")
            }
            _ => Err("target is not a supported Linux executable"),
        }
    }

    #[cfg(target_os = "windows")]
    {
        match (file_type, architecture) {
            (FileType::PE, TargetArchitecture::X86 | TargetArchitecture::X86_64) => Ok("win32"),
            (FileType::PE, TargetArchitecture::Arm | TargetArchitecture::Aarch64) => {
                Err("the IDA SDK does not provide a Windows-on-ARM user debugger")
            }
            _ => Err("target is not a supported Windows executable"),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (file_type, architecture);
        Err("debugger support is unavailable on this platform")
    }
}

fn debugger_backend(database: &IDB) -> Result<(&'static str, TargetArchitecture), ToolError> {
    let file_type = database.meta().filetype();
    let architecture = target_architecture(database)?;
    let backend = debugger_backend_for_target(file_type, architecture).map_err(|reason| {
        ToolError::NotSupported(format!(
            "no debugger backend for target {file_type:?}/{architecture:?}: {reason}"
        ))
    })?;
    Ok((backend, architecture))
}

#[cfg(target_os = "macos")]
fn macos_debugger_helper_for_target(
    architecture: TargetArchitecture,
) -> Result<&'static str, &'static str> {
    match architecture {
        TargetArchitecture::Aarch64 => Ok(MACOS_ARM64_DEBUGGER_HELPER),
        TargetArchitecture::X86 | TargetArchitecture::X86_64 => Ok(MACOS_X86_DEBUGGER_HELPER),
        TargetArchitecture::Arm => Err("32-bit ARM macOS debugging is unsupported"),
    }
}

#[derive(Default)]
pub struct DebuggerRuntime {
    backend_loaded: bool,
    session: Option<DebugSessionKind>,
    #[cfg(target_os = "macos")]
    helper: Option<MacDebuggerHelper>,
}

#[cfg(target_os = "macos")]
struct MacDebuggerHelper {
    child: Child,
    port: u16,
    name: &'static str,
}

impl Drop for DebuggerRuntime {
    fn drop(&mut self) {
        self.stop_helper();
    }
}

impl DebuggerRuntime {
    fn ensure_start_allowed(&self) -> Result<(), ToolError> {
        if self.session.is_some() {
            return Err(ToolError::InvalidParams(
                "a debugger session is already active; call debug_stop before starting another"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn session_kind(&self) -> Result<DebugSessionKind, ToolError> {
        self.session.ok_or_else(|| {
            ToolError::InvalidParams(
                "no active debugger session; call debug_launch or debug_attach first".to_string(),
            )
        })
    }

    fn clear_session(&mut self) {
        self.session = None;
        self.backend_loaded = false;
        self.stop_helper();
    }

    fn retain_session_after_start_error(
        &mut self,
        session: DebugSessionKind,
        process_state: DebuggerProcessState,
    ) -> bool {
        let retained = !matches!(process_state, DebuggerProcessState::NoProcess);
        if retained && self.session.is_none() {
            self.session = Some(session);
        }
        retained
    }

    fn ensure_backend(&mut self, database: &IDB) -> Result<&'static str, ToolError> {
        let (backend, architecture) = debugger_backend(database)?;
        #[cfg(target_os = "macos")]
        {
            let helper_name = macos_debugger_helper_for_target(architecture).map_err(|reason| {
                ToolError::NotSupported(format!(
                    "no signed macOS debugger helper for target {architecture:?}: {reason}"
                ))
            })?;
            let port = self.ensure_macos_helper(helper_name)?;
            if !self.backend_loaded {
                database
                    .debugger_load(backend, true, Some("127.0.0.1"), Some(port))
                    .map_err(debugger_error)?;
                self.backend_loaded = true;
            }
            Ok(backend)
        }

        #[cfg(target_os = "linux")]
        {
            let _ = architecture;
            if !self.backend_loaded {
                database
                    .debugger_load(backend, false, None, None)
                    .map_err(debugger_error)?;
                self.backend_loaded = true;
            }
            Ok(backend)
        }

        #[cfg(target_os = "windows")]
        {
            let _ = architecture;
            if !self.backend_loaded {
                database
                    .debugger_load(backend, false, None, None)
                    .map_err(debugger_error)?;
                self.backend_loaded = true;
            }
            Ok(backend)
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = database;
            let _ = backend;
            let _ = architecture;
            Err(ToolError::InvalidParams(
                "debugger support is unavailable on this platform".to_string(),
            ))
        }
    }

    #[cfg(target_os = "macos")]
    fn ensure_macos_helper(&mut self, helper_name: &'static str) -> Result<u16, ToolError> {
        if self
            .helper
            .as_ref()
            .is_some_and(|helper| helper.name != helper_name)
        {
            self.stop_helper();
            self.backend_loaded = false;
        }
        if let Some(helper) = self.helper.as_mut() {
            match helper.child.try_wait() {
                Ok(None) => return Ok(helper.port),
                Ok(Some(status)) => {
                    debug!(%status, "signed macOS debugger helper exited; restarting");
                    self.helper = None;
                    self.backend_loaded = false;
                }
                Err(error) => {
                    return Err(ToolError::IdaError(format!(
                        "failed to inspect signed macOS debugger helper: {error}"
                    )));
                }
            }
        }

        let path = macos_helper_path(helper_name)?;
        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(|error| {
                ToolError::IdaError(format!("failed to reserve debugger loopback port: {error}"))
            })?;
        let port = listener
            .local_addr()
            .map_err(|error| {
                ToolError::IdaError(format!("failed to read debugger loopback port: {error}"))
            })?
            .port();
        drop(listener);
        let child = Command::new(&path)
            .args(["-i", "127.0.0.1", "-p", &port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                ToolError::IdaError(format!(
                    "failed to start IDA's signed loopback debugger helper {}: {error}",
                    path.display()
                ))
            })?;
        self.helper = Some(MacDebuggerHelper {
            child,
            port,
            name: helper_name,
        });
        thread::sleep(Duration::from_millis(250));
        let Some(helper) = self.helper.as_mut() else {
            return Err(ToolError::IdaError(
                "signed macOS debugger helper was not retained".to_string(),
            ));
        };
        if let Some(status) = helper.child.try_wait().map_err(|error| {
            ToolError::IdaError(format!(
                "failed to inspect signed macOS debugger helper: {error}"
            ))
        })? {
            self.helper = None;
            return Err(ToolError::IdaError(format!(
                "IDA's signed macOS debugger helper exited during startup: {status}"
            )));
        }
        Ok(port)
    }

    #[cfg(not(target_os = "macos"))]
    fn stop_helper(&mut self) {}

    #[cfg(target_os = "macos")]
    fn stop_helper(&mut self) {
        let Some(mut helper) = self.helper.take() else {
            return;
        };
        if let Err(error) = helper.child.kill()
            && error.kind() != std::io::ErrorKind::InvalidInput
        {
            warn!(%error, "failed to stop signed macOS debugger helper");
        }
        let _ = helper.child.wait();
    }

    pub fn close_session(&mut self, idb: &Option<IDB>) -> Result<(), ToolError> {
        let Some(database) = idb.as_ref() else {
            self.clear_session();
            return Ok(());
        };
        // An externally exited target can leave our ownership tag stale. IDA's
        // NoProcess state is an affirmative observation that no debuggee is
        // attached, so database closure is safe without inventing a terminal
        // event. Never infer this state merely from a teardown error.
        if self.session.is_some()
            && matches!(
                database.debugger_process_state(),
                DebuggerProcessState::NoProcess
            )
        {
            self.clear_session();
            return Ok(());
        }
        // Preserve the session kind until IDA confirms the terminal event.
        // Clearing it on an inconclusive teardown would make a later close
        // appear successful and allow the database to be reused unsafely.
        match self.session {
            Some(DebugSessionKind::Launched) => {
                database.debugger_terminate(DEBUGGER_TEARDOWN_TIMEOUT_SECS)
            }
            Some(DebugSessionKind::Attached) => {
                database.debugger_detach(DEBUGGER_TEARDOWN_TIMEOUT_SECS)
            }
            None => Ok(0),
        }
        .map_err(|error| ToolError::DebuggerTeardown(error.to_string()))?;
        self.clear_session();
        Ok(())
    }
}

pub fn runtime_status() -> Value {
    #[cfg(target_os = "macos")]
    {
        let arm64_helper = macos_helper_path(MACOS_ARM64_DEBUGGER_HELPER).ok();
        let x86_helper = macos_helper_path(MACOS_X86_DEBUGGER_HELPER).ok();
        if arm64_helper.is_some() || x86_helper.is_some() {
            let mut backends = Vec::with_capacity(2);
            if arm64_helper.is_some() {
                backends.push("arm_mac");
            }
            if x86_helper.is_some() {
                backends.push("mac");
            }
            json!({
                "status": "user_action_required",
                "platform": "macos",
                "backends": backends,
                "backend_selection": "opened_database_target",
                "transport": "signed_loopback_helper",
                "helper_paths": {
                    "arm64": arm64_helper,
                    "x86": x86_helper,
                },
                "authorization": "IDA's Take Control authorization may be required once per login before macOS permits task control",
                "message": "Debugger tools are opt-in. ida-mcp uses IDA's signed loopback helper and never requests root, disables SIP, changes authorizationdb, or re-signs binaries."
            })
        } else {
            json!({
                "status": "unavailable",
                "platform": "macos",
                "backends": [],
                "backend_selection": "opened_database_target",
                "transport": "signed_loopback_helper",
                "message": "Cannot find IDA's signed macOS debugger helpers mac_server_arm or mac_server; set IDADIR to the IDA 9.4 installation directory",
            })
        }
    }

    #[cfg(target_os = "linux")]
    {
        json!({
            "status": "unavailable",
            "platform": "linux",
            "backends": ["linux"],
            "backend_selection": "opened_database_target",
            "message": "Linux debugger advertisement is gated until the native integration oracle passes; ptrace_scope may also require user action for attach."
        })
    }

    #[cfg(target_os = "windows")]
    {
        json!({
            "status": "unavailable",
            "platform": "windows",
            "backends": ["win32"],
            "backend_selection": "opened_database_target",
            "message": "Windows debugger advertisement is gated until the native PowerShell integration oracle passes."
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    json!({
        "status": "unavailable",
        "platform": std::env::consts::OS,
        "message": "IDA debugger support is unavailable on this platform."
    })
}

/// Shared body of `launch` and `attach`: one session-ownership contract and
/// one macOS authorization surface, so the two entry points differ only in
/// the IDA call they make and the denial message they explain it with.
fn start_debug_session(
    runtime: &mut DebuggerRuntime,
    idb: &Option<IDB>,
    session: DebugSessionKind,
    timeout_seconds: u32,
    denial_message: &str,
    start: impl FnOnce(&IDB) -> Result<i32, idalib::IDAError>,
) -> Result<Value, ToolError> {
    validate_timeout(timeout_seconds)?;
    let database = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    runtime.ensure_start_allowed()?;
    let backend = runtime.ensure_backend(database)?;
    match start(database) {
        Ok(event_code) => {
            runtime.session = Some(session);
            Ok(start_session_result(database, backend, event_code))
        }
        Err(error) => {
            let process_state = database.debugger_process_state();
            let retained = runtime.retain_session_after_start_error(session, process_state);
            if cfg!(target_os = "macos") && macos_authorization_failure(&error.to_string()) {
                return Ok(json!({
                    "status": "user_action_required",
                    "platform": "macos",
                    "backend": backend,
                    "process_state": process_state_name(process_state),
                    "session_retained": retained,
                    "message": denial_message,
                    "error": error.to_string(),
                }));
            }
            Err(start_error(error, retained))
        }
    }
}

pub fn launch(
    runtime: &mut DebuggerRuntime,
    idb: &Option<IDB>,
    path: &str,
    arguments: Option<&str>,
    start_directory: Option<&str>,
    timeout_seconds: u32,
) -> Result<Value, ToolError> {
    start_debug_session(
        runtime,
        idb,
        DebugSessionKind::Launched,
        timeout_seconds,
        "macOS denied or cancelled task control. Complete IDA's Take Control authorization for this login, then retry. ida-mcp will not request root, disable SIP, change authorizationdb, or re-sign binaries.",
        |database| database.debugger_launch(path, arguments, start_directory, timeout_seconds),
    )
}

pub fn attach(
    runtime: &mut DebuggerRuntime,
    idb: &Option<IDB>,
    pid: u32,
    timeout_seconds: u32,
) -> Result<Value, ToolError> {
    start_debug_session(
        runtime,
        idb,
        DebugSessionKind::Attached,
        timeout_seconds,
        "macOS denied task attachment. Complete IDA's Take Control authorization for this login, then retry.",
        |database| database.debugger_attach(pid, timeout_seconds),
    )
}

pub fn modules(runtime: &mut DebuggerRuntime, idb: &Option<IDB>) -> Result<Value, ToolError> {
    let database = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    runtime.session_kind()?;
    let backend = runtime.ensure_backend(database)?;
    let modules = database.debugger_modules().map_err(debugger_error)?;
    let modules = modules
        .into_iter()
        .map(|module| {
            json!({
                "path": module.path,
                "base": format!("{:#x}", module.base),
                "base_value": module.base,
                "size": module.size,
                "end": format!("{:#x}", module.base.saturating_add(module.size)),
                "end_value": module.base.saturating_add(module.size),
                "rebase_to": format!("{:#x}", module.rebase_to),
                "rebase_to_value": module.rebase_to,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "status": "ready",
        "backend": backend,
        "process_state": process_state_name(database.debugger_process_state()),
        "module_count": modules.len(),
        "modules": modules,
    }))
}

pub fn stop(
    runtime: &mut DebuggerRuntime,
    idb: &Option<IDB>,
    action: DebugStopAction,
    timeout_seconds: u32,
) -> Result<Value, ToolError> {
    validate_timeout(timeout_seconds)?;
    let database = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let session = runtime.session_kind()?;
    let resolved = match action {
        DebugStopAction::Auto => match session {
            DebugSessionKind::Launched => DebugStopAction::Terminate,
            DebugSessionKind::Attached => DebugStopAction::Detach,
        },
        explicit => explicit,
    };
    if matches!(
        database.debugger_process_state(),
        DebuggerProcessState::NoProcess
    ) {
        let (backend, _) = debugger_backend(database)?;
        let mut result = session_result(database, backend, "ready", 0, Some(resolved.as_str()));
        result["already_stopped"] = json!(true);
        runtime.clear_session();
        return Ok(result);
    }
    let backend = runtime.ensure_backend(database)?;
    let event_code = match resolved {
        DebugStopAction::Detach => database.debugger_detach(timeout_seconds),
        DebugStopAction::Terminate => database.debugger_terminate(timeout_seconds),
        DebugStopAction::Auto => {
            return Err(ToolError::IdaError(
                "internal debugger stop policy was not resolved".to_string(),
            ));
        }
    }
    .map_err(debugger_error)?;
    let result = session_result(
        database,
        backend,
        "ready",
        event_code,
        Some(resolved.as_str()),
    );
    runtime.clear_session();
    Ok(result)
}

fn validate_timeout(timeout_seconds: u32) -> Result<(), ToolError> {
    if timeout_seconds == 0 || timeout_seconds > DEBUG_EVENT_TIMEOUT_MAX_SECS {
        return Err(ToolError::InvalidParams(format!(
            "debugger timeout must be between 1 and {DEBUG_EVENT_TIMEOUT_MAX_SECS} seconds"
        )));
    }
    Ok(())
}

fn session_result(
    database: &IDB,
    backend: &str,
    status: &str,
    event_code: i32,
    action: Option<&str>,
) -> Value {
    let mut result = json!({
        "status": status,
        "backend": backend,
        "event_code": event_code,
        "process_state": process_state_name(database.debugger_process_state()),
    });
    if let Some(action) = action {
        result["action"] = json!(action);
    }
    result
}

fn start_session_result(database: &IDB, backend: &str, event_code: i32) -> Value {
    let mut result = session_result(database, backend, "ready", event_code, None);
    result["session_retained"] = json!(true);
    result
}

fn process_state_name(state: DebuggerProcessState) -> String {
    match state {
        DebuggerProcessState::Suspended => "suspended".to_string(),
        DebuggerProcessState::NoProcess => "no_process".to_string(),
        DebuggerProcessState::Running => "running".to_string(),
        DebuggerProcessState::Unknown(value) => format!("unknown_{value}"),
    }
}

fn debugger_error(error: idalib::IDAError) -> ToolError {
    ToolError::IdaError(format!("IDA debugger operation failed: {error}"))
}

fn start_error(error: idalib::IDAError, session_retained: bool) -> ToolError {
    let error = debugger_error(error);
    if session_retained {
        ToolError::DebuggerStartRetained(error.to_string())
    } else {
        error
    }
}

fn macos_authorization_failure(message: &str) -> bool {
    let message = message.trim().to_ascii_lowercase();
    if message.contains("task_for_pid") || message.contains("take control") {
        return true;
    }

    let authorization_outcome = message.contains("denied")
        || message.contains("failed")
        || message.contains("required")
        || message.contains("cancelled")
        || message.contains("canceled");
    if message.contains("authorization") && authorization_outcome {
        return true;
    }

    // IDA's signed macOS helper reports a dismissed Take Control prompt with
    // one of these exact operation-level messages. Do not substring-match
    // generic cancellation text from transports, targets, or scripts.
    matches!(
        message.as_str(),
        "debug launch was cancelled"
            | "debug launch was canceled"
            | "debug attach was cancelled"
            | "debug attach was canceled"
    )
}

#[cfg(target_os = "macos")]
fn macos_helper_path(helper_name: &str) -> Result<PathBuf, ToolError> {
    let configured_dir = std::env::var_os("IDADIR")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from);
    let default_dirs = [
        Path::new("/Applications/IDA Professional 9.4.app/Contents/MacOS"),
        Path::new("/Applications/IDA Pro 9.4.app/Contents/MacOS"),
    ];

    find_macos_helper(
        configured_dir
            .as_deref()
            .into_iter()
            .chain(default_dirs),
        helper_name,
    )
    .ok_or_else(|| {
        ToolError::InvalidParams(format!(
            "cannot find signed macOS debugger helper {helper_name}; set IDADIR to the IDA 9.4 installation directory"
        ))
    })
}

#[cfg(target_os = "macos")]
fn find_macos_helper<'a>(
    ida_dirs: impl IntoIterator<Item = &'a Path>,
    helper_name: &str,
) -> Option<PathBuf> {
    ida_dirs
        .into_iter()
        .map(|ida_dir| ida_dir.join("dbgsrv").join(helper_name))
        .find(|helper| helper.is_file())
}

#[cfg(test)]
mod tests {
    use idalib::meta::FileType;

    use crate::error::ToolError;
    use crate::ida::handlers::debugger::{
        debugger_backend_for_target, macos_authorization_failure, DebugSessionKind,
        DebuggerRuntime, TargetArchitecture,
    };
    use crate::ida::types::DebugStopAction;

    #[cfg(target_os = "macos")]
    use crate::ida::handlers::debugger::{
        find_macos_helper, macos_debugger_helper_for_target, MACOS_ARM64_DEBUGGER_HELPER,
        MACOS_X86_DEBUGGER_HELPER,
    };

    #[test]
    fn stop_action_is_explicit_and_bounded() {
        assert_eq!(DebugStopAction::parse(None), Ok(DebugStopAction::Auto));
        assert_eq!(
            DebugStopAction::parse(Some("detach")),
            Ok(DebugStopAction::Detach)
        );
        assert!(DebugStopAction::parse(Some("continue")).is_err());
    }

    #[test]
    fn inactive_runtime_rejects_session_only_operations() {
        let runtime = DebuggerRuntime::default();

        let error = runtime
            .session_kind()
            .expect_err("a fresh runtime must not claim a debug session");
        assert!(error.to_string().contains("no active debugger session"));
    }

    #[test]
    fn active_process_retains_ownership_after_initial_wait_error() {
        let mut launched = DebuggerRuntime::default();
        assert!(launched.retain_session_after_start_error(
            DebugSessionKind::Launched,
            idalib::debugger::DebuggerProcessState::Running,
        ));
        assert_eq!(launched.session, Some(DebugSessionKind::Launched));

        let mut attached = DebuggerRuntime::default();
        assert!(attached.retain_session_after_start_error(
            DebugSessionKind::Attached,
            idalib::debugger::DebuggerProcessState::Suspended,
        ));
        assert_eq!(attached.session, Some(DebugSessionKind::Attached));
    }

    #[test]
    fn second_start_is_rejected_without_changing_ownership() {
        let mut runtime = DebuggerRuntime {
            backend_loaded: false,
            session: Some(DebugSessionKind::Attached),
            #[cfg(target_os = "macos")]
            helper: None,
        };

        let error = runtime
            .ensure_start_allowed()
            .expect_err("an active session must reject another start");
        assert!(matches!(error, ToolError::InvalidParams(_)));

        assert!(runtime.retain_session_after_start_error(
            DebugSessionKind::Launched,
            idalib::debugger::DebuggerProcessState::Running,
        ));
        assert_eq!(runtime.session, Some(DebugSessionKind::Attached));
    }

    #[test]
    fn no_process_does_not_claim_ownership_after_start_error() {
        let mut runtime = DebuggerRuntime::default();
        assert!(!runtime.retain_session_after_start_error(
            DebugSessionKind::Launched,
            idalib::debugger::DebuggerProcessState::NoProcess,
        ));
        assert_eq!(runtime.session, None);
    }

    #[test]
    fn macos_authorization_classification_does_not_hide_target_errors() {
        assert!(macos_authorization_failure(
            "user cancelled Take Control authorization"
        ));
        assert!(macos_authorization_failure(
            "task_for_pid authorization failed"
        ));
        assert!(!macos_authorization_failure(
            "permission denied while opening executable"
        ));
        assert!(!macos_authorization_failure(
            "process 999999999 does not exist"
        ));
        assert!(!macos_authorization_failure(
            "remote debugger protocol mismatch"
        ));
        assert!(!macos_authorization_failure(
            "debug launch canceled because the remote transport disconnected"
        ));
        assert!(macos_authorization_failure("debug launch was cancelled"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn loaded_x86_64_macho_selects_mac_backend() {
        assert_eq!(
            debugger_backend_for_target(FileType::MACHO, TargetArchitecture::X86_64),
            Ok("mac")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn loaded_aarch64_macho_selects_arm_mac_backend() {
        assert_eq!(
            debugger_backend_for_target(FileType::MACHO, TargetArchitecture::Aarch64),
            Ok("arm_mac")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_helper_selection_follows_the_debug_target() {
        for (architecture, expected) in [
            (TargetArchitecture::Aarch64, MACOS_ARM64_DEBUGGER_HELPER),
            (TargetArchitecture::X86_64, MACOS_X86_DEBUGGER_HELPER),
            (TargetArchitecture::X86, MACOS_X86_DEBUGGER_HELPER),
        ] {
            assert_eq!(macos_debugger_helper_for_target(architecture), Ok(expected));
        }
        assert!(macos_debugger_helper_for_target(TargetArchitecture::Arm).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn arm_linux_target_rejects_unconfigured_remote_backend() {
        assert!(debugger_backend_for_target(FileType::ELF, TargetArchitecture::Aarch64).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_arm_target_rejects_missing_user_backend() {
        assert!(debugger_backend_for_target(FileType::PE, TargetArchitecture::Aarch64).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_helper_discovery_does_not_require_idat() {
        let ida_dir =
            std::env::temp_dir().join(format!("ida-mcp-debugger-helper-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(ida_dir.join("dbgsrv")).expect("create debugger helper directory");
        for helper_name in [MACOS_ARM64_DEBUGGER_HELPER, MACOS_X86_DEBUGGER_HELPER] {
            let helper = ida_dir.join("dbgsrv").join(helper_name);
            std::fs::write(&helper, b"").expect("create debugger helper");
            assert_eq!(
                find_macos_helper([ida_dir.as_path()], helper_name),
                Some(helper)
            );
        }
        let _ = std::fs::remove_dir_all(&ida_dir);
    }
}
