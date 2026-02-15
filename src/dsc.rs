//! dyld_shared_cache (DSC) support utilities.
//!
//! Builds the IDA file type selector string and the IDAPython script
//! that drives the dscu plugin to load individual modules from a DSC.
//!
//! idalib's headless mode cannot handle the DSC loader's module
//! selection — `init_database()` calls `exit(1)`. So DSC loading is
//! a two-phase process:
//!   1. Run `idat -a- -A -S<script> -T<loader> -o<out.i64> <dsc>`
//!      to create the database via IDA's autonomous CLI mode.
//!   2. Open the resulting `.i64` with idalib for interactive analysis.

use std::path::{Path, PathBuf};

use crate::error::ToolError;

/// Escape a string for safe interpolation into Python double-quoted strings.
///
/// Prevents code injection when embedding user-supplied module/framework
/// paths into generated IDAPython scripts.
fn escape_python_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Build the IDA `-T` file type string for a dyld_shared_cache.
///
/// IDA 9.3 offers two DSC loader modes:
/// - `"(select module(s))"` — loads specific modules (was `"(single module)"` in IDA 8)
/// - `"(complete image)"` — loads the entire DSC
///
/// We always use `"(select module(s))"` for targeted module loading.
pub fn dsc_file_type(arch: &str, ida_version: u8) -> String {
    let mode = if ida_version >= 9 {
        "select module(s)"
    } else {
        "single module"
    };
    format!("Apple DYLD cache for {arch} ({mode})")
}

/// Locate the `idat` binary for running IDA in autonomous CLI mode.
///
/// Checks `$IDADIR` first, then falls back to platform-specific
/// default installation paths.
pub fn find_idat() -> Result<PathBuf, ToolError> {
    let bin_name = if cfg!(target_os = "windows") {
        "idat.exe"
    } else {
        "idat"
    };

    // Check IDADIR environment variable
    if let Ok(dir) = std::env::var("IDADIR") {
        let idat = Path::new(&dir).join(bin_name);
        if idat.exists() {
            return Ok(idat);
        }
    }

    // Platform defaults
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/Applications/IDA Professional 9.3.app/Contents/MacOS/idat",
            "/Applications/IDA Professional 9.0.app/Contents/MacOS/idat",
            "/Applications/IDA Pro 9.3.app/Contents/MacOS/idat",
            "/Applications/IDA Pro 9.0.app/Contents/MacOS/idat",
        ]
    } else if cfg!(target_os = "linux") {
        &["/opt/ida/idat", "/opt/idapro/idat"]
    } else if cfg!(target_os = "windows") {
        &[
            r"C:\Program Files\IDA Professional 9.3\idat.exe",
            r"C:\Program Files\IDA Pro 9.3\idat.exe",
            r"C:\Program Files\IDA Professional 9.0\idat.exe",
            r"C:\Program Files\IDA Pro 9.0\idat.exe",
        ]
    } else {
        &[]
    };

    for path in candidates {
        let p = Path::new(path);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }

    Err(ToolError::InvalidParams(
        "Cannot find idat binary. Set IDADIR environment variable \
         to your IDA installation directory."
            .into(),
    ))
}

/// Build the `idat` command-line arguments for DSC module loading.
///
/// Produces arguments matching the working invocation pattern:
/// ```text
/// idat -a- -A -P+ -Oobjc:+l -S<script> -T<loader> -o<out.i64> <dsc>
/// ```
pub fn idat_dsc_args(
    dsc_path: &Path,
    out_i64: &Path,
    script_path: &Path,
    file_type: &str,
    log_path: Option<&Path>,
) -> Vec<String> {
    let mut args = vec![
        "-a-".to_string(),       // enable auto-analysis
        "-A".to_string(),        // autonomous mode (no dialogs)
        "-P+".to_string(),       // compressed database
        "-Oobjc:+l".to_string(), // ObjC plugin options
    ];

    if let Some(log) = log_path {
        args.push(format!("-L{}", log.display()));
    }

    args.push(format!("-S{}", script_path.display()));
    args.push(format!("-T{file_type}"));
    args.push(format!("-o{}", out_i64.display()));
    args.push(dsc_path.display().to_string());

    args
}

/// Build the IDAPython script that loads modules from a DSC and
/// runs ObjC analysis.
///
/// The script uses `dscu_load_module` to communicate with the dscu
/// plugin via IDA's netnode API, then runs ObjC type, block, and
/// auto-analysis passes.
pub fn dsc_load_script(module: &str, frameworks: &[String]) -> String {
    let mut script = String::from(
        "\
import idaapi
from idc import *

def dscu_load_module(module):
    node = idaapi.netnode()
    node.create(\"$ dscu\")
    node.supset(2, module)
    load_and_run_plugin(\"dscu\", 1)
",
    );

    let escaped_module = escape_python_string(module);

    // Load primary module
    script.push_str(&format!(
        "\n# Load primary module\n\
         print(\"[ida-mcp] loading module: {escaped_module}\")\n\
         dscu_load_module(\"{escaped_module}\")\n"
    ));

    // Load additional frameworks
    for fw in frameworks {
        let escaped_fw = escape_python_string(fw);
        script.push_str(&format!(
            "\nprint(\"[ida-mcp] loading framework: {escaped_fw}\")\n\
             dscu_load_module(\"{escaped_fw}\")\n"
        ));
    }

    // ObjC and auto-analysis passes
    script.push_str(
        "\
\n# ObjC type analysis
print(\"[ida-mcp] analyzing objc types\")
load_and_run_plugin(\"objc\", 1)
print(\"[ida-mcp] analyzing NSConcreteGlobalBlock objects\")
load_and_run_plugin(\"objc\", 4)

# Auto-analysis
print(\"[ida-mcp] performing auto-analysis...\")
auto_mark_range(0, BADADDR, AU_FINAL)
auto_wait()

# Stack block analysis
print(\"[ida-mcp] analyzing NSConcreteStackBlock objects\")
load_and_run_plugin(\"objc\", 5)

print(\"[ida-mcp] DSC module loading complete\")
",
    );

    script
}

#[cfg(test)]
mod tests {
    use crate::dsc::{dsc_file_type, dsc_load_script, idat_dsc_args};
    use std::path::Path;

    #[test]
    fn file_type_ida9() {
        assert_eq!(
            dsc_file_type("arm64e", 9),
            "Apple DYLD cache for arm64e (select module(s))"
        );
    }

    #[test]
    fn file_type_ida8() {
        assert_eq!(
            dsc_file_type("arm64e", 8),
            "Apple DYLD cache for arm64e (single module)"
        );
    }

    #[test]
    fn idat_args_basic() {
        let args = idat_dsc_args(
            Path::new("/path/to/dsc"),
            Path::new("/out/dsc.i64"),
            Path::new("/tmp/script.py"),
            "Apple DYLD cache for arm64e (select module(s))",
            None,
        );
        assert!(args.contains(&"-a-".to_string()));
        assert!(args.contains(&"-A".to_string()));
        assert!(args.contains(&"-P+".to_string()));
        assert!(args.contains(&"-S/tmp/script.py".to_string()));
        assert!(args.contains(&"-o/out/dsc.i64".to_string()));
        assert!(args.contains(&"/path/to/dsc".to_string()));
    }

    #[test]
    fn idat_args_with_log() {
        let args = idat_dsc_args(
            Path::new("/path/to/dsc"),
            Path::new("/out/dsc.i64"),
            Path::new("/tmp/script.py"),
            "Apple DYLD cache for arm64e (select module(s))",
            Some(Path::new("/tmp/ida.log")),
        );
        assert!(args.contains(&"-L/tmp/ida.log".to_string()));
    }

    #[test]
    fn script_no_frameworks() {
        let script = dsc_load_script("/usr/lib/libobjc.A.dylib", &[]);
        assert!(script.contains("dscu_load_module(\"/usr/lib/libobjc.A.dylib\")"));
        assert!(script.contains("load_and_run_plugin(\"objc\", 1)"));
        assert!(script.contains("auto_wait()"));
    }

    #[test]
    fn script_with_frameworks() {
        let frameworks = vec![
            "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation".to_string(),
        ];
        let script = dsc_load_script("/usr/lib/libobjc.A.dylib", &frameworks);
        assert!(script.contains("dscu_load_module(\"/usr/lib/libobjc.A.dylib\")"));
        assert!(script.contains("Foundation"));
        assert!(script.contains("CoreFoundation"));
    }

    #[test]
    fn escape_python_string_basic() {
        use super::escape_python_string;
        assert_eq!(escape_python_string("normal/path"), "normal/path");
        assert_eq!(escape_python_string(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_python_string("a\\b"), "a\\\\b");
        assert_eq!(escape_python_string("a\nb"), "a\\nb");
        assert_eq!(escape_python_string("a\rb"), "a\\rb");
    }

    #[test]
    fn script_injection_escaped() {
        let malicious = r#""); import os; os.system("rm -rf /"); print(""#;
        let script = dsc_load_script(malicious, &[]);
        // The injected quotes should be escaped, keeping the string intact
        assert!(!script.contains("import os"));
        assert!(script.contains("\\\""));
    }
}
