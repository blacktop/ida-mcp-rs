use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Re-run linkage (rpath embedding) whenever the targeted IDA install changes.
    println!("cargo::rerun-if-env-changed=IDADIR");

    let (install_path, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);

    let using_sdk_stubs = !ida_path.exists() || !idalib_path.exists();
    if using_sdk_stubs {
        if idalib_build::requires_local_ida_install() {
            return Err(
                "IDA installation not found for a target that requires local IDA libraries".into(),
            );
        }
        println!("cargo::warning=IDA installation not found, using SDK stubs");
        idalib_build::configure_idasdk_linkage();
    } else {
        // Configure linkage to IDA libraries
        idalib_build::configure_linkage()?;
    }

    // Compile the C crash guard (sigsetjmp-based signal isolation)
    #[cfg(unix)]
    cc::Build::new()
        .file("src/crash_guard.c")
        .warnings(false)
        .compile("crash_guard");

    // Always set rpaths for runtime library discovery.
    // This adds the specified install path plus common default locations
    // so the binary can find IDA libraries without DYLD_LIBRARY_PATH.
    set_rpath(&install_path, using_sdk_stubs);

    Ok(())
}

/// Set rpath to the IDA installation directory for runtime library loading.
/// Adds multiple common IDA installation paths so the binary can find libraries
/// without requiring DYLD_LIBRARY_PATH to be set.
fn set_rpath(install_path: &Path, include_install_path: bool) {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "linux") {
            "linux".to_string()
        } else {
            "unknown".to_string()
        }
    });

    // configure_linkage() already adds the selected runtime path when a local
    // IDA install is present. Stub builds still need us to add it explicitly.
    if include_install_path {
        add_rpath(install_path);
    }

    let targeting_94 = install_path
        .components()
        .rev()
        .take(3)
        .any(|c| c.as_os_str().to_string_lossy().contains("9.4"));

    if os == "macos" {
        // Common macOS IDA installation paths (all editions)
        let default_paths: &[&str] = if targeting_94 {
            &[
                "/Applications/IDA Professional 9.4.app/Contents/MacOS",
                "/Applications/IDA Pro 9.4.app/Contents/MacOS",
                "/Applications/IDA Home 9.4.app/Contents/MacOS",
                "/Applications/IDA Essential 9.4.app/Contents/MacOS",
            ]
        } else {
            &[
                // IDA 9.3 paths
                "/Applications/IDA Professional 9.3.app/Contents/MacOS",
                "/Applications/IDA Pro 9.3.app/Contents/MacOS",
                "/Applications/IDA Home 9.3.app/Contents/MacOS",
                "/Applications/IDA Essential 9.3.app/Contents/MacOS",
                // IDA 9.2 paths
                "/Applications/IDA Professional 9.2.app/Contents/MacOS",
                "/Applications/IDA Pro 9.2.app/Contents/MacOS",
                "/Applications/IDA Home 9.2.app/Contents/MacOS",
                "/Applications/IDA Essential 9.2.app/Contents/MacOS",
            ]
        };
        for path in default_paths {
            add_rpath_if_not_install(Path::new(path), install_path);
        }
    } else if os == "linux" {
        // Common Linux IDA installation paths
        let home = env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let default_paths = if targeting_94 {
            vec![
                format!("{home}/idapro-9.4"),
                format!("{home}/ida-pro-9.4"),
                "/opt/idapro-9.4".to_string(),
                "/opt/ida-pro-9.4".to_string(),
                "/usr/local/idapro-9.4".to_string(),
            ]
        } else {
            vec![
                // IDA 9.3 paths
                format!("{}/idapro-9.3", home),
                format!("{}/ida-pro-9.3", home),
                "/opt/idapro-9.3".to_string(),
                "/opt/ida-pro-9.3".to_string(),
                "/usr/local/idapro-9.3".to_string(),
                // IDA 9.2 paths
                format!("{}/idapro-9.2", home),
                format!("{}/ida-pro-9.2", home),
                "/opt/idapro-9.2".to_string(),
                "/opt/ida-pro-9.2".to_string(),
                "/usr/local/idapro-9.2".to_string(),
            ]
        };
        for path in default_paths {
            add_rpath_if_not_install(Path::new(&path), install_path);
        }
    }
}

fn add_rpath_if_not_install(path: &Path, install_path: &Path) {
    if path != install_path {
        add_rpath(path);
    }
}

fn add_rpath(path: &Path) {
    println!("cargo::rustc-link-arg=-Wl,-rpath,{}", path.display());
}
