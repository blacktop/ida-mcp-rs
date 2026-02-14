use std::env;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (install_path, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);

    if !ida_path.exists() || !idalib_path.exists() {
        println!("cargo::warning=IDA installation not found, using SDK stubs");
        idalib_build::configure_idasdk_linkage();
    } else {
        // Configure linkage to IDA libraries
        idalib_build::configure_linkage()?;
    }

    // Always set rpaths for runtime library discovery.
    // This adds the specified install path plus common default locations
    // so the binary can find IDA libraries without DYLD_LIBRARY_PATH.
    set_rpath(&install_path);

    Ok(())
}

/// Set rpath to the IDA installation directory for runtime library loading.
/// Adds multiple common IDA installation paths so the binary can find libraries
/// without requiring DYLD_LIBRARY_PATH to be set.
fn set_rpath(install_path: &Path) {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "linux") {
            "linux".to_string()
        } else {
            "unknown".to_string()
        }
    });

    // Always add the specified install path first
    add_rpath(install_path);

    // Add common default paths as fallbacks (IDA 9.2 and 9.3 variants)
    if os == "macos" {
        // Common macOS IDA installation paths (all editions)
        let default_paths = [
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
        ];
        for path in default_paths {
            let p = PathBuf::from(path);
            if p != *install_path {
                add_rpath(&p);
            }
        }
    } else if os == "linux" {
        // Common Linux IDA installation paths
        let home = env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let default_paths = [
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
        ];
        for path in default_paths {
            let p = PathBuf::from(&path);
            if p != *install_path {
                add_rpath(&p);
            }
        }
    }
}

fn add_rpath(path: &Path) {
    println!("cargo::rustc-link-arg=-Wl,-rpath,{}", path.display());
}
