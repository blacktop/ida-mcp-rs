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
    set_rpath(&install_path, using_sdk_stubs, &sdk_ida_version()?);

    Ok(())
}

/// IDA version the bindings target, read from the SDK's `pro.h`
/// (`IDA_SDK_VERSION`, e.g. 950 → "9.5").
///
/// Fallback rpaths must match this version regardless of what IDADIR points
/// at during the build: the runtime rejects mismatched minors since 9.4, so
/// rpaths for any other version are pure hazard, and deriving the version
/// from the build-time install path breaks for unversioned or absent paths
/// (such as CI runners without an IDA install).
fn sdk_ida_version() -> Result<String, Box<dyn std::error::Error>> {
    let (sdk_path, _, _, _) = idalib_build::idalib_sdk_paths_with(false);
    let pro_h = sdk_path.join("include").join("pro.h");
    let text = std::fs::read_to_string(&pro_h).map_err(|e| {
        format!(
            "cannot read {} to derive the targeted IDA version: {e}",
            pro_h.display()
        )
    })?;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("#define IDA_SDK_VERSION") {
            let value: u32 = value
                .trim()
                .parse()
                .map_err(|e| format!("unparsable IDA_SDK_VERSION in {}: {e}", pro_h.display()))?;
            // IDA uses single-digit minors: 950 → 9.5.
            return Ok(format!("{}.{}", value / 100, (value % 100) / 10));
        }
    }
    Err(format!("IDA_SDK_VERSION not found in {}", pro_h.display()).into())
}

/// Set rpath to the IDA installation directory for runtime library loading.
/// Adds multiple common IDA installation paths so the binary can find libraries
/// without requiring DYLD_LIBRARY_PATH to be set.
fn set_rpath(install_path: &Path, include_install_path: bool, version: &str) {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "linux") {
            "linux".to_string()
        } else {
            "unknown".to_string()
        }
    });
    // rpaths are an ELF/Mach-O concept; MSVC's linker rejects -Wl,-rpath
    // (LNK4044), and Windows finds IDA's DLLs via the executable's directory.
    if os != "macos" && os != "linux" {
        return;
    }

    // configure_linkage() already adds the selected runtime path when a local
    // IDA install is present. Stub builds still need us to add it explicitly.
    if include_install_path {
        add_rpath(install_path);
    }

    if os == "macos" {
        // Common macOS IDA installation paths (all editions)
        for edition in ["Professional", "Pro", "Home", "Essential"] {
            let path = format!("/Applications/IDA {edition} {version}.app/Contents/MacOS");
            add_rpath_if_not_install(Path::new(&path), install_path);
        }
    } else if os == "linux" {
        // Common Linux IDA installation paths
        let home = env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        for path in [
            format!("{home}/idapro-{version}"),
            format!("{home}/ida-pro-{version}"),
            format!("/opt/idapro-{version}"),
            format!("/opt/ida-pro-{version}"),
            format!("/usr/local/idapro-{version}"),
        ] {
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
