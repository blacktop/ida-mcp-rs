use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (install_path, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);

    if !ida_path.exists() || !idalib_path.exists() {
        println!("cargo::warning=IDA installation not found, using SDK stubs");
        idalib_build::configure_idasdk_linkage();

        // Still set the rpath for runtime, even when building with SDK stubs.
        // This allows the binary to find IDA libraries on the target system.
        set_rpath(&install_path);
    } else {
        // Sets RPATH to IDA installation so libraries are found at runtime
        idalib_build::configure_linkage()?;
    }

    Ok(())
}

/// Set rpath to the IDA installation directory for runtime library loading.
fn set_rpath(install_path: &PathBuf) {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "linux") {
            "linux".to_string()
        } else {
            "unknown".to_string()
        }
    });

    if os == "macos" {
        println!(
            "cargo::rustc-link-arg=-Wl,-rpath,{}",
            install_path.display()
        );
    } else if os == "linux" {
        println!(
            "cargo::rustc-link-arg=-Wl,-rpath,{}",
            install_path.display()
        );
    }
}
