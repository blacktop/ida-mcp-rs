# Building from Source

## Prerequisites

- IDA Pro 9.3+ with valid license
- Rust 1.77+ (stable toolchain)
- LLVM/Clang (for C++ bindings)
- IDA SDK (from Hex-Rays)

## Platform-Specific Setup

### macOS (ARM64)

```bash
# Install Xcode command line tools (provides clang)
xcode-select --install

# Clone and build
git clone https://github.com/blacktop/ida-mcp-rs.git
cd ida-mcp-rs
cargo build --release
```

Default IDA path: `/Applications/IDA Professional 9.3.app/Contents/MacOS`

Override with `IDADIR`:
```bash
IDADIR='/Applications/IDA Home 9.3.app/Contents/MacOS' cargo build --release
```

### Linux (x86_64)

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential llvm clang libclang-dev

# Set IDA path
export IDADIR=/opt/idapro-9.3

# Clone and build
git clone https://github.com/blacktop/ida-mcp-rs.git
cd ida-mcp-rs
cargo build --release
```

Common Linux IDA paths:
- `/opt/idapro-9.3`
- `/home/<user>/idapro-9.3`
- `/usr/local/idapro-9.3`

### Windows (x86_64)

```powershell
# Install LLVM (required for bindgen)
# Option 1: winget
winget install LLVM.LLVM

# Option 2: Download from https://releases.llvm.org/

# Set environment variables
$env:IDADIR = "C:\Program Files\IDA Professional 9.3"
$env:PATH = "$env:IDADIR;$env:PATH"

# Ensure LLVM is in PATH
$env:PATH = "C:\Program Files\LLVM\bin;$env:PATH"

# Clone and build
git clone https://github.com/blacktop/ida-mcp-rs.git
cd ida-mcp-rs
cargo build --release
```

Common Windows IDA paths:
- `C:\Program Files\IDA Professional 9.3`
- `C:\IDA Professional 9.3`
- `C:\Program Files\IDA Home 9.3`

## Build Output

The binary is at:
- Linux/macOS: `target/release/ida-mcp`
- Windows: `target/release/ida-mcp.exe`

## IDA SDK (for CI builds)

CI builds require the IDA SDK. Set `IDASDKDIR` to the SDK path:

```bash
export IDASDKDIR=/path/to/idasdk
cargo build --release
```

## RPATH

The IDA library path is baked into the binary via RPATH at build time. On macOS, this means the binary "just works" if built with the correct `IDADIR`.

On Linux and Windows, users may need to set environment variables at runtime:
- Linux: `IDADIR` or `LD_LIBRARY_PATH`
- Windows: Add IDA directory to `PATH`

## Run modes

```bash
# Stdio (default, single-client)
./target/release/ida-mcp

# Streamable HTTP (multi-client, SSE)
./target/release/ida-mcp serve-http --bind 127.0.0.1:8765

# CLI probe (test IDA connection)
./target/release/ida-mcp probe --path /path/to/binary --list 10
```

## Cross-Compilation

**Not supported.** idalib links against IDA's native libraries at build time. You must build natively on each platform with IDA installed.
