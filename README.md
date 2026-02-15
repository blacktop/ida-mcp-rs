# ida-mcp

Headless IDA Pro MCP server for AI-powered reverse engineering.

## Prerequisites

- IDA 9.3+ (or 9.2) with valid license

## Getting Started

### Install

**macOS** (via [Homebrew](https://brew.sh))
```bash
brew install blacktop/tap/ida-mcp
```

**Linux / Windows**

Download the latest binary for your platform from [GitHub Releases](https://github.com/blacktop/ida-mcp-rs/releases).

**Build from source**

See [docs/BUILDING.md](docs/BUILDING.md).

### Platform Setup

#### macOS

Standard IDA installations in `/Applications` work automatically:
```bash
claude mcp add ida -- ida-mcp
```

If you see `Library not loaded: @rpath/libida.dylib`, set `DYLD_LIBRARY_PATH` to your IDA path:
```bash
claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/IDA.app/Contents/MacOS' -- ida-mcp
```

Supported paths (auto-detected):
- `/Applications/IDA Professional 9.3.app/Contents/MacOS`
- `/Applications/IDA Home 9.3.app/Contents/MacOS`
- `/Applications/IDA Essential 9.3.app/Contents/MacOS`
- `/Applications/IDA Professional 9.2.app/Contents/MacOS`

#### Linux

Standard IDA installations are auto-detected:
```bash
claude mcp add ida -- ida-mcp
```

If you see library loading errors, set `IDADIR`:
```bash
claude mcp add ida -e IDADIR='/path/to/ida' -- ida-mcp
```

Supported paths (auto-detected):
- `/opt/idapro-9.3`, `/opt/idapro-9.2`
- `$HOME/idapro-9.3`, `$HOME/idapro-9.2`
- `/usr/local/idapro-9.3`, `/usr/local/idapro-9.2`

#### Windows

Add your IDA directory to `PATH` (System Properties > Environment Variables):
```powershell
$env:PATH = "C:\Program Files\IDA Professional 9.3;$env:PATH"
claude mcp add ida -- ida-mcp
```

Common Windows IDA paths:
- `C:\Program Files\IDA Professional 9.3`
- `C:\Program Files\IDA Home 9.3`

### Runtime Requirements

The binary links against IDA's libraries at runtime. Standard installation paths are auto-detected via baked RPATHs. For non-standard paths:

| Platform | Library | Fallback Configuration |
|----------|---------|------------------------|
| macOS | `libida.dylib` | `DYLD_LIBRARY_PATH` |
| Linux | `libida.so` | `IDADIR` or `LD_LIBRARY_PATH` |
| Windows | `ida.dll` | Add IDA dir to `PATH` |

### Configure your AI agent

#### [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview)
```bash
claude mcp add ida -- ida-mcp
```

#### [Codex CLI](https://github.com/openai/codex)
```bash
codex mcp add ida -- ida-mcp
```

#### [Gemini CLI](https://github.com/google-gemini/gemini-cli)
```bash
gemini mcp add ida -- ida-mcp
```

#### [Cursor](https://cursor.com)
Add to `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "ida": { "command": "ida-mcp" }
  }
}
```

### Usage

Once configured, you can analyze binaries through your AI agent:

```
# Open a binary (IDA analyzes raw binaries automatically)
open_idb(path: "~/samples/malware")

# Discover available tools
tool_catalog(query: "find callers")

# List functions
list_functions(limit: 20)

# Disassemble by name
disasm_by_name(name: "main", count: 20)

# Decompile (requires Hex-Rays)
decompile(address: "0x100000f00")
```

#### `dyld_shared_cache` analysis

`open_dsc` opens a single module from Apple's dyld_shared_cache. On first use it runs `idat` in the background to create the `.i64` (this can take minutes). Subsequent opens are instant.

```
# Open a module from the DSC
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib")

# If a background task was started, poll until done
task_status(task_id: "dsc-1")

# Load additional frameworks for cross-module references
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib",
         frameworks: ["/System/Library/Frameworks/Foundation.framework/Foundation"])
```

Requirements:
- `idat` binary (from IDA installation) must be available via `$IDADIR` or standard install paths
- The DSC loader and `dscu` plugin (bundled with IDA 9.x)

#### IDAPython scripting

`run_script` executes Python code in the open database via IDA's IDAPython engine. stdout and stderr are captured.

```
# Inline script
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f))")

# Run a .py file from disk
run_script(file: "/path/to/analysis_script.py")

# With timeout (default 120s, max 600s)
run_script(code: "import ida_bytes; print(ida_bytes.get_bytes(0x1000, 16).hex())",
           timeout_secs: 30)
```

All `ida_*` modules, `idc`, and `idautils` are available. See the [IDAPython API reference](https://python.docs.hex-rays.com).

---

The default tool list includes all tools. Use `tool_catalog`/`tool_help` to discover capabilities and avoid dumping the full list into context.

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - Build from source
- [docs/TESTING.md](docs/TESTING.md) - Running tests

## License

MIT Copyright (c) 2026 **blacktop**
