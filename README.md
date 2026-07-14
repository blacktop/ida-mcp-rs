<p align="center">
  <!--<a href="https://github.com/blacktop/ida-mcp-rs"><img alt="Logo" src="https://raw.githubusercontent.com/blacktop/ida-mcp-rs/refs/heads/main/docs/logo.svg" height="400"/></a>-->
  <h1 align="center">ida-mcp-rs</h1>
  <h4><p align="center">Headless IDA Pro MCP server for AI-powered reverse engineering.</p></h4>
  <p align="center">
    <a href="https://github.com/blacktop/ida-mcp-rs/actions" alt="Actions">
          <img src="https://github.com/blacktop/ida-mcp-rs/actions/workflows/build.yml/badge.svg" /></a>
    <a href="https://github.com/blacktop/ida-mcp-rs/releases/latest" alt="Downloads">
          <img src="https://img.shields.io/github/downloads/blacktop/ida-mcp-rs/total.svg" /></a>
    <a href="https://github.com/blacktop/ida-mcp-rs/releases" alt="GitHub Release">
          <img src="https://img.shields.io/github/v/release/blacktop/ida-mcp-rs" /></a>
    <a href="http://doge.mit-license.org" alt="LICENSE">
          <img src="https://img.shields.io/:license-mit-blue.svg" /></a>
</p>
<br>

## Prerequisites

- IDA Pro 9.4 with valid license

## Getting Started

### Install

**macOS / Linux** (via [Homebrew](https://brew.sh))
```bash
brew install blacktop/tap/ida-mcp        # Latest (IDA 9.4)
```

**macOS (Apple Silicon), older IDA releases** (via versioned Homebrew casks)
```bash
brew install blacktop/tap/ida-mcp@9.3    # IDA 9.3/9.3sp1
brew install blacktop/tap/ida-mcp@9.2    # IDA 9.2
```

**Windows** (via [Scoop](https://scoop.sh))
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
```

> **Windows note:** See the [Windows platform setup](#windows) section below for DLL discovery options.

**macOS / Linux** (via [Nix](https://nixos.org))
```bash
nix shell github:blacktop/nur#ida-mcp \
  --extra-experimental-features 'nix-command flakes'
```

**Direct download** — grab the archive for your platform from [GitHub Releases](https://github.com/blacktop/ida-mcp-rs/releases).

**Build from source**

See [docs/BUILDING.md](docs/BUILDING.md).

> ida-mcp versions mirror IDA Pro versions (`v9.4.x` for IDA 9.4, `v9.3.x` for IDA 9.3, and `v9.2.x` for IDA 9.2). A version mismatch is detected at startup with a clear error message. Scoop and NUR publish the latest version. For older IDA versions, use the matching [GitHub Release](https://github.com/blacktop/ida-mcp-rs/releases) or, on Apple Silicon, the versioned Homebrew cask.

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
- `/Applications/IDA Professional 9.4.app/Contents/MacOS`
- `/Applications/IDA Home 9.4.app/Contents/MacOS`
- `/Applications/IDA Essential 9.4.app/Contents/MacOS`

#### Linux

The IDA installer defaults to `~/ida-pro-9.4` — the launcher script auto-detects this:
```bash
claude mcp add ida -- ida-mcp
```

For non-default install locations, set `IDADIR`:
```bash
claude mcp add ida -e IDADIR='/path/to/ida' -- ida-mcp
```

Resolution order: `$IDADIR` → `~/ida-pro-9.4` → `/opt/ida-pro-9.4` and other RUNPATH fallbacks.

#### Windows

**Option A** — Install `ida-mcp.exe` into your IDA directory (simplest, no env setup needed):
```powershell
# Copy the binary next to ida.dll / idalib.dll
copy ida-mcp.exe "C:\Program Files\IDA Professional 9.4\"
claude mcp add ida -- "C:\Program Files\IDA Professional 9.4\ida-mcp.exe"
```

**Option B** — Install via [Scoop](https://scoop.sh) (auto-detects IDA and sets `IDADIR`):
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
claude mcp add ida -- ida-mcp
```

**Option C** — Set `IDADIR` manually:
```powershell
$idaDir = "C:\Program Files\IDA Professional 9.4"
[Environment]::SetEnvironmentVariable("IDADIR", $idaDir, "User")
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ";" | Where-Object { $_ })
if (-not ($pathEntries -contains $idaDir)) {
  [Environment]::SetEnvironmentVariable(
    "Path", (@($pathEntries + $idaDir) -join ";"), "User"
  )
}
# Then restart your terminal
claude mcp add ida -- ida-mcp
```

Windows requires `ida.dll` and `idalib.dll` to be discoverable before `ida-mcp` starts. Placing `ida-mcp.exe` in the IDA directory is the easiest approach. Otherwise, set `IDADIR` for build/install discovery and add the same IDA directory to `PATH` for runtime DLL loading.

Common IDA paths:
- `C:\Program Files\IDA Professional 9.4`
- `C:\Program Files\IDA Pro 9.4`
- `C:\Program Files\IDA Home 9.4`

### Runtime Requirements

The binary links against IDA's libraries at runtime. Standard installation paths are auto-detected via baked RPATHs. For non-standard paths:

| Platform | Library | Fallback Configuration |
|----------|---------|------------------------|
| macOS | `libida.dylib` | `DYLD_LIBRARY_PATH` |
| Linux | `libida.so` | `IDADIR` (launcher reads it) or `LD_LIBRARY_PATH` |
| Windows | `ida.dll` | Place exe in IDA dir, or set `IDADIR` and add IDA dir to `PATH` |

### Configure your AI agent

#### [Claude Code](https://code.claude.com/docs/en/mcp)
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
# Open a binary (returns quickly — analysis runs separately)
open_idb(path: "~/samples/malware")

# These work immediately, no analysis needed
list_functions(limit: 20)
disasm_by_name(name: "main", count: 20)
strings(limit: 10)

# For xrefs/decompile on large binaries, run analysis in background
analyze_funcs(background: true)   # returns task_id
task_status(task_id: "analyze-1") # poll progress

# Decompile (requires Hex-Rays + completed analysis)
decompile(address: "0x100000f00")

# Discover more tools
tool_catalog(query: "find callers")
```

#### HTTP/SSE worker pool

`serve-http` keeps the existing single in-process IDA worker by default. For
stateful multi-client HTTP/SSE usage, set `--max-workers` above `1` to route
sessions through child `ida-mcp worker` processes:

```bash
ida-mcp serve-http --bind 127.0.0.1:8765 --max-workers 4 --min-workers 1
```

Without `--max-workers N`, HTTP sessions still share one IDA context; a second
client opening another binary waits behind the first and then gets the normal
`A database is already open` error. Pooled startup logs include
`Starting pooled HTTP router` and `MCP pooled HTTP server listening`.

Each opened HTTP session leases one child worker until `close_idb`, HTTP
`DELETE`, session timeout, or server shutdown. `close_idb` releases the lease
immediately, but the child process may stay alive idle for reuse until
`--worker-idle-timeout-secs` elapses. If all workers are leased, new
`open_idb`/`open_dsc` calls fail with `Worker pool exhausted` so clients can
retry later. Pooled mode requires stateful HTTP sessions; `--max-workers > 1`
is rejected with `--stateless`.

If an SSE-capable client exits without sending `close_idb` or HTTP `DELETE`,
pooled mode closes the session after its standalone SSE stream disconnects and
the `--worker-disconnect-grace-secs` reconnect grace elapses.
POST-only clients do not always leave a stream for the server to observe, so
their orphaned sessions are reclaimed by `--session-keep-alive-secs` (default
1800 seconds). Lower it if you need faster pool reclaim for POST-only clients.

#### `dyld_shared_cache` analysis

`open_dsc` opens a single module from Apple's dyld_shared_cache. With IDA 9.4, ida-mcp opens the DSC header directly and loads images through IDA's native `dscu` service. Older IDA builds fall back to the legacy `idat` background flow when a generated `.i64` is needed.

```
# Open a module from the DSC
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib")

# If a legacy background task was started, poll until done
task_status(task_id: "dsc-1")

# Load additional frameworks for cross-module references
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib",
         frameworks: ["/System/Library/Frameworks/Foundation.framework/Foundation"])

# Incrementally load another DSC dylib into an already-open database
dsc_add_dylib(module: "/usr/lib/libSystem.B.dylib")

# Incrementally load a DSC data/GOT/stub region by address
dsc_add_region(address: "0x180116000")

# After dsc_add_dylib/dsc_add_region, confirm analysis readiness
analysis_status()
```

Requirements:
- IDA 9.4+ for native `dscu` loading
- For older IDA builds, `idat` must be available via `$IDADIR` or standard install paths

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

## Context Optimization

`ida-mcp` exposes 71 tools (~10k tokens of `tools/list` payload). Clients with dynamic tool discovery defer that cost; clients that preload schemas include it in every session. Filter the surface to only what you need:

| Flag | Env var | Effect |
|---|---|---|
| `--toolsets=cat1,cat2` | `IDA_MCP_TOOLSETS` | Replaces "all tools" with the union of selected categories |
| `--tools=t1,t2`        | `IDA_MCP_TOOLS`         | Adds individual tools (additive to `--toolsets`) |
| `--exclude-tools=t1,t2`| `IDA_MCP_EXCLUDE_TOOLS` | Subtracts from the include set; always wins |
| `--read-only`          | `IDA_MCP_READ_ONLY`     | Strips mutating/arbitrary-code tools (`run_script`, `patch*`, `rename`, `set_comments`, type/stack edits, `dsc_add_*`, `analyze_funcs`); keeps lifecycle/discovery |

No flags = all 71 tools (default). Categories: `core`, `functions`, `disassembly`, `decompile`, `xrefs`, `control_flow`, `memory`, `search`, `metadata`, `types`, `editing`, `scripting` (run `tool_catalog` to enumerate). Flags override env vars; unknown names rejected at startup.

### Recommendations by client

- **Claude Code, Cursor:** no action needed for context usage. Both clients defer MCP tool schemas and discover them on demand. Filtering is still useful when you want to constrain the available capabilities.
- **Codex CLI:** current models with tool-search support defer MCP tools automatically. For models without tool search, or to constrain the available capabilities, pick a focused subset:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile,xrefs
  ```
- **Clients without lazy tool loading:** each session receives the full ~10k-token schema payload. Pick a focused subset as shown above.
- **Gemini CLI:** filtering is optional, but a smaller surface can reduce tool-selection noise when several MCP servers are enabled:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile --read-only
  ```
- **Small / local models:** prefer the smallest workable surface. For triage:
  ```bash
  ida-mcp --toolsets=core,functions --tools=decompile,callees,callers --read-only
  ```

### Configuring through `mcpServers.json`

Most installed MCP configs run `ida-mcp` directly without a subcommand. The env vars apply on that path too:

```json
{
  "mcpServers": {
    "ida-mcp": {
      "command": "ida-mcp",
      "env": {
        "IDA_MCP_TOOLSETS": "core,functions,disassembly,decompile,xrefs",
        "IDA_MCP_READ_ONLY": "true"
      }
    }
  }
}
```

### Measuring

Run `just measure-tools` to see the per-tool char/token breakdown. Filtering doesn't change the numbers reported there (it acts at the protocol boundary), but the difference shows up in your client's context view (`/context` in Claude Code, equivalents elsewhere).

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - Build from source
- [docs/TESTING.md](docs/TESTING.md) - Running tests

## License

MIT Copyright (c) 2026 **blacktop**
