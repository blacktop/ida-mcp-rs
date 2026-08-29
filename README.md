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

# Keep the generated database away from a read-only input directory
open_idb(path: "/System/example", idb_out: "~/ida-work/example.i64")

# These work immediately, no analysis needed
list_functions(limit: 20)
disasm_by_name(name: "main", count: 20)
strings(limit: 10)

# For xrefs/decompile on large binaries, run analysis in background
analyze_funcs(background: true)   # returns task_id
task_status(task_id: "analyze-<random>") # poll progress (ID from the analyze_funcs response)

# Decompile (requires Hex-Rays + completed analysis)
decompile(address: "0x100000f00")

# Discover more tools
tool_catalog(query: "find callers")
```

### Raw blobs

Raw inputs still use IDA's normal loader by default and save to `<input>.i64`.
`idb_out` selects another database location, which is useful for read-only input
directories. An existing output is reused only when IDA's recorded input
SHA-256 matches the current file; `rebuild: true` can overwrite only a database
whose hash or recorded input path proves that it belongs to the input.

For headerless blobs, the same `open_idb` tool accepts typed loader hints:

```text
open_idb(
  path: "~/firmware/boot.bin",
  idb_out: "~/ida-work/boot.i64",
  processor: "arm:ARMv7-M",
  bitness: 32,
  base_address: "0x08000000",
  entry_point: "0x08000101"
)
```

Processor families with multiple modes require an explicit IDA processor
variant; ambiguous bare names such as `arm` or `metapc` are rejected. These
target fields apply only while creating a raw-input database and never alter an
existing `.i64`/`.idb`. For 32-bit ARM targets, an odd `entry_point` is treated
as a Thumb pointer: ida-mcp clears bit 0 for the code address and records the
Thumb state before creating the entry instruction.

#### Multi-database workspace (opt-in)

The default remains one implicit IDA database, so existing agent prompts and
tool calls do not need a handle. For headless workflows that deliberately keep
several databases open, start with `--workspace`:

```bash
ida-mcp --workspace --workspace-max-workers 4
ida-mcp --workspace serve-http --bind 127.0.0.1:8765 --stateless
```

In workspace mode, each `open_idb`/`open_dsc` allocates and returns a
`database_id`. Every database-scoped call must send that ID; runtime tools such
as `tool_catalog` reject it. `close_idb(database_id: ...)` invalidates only the
selected handle. Idle handles are reaped after 30 minutes by default; use
`--workspace-idle-timeout-secs 0` to disable that database TTL.

`list_databases` recovers handles: it returns every routed `database_id` with
its database path and lifecycle state (`open`, `busy`, or `no_worker`), so an
agent that lost a response — or reconnected over stateless HTTP — can re-address
an open database instead of stranding it until the TTL expires. It is read-only
and, like every workspace tool, is absent unless the server runs `--workspace`.

Workspace routing and legacy pooled HTTP share one internal registry. The
legacy session behavior below is preserved, but there is no second independent
session-to-worker lease map.

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

#### Headless debugger (experimental opt-in)

Debugger tools are absent from the default schema. On supported builds, add
`--enable-debugger` to expose `debug_status`, `debug_launch`, `debug_attach`,
`debug_modules`, and `debug_stop`. `debug_open_module` additionally requires
`--workspace`, because it opens the selected runtime image in a new database
without replacing the database that owns the live debug session:

```text
debug_status()
debug_launch(database_id: "…", path: "/absolute/path/to/program")
debug_modules(database_id: "…")
debug_open_module(
  database_id: "…",
  module: "/usr/lib/libobjc.A.dylib",
  idb_out: "~/ida-work/libobjc.i64"
)
debug_stop(database_id: "…", action: "auto")
```

`debug_open_module` opens standalone binaries and dlopen'd plugins directly.
On macOS, it also resolves system libraries such as
`/usr/lib/libobjc.A.dylib` through the target architecture's host dyld shared
cache and loads the selected image through IDA 9.4's in-process DSC service;
it does not extract a temporary dylib or invoke `idat`.

`debug_open_module.idb_out` is always required. Runtime modules often live in
read-only system directories, and silently writing an IDB next to them is not a
valid headless workflow. The response includes a checked runtime slide; the new
database remains at its on-disk preferred addresses.

In workspace mode, a successfully launched or attached debug session pins its
database against the idle TTL until `debug_stop` succeeds or `close_idb`
releases the database.

Known limitation — a target that exits on its own keeps its pin. IDA's
process state is a cached value that only refreshes when a call drains the
pending debug event, so a debuggee killed outside ida-mcp is not observable in
the background. Its database stays pinned (and exempt from the idle TTL) until
`debug_stop`, `close_idb`, or worker loss clears it. Both `debug_stop` and
`close_idb` handle an already-exited target correctly.

Known limitation — worker loss does not stop the debuggee. If the worker
process hosting a live debug session is killed, crashes, or ida-mcp retires it
after a wedged debugger call, that process may never run its own teardown, so
IDA's debug-server helper can be reparented instead of terminated and the
target may keep running. When an in-flight tool call detects or causes that
retirement, ida-mcp returns a `Debugger session lost` error saying the target
may still be alive, clears the handle's debug pin, and never claims the
debuggee ended. A leased worker can also die while no request is in flight to
carry an error; `list_databases` may briefly report `no_worker` before the
reaper removes that terminal handle, even when healthy idle eviction is
disabled. Cleaning up a stray helper or debuggee is currently manual.

The first enabled platform is macOS on Apple Silicon. ida-mcp selects IDA's
signed loopback helper from the opened database's target architecture:
`mac_server_arm` for ARM64 and `mac_server` for x86/x86_64. macOS may require
IDA's supported “Take Control” authorization once per login; tools report
`user_action_required` when it is missing. ida-mcp never asks for root, disables
SIP, edits `authorizationdb`, or re-signs binaries. Linux and Windows remain
fail-closed rather than being advertised optimistically: IDA's ARM Linux
backend is remote-only and remote configuration is not exposed, while the SDK
does not provide a Windows-on-ARM user debugger. Their native ARM64 harnesses
pass by proving the debugger surface remains unavailable; x86 Linux and Windows
still require a positive local-backend oracle before advertisement.

MCP `2026-07-28` uses the sessionless `server/discover` lifecycle. It is
supported over stdio and the default single-worker HTTP mode, including
multi-round elicitation and the `io.modelcontextprotocol/tasks` extension for
background `open_dsc` calls. Pooled HTTP (`--max-workers > 1`) deliberately
advertises protocol versions only through `2025-11-25`: its worker lease is
session-affine, and MCP 2026 has no session identifier to preserve that routing
across requests. MCP 2026 requests to pooled HTTP fail with an unsupported
protocol-version error instead of risking dispatch to a different IDA worker.

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
task_status(task_id: "dsc-<random>")  # ID from the open_dsc response

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

## Lumina

`ida-mcp` disables IDA's automatic Lumina lookup by default, so starting the
server or opening a database does not automatically contact
`lumina.hex-rays.com`. The setting is applied only inside ida-mcp's isolated
IDA user profile and does not change the normal IDA GUI profile. On Windows,
ida-mcp also uses a process-local registry mapping because IDA stores its
settings in the Windows registry instead of under `IDAUSR`. Startup fails
closed if the private profile cannot be established.

To allow IDA to use the configured Lumina servers, opt in for that process:

```bash
ida-mcp --allow-lumina
```

The equivalent environment setting is `IDA_MCP_ALLOW_LUMINA=true`.

With that opt-in enabled, two metadata tools are available:

- `lumina_lookup` queries one function and reports the available metadata
  without changing the database.
- `lumina_apply` pulls and applies metadata using IDA's upgrade policy.
  `force: true` may replace existing names, types, or comments.

`lumina_apply` is excluded by `--read-only`; `lumina_lookup` remains available
because it does not modify the database.

---

## Context Optimization

`ida-mcp` exposes the same 75 baseline tools by default (~12k tokens of
`tools/list` payload). Six debugger tools exist behind the explicit gates above,
so installing the new release does not enlarge existing clients' schema.
Clients with dynamic tool discovery defer that cost; clients that preload
schemas include it in every session. Filter the surface to only what you need:

| Flag | Env var | Effect |
|---|---|---|
| `--toolsets=cat1,cat2` | `IDA_MCP_TOOLSETS` | Replaces "all tools" with the union of selected categories |
| `--tools=t1,t2`        | `IDA_MCP_TOOLS`         | Adds individual tools (additive to `--toolsets`) |
| `--exclude-tools=t1,t2`| `IDA_MCP_EXCLUDE_TOOLS` | Subtracts from the include set; always wins |
| `--read-only`          | `IDA_MCP_READ_ONLY`     | Strips mutating/arbitrary-code tools (`run_script`, `patch*`, `rename`, `set_comments`, `lumina_apply`, type/stack edits, `dsc_add_*`, `analyze_funcs`, and debugger process control); keeps lifecycle/discovery |

No flags = all 75 baseline tools (default). Categories: `core`, `functions`,
`disassembly`, `decompile`, `xrefs`, `control_flow`, `memory`, `search`,
`metadata`, `types`, `editing`, `scripting`; `debug` appears only when its
startup/platform gate is active (run `tool_catalog` to enumerate). Flags
override env vars; unknown names are rejected at startup.

### Recommendations by client

- **Claude Code, Cursor:** no action needed for context usage. Both clients defer MCP tool schemas and discover them on demand. Filtering is still useful when you want to constrain the available capabilities.
- **Codex CLI:** current models with tool-search support defer MCP tools automatically. For models without tool search, or to constrain the available capabilities, pick a focused subset:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile,xrefs
  ```
- **Clients without lazy tool loading:** each session receives the full ~11k-token schema payload. Pick a focused subset as shown above.
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
