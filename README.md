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

## Why ida-mcp

- **Built for Apple targets.** Universal Mach-O slice selection, dSYM/DWARF
  loading, and dyld_shared_cache module and dylib loading are single tool
  calls with explicit parameters, not scripts the agent has to write. In a
  measured Claude Code run, selecting and analyzing the x86_64 slice of a
  universal binary took one call and about five seconds.
- **Fast and lean.** A native Rust server driving IDA through idalib. The
  28-tool `--profile=lean` cost 25% less than the full set in the
  [October 2026 Claude Code benchmark](bench/README.md), with the same task
  success rate. The full set is available when you need it.
- **Safe to leave running.** Exact-target edits, `save_idb` checkpoints,
  analysis flushed to disk as soon as it finishes, bounded graceful shutdown,
  and automatic replacement of crashed or wedged IDA workers.
- **Scriptable when the tools run out.** `run_script` returns a trailing
  expression as JSON and keeps state between calls, so one script can find,
  filter, and return only what matters.

## Prerequisites

- Released IDA Pro 9.5 with a valid license and the same host architecture as ida-mcp
- A Hex-Rays decompiler for the target processor when using pseudocode tools
- Working IDAPython when using `run_script`

Open IDA once and complete its first-launch setup, including reviewing and
accepting the license agreement yourself. The 9.5.0 release was validated with
IDA `9.5.261026` on macOS ARM64, Linux ARM64, and Windows ARM64.

## Getting started

### Install

**macOS / Linux** (via [Homebrew](https://brew.sh))
```bash
brew install blacktop/tap/ida-mcp        # Latest (IDA 9.5)
```

**macOS (Apple Silicon), older IDA releases** (via versioned Homebrew casks)
```bash
brew install blacktop/tap/ida-mcp@9.4    # IDA 9.4
brew install blacktop/tap/ida-mcp@9.3    # IDA 9.3/9.3sp1
brew install blacktop/tap/ida-mcp@9.2    # IDA 9.2
```

**Windows** (via [Scoop](https://scoop.sh))
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
```

> **Windows note:** see [Windows](#windows) below for DLL discovery options.

**macOS / Linux** (via [Nix](https://nixos.org))
```bash
nix shell github:blacktop/nur#ida-mcp \
  --extra-experimental-features 'nix-command flakes'
```

**Direct download:** [GitHub Releases](https://github.com/blacktop/ida-mcp-rs/releases/latest)
provides archives for macOS, Linux, and Windows, each for ARM64 and x86_64.
Each release includes `checksums.txt`.

**Build from source:** see [docs/BUILDING.md](docs/BUILDING.md).

> ida-mcp versions follow IDA Pro versions: `v9.5.x` for IDA 9.5, `v9.4.x` for IDA 9.4, `v9.3.x` for IDA 9.3, and `v9.2.x` for IDA 9.2. ida-mcp checks compatibility when it initializes IDA. An incompatible version causes IDA-backed tools to fail with an error identifying the detected version and, when available, the loaded library path. Scoop and NUR publish only the latest version. For an older IDA, use the matching [GitHub Release](https://github.com/blacktop/ida-mcp-rs/releases) or, on Apple Silicon, a versioned Homebrew cask.

#### Upgrading from the IDA 9.5 beta

Install the released IDA 9.5 runtime before switching to the stable server.
The `9.5.261001` beta uses a different Hex-Rays API and can report
`Decompiler not available` with the released SDK. If both installations are
present, make sure the server loads the released runtime.

For Homebrew, replace the beta cask with the stable cask:
```bash
brew uninstall --cask ida-mcp@beta
brew install blacktop/tap/ida-mcp
```

### Platform setup

#### macOS

Standard IDA installs in `/Applications` work without extra setup.

If a library cannot be loaded, or an older IDA install is selected, set
`DYLD_LIBRARY_PATH` for the server process:
```bash
env DYLD_LIBRARY_PATH='/path/to/IDA.app/Contents/MacOS' ida-mcp --version
```

Use the same environment setting in your MCP client configuration.

Paths found automatically:
- `/Applications/IDA Professional 9.5.app/Contents/MacOS`
- `/Applications/IDA Pro 9.5.app/Contents/MacOS`
- `/Applications/IDA Home 9.5.app/Contents/MacOS`
- `/Applications/IDA Essential 9.5.app/Contents/MacOS`

#### Linux

Linux release archives contain the `ida-mcp` launcher and `ida-mcp-bin`.
Keep both files in the same directory. The launcher looks for IDA at
`~/ida-pro-9.5` by default.

For another install location, set `IDADIR` for the launcher:
```bash
env IDADIR='/path/to/ida' ida-mcp --version
```

The launcher adds that directory to `LD_LIBRARY_PATH`; otherwise the binary's
RUNPATH fallbacks apply. A source-built binary has its preferred IDA path set
at build time. Rebuild it with the desired `IDADIR`, or set `LD_LIBRARY_PATH`
when launching it. See [Building from Source](docs/BUILDING.md#rpath).

#### Windows

**Option A:** put `ida-mcp.exe` in your IDA directory. This is the simplest route and needs no environment setup:
```powershell
# Copy the binary next to ida.dll / idalib.dll
copy ida-mcp.exe "C:\Program Files\IDA Professional 9.5\"
claude mcp add ida -- "C:\Program Files\IDA Professional 9.5\ida-mcp.exe"
```

**Option B:** install with [Scoop](https://scoop.sh), which finds IDA and sets `IDADIR`:
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
claude mcp add ida -- ida-mcp
```

**Option C:** set `IDADIR` yourself:
```powershell
$idaDir = "C:\Program Files\IDA Professional 9.5"
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

Windows has to find `ida.dll` and `idalib.dll` before `ida-mcp` starts. Putting `ida-mcp.exe` in the IDA directory is the easiest way. Otherwise, set `IDADIR` and add the same directory to `PATH` so the DLLs load at runtime.

Common IDA paths:
- `C:\Program Files\IDA Professional 9.5`
- `C:\Program Files\IDA Pro 9.5`
- `C:\Program Files\IDA Home 9.5`

### Runtime requirements

The binary links against IDA's libraries at runtime. Baked-in RPATHs cover the standard install paths. For anything else:

| Platform | Library | Fallback Configuration |
|----------|---------|------------------------|
| macOS | `libida.dylib`, `libidalib.dylib` | `DYLD_LIBRARY_PATH` |
| Linux | `libida.so`, `libidalib.so` | `IDADIR` (release launcher) or `LD_LIBRARY_PATH` |
| Windows | `ida.dll`, `idalib.dll` | Place exe in IDA dir, or set `IDADIR` and add IDA dir to `PATH` |

### Verify the installation

Check the server version, then use `probe` with a binary you want to analyze:

```bash
ida-mcp --version
mkdir -p ~/ida-work
ida-mcp probe --path /path/to/sample --idb-out ~/ida-work/sample.i64 --list 5
```

`--version` checks that the executable starts; `probe` also initializes IDA,
opens the input, and reports the loaded runtime. Use `ida-mcp --help` and
`ida-mcp serve-http --help` for the available startup options.

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

Once your agent is configured, it can drive the tools directly:

```
# Open one binary. Raw inputs default to analysis disabled.
open_idb(path: "~/samples/malware", idb_out: "~/ida-work/sample.i64")

# Check readiness, then run analysis when functions or xrefs are incomplete
analysis_status()
analyze_funcs(background: true)   # returns task_id
task_status(task_id: "analyze-<random>") # poll progress (ID from the analyze_funcs response)

# After analysis completes, inspect functions and resolve a real address
list_functions(limit: 20)
resolve_function(name: "main")
decompile(address: "<address returned by resolve_function>")
strings(limit: 10)

# Discover more tools
tool_catalog(query: "find callers")

# Save edits and release the database when finished
save_idb()
close_idb()
```

Tools that change the database (`rename`, `set_comments`, `patch`, `patch_asm`,
`apply_types`, `declare_stack`, `delete_stack`, and `lumina_apply`) take exactly
one address or one symbol name. Names must match exactly, case included. A near
miss changes nothing and returns up to eight similar names with their addresses.
A returned `target` record identifies the database, resolved symbol (or `null`),
and requested and effective addresses. Check the operation's result to determine
whether the change succeeded.

For Hex-Rays locals and arguments, use `list_lvars` with one function address
or exact `target_name`. `rename_lvar` and `set_lvar_type` take the same function
selector plus exactly one of `lvar_locator` or `lvar_name`. Prefer the opaque
`locator` returned by `list_lvars`: display names such as `v1` can move to a
different local after a prototype change. A stale or ambiguous locator fails
without making a change. Locals without a locator are edited by exact, unique
name.
The tools return the variable as it was before the edit and the resolved
function target. Use `save_idb` to checkpoint edits to disk.

```text
list_lvars(target_name: "interesting_function")
rename_lvar(target_name: "interesting_function", lvar_locator: "<locator from list_lvars>", new_name: "count")
set_lvar_type(target_name: "interesting_function", lvar_locator: "<locator from list_lvars>", decl: "unsigned int")
save_idb()
```

`list_lvars` is in the `decompile` toolset, `rename_lvar` in `editing`, and
`set_lvar_type` in `types`. Add them to lean with
`--profile=lean --tools=list_lvars,rename_lvar,set_lvar_type`.

For end-of-line comments in Hex-Rays pseudocode, use
`list_pseudocode_comments` with one function address or exact `target_name`.
It returns each commentable line's opaque `locator`, address, text, and
existing comment, paginated like `list_lvars`. Pass one `locator` to
`set_pseudocode_comment` as `comment_locator`; an empty comment removes it. A stale locator fails
without making a change; list the locations again after reanalysis.
`set_comments` edits disassembly comments, which pseudocode does not show.

```text
list_pseudocode_comments(target_name: "interesting_function")
set_pseudocode_comment(target_name: "interesting_function", comment_locator: "<locator from list_pseudocode_comments>", comment: "validated input")
save_idb()
```

`list_pseudocode_comments` is in the `decompile` toolset and
`set_pseudocode_comment` in `editing`.

## Opening binaries

### Raw blobs

Raw inputs use IDA's normal loader by default and save to `<input>.i64`. Pass
`idb_out` to put the database somewhere else, for example when the input
directory is read-only. An existing database is reused only when the input
SHA-256 recorded in it matches the current file. `rebuild: true` overwrites a
database only when its recorded hash or input path shows it was built from this
input.

For headerless blobs, `open_idb` also takes typed loader hints:

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

Processor families with several modes need an explicit IDA processor variant,
so bare names such as `arm` or `metapc` are rejected. The hints apply only when
creating a database from a raw input; they never change an existing
`.i64`/`.idb`. On 32-bit ARM, an odd `entry_point` is a Thumb pointer: ida-mcp
clears bit 0 for the code address and records the Thumb state before creating
the entry instruction.

### Universal (fat) Mach-O

When IDA loads a fat binary headlessly, it takes the x86_64 slice whenever one
exists, and it doesn't recognize 64-bit fat headers at all. So `open_idb` picks
the slice itself. Pass `arch` (for example `arm64e` or `x86_64`), or leave it out
and answer the prompt if your client supports input requests.

If no answer comes back, the call fails and lists the slices so an unattended
agent can retry with `arch`. That covers clients that can't prompt, a declined
prompt, and pre-2026 clients that don't reply within 30 seconds. MCP 2026
clients get the question back in the response and retry with the answer, so
the server never sits waiting on them.

The chosen slice is copied to `<input name>.<arch>` next to the output database
and opened as a single-architecture Mach-O. An identical copy already at that
path is reused; a different file there is never overwritten. The response's
`universal` field names the slice, and `loader` shows what IDA loaded.

### `dyld_shared_cache`

`open_dsc` opens one module from Apple's dyld_shared_cache. On IDA 9.4+, ida-mcp
reads the DSC header directly and loads images through IDA's native `dscu`
service. Older IDA builds fall back to the legacy `idat` background flow when a
`.i64` has to be generated.

```
# Open a module from the DSC
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib")

# If open_dsc returns a task_id, poll until done
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

## IDAPython scripting

`run_script` runs Python in the open database through IDA's IDAPython engine
and returns what the script wrote to stdout and stderr. A trailing expression
is returned as `result`, so a script can compute, filter, and hand back only
what matters:

- `result` is strict JSON of at most 1 MiB. A larger result fails the call
  rather than being truncated; return a smaller value or print a summary.
- A value that is not JSON-serializable (custom objects, `NaN`/`Infinity`,
  circular references) is returned as the string of its `repr()` with
  `result_is_repr: true`. So is any value containing an integer outside
  −2⁶³ … 2⁶⁴−1, which the server's JSON reader cannot hold exactly.

Imports, variables, and functions persist between calls on the same open
database.

```
# Inline script
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f))")

# Run a .py file from disk
run_script(file: "/path/to/analysis_script.py")

# Build state in one call, return a value from the next
run_script(code: "import idautils\nfuncs = list(idautils.Functions())")
run_script(code: "{'count': len(funcs), 'first': hex(funcs[0]) if funcs else None}")

# With timeout (default 120s, max 600s)
run_script(code: "import ida_bytes; print(ida_bytes.get_bytes(0x1000, 16).hex())",
           timeout_secs: 30)
```

All `ida_*` modules, `idc`, and `idautils` are available. See the [IDAPython API reference](https://python.docs.hex-rays.com).

## Structured results

`analysis_status`, `list_functions`, `resolve_function`, `function_at`,
`xrefs_to`, `xrefs_from`, `strings`, `list_lvars`, and
`list_pseudocode_comments` advertise an `outputSchema` and return
`structuredContent` alongside the same JSON as text. `rename_lvar`,
`set_lvar_type`, and `set_pseudocode_comment` also return structured results
but omit their output schemas to keep the tool inventory smaller. Other tools
return JSON text only; tools whose result is a bare array or a per-call shape
have no schema yet.

## Saving and crash handling

`save_idb` writes the open database to disk without closing it and returns
the database path it wrote. Use it to checkpoint renames, comments, types, and
patches; `close_idb` also saves. If the client exits without closing, the
server attempts a graceful shutdown on stdin EOF and on SIGTERM, SIGINT,
SIGQUIT, or SIGHUP, which closes and packs the open database; the log names
the signal. Default stdio and HTTP allow up to 120 seconds for the active
operation to settle and the database to save before retiring the child. A SIGKILL
skips graceful shutdown, and a caught
SDK crash deliberately discards unsaved changes, so `save_idb` remains the
only guarantee for edits. Finished auto-analysis is flushed to the database
as soon as a raw open or `analyze_funcs` completes, because some MCP clients
(Claude Code among them) end servers with SIGKILL when the conversation ends;
after such a kill the analysis is on disk and only later edits are lost.

Stdio JSON-RPC messages are limited to 16 MiB. An oversized request receives a
correlated error when its ID is recoverable from the bounded prefix. Otherwise
the server logs and discards the frame, leaving the connection open. The same
applies when the ID leaves no room for a bounded response. Oversized replies
return an error warning that the operation may already have changed the database.

If a call crashes inside the IDA SDK (SIGSEGV/SIGBUS), ida-mcp returns an error
for that call (a top-level error even from batch tools that normally report
per-item failures) and then stops using that database state: the database is closed
without saving, so changes since the last `save_idb` are lost, and the child
worker is replaced (stdio, HTTP, and `--workspace`). Call
`open_idb` again to continue.

The default stdio and HTTP servers run IDA in one supervised child process (the same
binary in `worker` mode), as pooled HTTP (`--max-workers N`) and `--workspace`
do. A call that overruns its `timeout_secs` (or the 1800 s operation watchdog,
`--workspace-worker-op-timeout-secs` for stdio, `--worker-op-timeout-secs` for
HTTP) kills that child and returns a timeout:
the database is then no longer open, changes since the last `save_idb` are
lost, and the next `open_idb` gets a fresh worker. If its replacement is still
starting, that open waits for startup, bounded to 30 seconds. This is what makes a
native IDA call that never returns recoverable; nothing can interrupt it in
place. On shared HTTP, cancelling a request or disconnecting stops that
client's wait; an already dispatched call continues under its watchdog so
other clients keep their database and unsaved edits.

### Removed tools

| Removed | Use instead |
|---|---|
| `list_funcs` | `list_functions` (same parameters) |
| `get_u8`, `get_u16`, `get_u32`, `get_u64` | `read_int` with `size` 1, 2, 4, or 8 |
| `int_convert` | no replacement; do the conversion client-side or in `run_script` |

Update `--tools` / `--exclude-tools` lists that name the removed tools; an
unknown name is rejected at startup.

## Multiple databases and HTTP

### Workspace mode (opt-in)

By default ida-mcp works on one implicit database, so tool calls don't carry a
handle. To keep several databases open at once, start with `--workspace`:

```bash
ida-mcp --workspace --workspace-max-workers 4
ida-mcp --workspace serve-http --bind 127.0.0.1:8765 --stateless
```

In workspace mode, each `open_idb`/`open_dsc` returns a `database_id`, and every
database-scoped call must send it. Runtime tools such as `tool_catalog` reject
it. `close_idb(database_id: ...)` closes only that handle. Idle handles are
reaped after 30 minutes; `--workspace-idle-timeout-secs 0` turns that off.

`list_databases` returns every routed `database_id` with its database path and
state (`open`, `busy`, or `no_worker`). An agent that lost a response, or
reconnected over stateless HTTP, can use it to find an open database again
instead of leaving it stranded until the idle timeout. It is read-only and only
appears when the server runs with `--workspace`.

### HTTP/SSE worker pool

`serve-http` shares one supervised IDA child by default. To serve several
stateful HTTP/SSE clients at once, set `--max-workers` above `1`. Each session
then gets its own child `ida-mcp worker` process:

```bash
ida-mcp serve-http --bind 127.0.0.1:8765 --max-workers 4 --min-workers 1
```

Without `--max-workers N`, all HTTP sessions share one IDA context. A second
client that opens another binary waits behind the first, then gets the usual
`A database is already open` error. Pooled startup logs include
`Starting pooled HTTP router` and `MCP pooled HTTP server listening`.

An HTTP session holds its worker from the first open until `close_idb`, HTTP
`DELETE`, session timeout, or server shutdown. `close_idb` releases the worker
right away, but the child process may stay alive for reuse until
`--worker-idle-timeout-secs` passes. When every worker is taken, new
`open_idb`/`open_dsc` calls fail with `Worker pool exhausted` so clients can
retry later. Pooled mode needs stateful HTTP sessions, so `--max-workers > 1`
is rejected together with `--stateless`.

If an SSE client exits without sending `close_idb` or HTTP `DELETE`, pooled
mode closes its session once the standalone SSE stream disconnects and the
`--worker-disconnect-grace-secs` reconnect window runs out. POST-only clients
don't always leave a stream to watch, so their abandoned sessions are reclaimed
by `--session-keep-alive-secs` (default 1800 seconds). Lower it if you need
pooled workers back sooner.

### MCP 2026-07-28

MCP `2026-07-28` uses the sessionless `server/discover` lifecycle. ida-mcp
supports it over stdio and in the default single-worker HTTP mode, including
multi-round elicitation and the `io.modelcontextprotocol/tasks` extension for
background `open_dsc` calls.

Pooled HTTP (`--max-workers > 1`) advertises protocol versions only up to
`2025-11-25`. Its workers are tied to sessions, and MCP 2026 has no session ID
to route on, so a request could reach a different IDA worker. MCP 2026 requests
to pooled HTTP fail with an unsupported protocol-version error instead.

## Headless debugger (experimental)

Debugger tools are off by default. On supported platforms (Apple Silicon macOS
for now), start with `--enable-debugger` or `IDA_MCP_ENABLE_DEBUGGER=true` to add
`debug_status`, `debug_launch`, `debug_attach`, `debug_modules`, and
`debug_stop`. `debug_open_module` also needs `--workspace`, because it opens the
runtime image in a new database and leaves the database that owns the live
debug session alone:

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

`debug_open_module` opens standalone binaries and dlopen'd plugins directly. On
macOS it also resolves system libraries such as `/usr/lib/libobjc.A.dylib`
through the host dyld shared cache for the target's architecture, then loads the
image with the native DSC service available in IDA 9.4 and later. It doesn't extract a temporary
dylib or run `idat`.

`debug_open_module` always requires `idb_out`. Runtime modules often live in
read-only system directories, and ida-mcp won't silently write an IDB next to
them. The response includes a checked runtime slide; the new database stays at
its on-disk preferred addresses.

In workspace mode, a launched or attached debug session pins its database so
the idle timeout skips it, until `debug_stop` succeeds or `close_idb` releases
the database.

Known limitations:

- **A target that exits on its own keeps its pin.** IDA caches the process
  state and refreshes it only when a call drains the pending debug event, so
  ida-mcp can't see a debuggee die in the background. The database stays
  pinned, and exempt from the idle timeout, until `debug_stop`, `close_idb`, or
  worker loss clears it. Both `debug_stop` and `close_idb` handle an
  already-exited target correctly.
- **Losing the worker doesn't stop the debuggee.** If the worker hosting a live
  session is killed, crashes, or is retired by ida-mcp after a wedged debugger
  call, it may never run its own teardown. IDA's debug-server helper can then be
  reparented instead of terminated, and the target may keep running. When an
  in-flight call detects or causes the retirement, ida-mcp returns a
  `Debugger session lost` error that says the target may still be alive, and
  clears the handle's debug pin. It never claims the debuggee ended. A leased
  worker can also die with no request in flight to carry an error;
  `list_databases` may briefly show `no_worker` before the reaper removes that
  handle, even with idle eviction disabled. Cleaning up a stray helper or
  debuggee is manual for now.

ida-mcp picks IDA's signed loopback helper from the opened database's target
architecture: `mac_server_arm` for ARM64 and `mac_server` for x86/x86_64. macOS
may require IDA's "Take Control" authorization once per login; until it's
granted, tools report `user_action_required`. ida-mcp does not ask for root,
disable SIP, edit `authorizationdb`, or re-sign binaries.

Linux and Windows don't advertise the debugger tools at all. IDA's ARM Linux
debugger only works remotely, and ida-mcp doesn't expose remote configuration.
The SDK has no Windows-on-ARM user-mode debugger. The native ARM64 test
harnesses on both platforms check that the tools stay unavailable. x86 Linux
and Windows stay off until a local debugger run passes on them.

## Lumina

ida-mcp turns off IDA's automatic Lumina lookup by default, so starting the
server or opening a database doesn't contact `lumina.hex-rays.com`. The setting
lives only in ida-mcp's private IDA user profile; your normal IDA GUI profile is
untouched. IDA on Windows keeps its settings in the registry rather than under
`IDAUSR`, so there ida-mcp also uses a process-local registry mapping. If
ida-mcp can't set up the private profile, it refuses to start.

To let IDA use its configured Lumina servers, opt in for that process:

```bash
ida-mcp --allow-lumina
```

The environment variable equivalent is `IDA_MCP_ALLOW_LUMINA=true`.

Two tools use it. Both are listed by default, but until you opt in they fail with
an error telling you to restart with `--allow-lumina`:

- `lumina_lookup` queries one function and reports the available metadata
  without changing the database.
- `lumina_apply` pulls and applies metadata using IDA's upgrade policy.
  `force: true` may replace existing names, types, or comments.

`--read-only` removes `lumina_apply` but keeps `lumina_lookup`, since a lookup
doesn't modify the database.

## Context optimization

By default `tools/list` returns 76 tools. In 9.5.0, its compact tool array is
about 62.2 KB of JSON, or roughly 15.5k tokens using the `measure-tools` estimate.
Six debugger tools are gated by `--enable-debugger` on supported hosts;
`debug_open_module` also needs `--workspace`. The seventh opt-in tool,
`list_databases`, appears in workspace mode. Clients with dynamic tool discovery defer
the schema cost; clients that preload schemas pay it every session. To trim the
surface to what you need:

| Flag | Env var | Effect |
|---|---|---|
| `--profile=lean`       | `IDA_MCP_PROFILE`       | Starts from the 28-tool `lean` set (below) instead of all tools |
| `--toolsets=cat1,cat2` | `IDA_MCP_TOOLSETS` | Replaces "all tools" with the union of selected categories |
| `--tools=t1,t2`        | `IDA_MCP_TOOLS`         | Adds individual tools (additive to `--toolsets`) |
| `--exclude-tools=t1,t2`| `IDA_MCP_EXCLUDE_TOOLS` | Subtracts from the include set; always wins |
| `--read-only`          | `IDA_MCP_READ_ONLY`     | Strips mutating/arbitrary-code tools (`run_script`, `save_idb`, `patch*`, `rename`, comment setters, `lumina_apply`, type/stack edits, `dsc_add_*`, `analyze_funcs`, and debugger process control); keeps lifecycle/discovery |

With no flags you get all 76 baseline tools. Categories: `core`, `functions`,
`disassembly`, `decompile`, `xrefs`, `control_flow`, `memory`, `search`,
`metadata`, `types`, `editing`, `scripting`; `debug` exists only when the
debugger is enabled on a supported platform (run `tool_catalog` to list them).
Flags override env vars, and unknown names are rejected at startup.

`--read-only` filters the exposed MCP tools. Database lifecycle calls remain
available and can create or save IDB files; it is not a filesystem sandbox.

### The `lean` profile

`--profile=lean` advertises 28 tools, about 26.3 KB of `tools/list` JSON, chosen for Apple
reverse engineering: opening binaries, caches and debug info
(`open_idb`, `open_dsc`, `dsc_add_dylib`, `dsc_add_region`, `load_debug_info`,
`analysis_status`, `analyze_funcs`, `save_idb`, `close_idb`, `task_status`),
reading code and references (`list_functions`, `resolve_function`,
`function_at`, `disasm`, `decompile`, `xrefs_to`, `xrefs_from`, `callers`,
`callees`, `strings`, `find_bytes`, `search`, `segments`, `imports`,
`exports`), annotating (`rename`, `set_comments`), and `run_script` for
everything else. `tool_catalog`/`tool_help` are left out because the schemas
are already advertised; the server instructions adapt to whatever is enabled.
The profile composes with the other flags: `--tools` adds to it,
`--exclude-tools` and `--read-only` subtract (`--profile=lean --read-only` is
21 tools, 21.9 KB). The default stays the full set for compatibility; the
profile is the measured recommendation for Claude Code (below).

```bash
ida-mcp --profile=lean
```

Measured with `bench/` (Claude Code 2.1.288, Sonnet 5.5, medium effort,
three trials per cell, 2026-10-03) on an annotate / string-xrefs / universal
Mach-O task mix: both profiles completed all nine conversations correctly.
Lean cost 25% less than full ($0.275 vs $0.367), used 42 vs 52 tool calls,
and recorded 0 vs 1 MCP tool errors; cache-read input fell from 849,325 to
442,166 tokens. The saving is almost all cache-read tokens from the smaller
inventory, so it applies to clients that send the tool list with every
request. No other client was measured. See [the benchmark harness](bench/README.md)
for the tasks, correctness oracles, and reproduction instructions.

### Recommendations by client

- **Claude Code:** use `--profile=lean` for the Apple RE workflows covered by the benchmark. Add `--tools` for anything you need beyond it.
- **Clients that load every schema into context:** choose a focused subset to reduce the advertised tool list:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile,xrefs
  ```
- **Clients with deferred tool discovery:** the full default is useful for broad work. Filters still let you constrain the operations available to the agent. A read-only disassembly setup is:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile --read-only
  ```
- **Small / local models:** use the smallest surface that works. For triage:
  ```bash
  ida-mcp --toolsets=core,functions --tools=decompile,callees,callers --read-only
  ```

### Configuring through `mcpServers.json`

Most MCP configs run `ida-mcp` with no subcommand. The env vars work there too:

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

`just measure-tools` prints a per-tool character count and a rough token estimate.
It measures the full default list unless filter environment variables are set.
For example, `env IDA_MCP_PROFILE=lean just measure-tools` measures the lean
profile. For the client's actual token usage, use its context view (`/context`
in Claude Code, or the equivalent elsewhere).

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - Build from source
- [docs/TESTING.md](docs/TESTING.md) - Running tests

## License

MIT Copyright (c) 2026 **blacktop**
