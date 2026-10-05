# Transports

## Stdio (default)

- Single-client, simplest setup.
- Use with CLI agents that launch a child process.
- Uses one implicit database by default, served by one supervised IDA child
  process: a call that overruns its bound kills the child (the database is
  no longer open; reopen it) and the next open starts a fresh one. Idle
  reaping is off in this mode; `--workspace-worker-op-timeout-secs` sets the
  watchdog. Add `--workspace` when an agent needs several explicit database
  handles in one stdio connection.

```bash
./target/release/ida-mcp

# Explicit multi-database workspace
./target/release/ida-mcp --workspace --workspace-max-workers 4
```

### Progress observability

The server does not emit MCP `notifications/progress` messages. On stdio they
race with the response on fast tools (under ~100 ms): Node-based clients
(e.g. Claude Code) deliver coalesced messages in a single `data` event and
process the response — which retires the `progressToken` — before the
notification handlers run, dropping the transport with "unknown progress
token". Phase progress is recorded server-side instead and surfaced via the
`recent_operations` tool. Long-running work (e.g. `analyze_funcs`) should be
launched with the tool's background option and polled through `task_status`.
Clients declaring the MCP Tasks extension also receive native task handles for
background `open_dsc` calls.

## Streamable HTTP (multi-client transport)

- Supports multiple clients over HTTP.
- By default, those clients share one IDA worker and one active IDB context.
- Explicit workspace mode routes calls by `database_id` and works with both
  stateful and stateless HTTP.
- Legacy pooled mode binds one child worker to each stateful HTTP session. It
  remains available for clients that cannot send explicit database handles.
- Responses use SSE where streaming is applicable; sessionless requests can
  prefer JSON framing with `--json-response`.
- The server validates `Origin` and `Host` headers. IP-literal `Host` values
  that are reachable through the bind address are accepted automatically; DNS
  names must be added with `--allow-host`.

```bash
./target/release/ida-mcp serve-http --bind 127.0.0.1:8765

# Concurrent multi-IDB sessions
./target/release/ida-mcp serve-http \
  --bind 127.0.0.1:8765 \
  --max-workers 4 \
  --min-workers 1

# Explicit handles over sessionless HTTP
./target/release/ida-mcp --workspace serve-http \
  --bind 127.0.0.1:8765 \
  --stateless

# Exposing on a LAN by IP address
./target/release/ida-mcp serve-http \
  --bind 0.0.0.0:8765 \
  --allow-origin http://10.0.0.5:8765

# Exposing on a LAN by DNS name
./target/release/ida-mcp serve-http \
  --bind 0.0.0.0:8765 \
  --allow-host ida-box.local \
  --allow-origin http://ida-box.local:8765
```

Options (workspace flags are global):

- `--workspace`: enable explicit multi-database routing. `open_idb` and
  `open_dsc` return a `database_id`; every database-scoped call must send it.
- `--workspace-max-workers`: maximum child workers used by explicit workspace
  mode (default 4). Legacy `--max-workers`/`--min-workers` do not configure a
  workspace.
- `--workspace-idle-timeout-secs`: seconds before an unpinned idle database
  handle is closed and removed (default 1800; 0 disables database TTL).
- `--workspace-worker-idle-timeout-secs`: seconds before an idle workspace
  child process is reaped (default 300; 0 disables worker reaping).
- `--workspace-worker-op-timeout-secs`: workspace child-operation watchdog
  (default 1800; must be at least 1).
- `--stateless`: force POST-only mode for legacy protocols. MCP `2026-07-28`
  is always sessionless, with or without this flag.
- `--json-response`: prefer `application/json` over SSE framing for
  sessionless responses (`--stateless` mode and all MCP `2026-07-28`
  requests)
- `--max-request-body-mib`: maximum accepted request body (default 16, range
  1-1024). Bulk `patch` sends binary as hex at ~2x the raw size and
  `run_script` sends whole sources, so rmcp's 4 MiB default is too small; the
  endpoint is unauthenticated and each in-flight request can retain up to this
  much, so raise it deliberately. Over-cap requests get a transport-level HTTP
  413 that names the limit, outside the JSON-RPC envelope.
- `--allow-origin`: comma-separated `Origin` allowlist (default: `http://localhost,http://127.0.0.1`)
- `--allow-host`: comma-separated extra `Host` allowlist for DNS names or
  alternate authorities; pass a quoted `*` or an empty value to disable the check
- `--sse-keep-alive-secs`: keep-alive interval (0 disables)
- `--session-keep-alive-secs`: HTTP session inactivity timeout (default 1800s;
  0 disables). In pooled mode this is the fallback reclaim for POST-only
  clients — SSE clients are reclaimed faster via `--worker-disconnect-grace-secs`.
- `--max-workers`: maximum child worker processes for concurrent multi-IDB
  sessions; `1` shares one supervised child and disables idle reaping
- `--min-workers`: idle child workers to keep warm when pooled mode is enabled
- `--worker-idle-timeout-secs`: seconds before an idle pooled worker process is
  reaped (default 300s; 0 disables)
- `--worker-op-timeout-secs`: per-child operation watchdog (default 1800s).
  The parent kills a child that exceeds it; this guards against wedged
  workers, not normal long analysis.
- `--worker-disconnect-grace-secs`: reconnect grace before a pooled session is
  closed after the client drops its standalone SSE stream

## Protocol lifecycle

The server supports the legacy `initialize` lifecycle from `2024-11-05`
through `2025-11-25`. MCP `2026-07-28` uses `server/discover` and per-request
metadata instead; it is supported on stdio and single-worker HTTP. Single-worker
HTTP shares task, operation, and MRTR state across the fresh handler instances
created for sessionless requests. Background tasks (DSC loading, auto-analysis)
spawned by a legacy session are cancelled when that session closes; tasks
spawned by sessionless MCP 2026 requests outlive their request and run until
completion, `tasks/cancel`, or server shutdown. Legacy task IDs are scoped to
their owning session for deduplication, polling, updates, and cancellation; a
different legacy session receives the same response as it would for an unknown
ID. Stdio task ownership remains connection-scoped even if request metadata is
present on only some messages. Sessionless HTTP requests share the runtime task
owner because MCP 2026 provides no stable session identity across requests.
Under `--stateless`, every HTTP request is served by a per-request handler
regardless of protocol version, so legacy requests there also use the shared
runtime owner and lifetime — their background tasks survive the request and
stay pollable across requests. Within that shared owner, the task ID is the
only access credential: IDs carry full per-task randomness and should be
treated like a `close_token`, not logged or shared.

Task cancellation is cooperative. A cancellation request signals the active
operation, but the task remains `working` while an uncancellable synchronous
IDA call settles. Only then does the server publish the terminal `cancelled`
state, so a terminal task never has IDA work still running behind it. The
legacy idat subprocess is the exception: cancellation kills it, reaps it, and
removes its partial database output before publishing `cancelled`, so a later
`open_dsc` cannot reuse a half-written database.

Pooled HTTP (`--max-workers > 1`) is intentionally limited to protocol versions
through `2025-11-25`. Its IDA worker lease is bound to a legacy HTTP session,
while MCP 2026 removes sessions. The server advertises that boundary through
`server/discover` and rejects MCP 2026 requests rather than losing worker
affinity between calls. Tool calls that carry the full sessionless request
metadata with a legacy protocol version are rejected for the same reason: the
transport routes them without a session, which would lease a fresh IDA worker
per request.

Workspace mode works across sessionless requests because the client sends a
`database_id` on every database-scoped call. `open_idb` and `open_dsc` return
the ID; `list_databases` can recover it after a lost response or reconnect.
Runtime tools such as `tool_catalog` do not accept a database ID.

## Concurrency model

IDA requires main-thread access, and one IDA process can own only one active
database at a time. Default stdio and single-worker HTTP serialize calls through
one supervised child worker. HTTP clients share its database and close-token
ownership; a retired child loses that binding and the next open creates a new one.
Cancelling a shared HTTP request leaves any dispatched call running under its
watchdog. Graceful shutdown allows up to 120 seconds for the active call to
settle and the database to save before it cancels background tasks or retires
the child.

With `--workspace`, each open database owns a child-worker lease addressed by
its `database_id`. Calls to different handles can run concurrently up to
`--workspace-max-workers`. `close_idb` removes only the selected handle. Idle,
unpinned handles are removed after `--workspace-idle-timeout-secs`; active
debug sessions pin their lease until `debug_stop`, `close_idb`, or worker loss.
Database TTL and child-process idle reaping are separate controls.

With legacy `--max-workers N` where `N > 1`, each opened HTTP session leases a
child worker instead. The lease lasts until `close_idb`, HTTP `DELETE`, session
timeout, or server shutdown. If an SSE-capable client exits without closing,
the disconnect grace reclaims it; POST-only legacy clients fall back to
`--session-keep-alive-secs`. Both modes use the same registry internally, but
clients address them differently: `database_id` for workspace mode, HTTP
session for the legacy pool.

## Logging and sensitive payloads

Tool spans record only sanitized fields (paths, sizes, booleans) — never
ownership tokens, MRTR state, elicitation answers, script sources, patch
bytes, or comment/rename text.

Scope the filter when troubleshooting: `RUST_LOG=ida_mcp=debug`. A bare
`RUST_LOG=debug` also enables the MCP SDK's own request logging, which writes
whole JSON-RPC envelopes — including tool arguments — to stderr.

Application logs use a nonblocking stderr queue capped at 256 events and
16 KiB per event. Oversized events are truncated and excess events are dropped
when the reader falls behind, so logging cannot stop worker deadlines or hold
shutdown open. Child processes inherit stderr directly.

## Known limitations

- **Sessionless `close_token` recovery outside workspace mode.** Under MCP 2026
  every HTTP request is a fresh ownership context, so re-opening an already-open
  implicit database does not re-issue its `close_token`. A client that lost the
  token from the original `open_idb` response must use `close_idb` with
  `force=true`. Workspace clients instead recover the explicit handle with
  `list_databases` and close it by `database_id`.
- **Single active operation marker.** Single-worker HTTP shares one operation
  registry across all clients: `recent_operations` reports one active
  operation at a time and its history is visible to every connected client
  (including target file paths). Concurrent clients can each see the other's
  operations misattributed as the active one during timeout triage.
- **No task enumeration.** The MCP tasks extension (SEP-2663) defines
  `tasks/get`, `tasks/update`, and `tasks/cancel` only. Clients that used the
  experimental `tasks/list` / `tasks/result` methods from pre-3.0 rmcp SDKs
  must retain the `task_id` returned by the spawning tool call; a task whose
  id is lost can only be waited out.
- **Bounded task retention.** The server retains up to 256 running and terminal
  tasks. Terminal results normally remain available for the advertised 24-hour
  TTL, but the TTL is an upper bound, not a guarantee: when the registry hits
  its cap, admitting new background work reclaims the least recently updated
  terminal results early. Running tasks are never reclaimed, so a registry
  full of in-flight work still rejects new background work until something
  settles. Fetch results promptly rather than relying on the full TTL.

## Shutdown

The server listens for SIGINT/SIGTERM/SIGQUIT/SIGHUP and will close the open
database before exiting when possible. Default stdio also handles stdin EOF.
It allows up to 120 seconds for the active operation and database save, then
shuts down the supervised pool and retires any remaining child. Unsaved changes
can be lost if closing IDA exceeds that bound.
