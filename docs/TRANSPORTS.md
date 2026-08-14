# Transports

## Stdio (default)

- Single-client, simplest setup.
- Use with CLI agents that launch a child process.

```bash
./target/release/ida-mcp
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
- For concurrent multi-IDB analysis, set `--max-workers` above `1` to enable
  the child-process worker pool.
- SSE is used for streaming responses within this transport.
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

Options:
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
  sessions; `1` keeps the legacy in-process worker
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

## Concurrency model

IDA requires main-thread access, and one IDA process can own only one active
database at a time. With `--max-workers 1`, all HTTP sessions are serialized
through one worker loop. With `--max-workers N` where `N > 1`, each opened HTTP
session leases a child `ida-mcp worker` process, so different sessions can own
different IDBs concurrently until `close_idb`, HTTP `DELETE`, session timeout,
or server shutdown. `close_idb` releases the lease immediately; the child
process can remain idle for reuse until `--worker-idle-timeout-secs` elapses.
If an SSE-capable client exits without sending `close_idb` or HTTP `DELETE`,
pooled mode closes the abandoned session when its standalone SSE stream
disconnects and the reconnect grace elapses. POST-only clients have no
persistent stream to observe, so their orphaned sessions are reclaimed by
`--session-keep-alive-secs`.

## Logging and sensitive payloads

Tool spans record only sanitized fields (paths, sizes, booleans) — never
ownership tokens, MRTR state, elicitation answers, script sources, patch
bytes, or comment/rename text.

Scope the filter when troubleshooting: `RUST_LOG=ida_mcp=debug`. A bare
`RUST_LOG=debug` also enables the MCP SDK's own request logging, which writes
whole JSON-RPC envelopes — including tool arguments — to stderr.

## Known limitations

- **Sessionless `close_token` recovery.** Under MCP 2026 every HTTP request is
  a fresh ownership context, so re-opening an already-open database does not
  re-issue its `close_token`. A client that lost the token from the original
  `open_idb` response must use `close_idb` with `force=true` to release the
  database.
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

The server listens for SIGINT/SIGTERM/SIGQUIT and will close the open database
before exiting when possible.
