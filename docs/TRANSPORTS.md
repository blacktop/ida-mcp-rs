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
launched through the task system (`enqueue_task` + poll `task_status`).

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
- `--stateless`: POST-only mode (no sessions)
- `--allow-origin`: comma-separated `Origin` allowlist (default: `http://localhost,http://127.0.0.1`)
- `--allow-host`: comma-separated extra `Host` allowlist for DNS names or
  alternate authorities; pass a quoted `*` or an empty value to disable the check
- `--sse-keep-alive-secs`: keep-alive interval (0 disables)
- `--session-keep-alive-secs`: HTTP session inactivity timeout (defaults to
  1800s with `--max-workers 1`, 300s with pooled workers; 0 disables)
- `--max-workers`: maximum child worker processes for concurrent multi-IDB
  sessions; `1` keeps the legacy in-process worker
- `--min-workers`: idle child workers to keep warm when pooled mode is enabled
- `--worker-disconnect-grace-secs`: reconnect grace before a pooled session is
  closed after the client drops its standalone SSE stream

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

## Shutdown

The server listens for SIGINT/SIGTERM/SIGQUIT and will close the open database
before exiting when possible.
