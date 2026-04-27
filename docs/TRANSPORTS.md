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

## Streamable HTTP (multi-client)

- Supports multiple clients over HTTP.
- SSE is used for streaming responses within this transport.
- The server validates `Origin` and `Host` headers; defaults allow loopback only.
  When binding to a non-loopback address, override both allowlists.

```bash
./target/release/ida-mcp serve-http --bind 127.0.0.1:8765
# Exposing on a LAN: authorize the matching Host and Origin values
./target/release/ida-mcp serve-http \
  --bind 0.0.0.0:8765 \
  --allow-host 10.0.0.5 \
  --allow-origin http://10.0.0.5:8765
```

Options:
- `--stateless`: POST-only mode (no sessions)
- `--allow-origin`: comma-separated `Origin` allowlist (default: `http://localhost,http://127.0.0.1`)
- `--allow-host`: comma-separated `Host` allowlist (default: `localhost,127.0.0.1,::1`; pass an empty value to disable the check)
- `--sse-keep-alive-secs`: keep-alive interval (0 disables)

## Concurrency model

IDA requires main-thread access. All IDA operations are serialized through a single
worker loop, while multiple clients can submit requests concurrently.

## Shutdown

The server listens for SIGINT/SIGTERM/SIGQUIT and will close the open database
before exiting when possible.
