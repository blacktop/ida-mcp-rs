//! Headless IDA Pro MCP Server
//!
//! This binary runs an MCP server that provides headless IDA Pro access
//! via stdin/stdout transport.
//!
//! Architecture:
//! - Main thread: Runs IDA worker loop (IDA requires main thread)
//! - Background thread: Runs tokio runtime with async MCP server

use axum::Router;
use clap::{Args, Parser, Subcommand};
use ida_mcp::server::http_access::{HttpAccessPolicy, HttpAccessService};
use ida_mcp::server::http_config::{
    build_session_manager, build_streamable_config, HttpServerOptions,
};
use ida_mcp::server::tool_filter::ToolFilter;
use ida_mcp::server::SanitizedIdaServer;
use ida_mcp::{
    disasm::generate_disasm_line, expand_path, ida, DbInfo, FunctionInfo, IdaMcpServer, IdaWorker,
    ServerMode,
};
use idalib::{idb::IDBOpenOptions, Address, IDB};
use rmcp::transport::stdio;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::ServiceExt;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const REQUEST_QUEUE_CAPACITY: usize = 64;

#[derive(Parser)]
#[command(name = "ida-mcp", version, about = "Headless IDA Pro MCP Server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the MCP server (default)
    Serve(ServeArgs),
    /// Run the MCP server over Streamable HTTP (SSE)
    ServeHttp(ServeHttpArgs),
    /// Run a direct CLI probe to exercise idalib
    Probe(ProbeArgs),
}

/// Tool filter flags shared by both `serve` and `serve-http`.
///
/// Compose order (locked): no include flags → all tools; otherwise the
/// union of `--toolsets` and `--tools`; then `--exclude-tools`; then
/// `--read-only` strips the curated mutating/arbitrary-code deny-list.
/// Flags override env vars (clap behavior with `env =`).
#[derive(Args, Debug, Clone, Default)]
struct ToolFilterArgs {
    /// Categories to include (comma-separated). When set, replaces the
    /// implicit "all tools" default. Example: --toolsets=disassembly,decompile
    #[arg(long, value_delimiter = ',', env = "IDA_MCP_TOOLSETS")]
    toolsets: Vec<String>,
    /// Individual tool names to include (additive to --toolsets).
    /// Example: --tools=open_idb,decompile,callees
    #[arg(long, value_delimiter = ',', env = "IDA_MCP_TOOLS")]
    tools: Vec<String>,
    /// Tool names to exclude (always wins over includes).
    #[arg(long, value_delimiter = ',', env = "IDA_MCP_EXCLUDE_TOOLS")]
    exclude_tools: Vec<String>,
    /// Strip mutating and arbitrary-code tools (run_script, patch, rename,
    /// type/stack edits, dsc_add_*, analyze_funcs). Lifecycle/discovery
    /// tools (open_idb, close_idb, status, catalog, help) stay enabled.
    #[arg(long, env = "IDA_MCP_READ_ONLY")]
    read_only: bool,
}

impl ToolFilterArgs {
    fn build(&self) -> Result<ToolFilter, String> {
        ToolFilter::from_inputs(
            &self.toolsets,
            &self.tools,
            &self.exclude_tools,
            self.read_only,
        )
        .map_err(|e| e.to_string())
    }
}

#[derive(Args, Default)]
struct ServeArgs {
    #[command(flatten)]
    filter: ToolFilterArgs,
}

#[derive(Args)]
struct ServeHttpArgs {
    /// Bind address (e.g., 127.0.0.1:8765)
    #[arg(long, default_value = "127.0.0.1:8765")]
    bind: String,
    /// SSE keep-alive interval in seconds (0 disables)
    #[arg(long, default_value_t = 15)]
    sse_keep_alive_secs: u64,
    /// HTTP session inactivity timeout in seconds (0 disables, but may leak
    /// zombie sessions on silent disconnects). rmcp defaults to 300s, which
    /// kills sessions during long IDA analyses; see issue #19.
    #[arg(long, default_value_t = 1800)]
    session_keep_alive_secs: u64,
    /// Use stateless mode (POST only; no sessions)
    #[arg(long)]
    stateless: bool,
    /// Return application/json in stateless mode instead of SSE framing.
    #[arg(long)]
    json_response: bool,
    /// Allowed Origin values (comma-separated). Defaults to localhost only.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "http://localhost,http://127.0.0.1"
    )]
    allow_origin: Vec<String>,
    /// Extra allowed Host header values (comma-separated). IP-literal hosts
    /// reachable through --bind are accepted automatically; add DNS names here.
    /// Pass `*` or an empty value to disable the Host check.
    #[arg(long, value_delimiter = ',')]
    allow_host: Option<Vec<String>>,
    #[command(flatten)]
    filter: ToolFilterArgs,
}

#[derive(Args)]
struct ProbeArgs {
    /// Path to the .i64/.idb database
    #[arg(long)]
    path: String,
    /// Output .i64/.idb path when opening a raw binary (defaults to <path>.i64)
    #[arg(long)]
    idb_out: Option<String>,
    /// Force auto-analysis (default: on for raw binaries, off for .i64/.idb)
    #[arg(long)]
    auto_analyse: bool,
    /// List the first N functions (optional)
    #[arg(long)]
    list: Option<usize>,
    /// Resolve a function name (optional)
    #[arg(long)]
    resolve: Option<String>,
    /// Disassemble a function by name (optional)
    #[arg(long)]
    disasm_by_name: Option<String>,
    /// Disassemble at an address (hex 0x... or decimal, optional)
    #[arg(long)]
    disasm_addr: Option<String>,
    /// Decompile a function at an address (hex 0x... or decimal, optional)
    #[arg(long)]
    decompile_addr: Option<String>,
    /// Instruction count for disassembly (default: 20)
    #[arg(long, default_value_t = 20)]
    count: usize,
    /// Enable IDA console messages (may be verbose)
    #[arg(long)]
    ida_console: bool,
}

fn main() -> anyhow::Result<()> {
    // Initialize logging to stderr (stdout is used for MCP protocol)
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("ida_mcp=info")))
        .init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve(ServeArgs::default())) {
        Command::Serve(args) => run_server(args),
        Command::ServeHttp(args) => run_server_http(args),
        Command::Probe(args) => run_probe(args),
    }
}

async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigquit = signal(SignalKind::quit())?;
        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
            _ = sigquit.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}

fn init_stdio_ida_state() -> anyhow::Result<ida::IdaInitState> {
    // On Windows, IDA's init_library() probes console handles during
    // startup. In stdio mode the MCP transport captures stdin/stdout
    // for JSON-RPC framing, so init must run *before* the transport
    // starts — otherwise init_library() deadlocks on the owned handle.
    #[cfg(target_os = "windows")]
    {
        ida::init_ida_library()
            .map_err(|e| anyhow::anyhow!("IDA library initialization failed: {e}"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(ida::IdaInitState::deferred())
    }
}

fn run_server(args: ServeArgs) -> anyhow::Result<()> {
    info!("Starting IDA MCP Server (server mode)");
    let filter = Arc::new(
        args.filter
            .build()
            .map_err(|e| anyhow::anyhow!("invalid tool filter: {e}"))?,
    );
    let init_state = init_stdio_ida_state()?;

    // Create channel for IDA requests
    let (tx, rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    let worker = IdaWorker::new(tx);

    // Spawn background thread for tokio runtime and MCP server
    let worker_for_server = worker.clone();
    let worker_for_shutdown = worker.clone();
    let filter_for_server = filter.clone();
    let server_handle = thread::spawn(move || {
        // Create tokio runtime on this background thread
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create tokio runtime: {e}"))?;

        rt.block_on(async move {
            info!("MCP server listening on stdio");
            let server = IdaMcpServer::with_filter(
                Arc::new(worker_for_server),
                ServerMode::Stdio,
                filter_for_server.clone(),
            );
            let sanitized = SanitizedIdaServer::with_filter(server, filter_for_server);
            let mut service = Some(sanitized.serve(stdio()).await?);
            let shutdown_notify = Arc::new(Notify::new());
            let shutdown_signal = shutdown_notify.clone();

            let shutdown_worker = worker_for_shutdown.clone();
            tokio::spawn(async move {
                if wait_for_shutdown_signal().await.is_ok() {
                    info!("Shutdown signal received");
                    let _ = shutdown_worker.close_for_shutdown().await;
                    let _ = shutdown_worker.shutdown().await;
                    shutdown_signal.notify_one();
                } else {
                    info!("Shutdown signal handler failed; server will continue running");
                }
            });

            loop {
                tokio::select! {
                    _ = shutdown_notify.notified() => {
                        if let Some(mut running) = service.take() {
                            let _ = running.close().await?;
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if let Some(running) = service.as_ref() {
                            if running.is_transport_closed() {
                                if let Some(running) = service.take() {
                                    let _ = running.waiting().await?;
                                }
                                break;
                            }
                        }
                    }
                }
            }
            info!("MCP server shutting down");
            let _ = worker_for_shutdown.close_for_shutdown().await;
            let _ = worker_for_shutdown.shutdown().await;
            Ok::<_, anyhow::Error>(())
        })
    });

    // Run IDA worker loop on the main thread after startup preflight.
    info!("Starting IDA worker loop");
    ida::run_ida_loop(rx, init_state);
    info!("IDA worker loop finished");

    // Wait for server thread to finish
    match server_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("Server thread failed: {e}"),
        Err(e) => error!("Server thread panicked: {:?}", e),
    }

    info!("Server stopped");
    Ok(())
}

fn run_server_http(args: ServeHttpArgs) -> anyhow::Result<()> {
    info!("Starting IDA MCP Server (streamable HTTP mode)");
    let filter = Arc::new(
        args.filter
            .build()
            .map_err(|e| anyhow::anyhow!("invalid tool filter: {e}"))?,
    );
    let init_state = ida::IdaInitState::deferred();
    if args.json_response && !args.stateless {
        info!("--json-response is ignored unless --stateless is also set");
    }

    let bind_addr: SocketAddr = args
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;

    let (tx, rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    let worker = Arc::new(IdaWorker::new(tx));

    let worker_for_factory = worker.clone();
    let worker_for_shutdown = worker.clone();
    let filter_for_factory = filter.clone();
    let server_handle = thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                error!("Failed to create tokio runtime: {e}");
                return;
            }
        };

        let result = rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind(bind_addr)
                .await
                .map_err(|e| anyhow::anyhow!("bind failed: {e}"))?;
            let listen_addr = listener
                .local_addr()
                .map_err(|e| anyhow::anyhow!("failed to read listener address: {e}"))?;

            let access_policy = HttpAccessPolicy::from_cli(
                listen_addr,
                &args.allow_origin,
                args.allow_host.as_deref(),
            );
            info!("HTTP Host guard: {}", access_policy.host_policy_summary());

            let session_manager = build_session_manager(args.session_keep_alive_secs);
            let cancel = tokio_util::sync::CancellationToken::new();
            let config = build_streamable_config(
                HttpServerOptions {
                    sse_keep_alive_secs: args.sse_keep_alive_secs,
                    stateless: args.stateless,
                    json_response: args.json_response,
                },
                cancel.clone(),
            );

            let service = StreamableHttpService::new(
                move || {
                    let inner = IdaMcpServer::with_filter(
                        worker_for_factory.clone(),
                        ServerMode::Http,
                        filter_for_factory.clone(),
                    );
                    Ok(SanitizedIdaServer::with_filter(
                        inner,
                        filter_for_factory.clone(),
                    ))
                },
                session_manager,
                config,
            );
            let service = HttpAccessService::new(service, access_policy);

            let router = Router::new().route_service("/", service);
            info!("MCP HTTP server listening on http://{listen_addr}");

            let shutdown_worker = worker_for_shutdown.clone();
            let cancel_for_shutdown = cancel.clone();
            tokio::spawn(async move {
                if wait_for_shutdown_signal().await.is_ok() {
                    info!("Shutdown signal received");
                    let _ = shutdown_worker.close_for_shutdown().await;
                    let _ = shutdown_worker.shutdown().await;
                    cancel_for_shutdown.cancel();
                }
            });

            let cancel_for_serve = cancel.clone();
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    cancel_for_serve.cancelled().await;
                    info!("HTTP server shutting down");
                })
                .await
                .map_err(|e| anyhow::anyhow!("serve failed: {e}"))?;
            Ok::<_, anyhow::Error>(())
        });
        if let Err(err) = result {
            error!("HTTP server error: {err}");
        }
    });

    info!("Starting IDA worker loop");
    ida::run_ida_loop(rx, init_state);
    info!("IDA worker loop finished");

    if let Err(e) = server_handle.join() {
        error!("Server thread panicked: {:?}", e);
    }

    info!("Server stopped");
    Ok(())
}

fn run_probe(args: ProbeArgs) -> anyhow::Result<()> {
    info!("Starting IDA MCP Server (probe mode)");
    if let Ok(idadir) = std::env::var("IDADIR") {
        info!("IDADIR={}", idadir);
    }
    info!("Initializing IDA library on main thread");
    idalib::init_library()
        .map_err(|e| anyhow::anyhow!("IDA library initialization failed: {e}"))?;
    info!("IDA library initialized successfully");
    if let Ok(ver) = idalib::version() {
        info!(
            "IDA version {}.{}.{}",
            ver.major(),
            ver.minor(),
            ver.build()
        );
    }
    if args.ida_console {
        idalib::enable_console_messages(true)
            .map_err(|e| anyhow::anyhow!("failed to enable console messages: {e}"))?;
        info!("IDA console messages enabled");
    }

    let path = expand_path(&args.path);
    info!("Opening database: {}", path.display());

    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();
    let path_display = path.display().to_string();
    let ticker = thread::spawn(move || {
        let start = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(10));
            if done_clone.load(Ordering::Relaxed) {
                break;
            }
            info!(
                path = %path_display,
                elapsed = start.elapsed().as_secs(),
                "Still opening database..."
            );
        }
    });

    let open_start = Instant::now();
    let db = open_db_for_probe(&path, &args);
    done.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    let db =
        db.map_err(|e| anyhow::anyhow!("Failed to open database: {}: {}", path.display(), e))?;

    let meta = db.meta();
    let info = DbInfo {
        path: path.display().to_string(),
        file_type: format!("{:?}", meta.filetype()),
        processor: db.processor().long_name(),
        bits: if meta.is_64bit() {
            64
        } else if meta.is_32bit_exactly() {
            32
        } else {
            16
        },
        function_count: db.function_count(),
        debug_info: None,
        analysis_status: ida::handlers::analysis::build_analysis_status(&db),
    };
    info!("Database opened in {}s", open_start.elapsed().as_secs());
    println!("{}", serde_json::to_string_pretty(&info)?);

    if let Some(limit) = args.list {
        let list = list_functions(&db, 0, limit);
        println!("{}", serde_json::to_string_pretty(&list)?);
    }

    if let Some(name) = args.resolve.as_deref() {
        let func = resolve_function(&db, name)?;
        println!("{}", serde_json::to_string_pretty(&func)?);
    }

    if let Some(name) = args.disasm_by_name.as_deref() {
        let text = disasm_by_name(&db, name, args.count)?;
        println!("{}", text);
    }

    if let Some(addr_str) = args.disasm_addr.as_deref() {
        let addr = parse_address(addr_str)?;
        let text = disasm_at(&db, addr, args.count)?;
        println!("{}", text);
    }

    if let Some(addr_str) = args.decompile_addr.as_deref() {
        let addr = parse_address(addr_str)?;
        let func = db
            .function_at(addr)
            .ok_or_else(|| anyhow::anyhow!("Function not found at address {:#x}", addr))?;
        if !db.decompiler_available() {
            return Err(anyhow::anyhow!("Decompiler not available"));
        }
        let cfunc = db
            .decompile(&func)
            .map_err(|e| anyhow::anyhow!("Decompile failed: {}", e))?;
        println!("{}", cfunc.pseudocode());
    }

    info!("Probe completed");
    Ok(())
}

fn open_db_for_probe(path: &PathBuf, args: &ProbeArgs) -> Result<IDB, idalib::IDAError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_idb = ext == "i64" || ext == "idb" || ext == "id0";
    let init_args = probe_init_database_args();

    if is_idb {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(args.auto_analyse).save(true);
        for arg in &init_args {
            opts.arg(arg);
        }
        if args.auto_analyse {
            info!("Opening existing IDB with auto-analysis enabled");
        }
        opts.open(path)
    } else {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(true);
        let out_path = if let Some(out) = args.idb_out.as_deref() {
            PathBuf::from(out)
        } else {
            idb_path_for_raw_binary(path)
        };
        info!(
            "Opening raw binary with auto-analysis (idb_out={})",
            out_path.display()
        );
        for arg in &init_args {
            opts.arg(arg);
        }
        opts.idb(&out_path).save(true).open(path)
    }
}

fn idb_path_for_raw_binary(path: &Path) -> PathBuf {
    let mut raw_idb = OsString::from(path.as_os_str());
    raw_idb.push(".i64");
    PathBuf::from(raw_idb)
}

fn probe_init_database_args() -> Vec<String> {
    vec!["-A".to_string()]
}

fn parse_address(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|_| anyhow::anyhow!("Invalid address format: {}", s))
    } else {
        s.parse::<u64>()
            .map_err(|_| anyhow::anyhow!("Invalid address format: {}", s))
    }
}

fn list_functions(db: &IDB, offset: usize, limit: usize) -> ida_mcp::FunctionListResult {
    let total = db.function_count();
    let mut functions = Vec::with_capacity(limit.min(total.saturating_sub(offset)));

    for (idx, (_id, func)) in db.functions().enumerate() {
        if idx < offset {
            continue;
        }
        if functions.len() >= limit {
            break;
        }

        let addr = func.start_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));
        let size = func.len();

        functions.push(FunctionInfo {
            address: format!("{:#x}", addr),
            name,
            size,
        });
    }

    let next_offset = if offset + functions.len() < total {
        Some(offset + functions.len())
    } else {
        None
    };

    ida_mcp::FunctionListResult {
        functions,
        total,
        next_offset,
    }
}

fn resolve_function(db: &IDB, name: &str) -> anyhow::Result<FunctionInfo> {
    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name() {
            if func_name == name || func_name.contains(name) {
                let addr = func.start_address();
                let size = func.len();
                return Ok(FunctionInfo {
                    address: format!("{:#x}", addr),
                    name: func_name,
                    size,
                });
            }
        }
    }

    Err(anyhow::anyhow!("Function not found: {}", name))
}

fn disasm_by_name(db: &IDB, name: &str, count: usize) -> anyhow::Result<String> {
    let func = resolve_function(db, name)?;
    let addr = parse_address(&func.address)?;
    disasm_at(db, addr, count)
}

fn disasm_at(db: &IDB, addr: Address, count: usize) -> anyhow::Result<String> {
    let mut lines = Vec::with_capacity(count);
    let mut current_addr: Address = addr;

    for _ in 0..count {
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            break;
        }

        if let Some(insn) = db.insn_at(current_addr) {
            current_addr += insn.len() as u64;
        } else if let Some(next) = db.next_head(current_addr) {
            if next <= current_addr {
                break;
            }
            current_addr = next;
        } else {
            break;
        }
    }

    if lines.is_empty() {
        return Err(anyhow::anyhow!("Address out of range: {:#x}", addr));
    }

    Ok(lines.join("\n"))
}
