//! `cordond` — the gater daemon.
//!
//! Wires the privilege-agnostic policy core to an enforcement backend and serves
//! the IPC control plane over a Unix socket (thread-per-connection). It holds the
//! engine behind a `Mutex` so the backend thread and IPC threads share one store.
//! Dev runs the `mock` backend (`systemctl --user`); the real Linux boundary is
//! the root `fanotify` backend.

mod backend;
mod ipc;
#[cfg(target_os = "linux")]
mod proc;

use clap::Parser;
use cordon_core::backend::{BackendKind, Shutdown};
use cordon_core::{Config, Engine, Mode, Store, config};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{error, info};

/// Shared daemon state + the IPC server behavior over it (see `ipc.rs` for the
/// `impl`). Held as `Arc<Ctx>`; each connection thread gets a clone.
pub struct Ctx {
    pub engine: Arc<Mutex<Engine>>,
    pub backend: BackendKind,
    pub mode: Mode,
    pub store: PathBuf,
    pub socket: PathBuf,
}

#[derive(Parser, Debug)]
#[command(name = "cordond", about = "cordon gater daemon", version)]
struct Args {
    /// Config file path (overrides $CORDON_CONFIG / default).
    #[arg(long)]
    config: Option<PathBuf>,
    /// IPC socket path (overrides the config file).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// SQLite store path (overrides the config file).
    #[arg(long)]
    store: Option<PathBuf>,
    /// Enforcement backend: `mock` (dev) or `fanotify` (Linux, root).
    #[arg(long)]
    backend: Option<String>,
    /// Enforcement mode: `enforce` (block) or `audit` (log would-deny, allow).
    #[arg(long)]
    mode: Option<String>,
}

fn main() -> std::process::ExitCode {
    init_tracing();
    match run(Args::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "fatal");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Logs to stderr; level via `RUST_LOG` (default `info`).
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn run(args: Args) -> cordon_core::Result<()> {
    // Config file (with ${ENV} interpolation) + built-in defaults, then CLI
    // overrides on top.
    let mut cfg = Config::load(args.config.as_deref())?;
    if let Some(s) = args.socket {
        cfg.socket = s;
    }
    if let Some(s) = args.store {
        cfg.store = s;
    }
    if let Some(b) = args.backend {
        cfg.backend = b.parse()?;
    }
    if let Some(m) = args.mode {
        cfg.mode = m.parse()?;
    }

    let store = Store::open(&cfg.store)?;
    if store.seed_zones(&cfg.zones)? {
        info!("seeded zones");
    }
    let engine = Arc::new(Mutex::new(Engine::new(store)?));

    let backend = backend::select(cfg.backend, cfg.mode)?;

    info!(
        backend = backend.name(),
        mode = cfg.mode.as_str(),
        store = %cfg.store.display(),
        socket = %cfg.socket.display(),
        privilege = if config::is_root() { "root" } else { "user (NOT a boundary)" },
        "cordond started",
    );

    let shutdown = Shutdown::new();
    let backend_engine = Arc::clone(&engine);
    let backend_shutdown = Arc::clone(&shutdown);
    let backend_thread = std::thread::spawn(move || backend.run(backend_engine, backend_shutdown));

    let ctx = Arc::new(Ctx {
        engine,
        backend: cfg.backend,
        mode: cfg.mode,
        store: cfg.store,
        socket: cfg.socket,
    });

    // Serve until the listener fails (or the process is signalled). On the next
    // start a stale socket is unlinked, so an un-graceful exit is harmless.
    let serve_result = ctx.serve();

    shutdown.trigger();
    if let Ok(Err(e)) = backend_thread.join() {
        error!(error = %e, "backend exited with error");
    }
    serve_result
}
