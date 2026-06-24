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
use cordon_core::backend::Shutdown;
use cordon_core::{Engine, Store, config};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{error, info};

/// Shared daemon context handed to each IPC connection.
pub struct Ctx {
    pub engine: Arc<Mutex<Engine>>,
    pub backend: String,
    pub store_path: String,
    pub socket_path: String,
}

#[derive(Parser, Debug)]
#[command(name = "cordond", about = "cordon gater daemon", version)]
struct Args {
    /// IPC socket path (overrides $CORDON_SOCK / default).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// SQLite store path (overrides $CORDON_STORE / default).
    #[arg(long)]
    store: Option<PathBuf>,
    /// Enforcement backend: `mock` (dev) or `fanotify` (Linux, root).
    #[arg(long)]
    backend: Option<String>,
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
    let socket_path = args.socket.unwrap_or_else(config::socket_path);
    let store_path = args.store.unwrap_or_else(config::store_path);
    let backend_name = args.backend.unwrap_or_else(config::backend_name);

    let store = Store::open(&store_path)?;
    if store.seed_zones(&config::default_zones())? {
        info!("seeded default zones");
    }
    let engine = Arc::new(Mutex::new(Engine::new(store)?));

    let backend = backend::select(&backend_name)?;

    info!(
        backend = backend.name(),
        store = %store_path.display(),
        socket = %socket_path.display(),
        privilege = if config::is_root() { "root" } else { "user (NOT a boundary)" },
        "cordond started",
    );

    let shutdown = Shutdown::new();
    let backend_engine = Arc::clone(&engine);
    let backend_shutdown = Arc::clone(&shutdown);
    let backend_thread = std::thread::spawn(move || backend.run(backend_engine, backend_shutdown));

    let ctx = Arc::new(Ctx {
        engine,
        backend: backend_name,
        store_path: store_path.display().to_string(),
        socket_path: socket_path.display().to_string(),
    });

    // Serve until the listener fails (or the process is signalled). On the next
    // start a stale socket is unlinked, so an un-graceful exit is harmless.
    let serve_result = ipc::serve(&socket_path, ctx);

    shutdown.trigger();
    if let Ok(Err(e)) = backend_thread.join() {
        error!(error = %e, "backend exited with error");
    }
    serve_result
}
