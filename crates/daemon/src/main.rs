//! `cordond` — the gater daemon.
//!
//! Phase 0 wires the privilege-agnostic policy core to the `mock` backend and
//! serves the IPC control plane over a Unix socket (thread-per-connection). It
//! holds the engine behind a `Mutex` so the backend thread and IPC threads share
//! one store. Phase 1 swaps in the root `fanotify` backend behind the same trait.

mod ipc;

use clap::Parser;
use cordon_core::backend::{Backend, MockBackend, Shutdown};
use cordon_core::{Engine, Store, config};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
    /// Enforcement backend (Phase 0: only `mock`).
    #[arg(long)]
    backend: Option<String>,
}

fn main() -> std::process::ExitCode {
    match run(Args::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cordond: fatal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> cordon_core::Result<()> {
    let socket_path = args.socket.unwrap_or_else(config::socket_path);
    let store_path = args.store.unwrap_or_else(config::store_path);
    let backend_name = args.backend.unwrap_or_else(config::backend_name);

    let store = Store::open(&store_path)?;
    if store.seed_zones(&config::default_zones())? {
        eprintln!("cordond: seeded default zones");
    }
    let engine = Arc::new(Mutex::new(Engine::new(store)?));

    let backend: Box<dyn Backend> = match backend_name.as_str() {
        "mock" => Box::new(MockBackend),
        other => {
            return Err(cordon_core::Error::msg(format!(
                "unknown backend '{other}' (Phase 0 ships only 'mock'). \
                 fanotify/endpoint-security land in later phases."
            )));
        }
    };

    eprintln!(
        "cordond: backend={} store={} socket={} (privilege={})",
        backend.name(),
        store_path.display(),
        socket_path.display(),
        if config::is_root() {
            "root"
        } else {
            "user — NOT a boundary"
        },
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
    let _ = backend_thread.join();
    serve_result
}
