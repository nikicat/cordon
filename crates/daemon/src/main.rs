//! `cordond` — the gater daemon.
//!
//! Wires the rule-model enforcement backend (`bpf-lsm`) to the IPC control plane over
//! a Unix socket (thread-per-connection). The backend runs on its own thread; the IPC
//! threads reach it through a [`ControlSender`] (apply a policy, read the effective
//! one). There is no store/engine — policy is the compiled text file (DESIGN §15).

mod backend;
#[cfg(feature = "bpf-lsm")]
mod btf;
mod ipc;
#[cfg(target_os = "linux")]
mod proc;

use clap::Parser;
use cordon_core::backend::{BackendKind, ControlSender, Shutdown, control};
use cordon_core::config::SocketPath;
use cordon_core::proto::Nonce;
use cordon_core::{Config, config};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::{Mutex, mpsc};
use tracing::{error, info};

/// Shared daemon state + the IPC server behavior over it (the `impl` lives in
/// `ipc.rs`). Held as `Arc<Ctx>`; each connection thread gets a clone.
pub struct Ctx {
    /// Talk to the backend thread: apply a policy, read the effective one.
    pub control: ControlSender,
    pub backend: BackendKind,
    pub socket: PathBuf,
    pub policy: PathBuf,
    /// Blessing requests awaiting a root approval, by nonce (DESIGN §16.5). The value
    /// releases the connection thread parked in `serve_bless_request`; that thread owns
    /// its entry and removes it on every exit path, so there is no reaper and no TTL
    /// sweep — a nonce lives exactly as long as someone is waiting on it.
    pub pending: Mutex<HashMap<Nonce, mpsc::Sender<()>>>,
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
    /// Enforcement backend (only `bpf-lsm`).
    #[arg(long)]
    backend: Option<String>,
    /// Text policy file to compile + seed (overrides the config file).
    #[arg(long)]
    policy: Option<PathBuf>,
}

fn main() -> ExitCode {
    init_tracing();
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "fatal");
            ExitCode::FAILURE
        }
    }
}

/// Logs to stderr; level via `RUST_LOG` (default `info`). Drops the module-path target
/// (`cordond::backend::…` — noise in an audit line, not signal). On a terminal keep ANSI
/// + timestamps; under systemd/journald drop both (journald colours and timestamps).
fn init_tracing() {
    use std::io::IsTerminal;
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let terminal = std::io::stderr().is_terminal();
    let builder = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(terminal);
    if terminal {
        builder.init();
    } else {
        builder.without_time().init();
    }
}

fn run(args: Args) -> cordon_core::Result<()> {
    let mut cfg = Config::load(args.config.as_deref())?;
    if let Some(s) = args.socket {
        cfg.socket = SocketPath::Configured(s);
    }
    if let Some(b) = args.backend {
        cfg.backend = b.parse()?;
    }
    if let Some(p) = args.policy {
        cfg.policy = p;
    }

    let backend = backend::select(&cfg)?;
    info!(
        backend = backend.name(),
        socket = %cfg.socket.path().display(),
        policy = %cfg.policy.display(),
        privilege = if config::is_root() { "root" } else { "user (NOT a boundary)" },
        "cordond started",
    );

    let shutdown = Shutdown::new();
    let (policy_control, control_sender) = control();
    let backend_shutdown = Arc::clone(&shutdown);
    // Log a backend failure the moment `run` returns (a signal-kill never reaches the
    // join below, and a load/attach/verifier failure must be visible).
    let backend_thread = std::thread::spawn(move || {
        let result = backend.run(policy_control, backend_shutdown);
        if let Err(e) = &result {
            error!(error = %e, "backend exited with error");
        }
        result
    });

    let ctx = Arc::new(Ctx {
        control: control_sender,
        backend: cfg.backend,
        socket: cfg.socket.into(),
        policy: cfg.policy,
        pending: Mutex::new(HashMap::new()),
    });

    let serve_result = ctx.serve();
    shutdown.trigger();
    let _ = backend_thread.join();
    serve_result
}
