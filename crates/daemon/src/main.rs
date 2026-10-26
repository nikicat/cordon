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

use backend::Swept;

use clap::Parser;
use cordon_core::backend::{BackendKind, ControlSender, Shutdown, control};
use cordon_core::config::SocketPath;
use cordon_core::proto::Nonce;
use cordon_core::{Config, Error, config};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
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
    /// Remove the bpffs pins and exit, disarming enforcement.
    ///
    /// Stopping the daemon deliberately does *not* stop enforcement — the pinned links
    /// keep the boundary up so a restart or a crash is gapless. This is the explicit way
    /// to take it down, and it refuses while a daemon is running.
    ///
    /// Takes effect a moment after it returns: unlinking a pin drops the link's last
    /// reference and the kernel detaches the hooks on a workqueue.
    #[arg(long)]
    teardown: bool,
    /// Log line format. `json` writes one object per line, with each record's fields as
    /// top-level keys and an `event` key on the records a tool would wait for.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let args = Args::parse();
    init_tracing(args.log_format);
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "fatal");
            ExitCode::FAILURE
        }
    }
}

/// Logs to stderr; level via `RUST_LOG` (default `info`). Drops the module-path target
/// (`cordond::backend::…` — noise in an audit line, not signal). As text, on a terminal
/// keep ANSI + timestamps; under systemd/journald drop both (journald colours and
/// timestamps).
fn init_tracing(format: LogFormat) {
    use std::io::IsTerminal;
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let terminal = std::io::stderr().is_terminal();
    let builder = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(terminal);
    if let LogFormat::Json = format {
        builder.json().flatten_event(true).init();
    } else if terminal {
        builder.init();
    } else {
        builder.without_time().init();
    }
}

/// Resolve what to run, take the one lock both modes need, then do one of the two things
/// this binary does.
fn run(args: Args) -> cordon_core::Result<()> {
    let cfg = resolve_config(&args)?;

    // Before the kernel or the socket is touched: exactly one daemon per socket. Teardown
    // takes the same lock — removing a live daemon's pins would leave it enforcing on
    // handles nobody can see, and disarm the boundary the moment it happened to exit.
    let _singleton = acquire_singleton(cfg.socket.path())?;

    if args.teardown {
        return teardown_enforcement(&cfg);
    }
    serve_daemon(cfg)
}

/// The config file, then the CLI overrides on top. Flags win because they are the
/// per-invocation knob; the file is the durable answer.
fn resolve_config(args: &Args) -> cordon_core::Result<Config> {
    let mut cfg = Config::load(args.config.as_deref())?;
    if let Some(s) = &args.socket {
        cfg.socket = SocketPath::Configured(s.clone());
    }
    if let Some(b) = &args.backend {
        cfg.backend = b.parse()?;
    }
    if let Some(p) = &args.policy {
        cfg.policy = p.clone();
    }
    Ok(cfg)
}

/// `--teardown`: drop the pins that let enforcement outlive the daemon, and exit.
///
/// Deliberately loud. This is the one path that *reduces* protection, and it leaves the
/// box unenforced until a daemon starts again — so the journal should say so plainly
/// rather than exiting silently.
fn teardown_enforcement(cfg: &Config) -> cordon_core::Result<()> {
    match backend::teardown(cfg)? {
        // Not the same event, and saying "torn down" here would misreport the posture:
        // nothing was holding the boundary up in the first place.
        Swept::Nothing => info!(
            event = "teardown",
            generations = 0,
            pin_dir = %cfg.bpf_pin_dir.display(),
            "nothing was pinned — enforcement was already off, no change",
        ),
        Swept::Generations(n) => info!(
            event = "teardown",
            generations = n.get(),
            pin_dir = %cfg.bpf_pin_dir.display(),
            "enforcement torn down — the boundary is OFF until cordond starts again",
        ),
    }
    Ok(())
}

/// The daemon proper: the enforcement backend on its own thread, the IPC server on this
/// one. Returns when the IPC server stops.
fn serve_daemon(cfg: Config) -> cordon_core::Result<()> {
    let backend = backend::select(&cfg)?;
    info!(
        backend = cfg.backend.as_str(),
        socket = %cfg.socket.path().display(),
        policy = %cfg.policy.display(),
        privilege = if config::is_root() { "root" } else { "user (NOT a boundary)" },
        "cordond started",
    );

    let shutdown = Shutdown::new();
    let (policy_control, control_sender) = control();
    let backend_shutdown = Arc::clone(&shutdown);
    // Log a backend failure the moment `Backend::run` returns (a signal-kill never reaches
    // the join below, and a load/attach/verifier failure must be visible).
    let backend_thread = std::thread::spawn(move || {
        let result = backend.run(policy_control, backend_shutdown);
        if let Err(e) = &result {
            error!(event = "backend_failed", error = %e, "backend exited with error");
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

/// The singleton lock beside the socket. Keyed on the socket rather than the bpffs pin
/// directory so it covers every daemon flavour — a user-mode dev daemon has no pins but
/// still must not have its socket stolen.
pub fn lock_path(socket: &Path) -> PathBuf {
    let mut p = socket.as_os_str().to_os_string();
    p.push(".lock");
    PathBuf::from(p)
}

/// One daemon per socket. The returned handle **is** the lock — it is released when the
/// file closes, so a crash frees it with no stale-lock sweep and no pidfile to reconcile.
/// The lock file itself is never unlinked: removing it would let the next caller lock a
/// fresh inode while the old one still holds the original.
///
/// Without this a second daemon **silently steals the first one's socket**. [`Ctx::serve`]
/// unlinks any socket inode it finds without probing whether anyone is listening, so the
/// first daemon keeps running with a listener nobody can reach while every client talks to
/// the second. Once the LSM links are bpffs-pinned the stakes rise: two daemons also race
/// over the pin paths, and removing a pin to place your own detaches a boundary whose owner
/// still believes it is enforcing.
fn acquire_singleton(socket: &Path) -> cordon_core::Result<File> {
    let path = lock_path(socket);
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }
    // Not `truncate`: the lock is the inode, not its contents, and another holder's file
    // must not be disturbed by the attempt to lock it.
    let file = File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            error!(event = "already_running", socket = %socket.display(), "another cordond holds the lock");
            Err(Error::msg(format!(
                "another cordond is already running on {}; stop it first",
                socket.display()
            )))
        }
        Err(std::fs::TryLockError::Error(e)) => {
            Err(Error::msg(format!("cordond: lock {}: {e}", path.display())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: the second holder is refused rather than queued behind the first.
    /// `flock` is per open-file-description, so two `File`s in one process contend exactly
    /// as two processes do — which is what makes this testable without forking.
    #[test]
    fn singleton_refuses_a_second_holder() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let socket = dir.join("cordon.sock");

        let first = acquire_singleton(&socket).expect("first daemon takes the lock");
        let second = acquire_singleton(&socket);
        assert!(second.is_err(), "a second daemon must be refused");

        // …and the lock is the handle: drop it and the socket is claimable again, with no
        // cleanup step in between (this is the crash path).
        drop(first);
        assert!(acquire_singleton(&socket).is_ok(), "a dead daemon frees it");
    }
}
