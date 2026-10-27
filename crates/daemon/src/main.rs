//! The gater daemon. It runs the rule-model enforcement backend (`bpf-lsm`) on its own
//! thread and serves the IPC control plane on a Unix socket, one thread per connection.
//! The IPC threads reach the backend only through a [`ControlSender`]. The policy is the
//! compiled text file (DESIGN §15).

mod backend;
// Both serve only the bpf-lsm backend, so they share its gate (see backend/mod.rs).
#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
mod btf;
mod ipc;
#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
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

/// The daemon state that every IPC connection thread shares through its own `Arc` clone.
/// The server that runs on it lives in `ipc.rs`.
pub struct Ctx {
    /// The channel to the backend thread. It is the only way an IPC thread can apply a
    /// policy or read the effective one.
    pub control: ControlSender,
    pub backend: BackendKind,
    pub socket: PathBuf,
    pub policy: PathBuf,
    /// The blessing requests that await a root approval, by nonce (DESIGN §16.5). Sending
    /// on an entry releases the connection thread parked in `serve_bless_request`. That
    /// thread removes its own entry on every exit path, so a nonce lives exactly as long
    /// as someone waits on it, and nothing needs to reap stale entries.
    pub pending: Mutex<HashMap<Nonce, mpsc::Sender<()>>>,
}

#[derive(Parser, Debug)]
#[command(name = "cordond", about = "cordon gater daemon", version)]
struct Args {
    /// Path of the config file. Overrides $CORDON_CONFIG and the default path.
    #[arg(long)]
    config: Option<PathBuf>,
    /// IPC socket path (overrides the config file).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Enforcement backend. The only one is `bpf-lsm`.
    #[arg(long)]
    backend: Option<String>,
    /// Text policy file to compile and seed (overrides the config file).
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Remove the bpffs pins and exit, disarming enforcement.
    ///
    /// Stopping the daemon deliberately does not stop enforcement. The pinned links keep
    /// the boundary up, so a restart or a crash leaves no gap. This flag is the explicit
    /// way to take it down, and it refuses while a daemon is running.
    ///
    /// It takes effect a moment after it returns. Unlinking a pin drops the link's last
    /// reference, and the kernel then detaches the hooks on a workqueue.
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

/// Installs the global logger, which writes to stderr at the level `RUST_LOG` sets
/// (`info` by default). Text on a terminal keeps colours and timestamps. Text anywhere
/// else, such as under journald, drops both, because journald adds its own.
fn init_tracing(format: LogFormat) {
    use std::io::IsTerminal;
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let terminal = std::io::stderr().is_terminal();
    let builder = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        // The module path (`cordond::backend::…`) is noise in an audit line.
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

/// Runs the daemon, or removes the pins and exits when `args.teardown` is set.
///
/// Errors when the config does not resolve or another daemon holds the socket's lock.
fn run(args: Args) -> cordon_core::Result<()> {
    let cfg = resolve_config(&args)?;

    // Take the lock before the kernel or the socket is touched (see `acquire_singleton`).
    // Teardown takes the same lock, so it refuses while a daemon runs. Removing a live
    // daemon's pins would leave it enforcing on handles nobody can see, and the boundary
    // would be disarmed when that daemon exits.
    let _singleton = acquire_singleton(cfg.socket.path())?;

    if args.teardown {
        return teardown_enforcement(&cfg);
    }
    serve_daemon(cfg)
}

/// Returns the config file's settings with the command-line overrides applied. A flag
/// wins over the file because it is the choice for one run, while the file holds the
/// durable one.
///
/// Errors when the config file or the backend name does not parse.
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

/// Removes the pins (see `PinDir::teardown`) and logs whether enforcement was on.
///
/// It is deliberately loud. This is the one path that reduces protection, and it leaves
/// the box unenforced until a daemon starts again, so the journal should say so plainly.
fn teardown_enforcement(cfg: &Config) -> cordon_core::Result<()> {
    match backend::teardown(cfg)? {
        // Nothing was holding the boundary up; "torn down" would misreport it.
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

/// Runs the enforcement backend on its own thread and the IPC server on this one.
/// Returns when the IPC server stops, after the backend thread has shut down.
///
/// Errors when the backend cannot be built, or with the IPC server's error.
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
    // Log a backend failure the moment `Backend::run` returns. A signal-kill never reaches
    // the join below, and a failure to load, attach or verify must still be visible.
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

/// Returns the path of the singleton lock beside `socket`. The lock is keyed on the
/// socket rather than the bpffs pin directory so that it covers every kind of daemon. A
/// user-mode dev daemon has no pins, but its socket still must not be stolen.
pub fn lock_path(socket: &Path) -> PathBuf {
    let mut p = socket.as_os_str().to_os_string();
    p.push(".lock");
    PathBuf::from(p)
}

/// Takes the lock that allows one daemon per socket, and returns the handle that holds
/// it. The lock is released when the file closes, so a crash frees it with no stale-lock
/// sweep and no pidfile to reconcile. The lock file itself is never unlinked, because the
/// next caller would then lock a fresh inode while the old holder keeps the original.
///
/// Errors when another process holds the lock.
///
/// Without this lock a second daemon silently steals the first one's socket. [`Ctx::serve`]
/// unlinks any socket inode it finds without probing whether anyone is listening. The
/// first daemon then keeps a listener nobody can reach, while every client talks to the
/// second. With the LSM links pinned in bpffs the stakes rise. Two daemons also race over
/// the pin paths, and removing a pin to place your own detaches a boundary whose owner
/// still believes it is enforcing.
fn acquire_singleton(socket: &Path) -> cordon_core::Result<File> {
    let path = lock_path(socket);
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }
    // Not `truncate`, because the lock is the inode and not its contents. Another holder's
    // file must not be disturbed by the attempt to lock it.
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

    /// Checks that a second holder is refused rather than queued behind the first. `flock`
    /// is per open file description, so two `File`s in one process contend exactly as two
    /// processes do. That is what makes this testable without forking.
    #[test]
    fn singleton_refuses_a_second_holder() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let socket = dir.join("cordon.sock");

        let first = acquire_singleton(&socket).expect("first daemon takes the lock");
        let second = acquire_singleton(&socket);
        assert!(second.is_err(), "a second daemon must be refused");

        // …and the lock is the handle. Dropping it makes the socket claimable again with no
        // cleanup step in between, which is the crash path.
        drop(first);
        assert!(acquire_singleton(&socket).is_ok(), "a dead daemon frees it");
    }
}
