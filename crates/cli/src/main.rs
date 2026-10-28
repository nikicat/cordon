//! `cordon`, the command-line client for the flat rule model (ADR 0005).
//!
//! The policy lives in a root-owned text file, and this binary is how a person checks it,
//! sends it to the daemon and reads back what is enforced. The daemon compiles the policy
//! and seeds the in-kernel maps. Only `policy check` compiles locally, without a daemon.

mod bless;
mod edit;
mod sys;

use clap::{Parser, Subcommand};
use cordon_core::policy::PolicyRoot;
use cordon_core::proto::{Conn, Nonce, Pid, Request, Response};
use cordon_core::{Config, Error, Result, policy};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "cordon",
    about = "cordon — object-centric secret-dir gater",
    version
)]
struct Cli {
    /// Path to the config file, which names the socket and the policy. Overrides
    /// $CORDON_CONFIG and the default location.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Path to the daemon socket. Overrides the config file.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Print the raw JSON response instead of a rendered view.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Show the daemon's state and a summary of the effective policy.
    Status,
    /// Author and inspect the text policy (the flat rule model).
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Run a command under a fresh blessing, or `bless list` and `bless revoke <id>`.
    /// It runs as you, so it needs no `sudo` prefix. The human-presence check is a helper
    /// that it spawns.
    Bless(bless::BlessArgs),
    /// Approve a pending blessing. Only `cordon bless` runs this, through its elevation
    /// (see `bless::Elevation::approve`).
    #[command(hide = true)]
    BlessHelper {
        #[arg(long)]
        nonce: Nonce,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    /// Compile a policy file and print its diagnostics. Exits nonzero if the policy has
    /// errors. It never contacts the daemon, so it works in CI. Paths resolve through
    /// `stat` on this host, so unknown-executable and missing-path findings describe this
    /// machine.
    Check {
        /// Policy file (default: the configured `policy` path).
        file: Option<PathBuf>,
    },
    /// Compile a policy in the daemon and atomically replace the live one with it. If the
    /// policy has errors, the live policy stays unchanged and the exit status is nonzero.
    Apply {
        /// Policy file (default: the configured `policy` path).
        file: Option<PathBuf>,
    },
    /// Edit a policy in `$EDITOR`, then validate, apply and save it in one step, like
    /// sudoedit. The editor runs as the invoking user, not as root. The result is compiled
    /// and sent to the daemon, and the root-owned file is written only once the daemon
    /// accepts it. When no daemon is running, a valid policy is saved without being
    /// applied. Run it via `sudo` to edit a root-owned policy.
    ///
    /// With nothing named, it edits your own user tier. `--system` edits the system policy.
    Edit {
        #[command(flatten)]
        target: edit::EditTargetArgs,
        /// Launch the editor as root when there is no unprivileged invoker, such as on a
        /// root login without sudo. Off by default, because an editor running as root
        /// reopens the same-uid escalation that this command exists to prevent.
        #[arg(long)]
        allow_root_editor: bool,
    },
    /// Print the compiled policy that the daemon has loaded.
    Show,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let client = Client::new(&cli);
    exit_on(match &cli.cmd {
        Cmd::Status => client.run_request(&Request::Status),
        Cmd::Policy { cmd } => match cmd {
            // `check` must work without a daemon, so it never touches the socket.
            PolicyCmd::Check { file } => policy_check(file.as_deref(), &client),
            PolicyCmd::Show => client.run_request(&Request::PolicyShow),
            PolicyCmd::Apply { file } => {
                // The daemon compiles the sources itself (see `compile_fragments`), so
                // every source that `PolicyRoot::load` gathers is sent.
                let root = client.policy_root(file.as_deref());
                root.and_then(|r| r.load())
                    .and_then(|sources| client.run_request(&Request::PolicyApply { sources }))
            }
            // `edit` runs its own loop of editing, validating, applying and saving. It
            // reaches the daemon only through `PolicyApply`.
            PolicyCmd::Edit {
                target,
                allow_root_editor,
            } => edit::run(
                target.clone(),
                edit::RootEditor::from_flag(*allow_root_editor),
                &client,
            ),
        },
        // `bless` runs its own flow (see `bless::run`).
        Cmd::Bless(args) => bless::run(args, &client),
        // The approval half of the bless handshake (see `bless::Elevation::approve`).
        Cmd::BlessHelper { nonce } => client.run_request(&Request::BlessApprove {
            nonce: nonce.clone(),
        }),
    })
}

/// Returns `result`'s exit code, or prints its error and returns failure.
fn exit_on(result: Result<ExitCode>) -> ExitCode {
    result.unwrap_or_else(|e| {
        eprintln!("cordon: {e}");
        ExitCode::FAILURE
    })
}

/// The parsed command line together with the config it names. Every command reads its
/// settings through this type. The config loads on first use, so a command that never
/// needs a config never fails on one.
struct Client<'a> {
    cli: &'a Cli,
    config: std::cell::OnceCell<Config>,
}

impl<'a> Client<'a> {
    fn new(cli: &'a Cli) -> Self {
        Client {
            cli,
            config: std::cell::OnceCell::new(),
        }
    }

    fn config(&self) -> Result<&Config> {
        if let Some(cfg) = self.config.get() {
            return Ok(cfg);
        }
        let cfg = Config::load(self.cli.config.as_deref())?;
        Ok(self.config.get_or_init(|| cfg))
    }

    /// Returns the socket to dial. An explicit `--socket` wins. Otherwise it is the
    /// config's socket, chosen as
    /// [`SocketPath::for_client`](cordon_core::config::SocketPath::for_client) describes.
    /// Errors when there is no `--socket` and the config does not load.
    fn socket(&self) -> Result<PathBuf> {
        match &self.cli.socket {
            Some(s) => Ok(s.clone()),
            None => Ok(self.config()?.socket.clone().for_client(|p| p.exists())),
        }
    }

    /// Returns the policy at `file` when it is given, and at the configured `policy` path
    /// otherwise. Errors when `file` is `None` and the config does not load, or when the
    /// path cannot be inspected.
    fn policy_root(&self, file: Option<&Path>) -> Result<PolicyRoot> {
        match file {
            Some(p) => PolicyRoot::at(p),
            None => PolicyRoot::at(&self.config()?.policy),
        }
    }

    /// Sends `req` to the daemon, prints the reply and returns the exit code for it. With
    /// `--json` the reply prints as raw JSON. Errors when the socket can't be resolved or
    /// the daemon can't be reached, with a note on enforcement for the latter.
    fn run_request(&self, req: &Request) -> Result<ExitCode> {
        let socket = self.socket()?;
        let resp = round_trip(&socket, req).map_err(|e| {
            Error::msg(format!(
                "{e}\n       (is cordond running? socket: {})\n       {}",
                socket.display(),
                self.enforcement()
            ))
        })?;

        if self.cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_default()
            );
            return Ok(exit_for(&resp));
        }
        render(&resp);
        Ok(exit_for(&resp))
    }

    /// Returns whether enforcement is still up while the daemon can't be reached, as the
    /// bpffs pins say.
    ///
    /// The pinned LSM links keep the boundary up without the daemon (see
    /// `PinDir::pin_links` in cordond), so "connection refused" must not read as "nothing
    /// is enforced". A wrong answer misleads either way. Claiming the boundary is up when
    /// it is down invites a false sense of safety, and claiming it is down when it is up
    /// sends someone to debug a denial that works as designed. So an unreadable directory
    /// or config is [`Enforcement::Unknown`] rather than a guess. The pins are root-only
    /// on bpffs, so an unprivileged caller always gets that.
    fn enforcement(&self) -> Enforcement {
        let Ok(cfg) = self.config() else {
            return Enforcement::Unknown("no readable config".into());
        };
        let dir = cfg.bpf_pin_dir.clone();
        match std::fs::read_dir(&dir) {
            Ok(entries) => match entries.count() {
                0 => Enforcement::Off(dir),
                generations => Enforcement::Active { dir, generations },
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Enforcement::Off(dir),
            // Almost always EACCES.
            Err(_) => {
                Enforcement::Unknown(format!("{} is not readable as this user", dir.display()))
            }
        }
    }
}

/// Whether the pinned LSM links still enforce, from [`Client::enforcement`]. Any pin in
/// the pin directory means active, and an absent or empty directory means off.
enum Enforcement {
    Active { dir: PathBuf, generations: usize },
    Off(PathBuf),
    Unknown(String),
}

impl std::fmt::Display for Enforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Enforcement::Active { dir, generations } => write!(
                f,
                "enforcement is STILL ACTIVE ({generations} pinned generation(s) in {}); \
                 events are not being journaled while the daemon is down. \
                 `cordond --teardown` turns it off",
                dir.display()
            ),
            Enforcement::Off(dir) => {
                write!(f, "no pins under {} — enforcement is OFF", dir.display())
            }
            Enforcement::Unknown(why) => write!(f, "enforcement state unknown ({why})"),
        }
    }
}

/// Compiles a policy file locally, prints its diagnostics and a summary, and returns the
/// exit code, which is failure when the policy has errors. Errors when the file or the
/// config does not load.
fn policy_check(file: Option<&Path>, client: &Client) -> Result<ExitCode> {
    let root = client.policy_root(file)?;
    let sources = root.load()?;
    let path = root.path();
    let compiled =
        policy::compile_fragments(&sources, &policy::fallback_home(), policy::stat_resolver);
    for d in &compiled.diagnostics {
        eprintln!("{}:{d}", path.display());
    }
    if compiled.has_errors() {
        eprintln!(
            "cordon: {} has errors — `apply` would reject it",
            path.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    let rules: usize = compiled.objects.iter().map(|o| o.rules.len()).sum();
    println!(
        "{}: ok — objects={} rules={} pending={}",
        path.display(),
        compiled.objects.len(),
        rules,
        compiled.pending.len(),
    );
    Ok(ExitCode::SUCCESS)
}

fn render(resp: &Response) {
    match resp {
        Response::Status(s) => {
            println!("backend: {}", s.backend.as_str());
            println!("socket:  {}", s.socket.display());
            println!("policy:  {}", s.policy.display());
            match s.objects {
                Some(n) => println!("objects: {n}"),
                None => println!("objects: (no policy loaded)"),
            }
        }
        Response::PolicyApplied {
            applied,
            diagnostics,
        } => {
            for d in diagnostics {
                eprintln!("{d}");
            }
            println!(
                "{}",
                if *applied {
                    "applied"
                } else {
                    "not applied (see the errors above; live policy unchanged)"
                }
            );
        }
        Response::PolicyView(Some(v)) => {
            if v.objects.is_empty() {
                println!("(no protected objects)");
            }
            for o in &v.objects {
                let s = if o.rules == 1 { "" } else { "s" };
                println!("  {} ({} rule{s})", o.path.display(), o.rules);
            }
            if !v.pending.is_empty() {
                println!("pending (not yet enforced):");
                for p in &v.pending {
                    println!("  {}", p.display());
                }
            }
        }
        Response::PolicyView(None) => println!("(no policy loaded)"),
        Response::Blessings(list) => {
            if list.is_empty() {
                println!("(no live blessings)");
            }
            for b in list {
                let pids: Vec<String> = b.pids.iter().map(Pid::to_string).collect();
                println!(
                    "  {} class={} age={}s pids=[{}] cgroup={}",
                    b.id,
                    b.class,
                    b.age.as_secs(),
                    pids.join(","),
                    b.cgroup.display(),
                );
            }
        }
        Response::BlessRevoked { id } => println!("revoked: {id}"),
        // A successful `bless-helper` prints nothing on purpose. `cordon bless` spawns it
        // mid-command, and its exit status is its whole output.
        Response::BlessApproved => {}
        // Mid-handshake replies belong to the connection that `cordon bless` holds.
        // Reaching this arm means a client got the protocol wrong.
        Response::BlessPending { .. } | Response::BlessMinted(_) => {
            eprintln!("cordon: unexpected mid-handshake reply outside `cordon bless`")
        }
        Response::Error { message } => eprintln!("cordon: error: {message}"),
    }
}

/// Returns the exit code for a daemon reply. It is non-zero for an error, a rejected
/// `apply`, and a mid-handshake reply that only `cordon bless` should ever receive.
fn exit_for(resp: &Response) -> ExitCode {
    match resp {
        Response::Error { .. }
        | Response::PolicyApplied { applied: false, .. }
        | Response::BlessPending { .. }
        | Response::BlessMinted(_) => ExitCode::FAILURE,
        _ => ExitCode::SUCCESS,
    }
}

fn round_trip(socket: &Path, req: &Request) -> Result<Response> {
    let mut conn = Conn::connect(socket)?;
    conn.send(req)?;
    conn.recv()?
        .ok_or_else(|| Error::msg("daemon closed the connection without replying"))
}
