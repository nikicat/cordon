//! `cordon` — the control CLI for the flat rule model (DESIGN §15).
//!
//! Policy is authored in a root-owned text file. `policy check` lints a file locally
//! (no daemon); `policy apply` sends its text to the daemon, which compiles + seeds
//! the in-kernel maps; `policy show` and `status` read the effective policy.

mod bless;
mod edit;
mod sys;

use clap::{Parser, Subcommand};
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
    /// Config file path (to locate the socket; overrides $CORDON_CONFIG / default).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Daemon socket path (overrides the config file).
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
    /// Daemon + effective-policy summary.
    Status,
    /// Author/inspect the text policy (the flat rule model).
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Run a command under a fresh blessing; also `bless list` / `bless revoke <id>`.
    /// Runs as you — no `sudo` prefix; the human-presence check is a helper it spawns.
    Bless(bless::BlessArgs),
    /// Internal: approve a pending blessing. Spawned by `cordon bless` (see
    /// `bless::elevate`), never invoked by hand; hidden from `--help`.
    #[command(hide = true)]
    BlessHelper {
        #[arg(long)]
        nonce: Nonce,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    /// Parse + compile a policy file and print diagnostics (nonzero exit on error).
    /// Local — does not contact the daemon, so it lints in CI. Inode resolution uses
    /// `stat`, so unknown-exe / missing-path findings reflect *this* host.
    Check {
        /// Policy file (default: the configured `policy` path).
        file: Option<PathBuf>,
    },
    /// Compile + apply a policy via the daemon, atomically replacing the live one.
    /// Nonzero exit if it has errors (the live policy is left unchanged).
    Apply {
        /// Policy file (default: the configured `policy` path).
        file: Option<PathBuf>,
    },
    /// Edit a policy in `$EDITOR`, then validate + apply + save in one step — the
    /// sudoedit analog. The editor runs as the invoking user (never root); the result is
    /// compiled and pushed to the daemon, and the root-owned file is written only once the
    /// daemon accepts it, or saved unapplied when no daemon is running. Run via `sudo` for
    /// a root-owned policy.
    ///
    /// With nothing named, edits your own user tier; `--system` edits the system policy.
    Edit {
        #[command(flatten)]
        target: edit::EditTargetArgs,
        /// Launch the editor as root when there is no unprivileged invoker (e.g. a root
        /// login without sudo). Off by default — running an editor as root re-opens the
        /// same-uid escalation this command exists to avoid.
        #[arg(long)]
        allow_root_editor: bool,
    },
    /// Show the effective (currently-loaded) compiled policy.
    Show,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let client = Client::new(&cli);

    // `policy check` is local — it never touches the daemon socket.
    if let Cmd::Policy {
        cmd: PolicyCmd::Check { file },
    } = &cli.cmd
    {
        return policy_check(file.as_deref(), &client);
    }

    // `policy edit` drives its own flow (editor → validate → apply → save), reaching the
    // daemon only via the shared `PolicyApply` path, so it routes here rather than through
    // the single-request round-trip below.
    if let Cmd::Policy {
        cmd: PolicyCmd::Edit {
            target,
            allow_root_editor,
        },
    } = &cli.cmd
    {
        let root_editor = edit::RootEditor::from_flag(*allow_root_editor);
        return edit::run(target.clone(), root_editor, &client);
    }

    // `bless` drives its own flow (see `bless::run`); its `list`/`revoke` subcommands
    // come back through `run_request` like any other.
    if let Cmd::Bless(args) = &cli.cmd {
        return bless::run(args, &client);
    }

    // The approval half of the bless handshake (see `bless::elevate`).
    if let Cmd::BlessHelper { nonce } = &cli.cmd {
        return client.run_request(&Request::BlessApprove {
            nonce: nonce.clone(),
        });
    }

    let req = match build_request(&client) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cordon: {e}");
            return ExitCode::FAILURE;
        }
    };
    client.run_request(&req)
}

/// The command line and the config it names, which every command reads through. The
/// config is loaded on first use, so a command that never needs it never fails on it.
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
    fn socket(&self) -> Result<PathBuf> {
        match &self.cli.socket {
            Some(s) => Ok(s.clone()),
            None => Ok(self.config()?.socket.clone().for_client(|p| p.exists())),
        }
    }

    /// The policy file to act on: an explicit arg, else the configured `policy` path.
    fn policy_path(&self, file: Option<&Path>) -> Result<PathBuf> {
        match file {
            Some(p) => Ok(p.to_path_buf()),
            None => Ok(self.config()?.policy.clone()),
        }
    }

    /// Send one request to the daemon and render the reply (honoring `--json`) — the
    /// shared tail of every daemon-bound command.
    fn run_request(&self, req: &Request) -> ExitCode {
        let socket = match self.socket() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cordon: {e}");
                return ExitCode::FAILURE;
            }
        };
        let resp = match round_trip(&socket, req) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("cordon: {e}");
                eprintln!("       (is cordond running? socket: {})", socket.display());
                eprintln!("       {}", self.enforcement_note());
                return ExitCode::FAILURE;
            }
        };

        if self.cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_default()
            );
            return exit_for(&resp);
        }
        render(&resp);
        exit_for(&resp)
    }

    /// Returns what the bpffs pins say about enforcement, for when the daemon can't be
    /// reached.
    ///
    /// The pinned LSM links keep the boundary up without the daemon (see
    /// `PinDir::pin_links` in cordond), so "connection refused" must not read as "nothing
    /// is enforced". There are three answers, because a wrong one misleads either way:
    /// claiming the boundary is up when it isn't invites a false sense of safety, and
    /// claiming it is down when it is up sends someone debugging a denial that is working
    /// as designed. Pins present means active; an absent or empty pin directory means off;
    /// an unreadable one (bpffs is root-only, so any unprivileged caller) or an unreadable
    /// config means unknown rather than a guess.
    fn enforcement_note(&self) -> String {
        let Ok(cfg) = self.config() else {
            return "enforcement state unknown (no readable config)".into();
        };
        let dir = &cfg.bpf_pin_dir;
        match std::fs::read_dir(dir) {
            Ok(entries) => match entries.count() {
                0 => format!("no pins under {} — enforcement is OFF", dir.display()),
                n => format!(
                    "enforcement is STILL ACTIVE ({n} pinned generation(s) in {}); \
                     events are not being journaled while the daemon is down. \
                     `cordond --teardown` turns it off",
                    dir.display()
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                format!("no pins under {} — enforcement is OFF", dir.display())
            }
            // Almost always EACCES.
            Err(_) => format!(
                "enforcement state unknown — {} is not readable as this user",
                dir.display()
            ),
        }
    }
}

/// Build the IPC request for a daemon-bound command (reading the policy file for
/// `apply`). `check` is handled locally before this is reached.
fn build_request(client: &Client) -> Result<Request> {
    match &client.cli.cmd {
        Cmd::Status => Ok(Request::Status),
        Cmd::Policy { cmd } => match cmd {
            PolicyCmd::Show => Ok(Request::PolicyShow),
            PolicyCmd::Apply { file } => {
                let path = client.policy_path(file.as_deref())?;
                // Ship every source `load_policy` gathers; the daemon compiles them (see
                // `compile_fragments`).
                let sources = policy::load_policy(&path)?;
                Ok(Request::PolicyApply { sources })
            }
            PolicyCmd::Check { .. } => unreachable!("check is handled locally"),
            PolicyCmd::Edit { .. } => unreachable!("edit is handled locally"),
        },
        Cmd::Bless(_) => unreachable!("bless is handled locally"),
        Cmd::BlessHelper { .. } => unreachable!("bless-helper is handled locally"),
    }
}

/// `cordon policy check` — compile a policy file locally and report diagnostics.
/// Local + daemon-free so it lints in CI; exits non-zero if the policy has errors.
fn policy_check(file: Option<&Path>, client: &Client) -> ExitCode {
    let path = match client.policy_path(file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cordon: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sources = match policy::load_policy(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cordon: {e}");
            return ExitCode::FAILURE;
        }
    };
    let compiled = policy::compile_fragments(&sources, &home(), policy::stat_resolver);
    for d in &compiled.diagnostics {
        eprintln!("{}:{d}", path.display());
    }
    if compiled.has_errors() {
        eprintln!(
            "cordon: {} has errors — `apply` would reject it",
            path.display()
        );
        return ExitCode::FAILURE;
    }
    let rules: usize = compiled.objects.iter().map(|o| o.rules.len()).sum();
    println!(
        "{}: ok — objects={} rules={} pending={}",
        path.display(),
        compiled.objects.len(),
        rules,
        compiled.pending.len(),
    );
    ExitCode::SUCCESS
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
                    "not applied (policy has errors; live policy unchanged)"
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
        // `bless-helper` succeeding is silent on purpose — it is spawned mid-command, not
        // run by a human, and its whole output is its exit status.
        Response::BlessApproved => {}
        // Mid-handshake replies belong to `cordon bless`'s own connection; reaching here
        // means a client got the protocol wrong.
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

/// `$HOME` for `~`-expansion in the policy being checked (falls back to `/`).
fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn round_trip(socket: &Path, req: &Request) -> Result<Response> {
    let mut conn = Conn::connect(socket)?;
    conn.send(req)?;
    conn.recv()?
        .ok_or_else(|| Error::msg("daemon closed the connection without replying"))
}
