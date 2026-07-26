//! `cordon` — the control CLI for the flat rule model (DESIGN §15).
//!
//! Policy is authored in a root-owned text file. `policy check` lints a file locally
//! (no daemon); `policy apply` sends its text to the daemon, which compiles + seeds
//! the in-kernel maps; `policy show` and `status` read the effective policy. There are
//! no per-object owner mutations — the owner model was retired with the rule model.

mod edit;
mod sys;

use clap::{Parser, Subcommand};
use cordon_core::policy::UserName;
use cordon_core::proto::{Pid, Request, Response, read_msg, write_msg};
use cordon_core::{Config, Error, Result, policy};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
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
    /// Edit the policy in `$EDITOR`, then validate + apply + save in one step — the
    /// sudoedit analog. The editor runs as the invoking user (never root); the result is
    /// compiled and pushed to the daemon, and the root-owned file is written only once the
    /// daemon accepts it. Run via `sudo` for a root-owned policy.
    Edit {
        /// Policy file to edit (default: the configured `policy` path; for a conf.d
        /// directory, name a fragment, e.g. `local` → `…/conf.d/local.toml`).
        file: Option<PathBuf>,
        /// Edit the user-tier policy a system `[[include]]` binds to this user (its rules
        /// are confined to that user's home). Mutually exclusive with FILE.
        #[arg(long, conflicts_with = "file")]
        user: Option<UserName>,
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

    // `policy check` is local — it never touches the daemon socket.
    if let Cmd::Policy {
        cmd: PolicyCmd::Check { file },
    } = &cli.cmd
    {
        return policy_check(file.as_deref(), &cli);
    }

    // `policy edit` drives its own flow (editor → validate → apply → save), reaching the
    // daemon only via the shared `PolicyApply` path, so it routes here rather than through
    // the single-request round-trip below.
    if let Cmd::Policy {
        cmd:
            PolicyCmd::Edit {
                file,
                user,
                allow_root_editor,
            },
    } = &cli.cmd
    {
        // `--user` and FILE are mutually exclusive (clap-enforced), so one selects the target.
        let target = match user {
            Some(u) => edit::EditTarget::User(u.clone()),
            None => edit::EditTarget::File(file.clone()),
        };
        return edit::run(
            target,
            edit::RootEditor::from_flag(*allow_root_editor),
            &cli,
        );
    }

    let socket = match resolve_socket(&cli) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cordon: {e}");
            return ExitCode::FAILURE;
        }
    };
    let req = match build_request(&cli) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cordon: {e}");
            return ExitCode::FAILURE;
        }
    };
    let resp = match round_trip(&socket, &req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cordon: {e}");
            eprintln!("       (is cordond running? socket: {})", socket.display());
            return ExitCode::FAILURE;
        }
    };

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_default()
        );
        return exit_for(&resp);
    }
    render(&resp);
    exit_for(&resp)
}

/// Build the IPC request for a daemon-bound command (reading the policy file for
/// `apply`). `check` is handled locally before this is reached.
fn build_request(cli: &Cli) -> Result<Request> {
    match &cli.cmd {
        Cmd::Status => Ok(Request::Status),
        Cmd::Policy { cmd } => match cmd {
            PolicyCmd::Show => Ok(Request::PolicyShow),
            PolicyCmd::Apply { file } => {
                let path = policy_path(file.as_deref(), cli)?;
                // Read the policy source (a file, or a conf.d dir of fragments) and expand
                // any `[[include]]` user-tier files; ship the lot. The daemon resolves
                // per-fragment homes, merges, and compiles.
                let sources = policy::load_policy(&path)?;
                Ok(Request::PolicyApply { sources })
            }
            PolicyCmd::Check { .. } => unreachable!("check is handled locally"),
            PolicyCmd::Edit { .. } => unreachable!("edit is handled locally"),
        },
    }
}

/// `cordon policy check` — compile a policy file locally and report diagnostics.
/// Local + daemon-free so it lints in CI; exits non-zero if the policy has errors.
fn policy_check(file: Option<&Path>, cli: &Cli) -> ExitCode {
    let path = match policy_path(file, cli) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cordon: {e}");
            return ExitCode::FAILURE;
        }
    };
    // A file → one fragment; a conf.d dir → every `*.toml`; plus any `[[include]]`
    // user-tier files. Each resolves with its own home (the owning user's, else the CLI
    // `$HOME`); per-fragment errors fold into the compile diagnostics, naming the fragment.
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
        Response::BlessMinted(b) => {
            println!(
                "blessed: id={} class={} cgroup={}",
                b.id,
                b.class,
                b.cgroup.display()
            );
        }
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
        Response::Error { message } => eprintln!("cordon: error: {message}"),
    }
}

/// Exit code: errors fail; a rejected `apply` exits non-zero so CI/scripts can branch.
fn exit_for(resp: &Response) -> ExitCode {
    match resp {
        Response::Error { .. } => ExitCode::FAILURE,
        Response::PolicyApplied { applied: false, .. } => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    }
}

/// The policy file to act on: an explicit arg, else the configured `policy` path.
fn policy_path(file: Option<&Path>, cli: &Cli) -> Result<PathBuf> {
    match file {
        Some(p) => Ok(p.to_path_buf()),
        None => Ok(Config::load(cli.config.as_deref())?.policy),
    }
}

/// `$HOME` for `~`-expansion in the policy being checked (falls back to `/`).
fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// `--socket` wins; otherwise the socket from the config file (or its default).
fn resolve_socket(cli: &Cli) -> Result<PathBuf> {
    if let Some(s) = cli.socket.clone() {
        return Ok(s);
    }
    Ok(Config::load(cli.config.as_deref())?.socket)
}

fn round_trip(socket: &Path, req: &Request) -> Result<Response> {
    let stream = UnixStream::connect(socket)?;
    let mut writer = BufWriter::new(stream.try_clone()?);
    let mut reader = BufReader::new(stream);
    write_msg(&mut writer, req)?;
    read_msg(&mut reader)?
        .ok_or_else(|| Error::msg("daemon closed the connection without replying"))
}
