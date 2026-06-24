//! `cordon` — the control CLI.
//!
//! Every command is one round-trip over the daemon's Unix socket (DESIGN §5: the
//! store is daemon-owned and never touched directly). `submit` drives a
//! synthetic access event through the engine and exits non-zero on a deny — handy
//! for the test harness and for eyeballing policy.

use clap::{Args, Parser, Subcommand, ValueEnum};
use cordon_core::event::Op;
use cordon_core::proto::{Request, Response, read_msg, write_msg};
use cordon_core::{config, decision::Decision};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "cordon",
    about = "cordon — object-centric secret-dir gater",
    version
)]
struct Cli {
    /// Daemon socket path (overrides $CORDON_SOCK / default).
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
    /// Daemon + store summary.
    Status,
    /// List owner groups (identities + owned subtrees).
    Owners,
    /// List explicit rules.
    Rules,
    /// Add an explicit rule (default: allow; --deny to revoke).
    Add(AddArgs),
    /// Remove an explicit rule by id.
    Rm { id: i64 },
    /// Claim a pre-existing subtree for an identity (adopt).
    Adopt {
        path: String,
        /// Owning exe path.
        #[arg(long, visible_alias = "as")]
        identity: String,
    },
    /// Add an identity to the owner group of an existing subtree.
    Claim {
        subtree: String,
        #[arg(long)]
        add: String,
    },
    /// Drop ownership of a subtree.
    Disown { subtree: String },
    /// Manage zone roots (the dirs whose first-level subtrees are claimable).
    Zone {
        #[command(subcommand)]
        cmd: ZoneCmd,
    },
    /// Drive a synthetic access event and print the verdict (dev/test).
    Submit(SubmitArgs),
}

#[derive(Args, Debug)]
struct AddArgs {
    /// Exe path the rule applies to ('*' = any caller).
    #[arg(long)]
    identity: String,
    /// Subtree prefix the rule covers.
    #[arg(long)]
    path: String,
    /// Access mode: r, w, or rw.
    #[arg(long, default_value = "rw")]
    mode: String,
    /// Make this a deny rule (default is allow).
    #[arg(long)]
    deny: bool,
    /// Time-to-live in seconds (omit for a permanent rule).
    #[arg(long)]
    ttl: Option<i64>,
}

#[derive(Subcommand, Debug)]
enum ZoneCmd {
    /// Register a new zone root.
    Add { path: String },
}

#[derive(Args, Debug)]
struct SubmitArgs {
    #[arg(long)]
    path: String,
    #[arg(long)]
    exe: String,
    /// Ancestor exe (repeatable, nearest-first) for chain matching.
    #[arg(long = "ancestor")]
    ancestors: Vec<String>,
    #[arg(long, value_enum, default_value_t = OpArg::Read)]
    op: OpArg,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OpArg {
    Read,
    Write,
    Create,
}

impl From<OpArg> for Op {
    fn from(o: OpArg) -> Op {
        match o {
            OpArg::Read => Op::Read,
            OpArg::Write => Op::Write,
            OpArg::Create => Op::Create,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let socket = cli.socket.clone().unwrap_or_else(config::socket_path);
    let req = to_request(&cli.cmd);
    let is_submit = matches!(cli.cmd, Cmd::Submit(_));

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
        return exit_for(&resp, is_submit);
    }
    render(&resp);
    exit_for(&resp, is_submit)
}

fn to_request(cmd: &Cmd) -> Request {
    match cmd {
        Cmd::Status => Request::Status,
        Cmd::Owners => Request::Owners,
        Cmd::Rules => Request::Rules,
        Cmd::Add(a) => Request::AddRule {
            identity: a.identity.clone(),
            path: a.path.clone(),
            mode: a.mode.clone(),
            allow: !a.deny,
            ttl_secs: a.ttl,
        },
        Cmd::Rm { id } => Request::RemoveRule { id: *id },
        Cmd::Adopt { path, identity } => Request::Adopt {
            path: path.clone(),
            identity: identity.clone(),
        },
        Cmd::Claim { subtree, add } => Request::Claim {
            subtree: subtree.clone(),
            add: add.clone(),
        },
        Cmd::Disown { subtree } => Request::Disown {
            subtree: subtree.clone(),
        },
        Cmd::Zone {
            cmd: ZoneCmd::Add { path },
        } => Request::AddZone { path: path.clone() },
        Cmd::Submit(s) => Request::Submit {
            path: s.path.clone(),
            exe: s.exe.clone(),
            ancestors: s.ancestors.clone(),
            op: s.op.into(),
            pid: None,
        },
    }
}

fn round_trip(socket: &std::path::Path, req: &Request) -> cordon_core::Result<Response> {
    let stream = UnixStream::connect(socket)?;
    let mut writer = BufWriter::new(stream.try_clone()?);
    let mut reader = BufReader::new(stream);
    write_msg(&mut writer, req)?;
    read_msg(&mut reader)?
        .ok_or_else(|| cordon_core::Error::msg("daemon closed the connection without replying"))
}

fn render(resp: &Response) {
    match resp {
        Response::Status(s) => {
            println!("backend:  {}", s.backend);
            println!("store:    {}", s.store_path);
            println!("socket:   {}", s.socket_path);
            println!("owners:   {}", s.owners);
            println!("subtrees: {}", s.subtrees);
            println!("rules:    {}", s.rules);
            println!("zones:");
            for z in &s.zones {
                println!("  {z}");
            }
        }
        Response::Owners(owners) => {
            if owners.is_empty() {
                println!("(no owners)");
            }
            for o in owners {
                println!("{}", o.name);
                println!("  identities: {}", o.identities.join(", "));
                if !o.subtrees.is_empty() {
                    println!("  subtrees:   {}", o.subtrees.join(", "));
                }
            }
        }
        Response::Rules(rules) => {
            if rules.is_empty() {
                println!("(no rules)");
            }
            for r in rules {
                let pol = if r.allow { "allow" } else { "deny " };
                let ttl = r
                    .expires_at
                    .map(|e| format!(" expires@{e}"))
                    .unwrap_or_default();
                println!(
                    "#{} {} {} {} {}{}",
                    r.id, pol, r.mode, r.identity, r.path, ttl
                );
            }
        }
        Response::Decision(d) => {
            let (verb, reason) = match d {
                Decision::Allow { reason } => ("ALLOW", reason),
                Decision::Deny { reason } => ("DENY", reason),
            };
            println!("{verb} ({reason:?})");
        }
        Response::RuleAdded { id } => println!("added rule #{id}"),
        Response::Done { changed } => println!("{}", if *changed { "ok" } else { "no change" }),
        Response::Error { message } => eprintln!("cordon: error: {message}"),
    }
}

/// Map the response to a process exit code: errors fail; a `submit` deny exits
/// non-zero so scripts and the test harness can branch on the verdict.
fn exit_for(resp: &Response, is_submit: bool) -> ExitCode {
    match resp {
        Response::Error { .. } => ExitCode::FAILURE,
        Response::Decision(d) if is_submit && !d.allowed() => ExitCode::from(13),
        _ => ExitCode::SUCCESS,
    }
}
