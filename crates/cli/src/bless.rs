//! `cordon bless` — run a command under a fresh blessing (DESIGN §16).
//!
//! Sudo-gated: the command must run as root (`sudo cordon bless …`) — sudo's PAM stack
//! is the human-presence authenticator, the daemon's mint verb requires peer uid 0,
//! and joining the root-owned carrier cgroup requires root anyway. The flow:
//!
//! 1. Mint via the daemon → a carrier cgroup registered in the kernel's BLESSED map,
//!    with its `cgroup.procs` handed back **as a descriptor** (`SCM_RIGHTS`) rather than
//!    a path: the daemon opened it as root, and that is what the kernel checks.
//! 2. Fork the target; its `pre_exec` writes the child pid through that fd, *then* drops
//!    to the sudo invoker, then execs — the target never runs a single instruction
//!    unblessed, with natural tty/job control/signals/exit code.
//!
//! No CLI-side cleanup: the daemon GCs the carrier when it empties (its mint grace
//! covers a CLI that dies before the join).

use crate::Cli;
use crate::sys::{self, DropTo};
use clap::Subcommand;
use cordon_core::policy::ClassName;
use cordon_core::proto::{BlessId, CarrierProcs, Request, Response, read_msg_with_fd, write_msg};
use cordon_core::{Error, Result, config};
use nix::unistd::{Gid, Uid, User};
use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// `cordon bless [--class <name>] [-- <command>…]` | `bless list` | `bless revoke <id>`.
/// `list`/`revoke` are subcommands; a command literally named `list` runs via
/// `cordon bless -- list`.
#[derive(clap::Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct BlessArgs {
    #[command(subcommand)]
    cmd: Option<BlessCmd>,
    /// Blessing class to mint (default: the sole class the policy declares).
    #[arg(long)]
    class: Option<ClassName>,
    /// Command to run blessed (default: your login shell). Use `--` before a command
    /// whose name collides with a subcommand (`cordon bless -- list`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Subcommand, Debug)]
enum BlessCmd {
    /// List the live blessings.
    List,
    /// Revoke a live blessing: kill its process tree and reap the carrier (root).
    Revoke { id: BlessId },
}

pub fn run(args: &BlessArgs, cli: &Cli) -> ExitCode {
    match &args.cmd {
        // list/revoke are plain round trips — render like any other command (the
        // daemon gates revoke on peer uid 0 and says so if refused).
        Some(sub) => {
            let req = match sub {
                BlessCmd::List => Request::BlessList,
                BlessCmd::Revoke { id } => Request::BlessRevoke { id: *id },
            };
            crate::run_request(&req, cli)
        }
        None => match mint_and_exec(args, cli) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("cordon: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

/// The blessed-exec flow: mint, then fork the target into the carrier.
fn mint_and_exec(args: &BlessArgs, cli: &Cli) -> Result<ExitCode> {
    if !config::is_root() {
        return Err(Error::msg(
            "blessing requires root — invoke via `sudo cordon bless`",
        ));
    }
    let socket = crate::resolve_socket(cli)?;
    let procs = mint(
        &socket,
        &Request::BlessMint {
            class: args.class.clone(),
        },
    )?;

    let invoker = invoker()?;
    let mut cmd = build_command(&args.command, invoker.as_ref())?;
    sys::join_cgroup_and_drop_on_exec(&mut cmd, procs, invoker.map(|i| i.drop));
    let status = cmd
        .status()
        .map_err(|e| Error::msg(format!("spawn blessed command: {e}")))?;
    Ok(ExitCode::from(exit_byte(status.code(), status.signal())))
}

/// Mint a blessing and take delivery of the carrier's `cgroup.procs`.
///
/// The fd — not the path — is the grant: the daemon opened it as root, and cgroup-v2
/// checks migration permission against the *opener's* credentials, so writing a pid
/// through it works without privilege (DESIGN §16.4). It also has to be a dedicated
/// connection rather than [`crate::round_trip`], because ancillary data is lost to any
/// buffered read.
fn mint(socket: &Path, req: &Request) -> Result<CarrierProcs> {
    let stream = std::os::unix::net::UnixStream::connect(socket).map_err(|e| {
        Error::msg(format!(
            "connect {}: {e} (is cordond running?)",
            socket.display()
        ))
    })?;
    write_msg(&mut &stream, req)?;
    match read_msg_with_fd::<Response>(&stream)? {
        Some((Response::BlessMinted(_view), Some(procs))) => Ok(CarrierProcs(procs)),
        Some((Response::BlessMinted(view), None)) => Err(Error::msg(format!(
            "daemon minted {} but passed no cgroup.procs descriptor",
            view.cgroup.display()
        ))),
        Some((Response::Error { message }, _)) => Err(Error::msg(format!("daemon: {message}"))),
        Some((other, _)) => Err(Error::msg(format!("unexpected daemon reply: {other:?}"))),
        None => Err(Error::msg("daemon closed the connection without replying")),
    }
}

/// The sudo invoker to drop the blessed child to, resolved from `SUDO_UID`/`SUDO_GID`
/// and passwd. `None` ⇒ stay root: true root without sudo, or `SUDO_UID=0` (root
/// sudo-ing — no one lower to drop to).
struct Invoker {
    drop: DropTo,
    name: String,
    home: PathBuf,
    /// The invoker's login shell from passwd — the no-command default (`$SHELL` is
    /// reset by sudo, so it can't be trusted as *their* shell).
    shell: Option<PathBuf>,
}

fn invoker() -> Result<Option<Invoker>> {
    let (Ok(u), Ok(g)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) else {
        return Ok(None);
    };
    let uid = Uid::from_raw(
        u.parse::<u32>()
            .map_err(|_| Error::msg(format!("invalid SUDO_UID: {u:?}")))?,
    );
    let gid = Gid::from_raw(
        g.parse::<u32>()
            .map_err(|_| Error::msg(format!("invalid SUDO_GID: {g:?}")))?,
    );
    if uid.is_root() {
        return Ok(None);
    }
    let user = User::from_uid(uid)
        .map_err(|e| Error::msg(format!("passwd lookup for uid {uid}: {e}")))?
        .ok_or_else(|| Error::msg(format!("uid {uid} (SUDO_UID) has no passwd entry")))?;
    // The full supplementary list, resolved now — the pre_exec closure must not touch
    // the group database. A blessed shell is the user's normal session, groups intact.
    let cname = std::ffi::CString::new(user.name.clone())
        .map_err(|_| Error::msg("passwd name contains NUL"))?;
    let groups = nix::unistd::getgrouplist(&cname, gid)
        .map_err(|e| Error::msg(format!("getgrouplist({}): {e}", user.name)))?;
    Ok(Some(Invoker {
        drop: DropTo { uid, gid, groups },
        name: user.name,
        home: user.dir,
        shell: (!user.shell.as_os_str().is_empty()).then_some(user.shell),
    }))
}

/// The target `Command`: the given argv, or (empty) the invoker's shell. When dropping
/// to an invoker, hand the child *their* `HOME`/`USER`/`LOGNAME` — sudo left root's.
fn build_command(argv: &[OsString], invoker: Option<&Invoker>) -> Result<Command> {
    let mut cmd = match argv.split_first() {
        Some((program, rest)) => {
            let mut c = Command::new(program);
            c.args(rest);
            c
        }
        None => Command::new(default_shell(
            invoker.and_then(|i| i.shell.clone()),
            std::env::var_os("SHELL").map(PathBuf::from),
        )),
    };
    if let Some(i) = invoker {
        cmd.env("HOME", &i.home)
            .env("USER", &i.name)
            .env("LOGNAME", &i.name);
    }
    Ok(cmd)
}

/// The no-command shell: the invoker's passwd shell, else `$SHELL`, else `/bin/sh`.
fn default_shell(passwd_shell: Option<PathBuf>, env_shell: Option<PathBuf>) -> PathBuf {
    passwd_shell
        .or(env_shell)
        .filter(|s| !s.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

/// The exit byte to propagate: the child's own code, or `128 + signal` for a
/// signal death (the shell convention), or 1 if the wait status is somehow neither.
fn exit_byte(code: Option<i32>, signal: Option<i32>) -> u8 {
    match (code, signal) {
        (Some(c), _) => c as u8,
        (None, Some(s)) => 128u8.wrapping_add(s as u8),
        (None, None) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Parse through the real `Cli` so the `args_conflicts_with_subcommands` shape is
    /// tested exactly as shipped.
    fn parse(argv: &[&str]) -> BlessArgs {
        match Cli::try_parse_from(argv).expect("parse").cmd {
            crate::Cmd::Bless(args) => args,
            other => panic!("expected bless, got {other:?}"),
        }
    }

    #[test]
    fn clap_shape_subcommands_vs_trailing_command() {
        // `bless list` / `bless revoke <id>` are subcommands.
        assert!(matches!(
            parse(&["cordon", "bless", "list"]).cmd,
            Some(BlessCmd::List)
        ));
        assert!(matches!(
            parse(&["cordon", "bless", "revoke", "7"]).cmd,
            Some(BlessCmd::Revoke { id: BlessId(7) })
        ));
        // `bless -- list` runs a *command* named list.
        let a = parse(&["cordon", "bless", "--", "list"]);
        assert!(a.cmd.is_none());
        assert_eq!(a.command, vec![OsString::from("list")]);
        // Flags + a real command line.
        let a = parse(&["cordon", "bless", "--class", "ro", "--", "aws", "s3", "ls"]);
        assert_eq!(a.class, Some(ClassName::new("ro")));
        assert_eq!(a.command.len(), 3);
        // A non-subcommand word needs no `--`.
        let a = parse(&["cordon", "bless", "echo", "hi"]);
        assert!(a.cmd.is_none());
        assert_eq!(
            a.command,
            vec![OsString::from("echo"), OsString::from("hi")]
        );
        // Bare `bless`: no subcommand, no command → the invoker's shell, sole class.
        let a = parse(&["cordon", "bless"]);
        assert!(a.cmd.is_none() && a.command.is_empty() && a.class.is_none());
    }

    #[test]
    fn default_shell_prefers_passwd_then_env_then_sh() {
        let passwd = Some(PathBuf::from("/bin/fish"));
        let env = Some(PathBuf::from("/bin/zsh"));
        assert_eq!(
            default_shell(passwd.clone(), env.clone()),
            PathBuf::from("/bin/fish")
        );
        assert_eq!(default_shell(None, env), PathBuf::from("/bin/zsh"));
        assert_eq!(default_shell(None, None), PathBuf::from("/bin/sh"));
        // An empty $SHELL (set but blank) falls through to /bin/sh.
        assert_eq!(
            default_shell(None, Some(PathBuf::new())),
            PathBuf::from("/bin/sh")
        );
    }

    #[test]
    fn exit_byte_maps_code_signal_and_neither() {
        assert_eq!(exit_byte(Some(0), None), 0);
        assert_eq!(exit_byte(Some(3), None), 3);
        // SIGKILL(9) → 137, SIGTERM(15) → 143 — the shell convention.
        assert_eq!(exit_byte(None, Some(9)), 137);
        assert_eq!(exit_byte(None, Some(15)), 143);
        assert_eq!(exit_byte(None, None), 1);
    }
}
