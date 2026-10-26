//! `cordon bless` — run a command under a fresh blessing (DESIGN §16).
//!
//! **Runs as you.** `cordon bless` is an ordinary child of your shell and never holds
//! privilege; what it obtains from the daemon is a *descriptor*, not authority. That
//! inversion is the point: the blessed command inherits your environment, cwd, tty, job
//! control and **logind session** because nothing ever moved it — where the older,
//! root-first shape was born under a privilege tool (under `run0`, a transient unit with
//! no session at all) and then relocated, losing `$DISPLAY` and breaking polkit.
//!
//! The flow (DESIGN §16.5):
//!
//! 1. Send `BlessRequest` and hold the connection open. The daemon replies with a
//!    single-use nonce; nothing is minted yet.
//! 2. Spawn `$CORDON_SUDO cordon bless-helper --nonce=…`. The human authenticates to
//!    whatever that tool is; the helper reaches the daemon as **uid 0**, which is the
//!    entire proof of human presence, and approves.
//! 3. The daemon mints and sends the carrier's `cgroup.procs` back down *our* connection.
//! 4. Fork the target; its `pre_exec` writes the child pid through that descriptor and
//!    execs — so the target runs zero instructions unblessed, with a natural exit code.
//!
//! Security lives in the daemon's uid-0 check on the approval, never in `$CORDON_SUDO`:
//! a faked elevation simply yields a non-root helper whose approval is refused. That is
//! what makes the variable safe to expose as a test seam.
//!
//! No CLI-side cleanup: the daemon GCs the carrier when it empties (its mint grace
//! covers a CLI that dies before the join).

use crate::Client;
use crate::sys;
use clap::Subcommand;
use cordon_core::policy::ClassName;
use cordon_core::proto::{BlessId, CarrierProcs, Conn, Nonce, Request, Response};
use cordon_core::{Context, Error, Result, Uid};
use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The elevation command `cordon bless` spawns its approval helper under. A command
/// string, so `CORDON_SUDO="setpriv --reuid 0"` works as well as a bare program.
const ELEVATION_ENV: &str = "CORDON_SUDO";
const DEFAULT_ELEVATION: &str = "sudo";

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
    /// Revoke a live blessing you minted, or any blessing as root. Kills its process tree
    /// and reaps the carrier.
    Revoke { id: BlessId },
}

pub fn run(args: &BlessArgs, client: &Client) -> ExitCode {
    match &args.cmd {
        // list/revoke are plain round trips — render like any other command (revoke is
        // yours to call for a blessing you minted; the daemon says so if it isn't).
        Some(sub) => {
            let req = match sub {
                BlessCmd::List => Request::BlessList,
                BlessCmd::Revoke { id } => Request::BlessRevoke { id: *id },
            };
            client.run_request(&req)
        }
        None => match mint_and_exec(args, client) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("cordon: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

/// The blessed-exec flow: request → elevate → receive the carrier → fork the target.
fn mint_and_exec(args: &BlessArgs, client: &Client) -> Result<ExitCode> {
    let socket = client.socket()?;
    let procs = request_and_approve(&socket, args.class.clone())?;
    let mut cmd = build_command(&args.command);
    sys::join_cgroup_on_exec(&mut cmd, procs);
    let status = cmd.status().context("spawn blessed command")?;
    Ok(ExitCode::from(exit_byte(status.code(), status.signal())))
}

/// Run the mint handshake and take delivery of the carrier's `cgroup.procs`.
///
/// One connection, two replies, an elevation in between — and it must be a dedicated
/// connection rather than [`crate::round_trip`], because ancillary data is lost to any
/// buffered read (see `Conn::recv_with_fd`).
fn request_and_approve(socket: &Path, class: Option<ClassName>) -> Result<CarrierProcs> {
    let stream = UnixStream::connect(socket).map_err(|e| {
        Error::msg(format!(
            "connect {}: {e} (is cordond running?)",
            socket.display()
        ))
    })?;
    let conn = Conn::new(stream)?;
    require_root_daemon(&conn, socket)?;
    conn.send(&Request::BlessRequest { class })?;
    let nonce = match reply(&conn)? {
        (Response::BlessPending { nonce }, _) => nonce,
        (other, _) => return Err(unexpected(other)),
    };

    // Blocks while the human authenticates. Waiting for the helper to exit first means a
    // cancelled password prompt reports itself immediately, instead of stalling until the
    // daemon's approval timeout. The same `socket` goes to the helper, so both halves of
    // the handshake provably reach the daemon we just vetted.
    elevate(&nonce, socket)?;

    match reply(&conn)? {
        (Response::BlessMinted(_), Some(procs)) => Ok(CarrierProcs(procs)),
        (Response::BlessMinted(view), None) => Err(Error::msg(format!(
            "daemon minted {} but passed no cgroup.procs descriptor",
            view.cgroup.display()
        ))),
        (other, _) => Err(unexpected(other)),
    }
}

/// Refuse to continue unless the process on the other end of `stream` is **root**.
///
/// Without this the nonce is a bearer token handed to whoever answers the socket, and the
/// elevation that follows is a confused deputy: a local user who leaves a listener at the
/// client's socket path (`$XDG_RUNTIME_DIR/cordon.sock`, or `/tmp/cordon-<uid>.sock` when
/// `XDG_RUNTIME_DIR` is unset — a world-writable directory) can park its *own* request on
/// the real daemon, answer us with *that* nonce, and let the human's authentication mint a
/// carrier for the attacker. The human really did authenticate — just not for this request.
///
/// So the check is not "is a daemon there" but "is the thing I am about to have a root
/// process approve actually the root daemon". Blessing against a non-root daemon could
/// never work anyway: the carrier's whole boundary is that only root can place tasks in it
/// (DESIGN §16.4), so a user-owned daemon has nothing to grant.
fn require_root_daemon(conn: &Conn, socket: &Path) -> Result<()> {
    let uid = conn.peer_uid();
    if uid != Uid::ROOT {
        return Err(Error::msg(format!(
            "the daemon on {} runs as uid {}, not root — refusing to request a blessing \
             from it (it could grant nothing, and approving its request would spend your \
             authentication on whatever it asked for)",
            socket.display(),
            uid,
        )));
    }
    Ok(())
}

/// Read one reply, turning a daemon-side `Error` and a hang-up into our error type so
/// callers only ever match the replies they expect.
fn reply(conn: &Conn) -> Result<(Response, Option<std::os::fd::OwnedFd>)> {
    match conn.recv_with_fd::<Response>()? {
        Some((resp, fd)) => Ok((resp.into_result()?, fd)),
        None => Err(Error::msg("daemon closed the connection without replying")),
    }
}

fn unexpected(resp: Response) -> Error {
    Error::msg(format!("unexpected daemon reply: {resp:?}"))
}

/// Prove a human is present: run `cordon bless-helper --nonce=…` under `$CORDON_SUDO`,
/// which authenticates and reaches the daemon as root.
///
/// `--nonce=VALUE` is deliberately **one argv token**: elevation wrappers vary in how
/// they re-split arguments, and a separated flag and value is the sort of thing one of
/// them will helpfully rearrange.
///
/// `socket` is passed explicitly rather than left to the helper to re-derive. Elevation
/// resets the environment, so a helper that resolved its own path would consult *root's*
/// config and could end up approving at a different daemon than the one we asked — which
/// silently breaks `--socket` and a per-user config, and would leave the two halves of the
/// handshake talking past each other. Naming it keeps them provably on the one daemon
/// [`require_root_daemon`] just vetted.
fn elevate(nonce: &Nonce, socket: &Path) -> Result<()> {
    let elevation = std::env::var(ELEVATION_ENV).unwrap_or_else(|_| DEFAULT_ELEVATION.to_string());
    let mut words = elevation.split_whitespace();
    let program = words
        .next()
        .ok_or_else(|| Error::msg(format!("${ELEVATION_ENV} is empty")))?;
    let me = std::env::current_exe().context("cannot locate the cordon binary")?;
    let status = Command::new(program)
        .args(words)
        .arg(me)
        .arg("--socket")
        .arg(socket)
        .arg("bless-helper")
        .arg(format!("--nonce={nonce}"))
        .status()
        .with_context(|| format!("spawn {program}"))?;
    if !status.success() {
        return Err(Error::msg(format!(
            "elevation via {program} did not succeed ({status}) — blessing refused"
        )));
    }
    Ok(())
}

/// The target `Command`: the given argv, or (empty) your shell. Nothing is set on the
/// environment — we are an ordinary child of the caller's shell, so it is already theirs.
fn build_command(argv: &[OsString]) -> Command {
    match argv.split_first() {
        Some((program, rest)) => {
            let mut c = Command::new(program);
            c.args(rest);
            c
        }
        None => Command::new(default_shell(std::env::var_os("SHELL").map(PathBuf::from))),
    }
}

/// The no-command shell: `$SHELL`, else `/bin/sh`. `$SHELL` is trustworthy again now that
/// nothing re-parents us through a privilege tool that would have reset it.
fn default_shell(env_shell: Option<PathBuf>) -> PathBuf {
    env_shell
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

    /// The confused-deputy guard. A socketpair's peer is this very process, so the check
    /// sees our own uid — which makes the expected verdict a function of how the suite is
    /// run, and asserting it that way is the point: an earlier version asserted "refused"
    /// unconditionally and would have failed under `sudo cargo test` or a root container.
    #[test]
    fn the_daemon_end_must_be_root() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let ours = Conn::new(ours).unwrap();
        let peer_is_root = ours.peer_uid() == Uid::ROOT;
        let verdict = require_root_daemon(&ours, Path::new("/socketpair"));
        assert_eq!(
            verdict.is_err(),
            !peer_is_root,
            "a {} peer should have been {}",
            if peer_is_root { "root" } else { "non-root" },
            if peer_is_root { "accepted" } else { "refused" }
        );
        if let Err(e) = verdict {
            assert!(e.to_string().contains("not root"), "unclear refusal: {e}");
        }
    }

    /// …and the guard fires **before** anything is written. Sending `BlessRequest` would
    /// already be too late: the next step hands the reply's nonce to a process about to
    /// become root. Only meaningful when the suite is unprivileged, since a root peer is
    /// legitimately accepted and the flow would then block waiting for a real daemon.
    #[test]
    fn a_non_root_daemon_learns_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let path = dir.join("cordon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        if Conn::connect(&path).unwrap().peer_uid() == Uid::ROOT {
            return; // running as root: this listener is a legitimate daemon end
        }

        assert!(request_and_approve(&path, None).is_err());

        // By now the client has hung up, so an empty read is EOF rather than a
        // would-block — either way what matters is that zero bytes arrived.
        listener.set_nonblocking(true).unwrap();
        let (peer, _) = listener.accept().expect("the client did connect");
        peer.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 64];
        let sent = match std::io::Read::read(&mut &peer, &mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(e) => panic!("reading the squatted socket: {e}"),
        };
        assert_eq!(sent, 0, "the client sent bytes to a non-root daemon");
    }

    /// Parse through the real `Cli` so the `args_conflicts_with_subcommands` shape is
    /// tested exactly as shipped.
    fn parse(argv: &[&str]) -> BlessArgs {
        match crate::Cli::try_parse_from(argv).expect("parse").cmd {
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
    fn default_shell_prefers_env_then_sh() {
        // `$SHELL` is authoritative again: nothing re-parents us through sudo, so it is
        // still the shell the user is actually running under.
        assert_eq!(
            default_shell(Some(PathBuf::from("/bin/fish"))),
            PathBuf::from("/bin/fish")
        );
        assert_eq!(default_shell(None), PathBuf::from("/bin/sh"));
        // An empty $SHELL (set but blank) falls through to /bin/sh.
        assert_eq!(
            default_shell(Some(PathBuf::new())),
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
