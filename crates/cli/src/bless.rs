//! `cordon bless`, which runs a command under a fresh blessing (DESIGN §16).
//!
//! The command runs as you and never holds privilege (see [`build_command`]). The daemon
//! hands over a carrier cgroup's descriptor, the target joins that carrier before it
//! runs, and the target's exit code becomes the exit code of `cordon bless` (see
//! [`mint_and_exec`]).
//!
//! The CLI has no cleanup to do. The daemon reaps the carrier once it empties, and its
//! mint grace covers a CLI that dies before the join (see `MINT_GRACE` in cordond).

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

/// The environment variable that names the elevation command for the approval helper. It
/// holds a command string, so `CORDON_SUDO="setpriv --reuid 0"` works as well as a bare
/// program.
///
/// Exposing it as a test seam is safe. The security lies in the daemon's uid check on the
/// approval (`authorize` in cordond), so a faked elevation only yields a non-root helper
/// whose approval is refused.
const ELEVATION_ENV: &str = "CORDON_SUDO";
const DEFAULT_ELEVATION: &str = "sudo";

/// The arguments of `cordon bless`, in one of three forms: `cordon bless [--class <name>]
/// [-- <command>…]`, `bless list` and `bless revoke <id>`. A command literally named
/// `list` runs as `cordon bless -- list`.
#[derive(clap::Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct BlessArgs {
    #[command(subcommand)]
    cmd: Option<BlessCmd>,
    /// Blessing class to mint (default: the sole class the policy declares).
    #[arg(long)]
    class: Option<ClassName>,
    /// Program and arguments to run under the blessing (default: `$SHELL`, or `/bin/sh`).
    /// Put `--` before a program whose name collides with a subcommand
    /// (`cordon bless -- list`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Subcommand, Debug)]
enum BlessCmd {
    /// Print every live blessing.
    List,
    /// Kill a live blessing's process tree and reap its carrier. You may end a blessing
    /// you minted, or any blessing as root.
    Revoke { id: BlessId },
}

pub fn run(args: &BlessArgs, client: &Client) -> ExitCode {
    match &args.cmd {
        // `list` and `revoke` are plain round trips, rendered like any other command. The
        // daemon decides who may revoke (see `may_revoke` in cordond).
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

/// Runs the command in `args` under a freshly minted blessing and returns its exit code,
/// mapped as [`exit_byte`] describes. Errors as [`Elevation::from_env`] does, and when the
/// socket can't be resolved, the mint handshake fails, or the command can't be spawned.
fn mint_and_exec(args: &BlessArgs, client: &Client) -> Result<ExitCode> {
    // Before the daemon is asked, so a bad `$CORDON_SUDO` never parks a request there.
    let elevation = Elevation::from_env()?;
    let socket = client.socket()?;
    let procs = request_and_approve(&socket, args.class.clone(), &elevation)?;
    let mut cmd = build_command(&args.command);
    sys::join_cgroup_on_exec(&mut cmd, procs);
    let status = cmd.status().context("spawn blessed command")?;
    Ok(ExitCode::from(exit_byte(status.code(), status.signal())))
}

/// Asks the daemon on `socket` to mint a blessing of `class`, gets the human's approval
/// through `elevation`, and returns the minted carrier's `cgroup.procs` descriptor. The
/// daemon half of this handshake is `Ctx::serve_bless_request` in cordond.
///
/// Errors when the daemon is unreachable or not root, when it refuses or replies out of
/// protocol, when the elevation fails, or when the mint reply carries no descriptor.
fn request_and_approve(
    socket: &Path,
    class: Option<ClassName>,
    elevation: &Elevation,
) -> Result<CarrierProcs> {
    // A dedicated connection rather than `crate::round_trip`, because any buffered read
    // loses the ancillary data that carries the descriptor (see `Conn::recv_with_fd`).
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
    // daemon's approval timeout.
    elevation.approve(&nonce, socket)?;

    match reply(&conn)? {
        (Response::BlessMinted(_), Some(procs)) => Ok(CarrierProcs(procs)),
        (Response::BlessMinted(view), None) => Err(Error::msg(format!(
            "daemon minted {} but passed no cgroup.procs descriptor",
            view.cgroup.display()
        ))),
        (other, _) => Err(unexpected(other)),
    }
}

/// Errors unless the process on the other end of `conn` is root.
///
/// Without this check the nonce is a bearer token for whoever answers the socket, and the
/// elevation that follows is a confused deputy. A local user can leave a listener at the
/// client's socket path. The per-user default that `SocketPath::for_client` tries first
/// lands in world-writable `/tmp` when `XDG_RUNTIME_DIR` is unset. That user can park its
/// own request on the real daemon, answer us with that request's nonce, and let the
/// human's authentication mint a carrier for the attacker. The human really did
/// authenticate, just not for this request.
///
/// So the question is not whether a daemon is there. It is whether the process that a
/// root helper is about to approve for is the root daemon. The check runs before anything
/// is sent, because the step after `BlessRequest` hands the reply's nonce to a process
/// about to become root. A non-root daemon could never grant a blessing anyway. The
/// carrier is root-owned and membership is the boundary (see `Blessings::mint` in
/// cordond), so a user-owned daemon has nothing to grant.
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

/// Returns the next reply on `conn` and any descriptor that came with it. Errors when the
/// daemon answers with an error or hangs up without replying, so callers match only the
/// replies they expect.
fn reply(conn: &Conn) -> Result<(Response, Option<std::os::fd::OwnedFd>)> {
    match conn.recv_with_fd::<Response>()? {
        Some((resp, fd)) => Ok((resp.into_result()?, fd)),
        None => Err(Error::msg("daemon closed the connection without replying")),
    }
}

fn unexpected(resp: Response) -> Error {
    Error::msg(format!("unexpected daemon reply: {resp:?}"))
}

/// The privilege tool that runs the root bless helper, as `$CORDON_SUDO` names it.
struct Elevation {
    program: String,
    args: Vec<String>,
}

impl Elevation {
    /// Returns the elevation that `$CORDON_SUDO` names, or [`DEFAULT_ELEVATION`] when it is
    /// unset. Errors when it is set but empty.
    fn from_env() -> Result<Elevation> {
        let spec = std::env::var(ELEVATION_ENV).unwrap_or_else(|_| DEFAULT_ELEVATION.to_string());
        let mut words = spec.split_whitespace().map(String::from);
        let program = words
            .next()
            .ok_or_else(|| Error::msg(format!("${ELEVATION_ENV} is empty")))?;
        Ok(Elevation {
            program,
            args: words.collect(),
        })
    }

    /// Runs `cordon bless-helper --nonce=…` under this elevation and waits for it. The
    /// helper approves `nonce` as root at the daemon on `socket`, and that authentication
    /// is the proof of human presence (see `authorize` in cordond). Errors when the
    /// elevation can't be spawned or doesn't succeed.
    fn approve(&self, nonce: &Nonce, socket: &Path) -> Result<()> {
        let program = &self.program;
        let me = std::env::current_exe().context("cannot locate the cordon binary")?;
        let status = Command::new(program)
            .args(&self.args)
            .arg(me)
            // The socket is named rather than re-derived by the helper. Elevation resets the
            // environment, so the helper would read root's config and could approve at a
            // different daemon, which silently breaks `--socket` and a per-user config. Naming
            // it keeps both halves of the handshake on the daemon `require_root_daemon` vetted.
            .arg("--socket")
            .arg(socket)
            .arg("bless-helper")
            // One argv token, because elevation wrappers differ in how they re-split arguments
            // and may rearrange a separate flag and value.
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
}

/// Returns the command that runs `argv`, or the shell from [`default_shell`] when `argv`
/// is empty. The command sets nothing in the environment. `cordon bless` is an ordinary
/// child of your shell that no privilege tool re-parents, and what it gets from the daemon
/// is a descriptor, not authority. So the target inherits your environment, cwd, tty, job
/// control and logind session unchanged, which keeps `$DISPLAY` and polkit working.
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

/// Returns `env_shell` when it is set and non-empty, and `/bin/sh` otherwise.
fn default_shell(env_shell: Option<PathBuf>) -> PathBuf {
    env_shell
        .filter(|s| !s.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

/// Returns the exit byte for a finished child. It is the child's own code, or
/// `128 + signal` when a signal killed it, as shells do. It is 1 when there is neither.
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

    /// Checks the confused-deputy guard. A socketpair's peer is this very process, so the
    /// check sees the suite's own uid. The expected verdict follows that uid, so the test
    /// also holds under `sudo cargo test` or in a root container.
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

    /// Checks that a non-root daemon receives zero bytes. The test means something only
    /// when the suite is unprivileged. A root peer is legitimately accepted, and the flow
    /// would then block waiting for a real daemon.
    #[test]
    fn a_non_root_daemon_learns_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let path = dir.join("cordon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        if Conn::connect(&path).unwrap().peer_uid() == Uid::ROOT {
            return; // As root, this listener is a legitimate daemon end.
        }

        // An elevation that would fail loudly if the check let it run.
        let never = Elevation {
            program: "false".into(),
            args: Vec::new(),
        };
        assert!(request_and_approve(&path, None, &never).is_err());

        // The client has hung up by now, so an empty read is EOF rather than a
        // would-block. Either way, what matters is that zero bytes arrived.
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

    /// Parses `argv` through the real `Cli`, so the tests see the
    /// `args_conflicts_with_subcommands` shape exactly as shipped. Panics unless `argv`
    /// parses to `bless`.
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
        // Flags and a real command line.
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
        // Bare `bless` has no subcommand and no command, so it runs the invoker's shell
        // under the sole class.
        let a = parse(&["cordon", "bless"]);
        assert!(a.cmd.is_none() && a.command.is_empty() && a.class.is_none());
    }

    #[test]
    fn default_shell_prefers_env_then_sh() {
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
        // SIGKILL (9) maps to 137 and SIGTERM (15) to 143, as shells do.
        assert_eq!(exit_byte(None, Some(9)), 137);
        assert_eq!(exit_byte(None, Some(15)), 143);
        assert_eq!(exit_byte(None, None), 1);
    }
}
