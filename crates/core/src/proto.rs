//! The IPC protocol between the `cordon` CLI and the `cordond` daemon — the
//! control/management plane, *not* the data path of a gated `open()` (that is
//! returned in-kernel by the bpf-lsm program).
//!
//! Wire format: one JSON value per line (newline-delimited), synchronous RPC. Types
//! here are runtime-agnostic so the same `Request`/`Response`/`handle` logic works
//! whether the accept loop is threads or async.
//!
//! The flat **rule model** (DESIGN §15): policy is authored in a root-owned text file
//! and pushed with `policy apply`; there are no per-object owner mutations on the wire.

use crate::Result;
use crate::policy::{ClassName, Diagnostic};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// A command from a client to the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Daemon summary (backend, the effective policy's object count).
    Status,
    /// Compile + apply a policy, atomically replacing the live one. The CLI sends the
    /// **fragments** it read from the policy path (one for a file, many for a conf.d
    /// directory): the daemon resolves each fragment's `user =` home, merges, compiles
    /// with its own mount-aware resolver, and swaps the in-kernel maps.
    PolicyApply {
        sources: Vec<crate::policy::PolicySource>,
    },
    /// The effective (currently-loaded) compiled policy.
    PolicyShow,
    /// Mint a blessing (DESIGN §16): create a carrier cgroup registered under `class`
    /// (`None` → the sole declared class) and return it for the CLI to exec into.
    /// **Root-gated** (`SO_PEERCRED` uid 0): sudo is the B1 authenticator.
    BlessMint { class: Option<ClassName> },
    /// The live blessings (carrier cgroup, member pids, age). Ungated — read-only,
    /// parity with `PolicyShow`.
    BlessList,
    /// Kill a live blessing's carrier cgroup and unregister it. Root-gated like
    /// `BlessMint`.
    BlessRevoke { id: BlessId },
}

/// A live blessing's daemon-assigned handle — what `cordon bless list` prints and
/// `cordon bless revoke <id>` names. Monotonic per daemon run (also embedded in the
/// carrier cgroup's directory name, so it survives daemon restarts via reconcile);
/// `Ord` because the allocator advances past the highest adopted id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlessId(pub u64);

impl BlessId {
    /// The id after this one — the allocator's step (a mint, or reconcile bumping
    /// past an adopted id).
    pub fn successor(self) -> BlessId {
        BlessId(self.0 + 1)
    }
}

impl std::fmt::Display for BlessId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for BlessId {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> std::result::Result<BlessId, Self::Err> {
        Ok(BlessId(s.parse()?))
    }
}

/// A reply from the daemon to a client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Status(StatusInfo),
    /// Result of `PolicyApply`: the compile diagnostics and whether it was applied
    /// (false ⇒ it had errors and the live policy is unchanged).
    PolicyApplied {
        applied: bool,
        diagnostics: Vec<Diagnostic>,
    },
    /// The effective policy (`PolicyShow`), or `None` if none is loaded.
    PolicyView(Option<PolicyView>),
    /// A freshly-minted blessing (`BlessMint`): the carrier cgroup the CLI now execs
    /// the target into.
    BlessMinted(BlessingView),
    /// The live blessings (`BlessList`).
    Blessings(Vec<BlessingView>),
    /// The blessing was revoked (`BlessRevoke`); its carrier is being killed + reaped.
    BlessRevoked {
        id: BlessId,
    },
    Error {
        message: String,
    },
}

/// One live blessing as shown to the CLI: its handle, class, carrier cgroup directory,
/// current member pids, and age.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlessingView {
    pub id: BlessId,
    pub class: ClassName,
    /// The carrier cgroup directory (`…/cordon-bless-<id>.<class>`); the CLI writes the
    /// target pid into its `cgroup.procs`.
    pub cgroup: PathBuf,
    /// The carrier's current members, as read from its `cgroup.procs`.
    pub pids: Vec<Pid>,
    /// How long since the blessing was minted.
    pub age: std::time::Duration,
}

/// The blessing carrier's `cgroup.procs`, **opened for write by the root daemon** — the
/// out-of-band half of a [`Response::BlessMinted`], passed over `SCM_RIGHTS` rather than
/// serialized (hence no `Serialize`; it rides beside the JSON, see [`send_msg_with_fd`]).
///
/// Writing a pid into it joins that task to the blessing. It is a **capability, not a
/// path**: cgroup-v2 checks migration permission against the credentials of whoever
/// *opened* the file, so holding this fd is what lets an unprivileged `cordon bless` place
/// its child in a root-owned carrier without ever being root (DESIGN §16.4). Conversely
/// the holder can move any task it can name — see the same section.
#[derive(Debug)]
pub struct CarrierProcs(pub std::os::fd::OwnedFd);

/// A process id (thread-group id) on the control plane — a carrier cgroup member as
/// listed in `cgroup.procs`. `u32` to match the kernel's pid width there; a newtype so
/// it can't be mixed up with a [`BlessId`] or a raw count (the wire discipline of the
/// bpf-common scalars, which this seam deliberately doesn't depend on).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pid(pub u32);

impl std::fmt::Display for Pid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusInfo {
    pub backend: crate::backend::BackendKind,
    pub socket: PathBuf,
    /// The policy file the backend compiles at startup / `apply` re-reads.
    pub policy: PathBuf,
    /// How many protected objects the effective policy has (`None` if none loaded).
    pub objects: Option<usize>,
}

/// A human-facing snapshot of the effective compiled policy, for `cordon policy show`.
/// Subjects are rendered (the compiled form keys them by inode, not path), so this is
/// a summary: the protected object paths, each with its rule count.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyView {
    pub objects: Vec<ObjectView>,
    /// Policy paths that don't exist yet (not enforced until created + re-applied).
    pub pending: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectView {
    pub path: PathBuf,
    pub rules: usize,
}

/// Write one newline-framed JSON message and flush.
pub fn write_msg<W: Write>(w: &mut W, value: &impl Serialize) -> Result<()> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()?;
    Ok(())
}

/// Read one newline-framed JSON message. `Ok(None)` on clean EOF.
pub fn read_msg<R: BufRead, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(line.trim_end())?))
}

/// Send one newline-framed JSON message with a file descriptor riding along as
/// `SCM_RIGHTS` ancillary data — the blessing hand-off (DESIGN §16.6): the daemon opens
/// the carrier's `cgroup.procs` as root and passes *only that fd*, so the CLI never needs
/// privilege to join.
///
/// The fd is attached to this one `sendmsg`, so it is delivered at exactly this point in
/// the byte stream; the peer must read it with [`read_msg_with_fd`].
#[cfg(target_os = "linux")]
pub fn send_msg_with_fd(
    sock: &UnixStream,
    value: &impl Serialize,
    fd: std::os::fd::BorrowedFd<'_>,
) -> Result<()> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    send_all_with_fd(sock, s.as_bytes(), fd)
}

/// `write_all` for a socket, with `fd` attached to the **first** chunk only.
///
/// The two rules a naive loop gets wrong: a `sendmsg` may write short, and re-attaching
/// the ancillary data to a continuation would install a *second* copy of the descriptor
/// in the peer.
#[cfg(target_os = "linux")]
fn send_all_with_fd(
    sock: &UnixStream,
    bytes: &[u8],
    fd: std::os::fd::BorrowedFd<'_>,
) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    use std::os::fd::{AsFd, AsRawFd};

    let raw = sock.as_fd().as_raw_fd();
    let passed = [fd.as_raw_fd()];
    let scm = [ControlMessage::ScmRights(&passed)];
    let mut sent = 0;
    while sent < bytes.len() {
        let iov = [std::io::IoSlice::new(&bytes[sent..])];
        let cmsgs: &[ControlMessage] = if sent == 0 { &scm } else { &[] };
        sent += sendmsg::<()>(raw, &iov, cmsgs, MsgFlags::empty(), None)
            .map_err(|e| crate::Error::msg(format!("sendmsg: {e}")))?;
    }
    Ok(())
}

/// Read one newline-framed JSON message off a socket, capturing an `SCM_RIGHTS` file
/// descriptor if the peer attached one. `Ok(None)` on clean EOF.
///
/// **Why this exists instead of a `BufReader`:** a plain `read(2)` on a socket carrying
/// ancillary data *discards* the descriptors — the kernel closes them — so the fd-bearing
/// connection can never be read through the buffered path. `recvmsg` is the only way to
/// claim them.
///
/// The descriptor arrives **close-on-exec** (`MSG_CMSG_CLOEXEC`). That is not the kernel's
/// default for `SCM_RIGHTS` and it matters here: without it the carrier's `cgroup.procs`
/// would survive into the blessed process, handing it a standing capability to move other
/// tasks into its own blessing (DESIGN §16.4). The `pre_exec` join happens before the exec
/// that would drop it, so nothing legitimate needs it to persist.
#[cfg(target_os = "linux")]
pub fn read_msg_with_fd<T: DeserializeOwned>(
    sock: &UnixStream,
) -> Result<Option<(T, Option<std::os::fd::OwnedFd>)>> {
    let mut line = Vec::new();
    let mut fd = None;
    loop {
        match recv_byte_with_fd(sock, &mut fd)? {
            Some(b'\n') => break,
            Some(b) => line.push(b),
            None if line.is_empty() => return Ok(None),
            None => return Err(crate::Error::msg("peer closed mid-message")),
        }
    }
    Ok(Some((serde_json::from_slice(&line)?, fd)))
}

/// Receive **one byte**, claiming any `SCM_RIGHTS` descriptor that arrives with it into
/// `fd`. `Ok(None)` at EOF.
///
/// ponytail: one byte per syscall. Deliberate, not an oversight — a buffered read could
/// pull bytes of the *next* message into a buffer the caller then throws away, and
/// ancillary data is delivered with the first byte of the message it rode in on, so a
/// one-byte read still claims the descriptor. This runs once per `cordon bless`, never on
/// the verdict path. If it ever lands somewhere hot, buffer here and hand the leftovers
/// back to the caller.
#[cfg(target_os = "linux")]
fn recv_byte_with_fd(
    sock: &UnixStream,
    fd: &mut Option<std::os::fd::OwnedFd>,
) -> Result<Option<u8>> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

    let mut byte = [0u8; 1];
    let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
    // Scoped so the borrow of `byte` (through the iovec, and through the returned message
    // that points at it) ends before the byte is read back out.
    let received = {
        let mut iov = [std::io::IoSliceMut::new(&mut byte)];
        let msg = recvmsg::<()>(
            sock.as_fd().as_raw_fd(),
            &mut iov,
            Some(&mut cmsg),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .map_err(|e| crate::Error::msg(format!("recvmsg: {e}")))?;
        for c in msg
            .cmsgs()
            .map_err(|e| crate::Error::msg(format!("recvmsg cmsgs: {e}")))?
        {
            if let ControlMessageOwned::ScmRights(fds) = c {
                for got in fds {
                    // SAFETY: the kernel just installed `got` in this process as a fresh
                    // descriptor; nothing else owns it.
                    let owned = unsafe { OwnedFd::from_raw_fd(got) };
                    // We only ever expect one; a surprise extra is dropped, i.e. closed,
                    // rather than leaked.
                    fd.get_or_insert(owned);
                }
            }
        }
        msg.bytes
    };
    Ok((received > 0).then_some(byte[0]))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsFd;

    /// The blessing hand-off in miniature: a message plus a descriptor over one socket,
    /// and the received fd is the *same open file* — not a copy of the number. Proven by
    /// writing through it and reading the bytes back on the sender's side.
    #[test]
    fn fd_rides_along_with_the_message() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut file = tempfile();

        send_msg_with_fd(&a, &Response::BlessRevoked { id: BlessId(7) }, file.as_fd()).unwrap();
        let (msg, fd) = read_msg_with_fd::<Response>(&b)
            .unwrap()
            .expect("a message");
        assert!(matches!(msg, Response::BlessRevoked { id: BlessId(7) }));

        let fd = fd.expect("an fd rode along");
        // Close-on-exec, so the carrier capability dies at the exec that starts the
        // blessed command instead of living on inside it (DESIGN §16.4). Not the
        // kernel's default for SCM_RIGHTS — it is `MSG_CMSG_CLOEXEC` that buys this.
        let flags = nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert!(
            nix::fcntl::FdFlag::from_bits_truncate(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "a received descriptor must not survive exec"
        );

        let mut received = std::fs::File::from(fd);
        received.write_all(b"joined").unwrap();
        file.rewind().unwrap();
        let mut back = String::new();
        file.read_to_string(&mut back).unwrap();
        assert_eq!(back, "joined", "the received fd is the same open file");
    }

    /// The ordinary case must keep working on the same reader: no ancillary data, no fd.
    #[test]
    fn a_message_without_an_fd_reads_back_bare() {
        let (a, b) = UnixStream::pair().unwrap();
        write_msg(&mut &a, &Response::BlessRevoked { id: BlessId(3) }).unwrap();
        let (msg, fd) = read_msg_with_fd::<Response>(&b)
            .unwrap()
            .expect("a message");
        assert!(matches!(msg, Response::BlessRevoked { id: BlessId(3) }));
        assert!(fd.is_none());
    }

    /// A closed peer is `None`, the same clean-EOF contract as [`read_msg`] — so a caller
    /// can't mistake a hang-up for a message.
    #[test]
    fn clean_eof_is_none() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(read_msg_with_fd::<Response>(&b).unwrap().is_none());
    }

    /// An unlinked temp file — an fd with observable identity, no cleanup to forget.
    fn tempfile() -> std::fs::File {
        let path = std::env::temp_dir().join(format!("cordon-proto-fd-{}", std::process::id()));
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file
    }
}
