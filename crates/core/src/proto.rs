//! The IPC protocol between the `cordon` CLI and the `cordond` daemon. It carries the
//! control plane only, and no verdict crosses it.
//!
//! Each message is one JSON value on its own line, and each request gets one reply. The
//! types here do not depend on a runtime, so the same request and response logic works
//! whether the accept loop uses threads or async.

use crate::policy::{ClassName, Diagnostic};
use crate::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// A command from a client to the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Asks for the daemon's [`StatusInfo`].
    Status,
    /// Compiles the given policy fragments and atomically replaces the live policy with
    /// the result. The CLI sends the fragments it read from the policy path, one for a
    /// file and many for a conf.d directory
    /// ([`compile_fragments`](crate::policy::compile_fragments)).
    PolicyApply {
        sources: Vec<crate::policy::PolicySource>,
    },
    /// Asks for the effective (currently loaded) compiled policy.
    PolicyShow,
    /// Asks for a blessing under `class`, or under the sole declared class when `class`
    /// is `None`. This is the unprivileged half of the mint handshake (DESIGN §16.5).
    ///
    /// The daemon replies [`Response::BlessPending`] with a [`Nonce`] and keeps this
    /// connection open. Once a matching [`Self::BlessApprove`] arrives on a second
    /// connection, [`Response::BlessMinted`] comes back on this one. The daemon's
    /// `Ctx::serve_bless_request` runs the handshake, and its `authorize` decides which
    /// verbs need root.
    BlessRequest { class: Option<ClassName> },
    /// Approves a pending [`Self::BlessRequest`]. This is the human-presence half of the
    /// handshake, and the daemon's `authorize` allows it only to root. The nonce is spent
    /// whether or not the mint then succeeds.
    BlessApprove { nonce: Nonce },
    /// Asks for the live blessings.
    BlessList,
    /// Kills a live blessing's carrier cgroup and unregisters it. The daemon's
    /// `may_revoke` decides who may do so.
    BlessRevoke { id: BlessId },
}

/// A single-use handle that binds an unprivileged [`Request::BlessRequest`] to the root
/// [`Request::BlessApprove`] that authorizes it.
///
/// A nonce is 128 bits from `getrandom(2)`, written as hex. It must be unguessable, which
/// is why it is not a counter. With a predictable value, an attacker could register their
/// own request, predict the nonce that your session is about to be issued, and have your
/// authenticated helper approve their request, which hands them the carrier. Knowing an
/// already issued nonce is harmless by contrast. Approving it still requires uid 0, and the
/// carrier descriptor goes back on the requester's own connection, never to the approver.
/// The daemon's `Ctx::approve` removes the nonce before it releases the requester, so a
/// replay finds nothing.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Nonce(String);

impl Nonce {
    /// The number of entropy bytes behind a nonce. That is far beyond guessing for a value
    /// that only has to survive the seconds between a request and its approval.
    const BYTES: usize = 16;

    /// Returns a fresh nonce from the kernel CSPRNG. Errors when `getrandom(2)` fails, so
    /// that the blessing is refused instead of getting a weak nonce.
    pub fn generate() -> Result<Nonce> {
        let mut buf = [0u8; Nonce::BYTES];
        getrandom::fill(&mut buf).context("getrandom")?;
        Ok(Nonce(buf.map(|b| format!("{b:02x}")).concat()))
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Nonce {
    type Error = crate::Error;
    fn try_from(s: String) -> Result<Nonce> {
        s.parse()
    }
}

impl std::str::FromStr for Nonce {
    type Err = crate::Error;
    /// Parses a nonce from its hex form. Errors when the value is not 32 hex digits. A
    /// malformed value could only miss in the pending table, but rejecting it here keeps
    /// junk out of the daemon's map keys.
    fn from_str(s: &str) -> Result<Nonce> {
        if s.len() == Nonce::BYTES * 2 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Nonce(s.to_ascii_lowercase()))
        } else {
            Err(crate::Error::msg("malformed bless nonce"))
        }
    }
}

/// The handle that the daemon assigns to a live blessing, which `cordon bless list` prints
/// and `cordon bless revoke <id>` takes. Ids only grow within a daemon run. Each id is also
/// part of the carrier cgroup's directory name, so it survives a daemon restart through
/// reconcile. The type is `Ord` so that the allocator can advance past the highest adopted
/// id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlessId(pub u64);

impl BlessId {
    /// Returns the id after this one.
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
    /// Answers `PolicyApply` with the compile diagnostics. When `applied` is false, the
    /// policy had errors and the live policy is unchanged.
    PolicyApplied {
        applied: bool,
        diagnostics: Vec<Diagnostic>,
    },
    /// Answers `PolicyShow` with the effective policy, or with `None` when no policy is
    /// loaded.
    PolicyView(Option<PolicyView>),
    /// Reports that a `BlessRequest` is registered and awaits approval.
    /// [`Self::BlessMinted`] follows on the same connection once it is approved.
    BlessPending {
        nonce: Nonce,
    },
    /// Reports that a `BlessApprove` was accepted and the waiting requester was released.
    BlessApproved,
    /// Carries the newly minted blessing to the requester once the approval lands. The
    /// carrier's `cgroup.procs` rides beside it as `SCM_RIGHTS` ([`CarrierProcs`]).
    BlessMinted(BlessingView),
    /// Answers `BlessList` with the live blessings.
    Blessings(Vec<BlessingView>),
    /// Answers `BlessRevoke`. The blessing is unregistered, and its carrier is being
    /// killed and reaped.
    BlessRevoked {
        id: BlessId,
    },
    Error {
        message: String,
    },
}

impl Response {
    /// Returns the reply unchanged. Errors with the daemon's message when the reply is a
    /// [`Response::Error`].
    pub fn into_result(self) -> Result<Response> {
        match self {
            Response::Error { message } => Err(crate::Error::msg(format!("daemon: {message}"))),
            other => Ok(other),
        }
    }
}

/// One live blessing as the daemon reports it to the CLI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlessingView {
    pub id: BlessId,
    pub class: ClassName,
    /// The carrier cgroup directory (`…/cordon-bless-<id>.<class>`). The CLI writes the
    /// target pid into its `cgroup.procs`.
    pub cgroup: PathBuf,
    /// The carrier's current members, as read from its `cgroup.procs`.
    pub pids: Vec<Pid>,
    /// The time since the blessing was minted.
    pub age: std::time::Duration,
}

/// The blessing carrier's `cgroup.procs`, opened for writing by the root daemon. It is the
/// out-of-band half of a [`Response::BlessMinted`], passed over `SCM_RIGHTS` beside the
/// JSON instead of serialized, which is why it has no `Serialize` ([`Conn::send_with_fd`]).
///
/// Writing a pid into it moves that task into the blessing. It is a capability, not a path,
/// because cgroup v2 checks migration permission against the credentials of whoever opened
/// the file. Holding this descriptor is what lets an unprivileged `cordon bless` place its
/// child in a root-owned carrier without ever being root (DESIGN §16.4). The flip side is
/// that the holder can move any task it can name, as the same section explains.
#[derive(Debug)]
pub struct CarrierProcs(pub std::os::fd::OwnedFd);

/// A process id (a thread-group id) on the control plane. It names a carrier cgroup member
/// as `cgroup.procs` lists it, or a socket peer as [`Conn::peer_pid`] reports it. It is a
/// `u32` to match the kernel's pid width there, and a newtype so that it cannot be mixed up
/// with a [`BlessId`] or a raw count. That follows the wire discipline of the bpf-common
/// scalars, without this seam depending on that crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pid(pub u32);

impl Pid {
    /// Returns the pid for a raw `pid_t` from the kernel, which is signed. A negative value
    /// becomes 0.
    ///
    /// Pids are non-negative, but `pid_t` carries a sign because the `kill(2)` family uses
    /// negative values to mean a process group. Nothing that reaches this type is such a
    /// value, since `SO_PEERCRED` reports a real peer, so a negative here is not a pid at
    /// all. It becomes 0, the same "no usable process" value that the non-Linux stub
    /// returns and that every consumer already treats as a reason to fall back. Converting
    /// in one place beats an `as u32` at each call site, where the sign question is
    /// invisible.
    pub fn from_raw(raw: i32) -> Pid {
        Pid(raw.max(0) as u32)
    }
}

impl std::fmt::Display for Pid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusInfo {
    pub backend: crate::backend::BackendKind,
    pub socket: PathBuf,
    /// The policy file that the backend compiles at startup and that `apply` reads again.
    pub policy: PathBuf,
    /// The number of protected objects in the effective policy, or `None` when no policy
    /// is loaded.
    pub objects: Option<usize>,
}

/// A human-facing snapshot of the effective compiled policy, for `cordon policy show`. It
/// is only a summary, because the compiled form keys subjects by inode rather than by
/// path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyView {
    pub objects: Vec<ObjectView>,
    /// The policy paths that do not resolve yet and so are not enforced (see
    /// `Compiler::objects`).
    pub pending: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectView {
    pub path: PathBuf,
    pub rules: usize,
}

/// One end of a connection between the CLI and the daemon. It sends and receives framed
/// messages, and knows who is on the other end.
pub struct Conn {
    stream: UnixStream,
    /// The buffer behind [`recv`](Self::recv). [`recv_with_fd`](Self::recv_with_fd) reads
    /// the socket directly, so it refuses while this buffer holds bytes it would skip.
    reader: BufReader<UnixStream>,
    peer_uid: crate::Uid,
    peer_pid: Pid,
}

impl Conn {
    /// Wraps a connected socket and records its peer's `SO_PEERCRED`. Errors when the
    /// credentials cannot be read or the socket cannot be cloned.
    pub fn new(stream: UnixStream) -> Result<Conn> {
        let (peer_uid, peer_pid) = peer_cred(&stream)?;
        Ok(Conn {
            reader: BufReader::new(stream.try_clone()?),
            stream,
            peer_uid,
            peer_pid,
        })
    }

    /// Connects to the socket at `path`. Errors with [`Error::Io`](crate::Error::Io) when
    /// `connect(2)` fails, so that a caller can tell that no daemon is listening.
    pub fn connect(path: &Path) -> Result<Conn> {
        Conn::new(UnixStream::connect(path)?)
    }

    /// Returns the peer's uid, as the kernel attests it.
    ///
    /// Both ends use it, and for the same reason. The daemon asks who is calling, so that
    /// it can gate the writes. The client asks who answered, because a socket path is not
    /// proof of a daemon (the CLI's `require_root_daemon`).
    ///
    /// It is the only identity in the protocol that the party it describes does not assert,
    /// which is why every authorization decision rests on it. Off Linux it is an impossible
    /// uid, so every check that consults it fails closed.
    pub fn peer_uid(&self) -> crate::Uid {
        self.peer_uid
    }

    /// Returns the peer's pid. The daemon reads the requester's cgroup through it to place a
    /// blessing carrier in that process's own logind session scope (DESIGN §16.6).
    ///
    /// It is weaker than [`peer_uid`](Self::peer_uid), and the difference matters. The
    /// kernel records the pid at `connect(2)`, so no client asserts it, and a pid that the
    /// client supplied would let a caller aim the carrier at another user's session. But
    /// the kernel records a number, and pid numbers are reused once the task is reaped.
    /// The whole approval wait sits between the connect and the daemon's read of
    /// `/proc/<pid>/cgroup`, so by then the pid may name a different process.
    /// `SO_PEERPIDFD` (Linux 6.5) fixes that kind of staleness, should this pid ever need
    /// to be authoritative.
    ///
    /// It does not need to be today, because placement is not authorization. The grant is
    /// gated on a uid-0 `BlessApprove`, and anyone able to complete one already has root. A
    /// stale pid resolves to nothing, or to a cgroup with no session scope, and placement
    /// then falls back to the daemon's own cgroup. Off Linux the pid is 0, which is not a
    /// real process, so the cgroup read fails and placement falls back the same way.
    pub fn peer_pid(&self) -> Pid {
        self.peer_pid
    }

    /// Sends one message.
    pub fn send(&self, msg: &impl Serialize) -> Result<()> {
        write_msg(&mut &self.stream, msg)
    }

    /// Receives one message, or `None` when the peer hung up between messages.
    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        read_msg(&mut self.reader)
    }

    /// Sends one message with `fd` attached as `SCM_RIGHTS` ancillary data, as the blessing
    /// hand-off of a [`CarrierProcs`] does (DESIGN §16.6). The peer must read it with
    /// [`recv_with_fd`](Self::recv_with_fd).
    #[cfg(target_os = "linux")]
    pub fn send_with_fd(
        &self,
        msg: &impl Serialize,
        fd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<()> {
        send_msg_with_fd(&self.stream, msg, fd)
    }

    /// Receives one message and the descriptor that came with it, if any. Returns `None`
    /// when the peer hung up between messages. Errors when an earlier
    /// [`recv`](Self::recv) buffered bytes past its message, since this read would skip
    /// them.
    #[cfg(target_os = "linux")]
    pub fn recv_with_fd<T: DeserializeOwned>(
        &self,
    ) -> Result<Option<(T, Option<std::os::fd::OwnedFd>)>> {
        if !self.reader.buffer().is_empty() {
            return Err(crate::Error::msg(
                "internal: a buffered read holds bytes past its message",
            ));
        }
        read_msg_with_fd(&self.stream)
    }
}

/// Writes one newline-framed JSON message and flushes the writer.
fn write_msg<W: Write>(w: &mut W, value: &impl Serialize) -> Result<()> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()?;
    Ok(())
}

/// Reads one newline-framed JSON message. Returns `None` at a clean EOF.
fn read_msg<R: BufRead, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(line.trim_end())?))
}

/// Returns the peer's uid and pid from one `SO_PEERCRED`.
#[cfg(target_os = "linux")]
fn peer_cred(sock: &UnixStream) -> Result<(crate::Uid, Pid)> {
    // Through nix, because std's `peer_cred()` is still unstable.
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let creds = getsockopt(sock, PeerCredentials).context("SO_PEERCRED")?;
    Ok((crate::Uid(creds.uid()), Pid::from_raw(creds.pid())))
}

/// Returns a uid and pid that every check fails closed on, because there is no
/// `SO_PEERCRED` off Linux. The enforcement backend is Linux-only anyway, and this stub
/// only keeps the non-Linux build compiling.
#[cfg(not(target_os = "linux"))]
fn peer_cred(_sock: &UnixStream) -> Result<(crate::Uid, Pid)> {
    Ok((crate::Uid(u32::MAX), Pid::from_raw(0)))
}

/// Sends one newline-framed JSON message with `fd` attached to it. The peer receives the
/// descriptor at exactly this point in the byte stream.
#[cfg(target_os = "linux")]
fn send_msg_with_fd(
    sock: &UnixStream,
    value: &impl Serialize,
    fd: std::os::fd::BorrowedFd<'_>,
) -> Result<()> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    send_all_with_fd(sock, s.as_bytes(), fd)
}

/// Writes all of `bytes` to the socket, with `fd` attached to the first chunk only.
///
/// A naive loop gets two things wrong. A `sendmsg` may write short, and attaching the
/// ancillary data again to a continuation would install a second copy of the descriptor
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
        sent += sendmsg::<()>(raw, &iov, cmsgs, MsgFlags::empty(), None).context("sendmsg")?;
    }
    Ok(())
}

/// Reads one newline-framed JSON message off a socket, along with an `SCM_RIGHTS` file
/// descriptor if the peer attached one. Returns `None` at a clean EOF. Errors when the
/// peer closes in the middle of a message.
///
/// It exists instead of a `BufReader` because a plain `read(2)` on a socket that carries
/// ancillary data discards the descriptors, and the kernel closes them. Only `recvmsg` can
/// claim them.
///
/// The descriptor arrives close-on-exec (`MSG_CMSG_CLOEXEC`). That is not the kernel's
/// default for `SCM_RIGHTS`, and it matters here. Without it, the carrier's `cgroup.procs`
/// would survive into the blessed process and hand it a standing capability to move other
/// tasks into its own blessing (DESIGN §16.4). The `pre_exec` join happens before the exec
/// that drops the descriptor, so nothing legitimate needs it to persist.
#[cfg(target_os = "linux")]
fn read_msg_with_fd<T: DeserializeOwned>(
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

/// Receives one byte, and stores any `SCM_RIGHTS` descriptor that arrives with it in
/// `fd`. Returns `None` at EOF.
///
/// ponytail: one byte per syscall, on purpose. A buffered read could pull bytes of the
/// next message into a buffer that the caller then throws away. Ancillary data arrives
/// with the first byte of the message it was sent with, so a one-byte read still claims
/// the descriptor. This runs once per `cordon bless` and never on the verdict path. If it
/// ever lands somewhere hot, buffer here and hand the leftovers back to the caller.
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
        .context("recvmsg")?;
        for c in msg.cmsgs().context("recvmsg cmsgs")? {
            if let ControlMessageOwned::ScmRights(fds) = c {
                for got in fds {
                    // SAFETY: the kernel just installed `got` in this process as a fresh
                    // descriptor, and nothing else owns it.
                    let owned = unsafe { OwnedFd::from_raw_fd(got) };
                    // Only one is ever expected. A surprise extra is dropped, which closes
                    // it instead of leaking it.
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
    use crate::config;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsFd;

    /// A nonce read off the socket is validated like one parsed from argv.
    #[test]
    fn nonce_wire_decode_rejects_junk() {
        let n = Nonce::generate().unwrap();
        let wire = serde_json::to_string(&n).unwrap();
        assert_eq!(serde_json::from_str::<Nonce>(&wire).unwrap(), n);
        for junk in ["", "nope", "zz112233445566778899aabbccddeeff"] {
            let wire = serde_json::to_string(junk).unwrap();
            assert!(
                serde_json::from_str::<Nonce>(&wire).is_err(),
                "decoded {junk:?}"
            );
        }
    }

    /// The blessing hand-off in miniature. A message and a descriptor go over one socket,
    /// and the received fd is the same open file, not a copy of the number. Writing
    /// through it and reading the bytes back on the sender's side proves that.
    #[test]
    fn fd_rides_along_with_the_message() {
        let (a, b) = UnixStream::pair().unwrap();
        // An unlinked temp file gives an fd with an observable identity.
        let mut file = tempfile::tempfile().unwrap();

        send_msg_with_fd(&a, &Response::BlessRevoked { id: BlessId(7) }, file.as_fd()).unwrap();
        let (msg, fd) = read_msg_with_fd::<Response>(&b)
            .unwrap()
            .expect("a message");
        assert!(matches!(msg, Response::BlessRevoked { id: BlessId(7) }));

        let fd = fd.expect("an fd rode along");
        // Close-on-exec; see `read_msg_with_fd` for why.
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

    /// The ordinary case, with no ancillary data and no fd, must keep working on the same
    /// reader.
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

    /// A descriptor read must not start behind bytes that a buffered `recv` already
    /// pulled off the socket. Those bytes, and a descriptor riding on them, would be lost.
    #[test]
    fn recv_with_fd_refuses_after_a_buffered_read() {
        let (a, b) = UnixStream::pair().unwrap();
        let (a, mut b) = (Conn::new(a).unwrap(), Conn::new(b).unwrap());
        a.send(&Response::BlessRevoked { id: BlessId(1) }).unwrap();
        a.send(&Response::BlessRevoked { id: BlessId(2) }).unwrap();
        drop(a);
        assert!(b.recv::<Response>().unwrap().is_some());
        assert!(b.recv_with_fd::<Response>().is_err());
    }

    /// `pid_t` is signed and pids are not. A real pid passes through unchanged. A negative
    /// value is a `kill(2)` process-group overload that never reaches this type, and it
    /// lands on 0, the "no usable process" value that consumers already fall back on.
    #[test]
    fn pid_from_raw_normalizes_the_kernels_signed_width() {
        assert_eq!(Pid::from_raw(4242), Pid(4242));
        assert_eq!(Pid::from_raw(0), Pid(0));
        assert_eq!(Pid::from_raw(i32::MAX), Pid(i32::MAX as u32));
        // Not wrapped to a huge pid, which is what a bare `as u32` would have done.
        assert_eq!(Pid::from_raw(-1), Pid(0));
        assert_eq!(Pid::from_raw(i32::MIN), Pid(0));
    }

    /// `SO_PEERCRED` reports the process on the other end, not the one asking. Both sides
    /// of a socketpair are this test, so both reads must be our own uid. That is enough
    /// to show that the value is real and not, say, a hardcoded zero that would make
    /// every uid check pass.
    #[test]
    fn peer_uid_reports_the_other_end() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = crate::Uid(config::euid());
        let a = Conn::new(a).unwrap();
        assert_eq!(a.peer_uid(), me);
        assert_eq!(Conn::new(b).unwrap().peer_uid(), me);
        // And a non-root test runner must not look like root to the caller's check.
        if !config::is_root() {
            assert_ne!(a.peer_uid(), crate::Uid::ROOT);
        }
    }

    /// A closed peer reads as `None`, the same clean-EOF contract as [`read_msg`], so a
    /// caller cannot mistake a hang-up for a message.
    #[test]
    fn clean_eof_is_none() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(read_msg_with_fd::<Response>(&b).unwrap().is_none());
    }
}
