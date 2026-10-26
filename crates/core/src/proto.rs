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
    /// Ask for a blessing under `class` (`None` → the sole declared class) — the
    /// **unprivileged** half of the mint handshake (DESIGN §16.5).
    ///
    /// Ungated on purpose: this connection's only power is to *ask*. The daemon replies
    /// [`Response::BlessPending`] with a single-use [`Nonce`] and **keeps the connection
    /// open**; nothing is minted until a uid-0 peer sends the matching [`Self::BlessApprove`]
    /// on a second connection, at which point the carrier and its `cgroup.procs` come back
    /// down *this* one. Reading the session placement from this peer, which cannot lie
    /// about its own credentials, is why the daemon is the rendezvous rather than the
    /// elevation helper.
    BlessRequest { class: Option<ClassName> },
    /// Approve a pending [`Self::BlessRequest`] — the human-presence half. **Root-gated**
    /// (`SO_PEERCRED` uid 0): reaching uid 0 is what proves a human authenticated, whatever
    /// tool did the elevating. Single-use; the nonce is consumed whether or not the mint
    /// then succeeds.
    BlessApprove { nonce: Nonce },
    /// The live blessings (carrier cgroup, member pids, age). Ungated — read-only,
    /// parity with `PolicyShow`.
    BlessList,
    /// Kill a live blessing's carrier cgroup and unregister it. Allowed for uid 0 **or the
    /// uid that requested the blessing** — having minted one unprivileged, you must be able
    /// to revoke it the same way.
    BlessRevoke { id: BlessId },
}

/// A single-use handle binding an unprivileged [`Request::BlessRequest`] to the root
/// [`Request::BlessApprove`] that authorizes it.
///
/// 128 bits from `/dev/urandom`, hex. It must be **unguessable**, which is the whole reason
/// it isn't a counter: with a predictable value an attacker could register their own
/// request, predict the nonce your session is about to be issued, and have *your*
/// authenticated helper approve *their* request — handing them the carrier. Knowing an
/// already-issued nonce is harmless by contrast: approving it still requires uid 0, and the
/// carrier descriptor goes back down the requester's own connection, never to whoever
/// approved.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Nonce(String);

impl Nonce {
    /// Bytes of entropy behind a nonce. 16 = 128 bits: far past guessing, and the value
    /// only has to survive the seconds between a request and its approval.
    const BYTES: usize = 16;

    /// Mint a fresh nonce from the kernel CSPRNG, via `getrandom(2)`.
    ///
    /// An error here refuses the blessing rather than minting a weak one — the
    /// fail-closed direction, and the only one that matters for an unguessable value.
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
    /// Parse the `--nonce=` argument the helper is spawned with. Validated rather than
    /// trusted: a malformed value can only ever miss in the pending table, but rejecting it
    /// at the boundary keeps junk out of the daemon's map keys.
    fn from_str(s: &str) -> Result<Nonce> {
        if s.len() == Nonce::BYTES * 2 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Nonce(s.to_ascii_lowercase()))
        } else {
            Err(crate::Error::msg("malformed bless nonce"))
        }
    }
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
    /// A `BlessRequest` is registered and awaiting approval. The connection stays open;
    /// the requester spawns an elevation helper with this nonce and then blocks for the
    /// [`Self::BlessMinted`] that follows.
    BlessPending {
        nonce: Nonce,
    },
    /// A `BlessApprove` was accepted: the waiting requester has been released.
    BlessApproved,
    /// A freshly-minted blessing, sent to the **requester** once approval landed. Carries
    /// the carrier's `cgroup.procs` out-of-band as `SCM_RIGHTS` ([`CarrierProcs`]) — the
    /// descriptor, not the path, is the grant.
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

impl Response {
    /// Returns the reply, or the daemon's [`Response::Error`] as an error.
    pub fn into_result(self) -> Result<Response> {
        match self {
            Response::Error { message } => Err(crate::Error::msg(format!("daemon: {message}"))),
            other => Ok(other),
        }
    }
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
/// serialized (hence no `Serialize`; it rides beside the JSON, see [`Conn::send_with_fd`]).
///
/// Writing a pid into it joins that task to the blessing. It is a **capability, not a
/// path**: cgroup-v2 checks migration permission against the credentials of whoever
/// *opened* the file, so holding this fd is what lets an unprivileged `cordon bless` place
/// its child in a root-owned carrier without ever being root (DESIGN §16.4). Conversely
/// the holder can move any task it can name — see the same section.
#[derive(Debug)]
pub struct CarrierProcs(pub std::os::fd::OwnedFd);

/// A process id (thread-group id) on the control plane: a carrier cgroup member as listed
/// in `cgroup.procs`, or a socket peer as reported by [`Conn::peer_pid`]. `u32` to match the
/// kernel's pid width there; a newtype so it can't be mixed up with a [`BlessId`] or a raw
/// count (the wire discipline of the bpf-common scalars, which this seam deliberately
/// doesn't depend on).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pid(pub u32);

impl Pid {
    /// A pid as the kernel hands it over: `pid_t`, which is **signed**.
    ///
    /// The width mismatch is the kernel's, not ours — pids are non-negative, but `pid_t`
    /// carries a sign because the `kill(2)` family overloads negatives to mean a process
    /// *group*. Nothing that reaches this type is such an overload (`SO_PEERCRED` reports a
    /// real peer), so a negative here is not a pid at all, and it becomes `0` — the same
    /// "no usable process" value the non-Linux stub returns, which every consumer already
    /// treats as "fall back". Converting in one place beats an `as u32` at each call site,
    /// where the sign question is invisible.
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

/// One end of a connection between the CLI and the daemon. It sends and receives framed
/// messages, and knows who is on the other end.
pub struct Conn {
    stream: UnixStream,
    /// Buffers [`recv`](Self::recv). [`recv_with_fd`](Self::recv_with_fd) reads the socket
    /// directly, and refuses while this holds bytes it would skip.
    reader: BufReader<UnixStream>,
    peer_uid: crate::Uid,
    peer_pid: Pid,
}

impl Conn {
    /// Wraps a connected socket and reads its peer's `SO_PEERCRED`.
    pub fn new(stream: UnixStream) -> Result<Conn> {
        let (peer_uid, peer_pid) = peer_cred(&stream)?;
        Ok(Conn {
            reader: BufReader::new(stream.try_clone()?),
            stream,
            peer_uid,
            peer_pid,
        })
    }

    /// Connects to the socket at `path`. A failed `connect(2)` is an [`Error::Io`](crate::Error::Io),
    /// so a caller can tell that no daemon is listening.
    pub fn connect(path: &Path) -> Result<Conn> {
        Conn::new(UnixStream::connect(path)?)
    }

    /// Returns the peer's **kernel-attested** uid.
    ///
    /// Used from **both** ends, and for the same reason each way. The daemon asks who is
    /// calling, so it can gate the writes. The client asks who answered, because a socket
    /// path is not proof of a daemon: `cordon bless` hands the reply's nonce to a process it
    /// then elevates to root, so it must know it is talking to the real root daemon and not
    /// to something a local user left listening at the same path (DESIGN §16.5).
    ///
    /// This is the only identity in the protocol that isn't asserted by the party it
    /// describes — which is exactly why every authorization decision rests on it. Off
    /// Linux it is an impossible uid, so every check that consults it fails closed.
    pub fn peer_uid(&self) -> crate::Uid {
        self.peer_uid
    }

    /// Returns the peer's pid. The daemon reads the requester's cgroup through it to place a
    /// blessing carrier in that process's own logind session scope (DESIGN §16.6).
    ///
    /// **Weaker than [`peer_uid`](Self::peer_uid), and the difference matters.** The kernel
    /// records this at `connect(2)`, so no client asserts it — but what it records is a
    /// *number*, and pid numbers are recycled once the task is reaped. Between the connect
    /// and the daemon's `/proc/<pid>/cgroup` read sits the whole approval wait, so a pid
    /// that has since been reused names a different process. `SO_PEERPIDFD` (Linux 6.5) is
    /// the fix for that class of staleness if this ever needs to be authoritative.
    ///
    /// It doesn't today, because placement is not authorization: the grant is gated on a
    /// uid-0 `BlessApprove`, and anyone able to complete one already has root. A stale pid
    /// resolves to nothing, or to a cgroup with no session scope, and placement falls back
    /// to the daemon's own cgroup — the safe, pre-B2 behaviour. Off Linux it is 0, which is
    /// not a real process, so the cgroup read fails and placement falls back the same way.
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

    /// Sends one message with `fd` attached as `SCM_RIGHTS` ancillary data — the blessing
    /// hand-off (DESIGN §16.6): the daemon opens the carrier's `cgroup.procs` as root and
    /// passes *only that fd*, so the CLI never needs privilege to join. The peer must read
    /// it with [`recv_with_fd`](Self::recv_with_fd).
    #[cfg(target_os = "linux")]
    pub fn send_with_fd(
        &self,
        msg: &impl Serialize,
        fd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<()> {
        send_msg_with_fd(&self.stream, msg, fd)
    }

    /// Receives one message and the descriptor that rode along with it, if any. `None`
    /// when the peer hung up between messages. Errors if an earlier [`recv`](Self::recv)
    /// buffered bytes past its message, since this read would skip them.
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

/// Write one newline-framed JSON message and flush.
fn write_msg<W: Write>(w: &mut W, value: &impl Serialize) -> Result<()> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()?;
    Ok(())
}

/// Read one newline-framed JSON message. `Ok(None)` on clean EOF.
fn read_msg<R: BufRead, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(line.trim_end())?))
}

/// Returns the peer's uid and pid from one `SO_PEERCRED` (std's `peer_cred()` is still
/// unstable).
#[cfg(target_os = "linux")]
fn peer_cred(sock: &UnixStream) -> Result<(crate::Uid, Pid)> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let creds = getsockopt(sock, PeerCredentials).context("SO_PEERCRED")?;
    Ok((crate::Uid(creds.uid()), Pid::from_raw(creds.pid())))
}

/// No `SO_PEERCRED` off Linux (the enforcement backend is Linux-only anyway; this keeps
/// the non-Linux build compiling): values every check fails closed on.
#[cfg(not(target_os = "linux"))]
fn peer_cred(_sock: &UnixStream) -> Result<(crate::Uid, Pid)> {
    Ok((crate::Uid(u32::MAX), Pid::from_raw(0)))
}

/// Send one newline-framed JSON message with `fd` attached to it.
///
/// The fd is attached to this one `sendmsg`, so it is delivered at exactly this point in
/// the byte stream.
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
        sent += sendmsg::<()>(raw, &iov, cmsgs, MsgFlags::empty(), None).context("sendmsg")?;
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
        .context("recvmsg")?;
        for c in msg.cmsgs().context("recvmsg cmsgs")? {
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

    /// The blessing hand-off in miniature: a message plus a descriptor over one socket,
    /// and the received fd is the *same open file* — not a copy of the number. Proven by
    /// writing through it and reading the bytes back on the sender's side.
    #[test]
    fn fd_rides_along_with_the_message() {
        let (a, b) = UnixStream::pair().unwrap();
        // An unlinked temp file: an fd with observable identity.
        let mut file = tempfile::tempfile().unwrap();

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

    /// A descriptor read must not start behind bytes that a buffered `recv` already
    /// pulled off the socket: those bytes, and a descriptor riding on them, would be lost.
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

    /// `pid_t` is signed and pids are not. A real pid passes through; a negative — which
    /// is a `kill(2)` process-group overload, never something that reaches this type —
    /// lands on `0`, the "no usable process" value whose consumers already fall back.
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
    /// of a socketpair are this test, so both reads must be our own uid — enough to pin
    /// that the value is real and not, say, a hardcoded zero that would make every
    /// uid check pass.
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

    /// A closed peer is `None`, the same clean-EOF contract as [`read_msg`] — so a caller
    /// can't mistake a hang-up for a message.
    #[test]
    fn clean_eof_is_none() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(read_msg_with_fd::<Response>(&b).unwrap().is_none());
    }
}
