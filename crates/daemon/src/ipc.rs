//! The IPC server — a blocking thread-per-connection Unix-socket loop and the
//! request dispatcher — as methods on [`Ctx`]. (`Ctx` is declared in `main.rs`.)
//!
//! Requests: `Status`, `PolicyShow` (read the effective compiled policy), `PolicyApply`
//! (hand the policy text to the backend thread and wait for the compile/seed outcome),
//! and the bless ops (`BlessRequest`/`BlessApprove`/`BlessList`/`BlessRevoke`, DESIGN
//! §16). The verdict path is in-kernel — none of this is on it.
//!
//! ## Authorization
//! `PolicyApply` and `BlessApprove` require the peer's kernel-attested uid (`SO_PEERCRED`)
//! to be **root**. Reads (`Status`, `PolicyShow`, `BlessList`) are open, and so is
//! `BlessRequest` — asking for a blessing is not getting one, since the request stays
//! inert until a uid-0 peer approves it. `BlessRevoke` passes this gate for anyone and is
//! ownership-checked in the backend, which is where the live table is: this gate answers
//! "may this uid speak this verb", not "is this particular object yours".
//!
//! The socket itself is `0666`, so the file mode carries no security weight: it decides
//! who can *reach* the daemon, `authorize()` decides what they may do. (A multi-user host
//! that must not disclose protected paths to every local account wants `0660` + a `cordon`
//! group instead — DESIGN §15.8.)
//!
//! ## The mint handshake
//! One blessing spans **two** connections: the unprivileged `cordon bless` sends
//! `BlessRequest` and holds its connection open; the root helper it spawns sends
//! `BlessApprove` with the returned nonce on a second one; the carrier and its
//! `cgroup.procs` descriptor then go back down the *first*. See `serve_bless_request`.

use crate::Ctx;
use cordon_core::backend::{ApplyRequest, BlessOp, ControlMsg};
use cordon_core::policy::ClassName;
use cordon_core::proto::{Conn, Nonce, Request, Response, StatusInfo};
use cordon_core::{Error, Result, Uid};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use tracing::{error, warn};

/// How long a request waits for the backend thread's reply (compile + seed for an
/// apply; a map write + mkdir for a bless op) before giving up.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a `BlessRequest` waits for its approval before giving up. Generous because a
/// human is in the loop: a polkit dialog or a mistyped password burns real seconds, and
/// the cost of waiting is one parked thread the requester is holding open anyway.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// How many requests may await approval at once. `BlessRequest` is ungated on a
/// world-connectable socket, so the table needs a ceiling; concurrent *pending* blessings
/// on one machine is a handful at most.
const MAX_PENDING: usize = 16;

impl Ctx {
    /// Bind the socket and accept connections forever, one handler thread each.
    pub fn serve(self: Arc<Self>) -> Result<()> {
        let socket = self.socket.clone();
        if let Some(dir) = socket.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        // Remove a stale socket from a prior (possibly un-graceful) run.
        if let Ok(meta) = std::fs::symlink_metadata(&socket)
            && meta.file_type().is_socket()
        {
            let _ = std::fs::remove_file(&socket);
        }

        let listener = UnixListener::bind(&socket)?;
        // Open the socket to every local user: `connect(2)` needs *write*, so without
        // this even the ungated read verbs are root-only in practice. Authorization is
        // `authorize()`'s job (uid 0 for every write), never the file mode. Widening
        // after `bind` is safe: until this lands the mode is `0777 & ~umask`, which is
        // narrower, so there is no window where the socket is more open than intended.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let ctx = Arc::clone(&self);
                    std::thread::spawn(move || {
                        if let Err(e) = ctx.handle_conn(stream) {
                            warn!(error = %e, "connection error");
                        }
                    });
                }
                Err(e) => error!(error = %e, "accept error"),
            }
        }
        Ok(())
    }

    fn handle_conn(&self, stream: UnixStream) -> Result<()> {
        let mut conn = Conn::new(stream)?;
        while let Some(req) = conn.recv::<Request>()? {
            // Any failure — refused, timed out, backend error — becomes an `Error` reply
            // rather than a dropped connection, so the CLI can say why.
            if let Err(e) = authorize(&req, conn.peer_uid()).and_then(|()| self.handle(&conn, req))
            {
                conn.send(&Response::Error {
                    message: e.to_string(),
                })?;
            }
        }
        Ok(())
    }

    /// The unprivileged half of the mint handshake (DESIGN §16.5).
    ///
    /// Register a nonce, hand it to the requester, and block until a **uid-0** peer
    /// approves it on a *different* connection. Only then mint, and send the carrier's
    /// `cgroup.procs` back down this connection.
    ///
    /// The daemon is the rendezvous — rather than the elevation helper forwarding the
    /// descriptor — because the helper's own credentials say nothing about *whose* session
    /// this is: under `run0` it lives in a transient unit with no session at all. Here the
    /// placement decision rests on this peer's kernel-attested identity, and the human
    /// presence check rests on the approver's. Neither is a client's assertion.
    fn serve_bless_request(&self, conn: &Conn, class: Option<ClassName>) -> Result<()> {
        let nonce = Nonce::generate()?;
        let approved = self.register_pending(nonce.clone())?;
        let sent = conn.send(&Response::BlessPending {
            nonce: nonce.clone(),
        });
        let waited = sent.and_then(|()| {
            approved.recv_timeout(APPROVAL_TIMEOUT).map_err(|_| {
                Error::msg("no approval within the timeout — was the elevation cancelled?")
            })
        });
        // Ours to clean up on every path, including the timeout: the entry lives exactly
        // as long as this call, which is why no reaper thread is needed.
        self.pending.lock().unwrap().remove(&nonce);
        waited?;

        // The carrier's placement follows *this* peer; see `Conn::peer_pid` for why a
        // pid is good enough for placement.
        let (view, procs) = self.bless(|reply| BlessOp::Mint {
            class,
            owner: conn.peer_uid(),
            requester: conn.peer_pid(),
            reply,
        })?;
        conn.send_with_fd(&Response::BlessMinted(view), procs.0.as_fd())
    }

    /// Park a nonce for an approver to release. Bounded: `BlessRequest` is ungated on a
    /// world-connectable socket, so the table must not be a place anyone can pile into.
    fn register_pending(&self, nonce: Nonce) -> Result<mpsc::Receiver<()>> {
        let (tx, rx) = mpsc::channel();
        let mut pending = self.pending.lock().unwrap();
        if pending.len() >= MAX_PENDING {
            return Err(Error::msg(
                "too many blessing requests are awaiting approval",
            ));
        }
        pending.insert(nonce, tx);
        Ok(rx)
    }

    /// Release the requester waiting on `nonce`. Removing before signalling is what makes
    /// a nonce single-use: a replay finds nothing parked.
    fn approve(&self, nonce: &Nonce) -> Result<Response> {
        let waiting = self
            .pending
            .lock()
            .unwrap()
            .remove(nonce)
            .ok_or_else(|| Error::msg("no blessing request is waiting for that nonce"))?;
        // A dropped receiver means the requester gave up first; the nonce is spent either
        // way, and there is nothing left to mint for.
        waiting
            .send(())
            .map_err(|_| Error::msg("the blessing request was abandoned"))?;
        Ok(Response::BlessApproved)
    }

    /// Send one bless op to the backend thread (which owns the maps and the carrier
    /// cgroups) and block on its reply — the same round trip as `PolicyApply`.
    fn bless<T>(
        &self,
        op: impl FnOnce(mpsc::Sender<std::result::Result<T, String>>) -> BlessOp,
    ) -> Result<T> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.control
            .msg_tx
            .send(ControlMsg::Bless(op(reply_tx)))
            .map_err(|_| Error::msg("backend is not accepting requests (is bpf-lsm running?)"))?;
        reply_rx
            .recv_timeout(REPLY_TIMEOUT)
            .map_err(|_| Error::msg("timed out waiting for the backend"))?
            .map_err(Error::msg)
    }

    /// Serves one authorized request, replying on `conn`.
    fn handle(&self, conn: &Conn, req: Request) -> Result<()> {
        let resp = match req {
            // The one verb that doesn't fit request→response: it replies twice, and the
            // second reply carries a descriptor.
            Request::BlessRequest { class } => return self.serve_bless_request(conn, class),

            Request::Status => {
                let objects = self
                    .control
                    .current
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|v| v.objects.len());
                Response::Status(StatusInfo {
                    backend: self.backend,
                    socket: self.socket.clone(),
                    policy: self.policy.clone(),
                    objects,
                })
            }

            Request::PolicyShow => {
                Response::PolicyView(self.control.current.lock().unwrap().clone())
            }

            Request::PolicyApply { sources } => {
                // Hand the fragments to the backend thread (which owns the BPF maps)
                // and block on its reply. The backend resolves per-fragment homes,
                // merges, compiles with its mount-aware resolver, and re-seeds the maps.
                let (reply_tx, reply_rx) = mpsc::channel();
                self.control
                    .msg_tx
                    .send(ControlMsg::Apply(ApplyRequest {
                        sources,
                        reply: reply_tx,
                    }))
                    .map_err(|_| {
                        Error::msg("backend is not accepting policy applies (is bpf-lsm running?)")
                    })?;
                let outcome = reply_rx.recv_timeout(REPLY_TIMEOUT).map_err(|_| {
                    Error::msg("timed out waiting for the backend to apply the policy")
                })?;
                Response::PolicyApplied {
                    applied: outcome.applied,
                    diagnostics: outcome.diagnostics,
                }
            }

            Request::BlessApprove { nonce } => self.approve(&nonce)?,

            Request::BlessList => Response::Blessings(self.bless(|reply| BlessOp::List { reply })?),

            Request::BlessRevoke { id } => {
                self.bless(|reply| BlessOp::Revoke {
                    id,
                    by: conn.peer_uid(),
                    reply,
                })?;
                Response::BlessRevoked { id }
            }
        };
        conn.send(&resp)
    }
}

/// The pure authorization gate, applied to every request before dispatch. Every write
/// requires the peer to be **root**, kernel-attested via `SO_PEERCRED`; reads are open.
/// The match is deliberately **exhaustive** (no `_` arm) so a new verb cannot be added
/// without choosing a side.
fn authorize(req: &Request, peer_uid: Uid) -> Result<()> {
    if peer_uid == Uid::ROOT {
        return Ok(());
    }
    match req {
        // The human-presence check: reaching uid 0 is what proves someone authenticated,
        // whatever tool did the elevating. A same-uid scraper reaching the socket directly
        // cannot approve its own request.
        Request::BlessApprove { .. } => Err(Error::msg(
            "approving a blessing requires root — `cordon bless` spawns this via $CORDON_SUDO",
        )),
        // The policy is root-owned; this gate is what lets the socket be world-
        // connectable without handing everyone the boundary.
        Request::PolicyApply { .. } => Err(Error::msg(
            "applying policy requires root — invoke via `sudo cordon policy apply`",
        )),
        // Reads stay open, the parity `BlessList` was specced with (DESIGN §16.5).
        // `BlessRequest` joins them: asking is not minting — the request is inert until a
        // uid-0 peer approves it. `BlessRevoke` is ownership-checked in the backend, which
        // is where the live table is; this gate only decides who may speak the verb.
        Request::Status
        | Request::PolicyShow
        | Request::BlessList
        | Request::BlessRequest { .. }
        | Request::BlessRevoke { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordon_core::proto::BlessId;

    fn a_nonce() -> Nonce {
        Nonce::generate().expect("/dev/urandom")
    }

    /// The authorization table. The security-critical row is `BlessApprove`: it is the
    /// human-presence check, so a same-uid scraper reaching the now-world-connectable
    /// socket must not be able to approve its own request.
    #[test]
    fn authorize_gates_writes_on_root() {
        for req in [
            Request::BlessApprove { nonce: a_nonce() },
            Request::PolicyApply {
                sources: Vec::new(),
            },
        ] {
            assert!(authorize(&req, Uid::ROOT).is_ok());
            assert!(authorize(&req, Uid(1000)).is_err());
            assert!(authorize(&req, Uid(u32::MAX)).is_err());
        }
        // Reads pass any uid, and so do the two verbs that are *not* gated here:
        // `BlessRequest` (asking is inert until approved) and `BlessRevoke` (ownership is
        // checked in the backend, which is the only place that knows who minted what).
        for req in [
            Request::Status,
            Request::PolicyShow,
            Request::BlessList,
            Request::BlessRequest { class: None },
            Request::BlessRevoke { id: BlessId(1) },
        ] {
            assert!(authorize(&req, Uid::ROOT).is_ok());
            assert!(authorize(&req, Uid(1000)).is_ok());
        }
    }

    /// A nonce must survive the round trip through argv — the helper is spawned with
    /// `--nonce=<value>` and parses it back — and must reject anything else.
    #[test]
    fn nonce_round_trips_and_rejects_junk() {
        let n = a_nonce();
        assert_eq!(n.to_string().parse::<Nonce>().unwrap(), n);
        assert_ne!(a_nonce(), a_nonce(), "nonces must not repeat");
        for junk in ["", "nope", "0011223344556677889900aabbccddeeff00"] {
            assert!(junk.parse::<Nonce>().is_err(), "accepted {junk:?}");
        }
    }
}
