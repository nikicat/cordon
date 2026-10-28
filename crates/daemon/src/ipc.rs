//! The daemon's control socket, served as methods on [`Ctx`]. Every request from the CLI
//! and the bless helper arrives here, and it reaches the backend thread only through the
//! control channel that `Ctx` holds. The verdict path is in-kernel, so none of this is on
//! it.
//!
//! Every request passes [`authorize`] before dispatch. The socket's file mode decides only
//! who can reach the daemon (see `Ctx::serve`). A blessing spans two connections (see
//! `Ctx::serve_bless_request`).

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

/// How long a `BlessRequest` waits for its approval before giving up. It is generous
/// because a human is in the loop, and a polkit dialog or a mistyped password burns real
/// seconds. Waiting costs one parked thread, which the requester holds open anyway.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// The most requests that may await approval at once. Any local user can send
/// `BlessRequest`, so the table needs a ceiling. One machine rarely has more than a
/// handful of blessings pending at the same time.
const MAX_PENDING: usize = 16;

impl Ctx {
    /// Binds the socket and serves every connection on it, each on its own thread. Replaces
    /// a stale socket file left at the path.
    ///
    /// Errors when the socket cannot be bound or opened to every local user.
    pub fn serve(self: Arc<Self>) -> Result<()> {
        let socket = self.socket.clone();
        if let Some(dir) = socket.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        // A prior run, even one that crashed, may have left its socket behind.
        if let Ok(meta) = std::fs::symlink_metadata(&socket)
            && meta.file_type().is_socket()
        {
            let _ = std::fs::remove_file(&socket);
        }

        let listener = UnixListener::bind(&socket)?;
        // Open the socket to every local user (`0666`). `connect(2)` needs write
        // permission, so without this even the ungated read verbs are root-only in
        // practice. The mode carries no security weight, because authorization is
        // `authorize()`'s job. A multi-user host that must not disclose protected paths to
        // every local account wants `0660` and a `cordon` group instead (ADR 0010).
        // Widening the mode after `bind` is safe. Until this call the mode is
        // `0777 & ~umask`, which is narrower, so the socket is never more open than
        // intended.
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
            if let Err(e) = authorize(&req, conn.peer().uid).and_then(|()| self.handle(&conn, req))
            {
                conn.send(&Response::Error {
                    message: e.to_string(),
                })?;
            }
        }
        Ok(())
    }

    /// Serves the unprivileged half of the mint handshake (ADR 0013). Waits for a uid-0
    /// peer to approve this request, then mints and sends the new carrier's `cgroup.procs`
    /// back on `conn`.
    ///
    /// One blessing spans two connections. The unprivileged `cordon bless` sends
    /// `BlessRequest` on this one and holds it open. The root helper it spawns sends
    /// `BlessApprove` with the nonce on a second one ([`Ctx::approve`]).
    ///
    /// Errors as [`Ctx::await_approval`] does, and when the backend refuses the mint.
    ///
    /// The daemon is the rendezvous, rather than the elevation helper forwarding the
    /// descriptor, because the helper's own credentials say nothing about whose session
    /// this is. Under `run0` the helper lives in a transient unit with no session at all.
    /// Here the placement rests on this peer's kernel-attested identity, and the
    /// human-presence check rests on the approver's. Neither is a client's assertion.
    fn serve_bless_request(&self, conn: &Conn, class: Option<ClassName>) -> Result<()> {
        self.await_approval(conn)?;
        // The carrier's placement follows *this* peer; see `PeerCred::pid` for why a
        // pid is good enough for placement.
        let (view, procs) = self.bless(|reply| BlessOp::Mint {
            class,
            requester: conn.peer(),
            reply,
        })?;
        conn.send_with_fd(&Response::BlessMinted(view), procs.0.as_fd())
    }

    /// Sends the requester on `conn` a fresh nonce and waits until a uid-0 peer approves
    /// it.
    ///
    /// Errors when too many requests are already pending, when the nonce can't be sent, or
    /// when no approval arrives within [`APPROVAL_TIMEOUT`].
    fn await_approval(&self, conn: &Conn) -> Result<()> {
        let nonce = Nonce::generate()?;
        let approved = self.register_pending(nonce.clone())?;
        let waited = conn
            .send(&Response::BlessPending {
                nonce: nonce.clone(),
            })
            .and_then(|()| {
                approved.recv_timeout(APPROVAL_TIMEOUT).map_err(|_| {
                    Error::msg("no approval within the timeout — was the elevation cancelled?")
                })
            });
        // Ours to clean up on every path, including the timeout (see `Ctx::pending`).
        self.pending.lock().unwrap().remove(&nonce);
        waited
    }

    /// Parks `nonce` for an approver to release, and returns the receiver that the
    /// release signals.
    ///
    /// Errors when [`MAX_PENDING`] requests are already parked.
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

    /// Releases the requester waiting on `nonce` and spends the nonce, so a replay finds
    /// nothing parked.
    ///
    /// Errors when no request waits on `nonce`, or when its requester has already given up.
    fn approve(&self, nonce: &Nonce) -> Result<Response> {
        // Removing before signalling is what makes a nonce single-use.
        let waiting = self
            .pending
            .lock()
            .unwrap()
            .remove(nonce)
            .ok_or_else(|| Error::msg("no blessing request is waiting for that nonce"))?;
        // A dropped receiver means the requester gave up first. The nonce is spent either
        // way, and nothing is left to mint for.
        waiting
            .send(())
            .map_err(|_| Error::msg("the blessing request was abandoned"))?;
        Ok(Response::BlessApproved)
    }

    /// Sends one bless op to the backend thread, which owns the maps and the carrier
    /// cgroups, and returns its reply.
    ///
    /// Errors as [`ControlSender::call`] does, or when the backend refuses the op.
    fn bless<T>(
        &self,
        op: impl FnOnce(mpsc::Sender<std::result::Result<T, String>>) -> BlessOp,
    ) -> Result<T> {
        self.control
            .call(|reply| ControlMsg::Bless(op(reply)))?
            .map_err(Error::msg)
    }

    /// Serves one authorized request, replying on `conn`.
    fn handle(&self, conn: &Conn, req: Request) -> Result<()> {
        let resp = match req {
            // The one verb that doesn't fit request→response: it replies twice, and the
            // second reply carries a descriptor.
            Request::BlessRequest { class } => return self.serve_bless_request(conn, class),

            Request::Status => {
                let objects = self.control.view().map(|v| v.objects.len());
                Response::Status(StatusInfo {
                    backend: self.backend,
                    socket: self.socket.clone(),
                    policy: self.policy.clone(),
                    objects,
                })
            }

            Request::PolicyShow => Response::PolicyView(self.control.view()),

            Request::PolicyApply { sources } => {
                // The backend thread owns the BPF maps, so it compiles and re-seeds while
                // this thread waits for the outcome.
                let outcome = self
                    .control
                    .call(|reply| ControlMsg::Apply(ApplyRequest { sources, reply }))?;
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
                    by: conn.peer().uid,
                    reply,
                })?;
                Response::BlessRevoked { id }
            }
        };
        conn.send(&resp)
    }
}

/// Checks whether the peer with `peer_uid` may send `req` at all. The writes
/// (`PolicyApply`, `BlessApprove`) need a root peer, as `SO_PEERCRED` attests it, and every
/// other request is open. Whether a particular object belongs to the peer is not checked
/// here.
///
/// Errors when the peer may not speak the verb.
fn authorize(req: &Request, peer_uid: Uid) -> Result<()> {
    if peer_uid == Uid::ROOT {
        return Ok(());
    }
    // No `_` arm, so a new verb cannot be added without choosing a side.
    match req {
        // This is the human-presence check. Reaching uid 0 proves that someone
        // authenticated, whatever tool did the elevating. A same-uid scraper that reaches
        // the socket directly cannot approve its own request.
        Request::BlessApprove { .. } => Err(Error::msg(
            "approving a blessing requires root — `cordon bless` spawns this via $CORDON_SUDO",
        )),
        // The policy is root-owned. This gate is what lets the socket be
        // world-connectable without handing everyone the boundary.
        Request::PolicyApply { .. } => Err(Error::msg(
            "applying policy requires root — invoke via `sudo cordon policy apply`",
        )),
        // Reads stay open, as `BlessList` was specified (ADR 0013). `BlessRequest` is
        // open too, because asking is not minting. The request stays inert until a uid-0
        // peer approves it. The backend checks ownership for `BlessRevoke`, because the
        // live table lives there.
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

    /// Checks the authorization table. The security-critical row is `BlessApprove`. It is
    /// the human-presence check, so a same-uid scraper that reaches the world-connectable
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
        // Reads pass any uid, and so do `BlessRequest` and `BlessRevoke`.
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

    /// Checks that a nonce survives the round trip through argv and that parsing rejects
    /// anything else. The helper is spawned with `--nonce=<value>` and parses it back.
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
