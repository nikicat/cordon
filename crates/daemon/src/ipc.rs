//! The IPC server — a blocking thread-per-connection Unix-socket loop and the
//! request dispatcher — as methods on [`Ctx`]. (`Ctx` is declared in `main.rs`.)
//!
//! Requests: `Status`, `PolicyShow` (read the effective compiled policy), `PolicyApply`
//! (hand the policy text to the backend thread and wait for the compile/seed outcome),
//! and the bless ops (`BlessMint`/`BlessList`/`BlessRevoke`, DESIGN §16). The verdict
//! path is in-kernel — none of this is on it.
//!
//! ## Authorization
//! Every **write** — `PolicyApply`, `BlessMint`, `BlessRevoke` — is gated on the peer's
//! kernel-attested uid (`SO_PEERCRED`) being **root**; reads (`Status`, `PolicyShow`,
//! `BlessList`) are open. The socket itself is `0666`, so the file mode carries no
//! security weight: it decides who can *reach* the daemon, `authorize()` decides what
//! they may do. (A multi-user host that must not disclose protected paths to every local
//! account wants `0660` + a `cordon` group instead — DESIGN §15.8.)

use crate::Ctx;
use cordon_core::backend::{ApplyRequest, BlessOp, ControlMsg};
use cordon_core::proto::{Request, Response, StatusInfo, read_msg, write_msg};
use cordon_core::{Error, Result, Uid};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use tracing::{error, warn};

/// How long a request waits for the backend thread's reply (compile + seed for an
/// apply; a map write + mkdir for a bless op) before giving up.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// The only uid `authorize` privileges. Named so the gate reads as intent rather than as
/// a bare zero.
const ROOT: Uid = Uid(0);

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
        // The peer's kernel-attested credentials, read once per connection — the uid
        // can't change for the lifetime of the socket, and `authorize` gates every
        // request on it.
        let peer_uid = peer_uid(&stream)?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = BufWriter::new(stream);
        while let Some(req) = read_msg::<_, Request>(&mut reader)? {
            let resp = match authorize(&req, peer_uid) {
                Ok(()) => self.dispatch(req),
                Err(e) => Err(e),
            }
            .unwrap_or_else(|e| Response::Error {
                message: e.to_string(),
            });
            write_msg(&mut writer, &resp)?;
        }
        Ok(())
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

    fn dispatch(&self, req: Request) -> Result<Response> {
        match req {
            Request::Status => {
                let objects = self
                    .control
                    .current
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|v| v.objects.len());
                Ok(Response::Status(StatusInfo {
                    backend: self.backend,
                    socket: self.socket.clone(),
                    policy: self.policy.clone(),
                    objects,
                }))
            }

            Request::PolicyShow => Ok(Response::PolicyView(
                self.control.current.lock().unwrap().clone(),
            )),

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
                Ok(Response::PolicyApplied {
                    applied: outcome.applied,
                    diagnostics: outcome.diagnostics,
                })
            }

            Request::BlessMint { class } => Ok(Response::BlessMinted(
                self.bless(|reply| BlessOp::Mint { class, reply })?,
            )),

            Request::BlessList => Ok(Response::Blessings(
                self.bless(|reply| BlessOp::List { reply })?,
            )),

            Request::BlessRevoke { id } => {
                self.bless(|reply| BlessOp::Revoke { id, reply })?;
                Ok(Response::BlessRevoked { id })
            }
        }
    }
}

/// The pure authorization gate, applied to every request before dispatch. Every write
/// requires the peer to be **root**, kernel-attested via `SO_PEERCRED`; reads are open.
/// The match is deliberately **exhaustive** (no `_` arm) so a new verb cannot be added
/// without choosing a side.
fn authorize(req: &Request, peer_uid: Uid) -> Result<()> {
    if peer_uid == ROOT {
        return Ok(());
    }
    match req {
        // Sudo's PAM stack is the human-presence authenticator (DESIGN §16.5), and a
        // same-uid scraper must not mint itself access.
        Request::BlessMint { .. } | Request::BlessRevoke { .. } => Err(Error::msg(
            "blessing requires root — invoke via `sudo cordon bless`",
        )),
        // The policy is root-owned; this gate is what lets the socket be world-
        // connectable without handing everyone the boundary.
        Request::PolicyApply { .. } => Err(Error::msg(
            "applying policy requires root — invoke via `sudo cordon policy apply`",
        )),
        // Reads stay open, the parity `BlessList` was specced with (B1 decision #1).
        Request::Status | Request::PolicyShow | Request::BlessList => Ok(()),
    }
}

/// The peer's kernel-attested uid, via `SO_PEERCRED` (std's `peer_cred()` is still
/// unstable).
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<Uid> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let creds =
        getsockopt(stream, PeerCredentials).map_err(|e| Error::msg(format!("SO_PEERCRED: {e}")))?;
    Ok(Uid(creds.uid()))
}

/// No `SO_PEERCRED` off Linux: report an impossible-to-authorize uid so the root-gated
/// ops are refused (the enforcement backend is Linux-only anyway; this keeps the
/// non-Linux build compiling, per the Cargo feature notes).
#[cfg(not(target_os = "linux"))]
fn peer_uid(_stream: &UnixStream) -> Result<Uid> {
    Ok(Uid(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordon_core::proto::BlessId;

    /// The authorization table: every write is root-only, every read is open — which is
    /// what lets the socket be `0666` without the mode carrying security weight.
    #[test]
    fn authorize_gates_writes_on_root() {
        for req in [
            Request::BlessMint { class: None },
            Request::BlessRevoke { id: BlessId(1) },
            Request::PolicyApply {
                sources: Vec::new(),
            },
        ] {
            assert!(authorize(&req, ROOT).is_ok());
            // Anyone else does not — including the same-uid scraper reaching the socket
            // directly, now that it is world-connectable.
            assert!(authorize(&req, Uid(1000)).is_err());
            assert!(authorize(&req, Uid(u32::MAX)).is_err());
        }
        // Reads stay open regardless of uid.
        for req in [Request::Status, Request::PolicyShow, Request::BlessList] {
            assert!(authorize(&req, ROOT).is_ok());
            assert!(authorize(&req, Uid(1000)).is_ok());
        }
    }
}
