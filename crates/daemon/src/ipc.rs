//! The IPC server — a blocking thread-per-connection Unix-socket loop and the
//! request dispatcher — as methods on [`Ctx`]. (`Ctx` is declared in `main.rs`.)
//!
//! Requests: `Status`, `PolicyShow` (read the effective compiled policy), `PolicyApply`
//! (hand the policy text to the backend thread and wait for the compile/seed outcome),
//! and the bless ops (`BlessMint`/`BlessList`/`BlessRevoke`, DESIGN §16). The verdict
//! path is in-kernel — none of this is on it.
//!
//! ## Authorization
//! Mint and revoke are gated on the peer's kernel-attested uid (`SO_PEERCRED`) being
//! **root** — sudo is the B1 authenticator, and the same-uid scraper must not be able
//! to mint itself a blessing. Everything else stays open (socket permissions are the
//! only other gate today; `PolicyApply` peer-cred gating is tracked in STATUS).

use crate::Ctx;
use cordon_core::backend::{ApplyRequest, BlessOp, ControlMsg};
use cordon_core::proto::{Request, Response, StatusInfo, read_msg, write_msg};
use cordon_core::{Error, Result};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use tracing::{error, warn};

/// How long a request waits for the backend thread's reply (compile + seed for an
/// apply; a map write + mkdir for a bless op) before giving up.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

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

/// The pure authorization gate, applied to every request before dispatch: minting and
/// revoking blessings require the peer to be **root** (kernel-attested via
/// `SO_PEERCRED`) — sudo's PAM stack is the human-presence authenticator (DESIGN
/// §16.5), and a same-uid scraper must not mint itself access. `BlessList` is
/// read-only and stays open, like `PolicyShow`.
fn authorize(req: &Request, peer_uid: u32) -> Result<()> {
    match req {
        Request::BlessMint { .. } | Request::BlessRevoke { .. } if peer_uid != 0 => Err(
            Error::msg("blessing requires root — invoke via `sudo cordon bless`"),
        ),
        _ => Ok(()),
    }
}

/// The peer's kernel-attested uid, via `SO_PEERCRED` (std's `peer_cred()` is still
/// unstable).
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let creds =
        getsockopt(stream, PeerCredentials).map_err(|e| Error::msg(format!("SO_PEERCRED: {e}")))?;
    Ok(creds.uid())
}

/// No `SO_PEERCRED` off Linux: report an impossible-to-authorize uid so the root-gated
/// ops are refused (the enforcement backend is Linux-only anyway; this keeps the
/// non-Linux build compiling, per the Cargo feature notes).
#[cfg(not(target_os = "linux"))]
fn peer_uid(_stream: &UnixStream) -> Result<u32> {
    Ok(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordon_core::proto::BlessId;

    /// The authorization table: mint/revoke are root-only; reads and applies pass any
    /// uid (socket permissions are their only gate today — see STATUS).
    #[test]
    fn authorize_gates_mint_and_revoke_on_root() {
        let mint = Request::BlessMint { class: None };
        let revoke = Request::BlessRevoke { id: BlessId(1) };
        // Root mints and revokes.
        assert!(authorize(&mint, 0).is_ok());
        assert!(authorize(&revoke, 0).is_ok());
        // Anyone else does not — including the same-uid scraper.
        assert!(authorize(&mint, 1000).is_err());
        assert!(authorize(&revoke, 1000).is_err());
        assert!(authorize(&mint, u32::MAX).is_err());
        // Reads and applies stay open regardless of uid.
        for req in [
            Request::Status,
            Request::PolicyShow,
            Request::BlessList,
            Request::PolicyApply {
                sources: Vec::new(),
            },
        ] {
            assert!(authorize(&req, 0).is_ok());
            assert!(authorize(&req, 1000).is_ok());
        }
    }
}
