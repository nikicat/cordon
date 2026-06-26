//! The IPC server — a blocking thread-per-connection Unix-socket loop and the
//! request dispatcher — as methods on [`Ctx`]. (`Ctx` is declared in `main.rs`.)
//!
//! Three requests: `Status`, `PolicyShow` (read the effective compiled policy), and
//! `PolicyApply` (hand the policy text to the backend thread and wait for the
//! compile/seed outcome). The verdict path is in-kernel — none of this is on it.

use crate::Ctx;
use cordon_core::backend::ApplyRequest;
use cordon_core::proto::{Request, Response, StatusInfo, read_msg, write_msg};
use cordon_core::{Error, Result};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use tracing::{error, warn};

/// How long an `apply` waits for the backend to compile + seed before giving up.
const APPLY_TIMEOUT: Duration = Duration::from_secs(10);

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
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = BufWriter::new(stream);
        while let Some(req) = read_msg::<_, Request>(&mut reader)? {
            let resp = self.dispatch(req).unwrap_or_else(|e| Response::Error {
                message: e.to_string(),
            });
            write_msg(&mut writer, &resp)?;
        }
        Ok(())
    }

    fn dispatch(&self, req: Request) -> Result<Response> {
        match req {
            Request::Status => {
                let current = self.control.current.lock().unwrap();
                let (mode, objects) = match &*current {
                    Some(v) => (Some(v.mode.clone()), Some(v.objects.len())),
                    None => (None, None),
                };
                Ok(Response::Status(StatusInfo {
                    backend: self.backend,
                    socket: self.socket.clone(),
                    policy: self.policy.clone(),
                    mode,
                    objects,
                }))
            }

            Request::PolicyShow => Ok(Response::PolicyView(
                self.control.current.lock().unwrap().clone(),
            )),

            Request::PolicyApply { text } => {
                // Hand the text to the backend thread (which owns the BPF maps) and
                // block on its reply. The backend compiles with its mount-aware
                // resolver and re-seeds the maps.
                let (reply_tx, reply_rx) = mpsc::channel();
                self.control
                    .apply_tx
                    .send(ApplyRequest {
                        text,
                        reply: reply_tx,
                    })
                    .map_err(|_| {
                        Error::msg("backend is not accepting policy applies (is bpf-lsm running?)")
                    })?;
                let outcome = reply_rx.recv_timeout(APPLY_TIMEOUT).map_err(|_| {
                    Error::msg("timed out waiting for the backend to apply the policy")
                })?;
                Ok(Response::PolicyApplied {
                    applied: outcome.applied,
                    diagnostics: outcome.diagnostics,
                })
            }
        }
    }
}
