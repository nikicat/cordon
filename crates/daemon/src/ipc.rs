//! The IPC server — a blocking thread-per-connection Unix-socket loop and the
//! request dispatcher — as methods on [`Ctx`]. (`Ctx` is declared in `main.rs`;
//! Rust lets the `impl` live here next to the serving logic.)

use crate::Ctx;
use cordon_core::event::AccessEvent;
use cordon_core::identity::{Caller, Process};
use cordon_core::proto::{OwnerInfo, Request, Response, RuleInfo, StatusInfo, read_msg, write_msg};
use cordon_core::{Error, Result, now_secs};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, warn};

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
                let engine = self.engine.lock().unwrap();
                let counts = engine.store().counts()?;
                Ok(Response::Status(StatusInfo {
                    backend: self.backend,
                    mode: self.mode,
                    store: self.store.clone(),
                    socket: self.socket.clone(),
                    zones: engine.store().zones()?,
                    owners: counts.owners,
                    subtrees: counts.subtrees,
                    rules: counts.rules,
                }))
            }

            Request::Owners => {
                let engine = self.engine.lock().unwrap();
                let owners = engine.store().owners_detailed()?;
                Ok(Response::Owners(
                    owners.into_iter().map(OwnerInfo::from).collect(),
                ))
            }

            Request::Rules => {
                let engine = self.engine.lock().unwrap();
                let rules = engine.store().rules()?;
                Ok(Response::Rules(
                    rules.into_iter().map(RuleInfo::from).collect(),
                ))
            }

            Request::AddRule {
                identity,
                path,
                mode,
                allow,
                ttl_secs,
            } => {
                validate_rule_mode(&mode)?;
                let expires_at = ttl_secs.map(|t| now_secs() + t);
                let engine = self.engine.lock().unwrap();
                let id = engine.store().add_rule(
                    &identity,
                    &PathBuf::from(path),
                    &mode,
                    allow,
                    expires_at,
                )?;
                engine.bump_policy();
                Ok(Response::RuleAdded { id })
            }

            Request::RemoveRule { id } => {
                let engine = self.engine.lock().unwrap();
                let changed = engine.store().remove_rule(id)?;
                engine.bump_policy();
                Ok(Response::Done { changed })
            }

            Request::Adopt { path, identity } => {
                let subtree = PathBuf::from(&path);
                let engine = self.engine.lock().unwrap();
                // Owner group named after the adopted subtree, seeded with the
                // given identity. "approve permanently" subsumes this (DESIGN §6).
                let owner = engine
                    .store()
                    .ensure_owner(&path, &PathBuf::from(identity))?;
                engine.store().claim_subtree(&subtree, owner, now_secs())?;
                engine.bump_policy();
                Ok(Response::Done { changed: true })
            }

            Request::Claim { subtree, add } => {
                let engine = self.engine.lock().unwrap();
                match engine.store().owner_of_subtree(&PathBuf::from(&subtree))? {
                    Some(owner) => {
                        engine.store().add_identity(owner, &PathBuf::from(add))?;
                        engine.bump_policy();
                        Ok(Response::Done { changed: true })
                    }
                    None => Err(Error::msg(format!("no owned subtree at {subtree}"))),
                }
            }

            Request::Disown { subtree } => {
                let engine = self.engine.lock().unwrap();
                let changed = engine.store().disown_subtree(&PathBuf::from(subtree))?;
                engine.bump_policy();
                Ok(Response::Done { changed })
            }

            Request::AddZone { path } => {
                let mut engine = self.engine.lock().unwrap();
                engine.store().add_zone(&PathBuf::from(path))?;
                engine.reload_zones()?;
                engine.bump_policy();
                Ok(Response::Done { changed: true })
            }

            Request::Submit {
                path,
                exe,
                ancestors,
                op,
                pid,
            } => {
                let caller = Caller::new(pid.unwrap_or(0), exe)
                    .with_ancestors(ancestors.into_iter().map(|e| Process::new(0, e)).collect());
                let event = AccessEvent::new(path, op, caller);
                let engine = self.engine.lock().unwrap();
                Ok(Response::Decision(engine.evaluate(&event)?))
            }
        }
    }
}

/// Validate an explicit-rule access mode (`r`/`w`/`rw`) — distinct from the
/// daemon's enforce/audit [`cordon_core::Mode`].
fn validate_rule_mode(mode: &str) -> Result<()> {
    if mode.is_empty() || !mode.chars().all(|c| c == 'r' || c == 'w') {
        return Err(Error::msg(format!(
            "invalid mode '{mode}' (expected r, w, or rw)"
        )));
    }
    Ok(())
}
