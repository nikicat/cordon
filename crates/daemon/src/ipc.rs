//! The IPC server: a blocking thread-per-connection Unix-socket loop and the
//! request dispatcher that maps protocol messages onto store/engine operations.

use crate::Ctx;
use cordon_core::event::AccessEvent;
use cordon_core::identity::{Caller, Process};
use cordon_core::proto::{OwnerInfo, Request, Response, RuleInfo, StatusInfo, read_msg, write_msg};
use cordon_core::{Error, Result, now_secs};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, warn};

/// Bind the socket and accept connections forever, one handler thread each.
pub fn serve(socket_path: &Path, ctx: Arc<Ctx>) -> Result<()> {
    if let Some(dir) = socket_path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }
    // Remove a stale socket from a prior (possibly un-graceful) run.
    if let Ok(meta) = std::fs::symlink_metadata(socket_path)
        && meta.file_type().is_socket()
    {
        let _ = std::fs::remove_file(socket_path);
    }

    let listener = UnixListener::bind(socket_path)?;
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let ctx = Arc::clone(&ctx);
                std::thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, ctx) {
                        warn!(error = %e, "connection error");
                    }
                });
            }
            Err(e) => error!(error = %e, "accept error"),
        }
    }
    Ok(())
}

fn handle_conn(stream: UnixStream, ctx: Arc<Ctx>) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);
    while let Some(req) = read_msg::<_, Request>(&mut reader)? {
        let resp = dispatch(req, &ctx).unwrap_or_else(|e| Response::Error {
            message: e.to_string(),
        });
        write_msg(&mut writer, &resp)?;
    }
    Ok(())
}

fn dispatch(req: Request, ctx: &Ctx) -> Result<Response> {
    match req {
        Request::Status => {
            let engine = ctx.engine.lock().unwrap();
            let store = engine.store();
            let counts = store.counts()?;
            let zones = store
                .zones()?
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            Ok(Response::Status(StatusInfo {
                backend: ctx.backend.clone(),
                store_path: ctx.store_path.clone(),
                socket_path: ctx.socket_path.clone(),
                zones,
                owners: counts.owners,
                subtrees: counts.subtrees,
                rules: counts.rules,
            }))
        }

        Request::Owners => {
            let engine = ctx.engine.lock().unwrap();
            let owners = engine.store().owners_detailed()?;
            Ok(Response::Owners(
                owners.into_iter().map(OwnerInfo::from).collect(),
            ))
        }

        Request::Rules => {
            let engine = ctx.engine.lock().unwrap();
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
            validate_mode(&mode)?;
            let expires_at = ttl_secs.map(|t| now_secs() + t);
            let engine = ctx.engine.lock().unwrap();
            let id = engine.store().add_rule(
                &identity,
                &PathBuf::from(path),
                &mode,
                allow,
                expires_at,
            )?;
            Ok(Response::RuleAdded { id })
        }

        Request::RemoveRule { id } => {
            let engine = ctx.engine.lock().unwrap();
            Ok(Response::Done {
                changed: engine.store().remove_rule(id)?,
            })
        }

        Request::Adopt { path, identity } => {
            let subtree = PathBuf::from(&path);
            let engine = ctx.engine.lock().unwrap();
            // Owner group is named after the adopted subtree; seeded with the
            // given identity. "approve permanently" subsumes this flow (DESIGN §6).
            let owner = engine
                .store()
                .ensure_owner(&path, &PathBuf::from(identity))?;
            engine.store().claim_subtree(&subtree, owner, now_secs())?;
            Ok(Response::Done { changed: true })
        }

        Request::Claim { subtree, add } => {
            let engine = ctx.engine.lock().unwrap();
            match engine.store().owner_of_subtree(&PathBuf::from(&subtree))? {
                Some(owner) => {
                    engine.store().add_identity(owner, &PathBuf::from(add))?;
                    Ok(Response::Done { changed: true })
                }
                None => Err(Error::msg(format!("no owned subtree at {subtree}"))),
            }
        }

        Request::Disown { subtree } => {
            let engine = ctx.engine.lock().unwrap();
            Ok(Response::Done {
                changed: engine.store().disown_subtree(&PathBuf::from(subtree))?,
            })
        }

        Request::AddZone { path } => {
            let mut engine = ctx.engine.lock().unwrap();
            engine.store().add_zone(&PathBuf::from(path))?;
            engine.reload_zones()?;
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
            let engine = ctx.engine.lock().unwrap();
            Ok(Response::Decision(engine.evaluate(&event)?))
        }
    }
}

fn validate_mode(mode: &str) -> Result<()> {
    if mode.is_empty() || !mode.chars().all(|c| c == 'r' || c == 'w') {
        return Err(Error::msg(format!(
            "invalid mode '{mode}' (expected r, w, or rw)"
        )));
    }
    Ok(())
}
