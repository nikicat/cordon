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
use crate::policy::Diagnostic;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
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
    Error {
        message: String,
    },
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
