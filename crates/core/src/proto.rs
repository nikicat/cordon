//! The IPC protocol between the `cordon` CLI (and, later, the prompt agent) and
//! the `cordond` daemon — the control/management plane, *not* the data path of a
//! gated `open()`.
//!
//! Wire format: one JSON value per line (newline-delimited). Request/response is
//! synchronous RPC today; the Phase-2 prompt push will add server-initiated
//! messages on a long-lived connection. Types here are runtime-agnostic: the
//! same `Request`/`Response` and `handle` logic work whether the daemon's accept
//! loop is threads or async.

use crate::Result;
use crate::event::Op;
use crate::store::{OwnerDetail, Rule};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

/// A command from a client to the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    /// Daemon + store summary.
    Status,
    /// List owner groups with their identities and owned subtrees.
    Owners,
    /// List explicit rules.
    Rules,
    /// Add an explicit allow/deny rule. `ttl_secs` = None for permanent.
    AddRule {
        identity: String,
        path: String,
        mode: String,
        allow: bool,
        ttl_secs: Option<i64>,
    },
    /// Remove an explicit rule by id.
    RemoveRule { id: i64 },
    /// Claim a pre-existing subtree for `identity` (subsumes the `adopt` flow).
    Adopt { path: String, identity: String },
    /// Add an identity to the owner group of an existing subtree.
    Claim { subtree: String, add: String },
    /// Drop ownership of a subtree.
    Disown { subtree: String },
    /// Register a new zone root (creates can TOFU-claim inside it).
    AddZone { path: String },
    /// Drive a synthetic access event through the engine and return the verdict.
    /// This is how the `mock` backend, the test harness, and (later)
    /// `cordon run` inject events — there is no kernel event source in Phase 0.
    Submit {
        path: String,
        exe: String,
        #[serde(default)]
        ancestors: Vec<String>,
        op: Op,
        #[serde(default)]
        pid: Option<i32>,
    },
}

/// A reply from the daemon to a client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Status(StatusInfo),
    Owners(Vec<OwnerInfo>),
    Rules(Vec<RuleInfo>),
    Decision(crate::decision::Decision),
    RuleAdded { id: i64 },
    Done { changed: bool },
    Error { message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusInfo {
    pub backend: String,
    pub store_path: String,
    pub socket_path: String,
    pub zones: Vec<String>,
    pub owners: i64,
    pub subtrees: i64,
    pub rules: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerInfo {
    pub name: String,
    pub identities: Vec<String>,
    pub subtrees: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleInfo {
    pub id: i64,
    pub identity: String,
    pub path: String,
    pub mode: String,
    pub allow: bool,
    pub expires_at: Option<i64>,
}

impl From<OwnerDetail> for OwnerInfo {
    fn from(o: OwnerDetail) -> Self {
        OwnerInfo {
            name: o.name,
            identities: o
                .identities
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            subtrees: o.subtrees.iter().map(|p| p.display().to_string()).collect(),
        }
    }
}

impl From<Rule> for RuleInfo {
    fn from(r: Rule) -> Self {
        RuleInfo {
            id: r.id,
            identity: r.identity_exe,
            path: r.path_prefix.display().to_string(),
            mode: r.mode,
            allow: r.allow,
            expires_at: r.expires_at,
        }
    }
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
