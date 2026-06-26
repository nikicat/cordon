//! cordon-core — the privilege-agnostic policy core.
//!
//! Everything here runs unprivileged: the decision flow (`engine`), the
//! ownership/rules store (`store`), caller identity (`identity`), the IPC
//! protocol (`proto`), and the enforcement-backend seam (`backend`). Only the
//! backend that feeds open-events and carries out verdicts needs privilege; the
//! rest is identical in the user-mode dev daemon and the root production daemon.
//!
//! See `docs/DESIGN.md` for the model this implements.

pub mod backend;
pub mod config;
pub mod decision;
pub mod engine;
pub mod event;
pub mod identity;
pub mod paths;
pub mod policy;
pub mod proto;
pub mod store;

pub use backend::BackendKind;
pub use config::{Config, Mode};
pub use decision::{Decision, Reason};
pub use engine::Engine;
pub use event::{AccessEvent, Op};
pub use identity::{Caller, Pid, Process};
pub use store::Store;

/// Errors surfaced by the policy core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("store: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("migration: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Msg(String),
}

impl Error {
    pub fn msg(s: impl Into<String>) -> Self {
        Error::Msg(s.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// Semantic aliases for the integers that flow through the store and the wire.
// They document intent (vs a bare `i64`); upgrade any to a newtype later if a
// mix-up becomes plausible.

/// Whole seconds since the Unix epoch — an absolute timestamp (`created_at`,
/// rule `expires_at`, the `now_secs()` clock).
pub type UnixSecs = i64;
/// A duration in whole seconds (e.g. a rule TTL).
pub type Secs = i64;
/// A count of stored rows.
pub type Count = i64;
/// A store row id for an owner group.
pub type OwnerId = i64;
/// A store row id for an explicit rule.
pub type RuleId = i64;

/// Current wall-clock time in whole seconds since the Unix epoch. Used for
/// `created_at` stamps and TTL-rule expiry. Saturates to 0 before the epoch.
pub fn now_secs() -> UnixSecs {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
