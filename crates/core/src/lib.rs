//! cordon-core — the privilege-agnostic policy core.
//!
//! Everything here runs unprivileged: the flat **rule model** (`policy` — parse,
//! resolve, compile a text policy into the kernel's flat decision table), the
//! operational `config`, the lexical `paths` helpers the compiler uses, the IPC
//! `proto`, and the enforcement-backend seam (`backend`). Only the backend that loads
//! the program and seeds the maps needs privilege.
//!
//! See `docs/DESIGN.md` §15 for the model this implements.

pub mod backend;
pub mod config;
pub mod passwd;
pub mod paths;
pub mod policy;
pub mod proto;

pub use backend::BackendKind;
pub use config::Config;
/// Re-exported so a `user` identity has ONE type across the tree — the kernel's audit
/// record ([`passwd`]), the socket's `SO_PEERCRED` peer, and any future caller identity —
/// without every consumer depending on `cordon-bpf-common` directly (the daemon pulls
/// that in only behind its `bpf-lsm` feature).
pub use cordon_bpf_common::Uid;

/// Errors surfaced by the policy core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Msg(String),
    /// An error at a known position in one policy source.
    #[error("{0}: {1}")]
    Located(policy::Pos, String),
}

impl Error {
    pub fn msg(s: impl Into<String>) -> Self {
        Error::Msg(s.into())
    }

    /// Returns an error at `pos` in a policy source.
    pub fn at(pos: policy::Pos, msg: impl Into<String>) -> Self {
        Error::Located(pos, msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Adds what was being done to a failure, so the error reads `"{what}: {cause}"`.
pub trait Context<T> {
    /// Returns the value, or an error naming `what` failed.
    fn context(self, what: &str) -> Result<T>;
    /// Like [`context`](Context::context), but builds the message only on failure.
    fn with_context(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: std::fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, what: &str) -> Result<T> {
        self.map_err(|e| Error::msg(format!("{what}: {e}")))
    }

    fn with_context(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::msg(format!("{}: {e}", what())))
    }
}
