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
}

impl Error {
    pub fn msg(s: impl Into<String>) -> Self {
        Error::Msg(s.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
