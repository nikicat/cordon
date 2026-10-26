//! The privilege-agnostic policy core, shared by the daemon and the CLI.
//!
//! Everything here runs unprivileged. That covers the flat rule model in `policy`, which
//! compiles a text policy into the kernel's flat decision table, as well as the
//! operational `config`, the lexical `paths` helpers, the IPC `proto`, and the `backend`
//! seam. Only the backend that loads the program and seeds the maps needs privilege.
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
/// Re-exported so that a user identity has one type across the tree, whether it comes
/// from the kernel's audit record ([`passwd`]) or from a socket peer's `SO_PEERCRED`.
/// Consumers then need not depend on `cordon-bpf-common` directly, which the daemon pulls
/// in only behind its `bpf-lsm` feature.
pub use cordon_bpf_common::Uid;

/// The error that every fallible call in the policy core returns.
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
    /// Returns the success value unchanged. Errors with `what` in front of the cause when
    /// the result is a failure.
    fn context(self, what: &str) -> Result<T>;
    /// Behaves like [`context`](Context::context), but builds the message only on failure.
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
