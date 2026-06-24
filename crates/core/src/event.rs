//! The access event the engine reasons about, and the abstract operation a
//! backend reports for it.

use crate::identity::Caller;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The abstract operation behind a mediated access. Backends map their native
/// signals onto these: Linux `fanotify` reports `FAN_OPEN_PERM` as Read/Write
/// and `FAN_CREATE` as Create; macOS ES maps its `AUTH_OPEN`/`AUTH_CREATE`
/// events the same way. The engine reasons only about these three.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Open an existing path for reading.
    Read,
    /// Open an existing path for writing.
    Write,
    /// Create a new path (`O_CREAT` of a not-yet-existing file/dir). This is the
    /// TOFU signal — the *only* operation that can claim ownership (DESIGN §5:
    /// "claim on create, never on read").
    Create,
}

impl Op {
    pub fn is_create(self) -> bool {
        matches!(self, Op::Create)
    }

    /// Whether a rule whose mode string contains these flags covers this op.
    /// Read needs `r`; Write and Create need `w`.
    pub(crate) fn covered_by_mode(self, mode: &str) -> bool {
        match self {
            Op::Read => mode.contains('r'),
            Op::Write | Op::Create => mode.contains('w'),
        }
    }
}

/// A single mediated access: who is touching what, and how.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEvent {
    pub path: PathBuf,
    pub op: Op,
    pub caller: Caller,
}

impl AccessEvent {
    pub fn new(path: impl Into<PathBuf>, op: Op, caller: Caller) -> Self {
        AccessEvent {
            path: path.into(),
            op,
            caller,
        }
    }
}
