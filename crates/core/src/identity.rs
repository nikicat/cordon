//! Caller identity: the immediate process plus its best-effort parent chain.
//!
//! Phase 0 identity granularity is `path` (the exe path string). The chain
//! solves the interpreter problem (caller exe = `python3`, an ancestor is the
//! real tool) and the helper/creator≠reader case. It is captured at event time
//! by the backend and is *best-effort* — double-fork launders ancestry, argv is
//! never trusted (DESIGN §5/§8). It raises cost; it is not a boundary.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A single process identified for policy purposes by its executable path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: i32,
    pub exe: PathBuf,
}

impl Process {
    pub fn new(pid: i32, exe: impl Into<PathBuf>) -> Self {
        Process {
            pid,
            exe: exe.into(),
        }
    }
}

/// The identity of an access: the immediate caller plus its parent chain
/// (nearest ancestor first), already bounded at the session/uid boundary by the
/// backend that captured it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caller {
    pub proc: Process,
    /// Ancestors nearest-first: parent, grandparent, ... session leader.
    #[serde(default)]
    pub ancestors: Vec<Process>,
}

impl Caller {
    pub fn new(pid: i32, exe: impl Into<PathBuf>) -> Self {
        Caller {
            proc: Process::new(pid, exe),
            ancestors: Vec::new(),
        }
    }

    /// Attach a best-effort parent chain (nearest-first).
    pub fn with_ancestors(mut self, ancestors: Vec<Process>) -> Self {
        self.ancestors = ancestors;
        self
    }

    /// The caller's exe followed by each ancestor's exe, nearest-first. An
    /// owner-group match succeeds if *any* of these is in the owner group
    /// (DESIGN §5: "caller *or* an ancestor within the session boundary").
    pub fn identity_chain(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.proc.exe.as_path())
            .chain(self.ancestors.iter().map(|p| p.exe.as_path()))
    }
}
