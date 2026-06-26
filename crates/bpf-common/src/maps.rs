//! The map names and POD records shared between the eBPF program and the loader
//! that are **not** part of the per-object rule table (that lives in
//! [`crate::policy_maps`]): the `(dev,inode)` [`FileId`] used everywhere as inode
//! identity, the one-element [`Settings`] control record, and the [`DecisionEvent`]
//! pushed on the ring buffer.
//!
//! Identity is inode, not path: the eBPF program cannot resolve paths at the
//! `file_open` LSM hook (`bpf_d_path` is not allowed there), so the daemon resolves
//! paths to `(dev,inode)` via `stat(2)` + the mount table at seed time, and both the
//! protected object and the caller's executable are matched by [`FileId`].

use crate::ids::{Decision, Dev, Ino, Mode, Pid};
use crate::policy_maps::{Action, ObjId};

// ---- map names ------------------------------------------------------------
// The program defines these maps; the loader resolves them by name. (The rule-table
// maps `PROTECTED`/`RULES`/`RULE_COUNT` are named in `policy_maps`.)

/// `Array<Settings>` (one element, index 0) — the daemon pid to fast-allow and the
/// global enforce/permissive/off mode. Swapped atomically by the loader.
pub const MAP_SETTINGS: &str = "SETTINGS";
/// `RingBuf` — the async learn path: one [`LearnEvent`] per logged decision (deny /
/// would-deny / audit), drained by the daemon into the journal.
pub const MAP_EVENTS: &str = "EVENTS";

/// A file or directory identified by its filesystem device + inode. Inode identity
/// (not path) is what the in-kernel dentry walk can cheaply compare, and is robust to
/// a rename of the object itself.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FileId {
    pub dev: Dev,
    pub ino: Ino,
}

impl FileId {
    pub const fn new(dev: Dev, ino: Ino) -> Self {
        FileId { dev, ino }
    }
}

/// The compact canonical human form (`dev=N ino=N`) — used in the daemon's journal,
/// where no path is available (no `bpf_d_path` at the hook). `no_std`: `core::fmt`.
impl core::fmt::Display for FileId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "dev={} ino={}", self.dev.0, self.ino.0)
    }
}

/// The one-element control record in `SETTINGS`: which pid is the daemon (always
/// allowed, so we never deadlock on our own opens) and the current global mode.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub daemon_pid: Pid,
    pub mode: Mode,
}

impl Settings {
    pub const fn new(daemon_pid: Pid, mode: Mode) -> Self {
        Settings { daemon_pid, mode }
    }
}

/// One logged decision, pushed to the ring buffer for the daemon to journal. Emitted
/// only when the matched policy logs (`audit`/`deny`) or on a default-deny — never for
/// a silent `allow`/`silence`. Carries inode identities (no `bpf_d_path` at this hook);
/// the daemon reverse-resolves them and reads `/proc/<pid>/exe` for a friendly line.
/// (Named for what it records — a decision — not a consumer; autolearn (M4) is one
/// future reader, the journal is today's.)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DecisionEvent {
    /// The caller's executable identity (the subject that hit the rule).
    pub exe: FileId,
    /// The matched protected object's inode identity.
    pub object: FileId,
    /// The matched protected object's id.
    pub obj: ObjId,
    /// The requested action(s) at this access (`read`/`write`/`create`).
    pub action: Action,
    /// Thread-group id (userspace pid) of the caller.
    pub pid: Pid,
    /// How it was handled (`DENY` blocked / `WOULD_DENY` permissive / `AUDIT`).
    pub decision: Decision,
    /// The matched policy (or `DENY` for a default-deny) — the cause, for the log.
    pub policy: crate::policy_maps::Policy,
    pub _pad: [u8; 7],
}

impl DecisionEvent {
    pub const fn new(
        pid: Pid,
        exe: FileId,
        object: FileId,
        obj: ObjId,
        action: Action,
        decision: Decision,
        policy: crate::policy_maps::Policy,
    ) -> DecisionEvent {
        DecisionEvent {
            exe,
            object,
            obj,
            action,
            pid,
            decision,
            policy,
            _pad: [0; 7],
        }
    }
}

// ---- userspace-only: mark the POD types usable as aya map keys/values -----

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: every field is a POD newtype/aggregate over integers, so any bit
    // pattern is a valid value and the types are `Copy` with a fixed `repr(C)` layout
    // — exactly aya's contract for `Pod`.
    unsafe impl aya::Pod for FileId {}
    unsafe impl aya::Pod for Settings {}
    unsafe impl aya::Pod for DecisionEvent {}
}
