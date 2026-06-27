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

use crate::ids::{Bank, Decision, Dev, Ino, Mode, Pid};
use crate::policy_maps::{Action, ObjId};

// ---- map names ------------------------------------------------------------
// The program defines these maps; the loader resolves them by name. (The rule-table
// maps `PROTECTED`/`RULES`/`RULE_COUNT` are named in `policy_maps`.)

/// `Array<Settings>` (one element, index 0) — the daemon pid to fast-allow, the
/// global enforce/permissive/off mode, and the live double-buffer bank. Written whole
/// per update; the bank flip that publishes a new policy is one such write.
pub const MAP_SETTINGS: &str = "SETTINGS";
/// `RingBuf` — the async learn path: one [`DecisionEvent`] per logged decision (deny /
/// would-deny / audit), drained by the daemon into the journal.
pub const MAP_EVENTS: &str = "EVENTS";
/// `LruHashMap<SuppressKey, SuppressVal>` — the in-kernel event suppressor (DESIGN
/// §15, M1 §1g). Throttles the ring to ~one [`DecisionEvent`] per `(exe, object,
/// action)` per window, counting the rest so volume stays visible without flooding.
/// **LRU**, not a plain hash: a full plain hash refuses *new* keys (`-E2BIG`), so a
/// fresh repeat-opener past the cap would never be throttled; LRU instead evicts the
/// coldest key, self-bounding to the hottest openers (where suppression matters). An
/// evicted key loses its pending `suppressed` count and re-emits as a first occurrence
/// — acceptable, since a cold key by definition wasn't flooding. Kernel-internal: the
/// daemon never reads or seeds it.
pub const MAP_SUPPRESS: &str = "SUPPRESS";

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
/// allowed, so we never deadlock on our own opens), the current global mode, and the
/// live double-buffer [`Bank`]. The kernel reads all three from one `Array::get(0)`
/// snapshot, so they stay mutually consistent; an `apply` fills the inactive bank and
/// then writes this record with `active_bank` flipped (and the new mode) to publish.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub daemon_pid: Pid,
    pub mode: Mode,
    pub active_bank: Bank,
    pub _pad: [u8; 4],
}

impl Settings {
    pub const fn new(daemon_pid: Pid, mode: Mode, active_bank: Bank) -> Self {
        Settings {
            daemon_pid,
            mode,
            active_bank,
            _pad: [0; 4],
        }
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
    /// How many identical decisions the in-kernel suppressor folded into this one since
    /// the previous emit for the same `(exe, object, action)` (M1 §1g). `0` on a first
    /// occurrence; nonzero means a repeat burst was collapsed — the daemon adds it to
    /// the coalesced record so the true volume is visible.
    pub suppressed: u32,
    /// The matched policy (or `DENY` for a default-deny) — the cause, for the log.
    pub policy: crate::policy_maps::Policy,
    pub _pad: [u8; 3],
}

impl DecisionEvent {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        pid: Pid,
        exe: FileId,
        object: FileId,
        obj: ObjId,
        action: Action,
        decision: Decision,
        policy: crate::policy_maps::Policy,
        suppressed: u32,
    ) -> DecisionEvent {
        DecisionEvent {
            exe,
            object,
            obj,
            action,
            pid,
            decision,
            suppressed,
            policy,
            _pad: [0; 3],
        }
    }
}

/// The in-kernel suppressor key ([`MAP_SUPPRESS`]): one decision identity. Sized to be
/// padding-free (16 + 4 + 4 = 24) so the BPF hash of the whole key is well-defined.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SuppressKey {
    /// The caller's executable identity.
    pub exe: FileId,
    /// The matched protected object's id.
    pub obj: ObjId,
    /// The requested action(s) for this open.
    pub action: Action,
}

impl SuppressKey {
    pub const fn new(exe: FileId, obj: ObjId, action: Action) -> Self {
        SuppressKey { exe, obj, action }
    }
}

/// The in-kernel suppressor value ([`MAP_SUPPRESS`]): when this key last emitted, and
/// how many identical decisions have been suppressed since (folded into the next emit).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SuppressVal {
    /// `bpf_ktime_get_ns()` at the last *emitted* decision for this key.
    pub last_ns: u64,
    /// Decisions suppressed since `last_ns` (carried into the next [`DecisionEvent`]).
    pub suppressed: u32,
    pub _pad: [u8; 4],
}

impl SuppressVal {
    pub const fn new(last_ns: u64, suppressed: u32) -> Self {
        SuppressVal {
            last_ns,
            suppressed,
            _pad: [0; 4],
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
