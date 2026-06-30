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

use crate::ids::{Bank, Decision, Dev, Ino, Nanos, Pid, Suppressed, Uid};
use crate::policy_maps::{Action, ObjId};

// ---- map names ------------------------------------------------------------
// The program defines these maps; the loader resolves them by name. (The rule-table
// maps `PROTECTED`/`RULES`/`RULE_COUNT` are named in `policy_maps`.)

/// `Array<Settings>` (one element, index 0) — the daemon pid to fast-allow and the live
/// double-buffer bank. Written whole per update; the bank flip that publishes a new
/// policy is one such write.
pub const MAP_SETTINGS: &str = "SETTINGS";
/// `RingBuf` — the async learn path: one [`DecisionEvent`] per logged decision (`deny` /
/// `audit`), drained by the daemon into the journal.
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
/// allowed, so we never deadlock on our own opens) and the live double-buffer [`Bank`].
/// The kernel reads both from one `Array::get(0)` snapshot; an `apply` fills the
/// inactive bank and then writes this record with `active_bank` flipped to publish.
/// `daemon_pid` never changes after startup, so the flip's only moving part is the
/// 4-byte `active_bank`, which can't tear.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub daemon_pid: Pid,
    pub active_bank: Bank,
}

impl Settings {
    pub const fn new(daemon_pid: Pid, active_bank: Bank) -> Self {
        Settings {
            daemon_pid,
            active_bank,
        }
    }
}

/// One logged decision, pushed to the ring buffer for the daemon to journal. Emitted
/// only when the matched policy logs (`audit`/`deny`) or on a default-deny — never for
/// a silent `allow`/`silence`. Carries inode identities (no `bpf_d_path` at this hook);
/// the daemon reverse-resolves them and reads `/proc/<pid>/exe` for a friendly line.
/// (Named for what it records — a decision — not a consumer; autolearn (M4) is one
/// future reader, the journal is today's.)
/// Max path components the kernel reconstructs (leaf → matched object). Deeper paths set
/// [`DecisionEvent::trunc`]. Bounds the dentry walk (verifier-friendly) and the record.
pub const PATH_MAX_DEPTH: usize = 8;
/// Max bytes per path component (incl. the NUL `bpf_probe_read_kernel_str` writes). A
/// longer name is truncated into the slot and sets [`DecisionEvent::trunc`].
pub const PATH_NAME_MAX: usize = 32;

/// One reconstructed path component in a [`DecisionEvent`]: a NUL-terminated (NUL-padded)
/// name, at most `PATH_NAME_MAX` bytes including the terminator. The kernel fills it with
/// `bpf_probe_read_kernel_str` (which always NUL-terminates within the slot); the daemon
/// reads the name back with [`name`](PathComp::name). A `repr(transparent)` byte array, so
/// it embeds in the POD record with no layout cost.
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct PathComp(pub [u8; PATH_NAME_MAX]);

impl PathComp {
    /// The zero (all-NUL) component — the fill value for unused slots.
    pub const EMPTY: PathComp = PathComp([0; PATH_NAME_MAX]);

    /// The component name: the bytes up to the first NUL (the whole slot if somehow
    /// unterminated). `no_std`/no-alloc, so it serves both the kernel and the daemon.
    pub fn name(&self) -> &[u8] {
        let end = match self.0.iter().position(|&b| b == 0) {
            Some(i) => i,
            None => self.0.len(),
        };
        &self.0[..end]
    }
}

/// The mutable backing array, for the kernel's `bpf_probe_read_kernel_str` to fill.
impl core::ops::DerefMut for PathComp {
    fn deref_mut(&mut self) -> &mut [u8; PATH_NAME_MAX] {
        &mut self.0
    }
}
impl core::ops::Deref for PathComp {
    type Target = [u8; PATH_NAME_MAX];
    fn deref(&self) -> &[u8; PATH_NAME_MAX] {
        &self.0
    }
}

/// ## Leaf path (DESIGN §15.10 flow B)
/// `bpf_d_path` is unavailable at `file_open`, so the kernel reconstructs the opened
/// file's path *relative to the matched protected object* by walking `d_name` up the
/// dentry chain: [`comps`](Self::comps) holds the component names **leaf-first**
/// (`comps[0]` = the opened file's own name, `comps[1]` = its parent, …),
/// [`depth`](Self::depth) of them, and [`trunc`](Self::trunc) marks a name/depth overflow.
/// The daemon reverses + joins them onto the object's known path → the full opened path.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DecisionEvent {
    /// The caller's executable identity (the subject that hit the rule).
    pub exe: FileId,
    /// The matched protected object's inode identity (the rule's `where`).
    pub object: FileId,
    /// The **opened file's own** inode identity — the per-file key the suppressor and the
    /// daemon coalesce on, so distinct files under one audited root surface separately
    /// (DESIGN §15.10 flow B). Equals `object` when the rule targets the file directly.
    pub leaf: FileId,
    /// The matched protected object's id.
    pub obj: ObjId,
    /// The requested action(s) at this access (`read`/`write`/`create`).
    pub action: Action,
    /// Thread-group id (userspace pid) of the caller.
    pub pid: Pid,
    /// The caller's **real** uid — the daemon resolves it to a login name for the audit
    /// line and, for a regular user, collapses a path under that user's home to `~`.
    pub uid: Uid,
    /// How it was handled (`DENY` blocked / `AUDIT` allowed-and-logged).
    pub decision: Decision,
    /// How many identical decisions the in-kernel suppressor folded into this one since
    /// the previous emit for the same `(exe, leaf, action)` (M1 §1g). `0` on a first
    /// occurrence; nonzero means a repeat burst was collapsed — the daemon adds it to
    /// the coalesced record so the true volume is visible.
    pub suppressed: Suppressed,
    /// The matched policy — the cause, for the log: an authored `audit`/`deny`, or the
    /// synthetic `DEFAULT_DENY` when no rule matched (vs an explicit `deny`).
    pub policy: crate::policy_maps::Policy,
    /// Number of valid entries in [`comps`](Self::comps) (`0` ⇒ the object *is* the
    /// opened file, or reconstruction read nothing).
    pub depth: u8,
    /// `1` if the path was truncated (deeper than [`PATH_MAX_DEPTH`] or a name longer than
    /// [`PATH_NAME_MAX`]) — the daemon renders a leading `…/` so it never reads as exact.
    pub trunc: u8,
    /// Trailing pad so the record's size is a multiple of its 8-byte alignment (the `u64`
    /// in [`FileId`]) with no implicit padding the kernel might leave uninitialized.
    pub _pad: [u8; 5],
    /// Leaf-first path components ([`PathComp`]), `depth` of them valid.
    pub comps: [PathComp; PATH_MAX_DEPTH],
}

impl DecisionEvent {
    /// Build a record with **no path** (`depth = 0`): for daemon-side tests and any
    /// caller that doesn't reconstruct the leaf path. The kernel fills `depth`/`comps`
    /// directly in the ring slot instead of going through this.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        pid: Pid,
        uid: Uid,
        exe: FileId,
        object: FileId,
        leaf: FileId,
        obj: ObjId,
        action: Action,
        decision: Decision,
        policy: crate::policy_maps::Policy,
        suppressed: Suppressed,
    ) -> DecisionEvent {
        DecisionEvent {
            exe,
            object,
            leaf,
            obj,
            action,
            pid,
            uid,
            decision,
            suppressed,
            policy,
            depth: 0,
            trunc: 0,
            _pad: [0; 5],
            comps: [PathComp::EMPTY; PATH_MAX_DEPTH],
        }
    }
}

/// The in-kernel suppressor key ([`MAP_SUPPRESS`]): one decision identity. Keyed on the
/// **opened file** (`leaf`), not the protected object, so distinct files under one audited
/// root each get their own throttle window (DESIGN §15.10 flow B). The explicit `_pad`
/// keeps it padding-free (16 + 16 + 4 + 4 = 40, align 8) and **zeroed** — a BPF hash-map
/// key hashes its whole byte span, so an uninitialized pad byte would split one logical
/// key across buckets.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SuppressKey {
    /// The caller's executable identity.
    pub exe: FileId,
    /// The opened file's inode identity.
    pub leaf: FileId,
    /// The requested action(s) for this open.
    pub action: Action,
    pub _pad: [u8; 4],
}

impl SuppressKey {
    pub const fn new(exe: FileId, leaf: FileId, action: Action) -> Self {
        SuppressKey {
            exe,
            leaf,
            action,
            _pad: [0; 4],
        }
    }
}

/// The in-kernel suppressor value ([`MAP_SUPPRESS`]): when this key last emitted, and
/// how many identical decisions have been suppressed since (folded into the next emit).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SuppressVal {
    /// `bpf_ktime_get_ns()` at the last *emitted* decision for this key.
    pub last_ns: Nanos,
    /// Decisions suppressed since `last_ns` (carried into the next [`DecisionEvent`]).
    pub suppressed: Suppressed,
    pub _pad: [u8; 4],
}

impl SuppressVal {
    pub const fn new(last_ns: Nanos, suppressed: Suppressed) -> Self {
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
