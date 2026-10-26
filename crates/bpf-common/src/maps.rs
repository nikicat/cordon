//! The map names and POD records shared between the eBPF program and the loader
//! that are **not** part of the per-object rule table (that lives in
//! [`crate::policy_maps`]): the `(dev,inode)` [`FileId`] used everywhere as inode
//! identity, the one-element [`Settings`] control record, and the [`DecisionEvent`]
//! pushed on the ring buffer.

use crate::ids::{Bank, Dev, Ino, Nanos, Pid, Suppressed, Uid};
use crate::policy_maps::{Action, ClassId};

// ---- map names ------------------------------------------------------------
// The program defines these maps; the loader resolves them by name. (The rule-table
// maps `PROTECTED`/`RULES`/`RULE_COUNT` are named in `policy_maps`.)

/// `Array<Settings>` (one element, index 0); see [`Settings`].
pub const MAP_SETTINGS: &str = "SETTINGS";
/// `RingBuf` of [`DecisionEvent`]s, drained by the daemon into the journal.
pub const MAP_EVENTS: &str = "EVENTS";

/// A file or directory identified by its filesystem device + inode — the identity of both
/// protected objects and callers' executables. Never a path: the eBPF program cannot
/// resolve paths at its hooks (`bpf_d_path` is not allowed at `file_open`), so the daemon
/// resolves each policy path to a `FileId` at seed time (its `proc::file_id`). Inode
/// identity is also what the in-kernel dentry walk can cheaply compare, and it survives a
/// rename of the object itself.
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

/// The compact canonical human form (`dev=N ino=N`) — used in the daemon's journal where
/// no path is available. `no_std`: `core::fmt`.
impl core::fmt::Display for FileId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "dev={} ino={}", self.dev.0, self.ino.0)
    }
}

padded_pod! {
    /// The one-element control record in `SETTINGS`: the daemon's identity, which the
    /// kernel fast-allows (pid *and* exe, never the pid alone — see the program's
    /// `live_bank`), and the live double-buffer [`Bank`] (see there for the flip). The
    /// kernel reads all of it from one `Array::get(0)` snapshot.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct Settings {
        pub daemon_pid: Pid,
        pub active_bank: Bank,
        pub daemon_exe: FileId,
    }
}

impl Settings {
    pub const fn new(daemon_pid: Pid, active_bank: Bank, daemon_exe: FileId) -> Self {
        Settings {
            daemon_pid,
            active_bank,
            daemon_exe,
            _pad: [0; Self::PAD],
        }
    }
}

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

padded_pod! {
    /// One decision whose policy [`logs`](crate::policy_maps::Policy::logs), pushed to the
    /// ring buffer for the daemon to journal. Carries [`FileId`]s and the leaf path's
    /// components; the daemon reverse-resolves them and reads `/proc/<pid>/exe` for a
    /// friendly line.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct DecisionEvent {
        /// The caller's executable identity (the subject that hit the rule).
        pub exe: FileId,
        /// The matched protected object's inode identity (the rule's `where`).
        pub object: FileId,
        /// The **opened file's own** inode identity (the suppressor keys on it, see
        /// [`SuppressKey`]). Equals `object` when the rule targets the file directly.
        pub leaf: FileId,
        /// The requested action(s) at this access (`read`/`write`/`create`).
        pub action: Action,
        /// Thread-group id (userspace pid) of the caller.
        pub pid: Pid,
        /// The caller's **real** uid, which the daemon names on the audit line.
        pub uid: Uid,
        /// Repeats the in-kernel suppressor folded into this record (see [`Suppressed`]).
        pub suppressed: Suppressed,
        /// The caller's resolved **blessing class** (DESIGN §16.3), or [`ClassId::UNBLESSED`]
        /// when the caller is in no blessed cgroup; the daemon prints it by class name.
        /// Placed among the `u32` scalars (before the `u8` `policy`/`depth`/`trunc`) to
        /// keep the record interior-padding-free.
        pub blessing: ClassId,
        /// The matched policy, which says both how the access was handled
        /// ([`denies`](crate::policy_maps::Policy::denies)) and why: an authored
        /// `audit`/`deny`, or a synthetic `DEFAULT_DENY`/`ESCAPE_DENY`.
        pub policy: crate::policy_maps::Policy,
        /// Number of valid entries in [`comps`](Self::comps) (`0` ⇒ the object *is* the
        /// opened file, or reconstruction read nothing).
        pub depth: u8,
        /// `1` if the path was truncated (deeper than [`PATH_MAX_DEPTH`] or a name longer than
        /// [`PATH_NAME_MAX`]) — the daemon renders a leading `…/` so it never reads as exact.
        pub trunc: u8,
        /// The opened file's path relative to the matched object, as [`PathComp`]s
        /// **leaf-first**: `comps[0]` is the file's own name, `comps[1]` its parent's,
        /// and so on up to but excluding the object; [`depth`](Self::depth) of them are
        /// valid and [`trunc`](Self::trunc) marks an overflow. The kernel fills them by
        /// walking `d_name` up the dentry chain, since it has no path (see [`FileId`]); the
        /// daemon reverses and joins them onto the object's known path (DESIGN §15.10
        /// flow B).
        pub comps: [PathComp; PATH_MAX_DEPTH],
    }
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
        action: Action,
        policy: crate::policy_maps::Policy,
        suppressed: Suppressed,
        blessing: ClassId,
    ) -> DecisionEvent {
        DecisionEvent {
            exe,
            object,
            leaf,
            action,
            pid,
            uid,
            suppressed,
            policy,
            blessing,
            depth: 0,
            trunc: 0,
            comps: [PathComp::EMPTY; PATH_MAX_DEPTH],
            _pad: [0; Self::PAD],
        }
    }
}

padded_pod! {
    /// The in-kernel suppressor key (the kernel's `SUPPRESS` map): one decision identity,
    /// `(exe, leaf, action)`. Keyed on the **opened file** (`leaf`), not the protected
    /// object, so distinct files under one audited object each get their own throttle
    /// window and surface separately in the journal (DESIGN §15.10 flow B). The
    /// `padded_pod!` `_pad` (16 + 16 + 4, padded to 40, align 8) keeps the hashed key
    /// zeroed; see the `layout` module docs.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct SuppressKey {
        /// The caller's executable identity.
        pub exe: FileId,
        /// The opened file's inode identity.
        pub leaf: FileId,
        /// The requested action(s) for this open.
        pub action: Action,
    }
}

impl SuppressKey {
    pub const fn new(exe: FileId, leaf: FileId, action: Action) -> Self {
        SuppressKey {
            exe,
            leaf,
            action,
            _pad: [0; Self::PAD],
        }
    }
}

padded_pod! {
    /// The in-kernel suppressor value (the kernel's `SUPPRESS` map): when this key last emitted, and
    /// how many identical decisions have been suppressed since (folded into the next emit).
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct SuppressVal {
        /// `bpf_ktime_get_ns()` at the last *emitted* decision for this key.
        pub last_ns: Nanos,
        /// Decisions suppressed since `last_ns` (carried into the next [`DecisionEvent`]).
        pub suppressed: Suppressed,
    }
}

impl SuppressVal {
    pub const fn new(last_ns: Nanos, suppressed: Suppressed) -> Self {
        SuppressVal {
            last_ns,
            suppressed,
            _pad: [0; Self::PAD],
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
