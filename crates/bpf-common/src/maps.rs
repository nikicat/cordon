//! The map names and POD records that the eBPF program and the loader share outside the
//! per-object rule table, which lives in [`crate::policy_maps`]. They carry the control
//! record that the daemon writes, the decisions that the program reports, and the
//! suppressor's state.

use crate::ids::{Bank, Dev, Ino, Nanos, Pid, Suppressed, Uid};
use crate::policy_maps::{Action, ClassId};

// ---- map names ------------------------------------------------------------
// The program defines these maps, and the loader resolves them by name. The rule-table
// maps `PROTECTED`, `RULES` and `RULE_COUNT` are named in `policy_maps`.

/// The name of the one-element `Array<Settings>`, read at index 0.
pub const MAP_SETTINGS: &str = "SETTINGS";
/// The index of the one [`Settings`] record in [`MAP_SETTINGS`].
pub const SETTINGS_INDEX: u32 = 0;
/// The name of the `RingBuf` of [`DecisionEvent`]s that the daemon drains into the journal.
pub const MAP_EVENTS: &str = "EVENTS";

/// A file or directory, identified by its filesystem device and inode. It is the identity
/// of both protected objects and callers' executables. It is never a path, because the eBPF
/// program cannot resolve paths at its hooks (`bpf_d_path` is not allowed at `file_open`).
/// So the daemon resolves each policy path to a `FileId` at seed time (its
/// `proc::file_id`). The in-kernel dentry walk can compare inode identity cheaply, and the
/// identity survives a rename of the object itself.
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

/// Writes the compact form `dev=N ino=N`, which the daemon's journal shows when it has no
/// path.
impl core::fmt::Display for FileId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "dev={} ino={}", self.dev.0, self.ino.0)
    }
}

padded_pod! {
    /// The one-element control record in `SETTINGS`, which the kernel reads as one
    /// `Array::get(0)` snapshot. It names the daemon, which the kernel fast-allows by pid
    /// and exe together, never by pid alone (see the program's `live_bank`). It also holds
    /// the live double-buffer [`Bank`] (its doc describes the flip).
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

    /// Returns settings that name no daemon, so no process is fast-allowed. No process
    /// runs as pid `u32::MAX`, and no real inode is `dev=0 ino=0`, so neither half of the
    /// identity can match.
    pub const fn no_daemon(active_bank: Bank) -> Self {
        Settings::new(Pid(u32::MAX), active_bank, FileId::new(Dev(0), Ino(0)))
    }
}

/// The most path components that the kernel reconstructs between the leaf and the matched
/// object. A deeper path sets [`DecisionEvent::trunc`]. The cap bounds both the dentry
/// walk, for the verifier, and the size of the record.
pub const PATH_MAX_DEPTH: usize = 8;
/// The most bytes in one path component, including the NUL that
/// `bpf_probe_read_kernel_str` writes. A longer name is truncated into the slot and sets
/// [`DecisionEvent::trunc`].
pub const PATH_NAME_MAX: usize = 32;

/// One reconstructed path component in a [`DecisionEvent`]. It holds a name that is
/// NUL-terminated and NUL-padded to `PATH_NAME_MAX` bytes. The kernel fills it with
/// `bpf_probe_read_kernel_str`, which always NUL-terminates within the slot, and the daemon
/// reads the name back with [`name`](PathComp::name). It is a `repr(transparent)` byte
/// array, so it embeds in the POD record at no layout cost.
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct PathComp(pub [u8; PATH_NAME_MAX]);

impl PathComp {
    /// Returns the component name, which is the bytes before the first NUL, or the whole
    /// slot if it has no NUL.
    pub fn name(&self) -> &[u8] {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        &self.0[..end]
    }
}

padded_pod! {
    /// One decision whose policy [`logs`](crate::policy_maps::Policy::logs), which the
    /// program pushes to the ring buffer for the daemon to journal. It carries [`FileId`]s
    /// and the components of the leaf path. The daemon turns them back into paths and reads
    /// `/proc/<pid>/exe` to write a readable line.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct DecisionEvent {
        /// The identity of the caller's executable, which is the subject that hit the rule.
        pub exe: FileId,
        /// The inode identity of the matched protected object, which is the rule's `where`.
        pub object: FileId,
        /// The opened file's own inode identity, which [`SuppressKey`] keys on. It equals
        /// `object` when the rule targets the file directly.
        pub leaf: FileId,
        /// The action or actions requested at this access, such as `read`, `write` or
        /// `create`.
        pub action: Action,
        /// The caller's thread-group id, which is its userspace pid.
        pub pid: Pid,
        /// The caller's real uid, which the daemon names on the audit line.
        pub uid: Uid,
        /// The repeats that the in-kernel suppressor held back before this record (see
        /// [`Suppressed`]).
        pub suppressed: Suppressed,
        /// The caller's resolved blessing class (DESIGN §16.3), or [`ClassId::UNBLESSED`]
        /// when the caller is in no blessed cgroup. The daemon prints it by class name. It
        /// sits among the `u32` fields, before the `u8` fields `policy`, `depth` and
        /// `trunc`, so that the record has no interior padding.
        pub blessing: ClassId,
        /// The matched policy. It says how the access was handled
        /// ([`denies`](crate::policy_maps::Policy::denies)), and it says why, as one of
        /// these: an authored `audit` or `deny`, or a synthetic `DEFAULT_DENY` or
        /// `ESCAPE_DENY`.
        pub policy: crate::policy_maps::Policy,
        /// The number of valid entries in [`comps`](Self::comps). It is `0` when the object
        /// is the opened file itself, or when reconstruction read nothing.
        pub depth: u8,
        /// `1` when the path was cut short, because it was deeper than [`PATH_MAX_DEPTH`],
        /// a name was longer than [`PATH_NAME_MAX`], or a component was unreadable. The
        /// daemon then renders a leading `…/`, so the path never reads as exact.
        pub trunc: u8,
        /// The opened file's path relative to the matched object, as [`PathComp`]s in
        /// leaf-first order. `comps[0]` is the file's own name and `comps[1]` is its
        /// parent's, up to but not including the object. The kernel fills them by walking
        /// `d_name` up the dentry chain, since it has no path (see [`FileId`]). The daemon
        /// reverses them and joins them onto the object's known path (DESIGN §15.10 flow
        /// B).
        pub comps: [PathComp; PATH_MAX_DEPTH],
    }
}

impl DecisionEvent {
    /// Returns the valid entries of [`comps`](Self::comps), leaf first. A `depth` past
    /// [`PATH_MAX_DEPTH`] counts as the whole array.
    pub fn valid_comps(&self) -> &[PathComp] {
        &self.comps[..(self.depth as usize).min(PATH_MAX_DEPTH)]
    }

    /// Checks whether the path walk was cut short (see [`trunc`](Self::trunc)).
    pub const fn is_truncated(&self) -> bool {
        self.trunc != 0
    }
}

padded_pod! {
    /// The key of the kernel's suppressor map `SUPPRESS`, which identifies one kind of
    /// decision by `(exe, leaf, action)`. It keys on the opened file (`leaf`) rather than
    /// the protected object, so distinct files under one audited object each get their own
    /// suppression window and surface separately in the journal (DESIGN §15.10 flow B). Its
    /// `padded_pod!` `_pad` pads the 16 + 16 + 4 bytes to 40 at 8-byte alignment, which
    /// keeps the hashed key zeroed (see the `layout` module docs).
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct SuppressKey {
        /// The identity of the caller's executable.
        pub exe: FileId,
        /// The opened file's inode identity.
        pub leaf: FileId,
        /// The action or actions that this open requests.
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
    /// The value of the kernel's suppressor map `SUPPRESS`. It records when its key last
    /// emitted a ring record, and how many identical decisions were suppressed since then.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct SuppressVal {
        /// The `bpf_ktime_get_ns()` reading at the last emitted decision for this key.
        pub last_ns: Nanos,
        /// The decisions suppressed since `last_ns`, which the next [`DecisionEvent`]
        /// carries.
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

// ---- userspace only, so the POD types can be aya map keys and values -------

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: every field is a POD newtype or aggregate over integers, so any bit pattern
    // is a valid value. The types are `Copy` with a fixed `repr(C)` layout, which is
    // aya's contract for `Pod`.
    unsafe impl aya::Pod for FileId {}
    unsafe impl aya::Pod for Settings {}
    unsafe impl aya::Pod for DecisionEvent {}
}
