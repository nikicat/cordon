//! BPF map schema: the names the program defines / the loader resolves, the mode
//! and decision codes, and the POD key/value/record types. The kernel-side maps
//! themselves are `BPF_MAP_TYPE_HASH` / `_ARRAY` / `_RINGBUF` provided by the
//! kernel and wrapped by aya — this module only fixes the *shapes* both sides read
//! and write.
//!
//! Everything is keyed on [`FileId`] — a `(device, inode)` pair. The eBPF program
//! cannot resolve paths at the `file_open` LSM hook (`bpf_d_path` is not allowed
//! there), so both the protected subtree *and* the caller's executable are matched
//! by inode identity, which the daemon resolves from paths via `stat(2)` at seed
//! time.

use crate::ids::{Decision, Dev, Ino, Mode, OwnerId, Pid};

// ---- map names ------------------------------------------------------------
// The program defines these maps; the loader resolves them by name. Constants so
// a rename can't silently desync the two crates.

/// `HashMap<FileId, OwnerId>` — a protected subtree root → the owner group that
/// owns it. Longest-prefix match is the dentry ancestor walk.
pub const MAP_SUBTREES: &str = "SUBTREES";
/// `HashMap<OwnerKey, u8>` — membership set of (owner id, exe `FileId`). Presence
/// means "this executable is an identity of that owner group".
pub const MAP_OWNER_IDS: &str = "OWNER_IDS";
/// `Array<Settings>` (one element, index 0) — the daemon pid to fast-allow and the
/// enforce/audit mode. Swapped atomically by the loader on a mode change.
pub const MAP_SETTINGS: &str = "SETTINGS";
/// `RingBuf` — the async learn path: one [`LearnEvent`] per mediated denial /
/// would-deny, drained by the daemon into the journal (and, later, TOFU claims).
pub const MAP_EVENTS: &str = "EVENTS";

/// A file or directory identified by its filesystem device + inode. Inode identity
/// (not path) is what the in-kernel dentry walk can cheaply compare, and is robust
/// to a rename of the object itself.
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

/// Membership key: an owner group plus the [`FileId`] of one of its executables.
/// The value side is a presence byte.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct OwnerKey {
    pub owner: OwnerId,
    pub exe: FileId,
}

impl OwnerKey {
    pub const fn new(owner: OwnerId, exe: FileId) -> Self {
        OwnerKey { owner, exe }
    }
}

/// The one-element control record in `SETTINGS`: which pid is the daemon (always
/// allowed, so we never deadlock on our own opens) and the current mode.
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

/// One mediated decision, pushed to the ring buffer for the daemon to log/persist.
/// Fixed size, no strings: `bpf_d_path` is unavailable at this hook, so the record
/// carries inode identities; the daemon reverse-resolves them (and reads
/// `/proc/<pid>/exe`) for a friendly log line.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LearnEvent {
    /// Thread-group id (userspace pid) of the caller.
    pub pid: Pid,
    /// `Decision::DENY` or `Decision::WOULD_DENY`.
    pub decision: Decision,
    /// The owning subtree's owner-group id.
    pub owner: OwnerId,
    /// The matched protected subtree root.
    pub subtree: FileId,
    /// The caller's executable (the identity that did *not* match).
    pub exe: FileId,
}

// ---- userspace-only: mark the POD types usable as aya map keys/values -----

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: every field is a POD newtype over an integer, so any bit pattern is a
    // valid value and the types are `Copy` with a fixed `repr(C)` layout — exactly
    // aya's contract for `Pod`.
    unsafe impl aya::Pod for FileId {}
    unsafe impl aya::Pod for OwnerKey {}
    unsafe impl aya::Pod for Settings {}
    unsafe impl aya::Pod for LearnEvent {}
}
