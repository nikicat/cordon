//! BPF map schema: the names the program defines / the loader resolves, the mode
//! and decision codes, and the POD key/value/record types. The kernel-side maps
//! themselves are `BPF_MAP_TYPE_HASH` / `_ARRAY` / `_RINGBUF` provided by the
//! kernel and wrapped by aya — this module only fixes the *shapes* both sides read
//! and write.

use crate::ids::{Decision, Dev, ExeHash, Ino, Mode, OwnerId, Pid};

// ---- map names ------------------------------------------------------------
// The program defines these maps; the loader resolves them by name. Constants so
// a rename can't silently desync the two crates.

/// `HashMap<SubtreeKey, u64>` — a protected subtree root (by device+inode) → the
/// owner-group id that owns it. Longest-prefix match is the dentry ancestor walk.
pub const MAP_SUBTREES: &str = "SUBTREES";
/// `HashMap<OwnerKey, u8>` — membership set of (owner id, exe-path hash). Presence
/// means "this executable is an identity of that owner group".
pub const MAP_OWNER_IDS: &str = "OWNER_IDS";
/// `Array<Settings>` (one element, index 0) — the daemon pid to fast-allow and the
/// enforce/audit mode. Swapped atomically by the loader on a mode change.
pub const MAP_SETTINGS: &str = "SETTINGS";
/// `RingBuf` — the async learn path: one [`LearnEvent`] per mediated denial /
/// would-deny, drained by the daemon into the journal (and, later, TOFU claims).
pub const MAP_EVENTS: &str = "EVENTS";

/// Cap on the path/exe byte strings carried in a [`LearnEvent`] and hashed for
/// identity. A power of two so the eBPF side can bound-mask its copy/hash loops
/// for the verifier. Real exe/secret paths sit well under this; a deeper path is
/// truncated for *observability*, and the identity hash is computed over the same
/// (capped) bytes on both sides so a truncation can never cause a false match.
pub const PATH_CAP: usize = 512;

// ---- map keys / values ----------------------------------------------------

/// A protected subtree root, identified by the filesystem device + inode of its
/// directory. Inode identity (not path) makes the match robust to a rename *of the
/// subtree itself* and is what the in-kernel dentry walk can cheaply compare. The
/// map value is the [`OwnerId`] that owns it.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SubtreeKey {
    pub dev: Dev,
    pub ino: Ino,
}

impl SubtreeKey {
    pub const fn new(dev: Dev, ino: Ino) -> Self {
        SubtreeKey { dev, ino }
    }
}

/// Membership key: an owner group plus the FNV-1a hash of one of its executable
/// identities (see [`crate::hash`]). The value side is a presence byte.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct OwnerKey {
    pub owner: OwnerId,
    pub exe: ExeHash,
}

impl OwnerKey {
    pub const fn new(owner: OwnerId, exe: ExeHash) -> Self {
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
/// Fixed size (no heap in eBPF): the path/exe are inline byte buffers with explicit
/// lengths. Field order groups the scalars before the big buffers to keep the
/// header compact.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LearnEvent {
    /// Thread-group id (userspace pid) of the caller.
    pub pid: Pid,
    /// `Decision::DENY` or `Decision::WOULD_DENY`.
    pub decision: Decision,
    /// The owning subtree's owner-group id.
    pub owner: OwnerId,
    /// FNV-1a of the caller's exe path (the identity that did *not* match).
    pub exe_hash: ExeHash,
    /// Device + inode of the matched protected subtree root.
    pub dev: Dev,
    pub ino: Ino,
    /// Valid prefix lengths of `path` / `exe` (≤ `PATH_CAP`).
    pub path_len: u32,
    pub exe_len: u32,
    /// The opened path and the caller's exe path (kernel `d_path` form).
    pub path: [u8; PATH_CAP],
    pub exe: [u8; PATH_CAP],
}

impl LearnEvent {
    /// The valid bytes of the opened path.
    pub fn path_bytes(&self) -> &[u8] {
        let n = (self.path_len as usize).min(PATH_CAP);
        &self.path[..n]
    }

    /// The valid bytes of the caller's exe path.
    pub fn exe_bytes(&self) -> &[u8] {
        let n = (self.exe_len as usize).min(PATH_CAP);
        &self.exe[..n]
    }
}

// ---- userspace-only: mark the POD types usable as aya map keys/values -----

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: every field is a plain integer or a byte array, so any bit pattern
    // is a valid value and the types are `Copy` with a fixed `repr(C)` layout —
    // exactly aya's contract for `Pod`.
    unsafe impl aya::Pod for SubtreeKey {}
    unsafe impl aya::Pod for OwnerKey {}
    unsafe impl aya::Pod for Settings {}
    unsafe impl aya::Pod for LearnEvent {}
}
