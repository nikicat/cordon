//! Semantic scalar types for the policy keys.
//!
//! `repr(transparent)` newtypes over integers: they compile to byte-identical BPF
//! (a `Dev` *is* its `u64`), so the kernel verifier and the map's byte-level key
//! comparison are unaffected — the cost is zero. They just stop a device number, an
//! inode, an owner id, and a path hash from being four interchangeable bare
//! integers. Because the layout is unchanged, the map key/value/record structs that
//! embed them stay POD (`aya::Pod`).

/// Filesystem device number, in the **kernel's** `s_dev` encoding (see the daemon's
/// `kernel_dev`, which re-packs `stat(2)`'s differently-encoded `st_dev` to match).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Dev(pub u64);

/// Inode number within a device.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ino(pub u64);

/// A process id (thread-group id). Wraps `u32` to match the natural width on both
/// sides — `std::process::id()` and the kernel's `bpf_get_current_pid_tgid() >> 32`
/// — distinct from core's `Pid(i32)`, which mirrors `/proc`/`nix`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Pid(pub u32);

/// How a mediated, logged access was handled — carried in [`crate::DecisionEvent`] for
/// the daemon's journal line. A `repr(transparent)` `u32` rather than an enum *on
/// purpose*: aya map values must be `Pod` (valid for any bit pattern), which an enum is
/// not — reading a stray discriminant out of map memory would be UB. Named values live
/// as associated consts.
///
/// There is no global enforcement mode (DESIGN §15.6): the per-rule `policy` is the only
/// enforcement level, so a denying policy always blocks and only the `deny`-vs-`audit`
/// distinction is journaled here.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Decision(pub u32);

impl Decision {
    /// A denying policy (`deny` / `silence` / the default-deny) → blocked (`-EPERM`).
    pub const DENY: Decision = Decision(0);
    /// An `audit` policy (allow + log) → allowed, logged for visibility.
    pub const AUDIT: Decision = Decision(2);
}

/// Which generation of the double-buffered rule table is live (DESIGN §15.8). The
/// kernel reads `Settings.active_bank`; a `cordon policy apply` fills the other bank
/// and [`flip`](Bank::flip)s to it in one atomic `SETTINGS` write. Only `0`/`1` are
/// valid; same `repr(transparent)`-not-enum rationale as [`Decision`] (it's read out of
/// map memory, so every bit pattern must be a sound value — [`index`](Bank::index)
/// masks a garbage read back into range).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Bank(pub u32);

impl Bank {
    /// The generation a fresh fill targets first (startup's initial active bank, with
    /// `SETTINGS` zero-initialized).
    pub const ZERO: Bank = Bank(0);

    /// The *other* generation: an `apply` fills this, then flips the active bank to it.
    pub const fn flip(self) -> Bank {
        Bank(self.index() ^ 1)
    }

    /// The bank as an array index, masked to a valid generation (`0`/`1`) so a stray
    /// value read from map memory can't push a [`crate::rule_slot`] index out of range.
    pub const fn index(self) -> u32 {
        self.0 & 1
    }

    /// This value normalized to a valid generation (`0`/`1`) — what the kernel keys the
    /// banked maps with, so a torn/garbage `active_bank` read degrades to an empty
    /// bucket (fail-open allow) rather than a wild lookup.
    pub const fn masked(self) -> Bank {
        Bank(self.index())
    }
}

// ---- userspace-only: usable as aya map keys/values ------------------------

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: each is a `repr(transparent)` wrapper over a `u64`, so every bit
    // pattern is valid and the type is `Copy` — aya's `Pod` contract.
    unsafe impl aya::Pod for Dev {}
    unsafe impl aya::Pod for Ino {}
    unsafe impl aya::Pod for Pid {}
    unsafe impl aya::Pod for Decision {}
    unsafe impl aya::Pod for Bank {}
}
