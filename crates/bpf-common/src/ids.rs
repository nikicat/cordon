//! Domain newtypes for the integers in the policy keys and the ring records.
//!
//! Each is a `repr(transparent)` wrapper over an integer, so it compiles to the same BPF as
//! the bare integer, and neither the verifier nor the map's byte-level key compare sees a
//! difference. The newtypes keep a device number, an inode, a pid, a uid and the rest from
//! being interchangeable. Because the layout is unchanged, the map keys, map values and
//! records that embed them stay POD (`aya::Pod`).

/// A filesystem device number in the kernel's `s_dev` encoding. The daemon's `proc::mkdev`
/// re-packs a mount's major and minor numbers into this encoding.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Dev(pub u64);

/// An inode number, unique within one device.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ino(pub u64);

/// A process id, meaning the thread-group id, as the kernel side records it. It is a `u32`
/// because both `std::process::id()` and the kernel's `bpf_get_current_pid_tgid() >> 32`
/// produce one. It is distinct from `cordon_core`'s control-plane `Pid`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Pid(pub u32);

/// A real user id that the kernel reported, never one that a client claimed. The eBPF
/// program reads it from `bpf_get_current_uid_gid()` into [`crate::DecisionEvent`] for the
/// audit line, and the IPC server reads it from `SO_PEERCRED` (`cordon_core`'s
/// `PeerCred::uid`) to authorize a request. It is a `u32` to match the kernel and passwd
/// width, and it is ordered so that it can be checked against `cordon_core`'s
/// `REGULAR_UID_RANGE`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Uid(pub u32);

impl Uid {
    /// The superuser's uid.
    pub const ROOT: Uid = Uid(0);
}

/// Writes the bare number. The journal uses it for the `user=` fallback when passwd has no
/// name for the uid, and for the `owner=` field of a minted blessing. With it, a caller can
/// log a uid without reaching past the newtype with `.0`.
impl core::fmt::Display for Uid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A cgroup-v2 id as `bpf_get_current_cgroup_id()` returns it. The kernel assigns each
/// cgroup directory a unique one. It keys [`crate::policy_maps::MAP_BLESSED`], and it is
/// the type of the reserved `cgroup` subject predicate ([`crate::SubjectMatch::cgroup`]).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CgroupId(pub u64);

/// The number of identical decisions that the in-kernel suppressor held back since the last
/// ring record for one [`crate::SuppressKey`]. It is `0` on a first occurrence. It travels
/// in [`crate::DecisionEvent`] and is held in [`crate::SuppressVal`].
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Suppressed(pub u32);

impl Suppressed {
    /// No opens were held back.
    pub const NONE: Suppressed = Suppressed(0);
}

/// A reading of the kernel's monotonic `bpf_ktime_get_ns()` clock, in nanoseconds. It holds
/// either an instant, such as [`crate::SuppressVal::last_ns`], or the time elapsed since
/// one. The elapsed time comes from [`wrapping_sub`](Nanos::wrapping_sub), so the
/// arithmetic stays defined across the practically unreachable wrap of the since-boot
/// counter.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Nanos(pub u64);

impl Nanos {
    /// Returns the time elapsed from `earlier` to `self`. A counter wrap between the two
    /// yields a small, defined gap instead of a panic.
    pub const fn wrapping_sub(self, earlier: Nanos) -> Nanos {
        Nanos(self.0.wrapping_sub(earlier.0))
    }
}

/// One generation of the double-buffered rule table (ADR 0010). The kernel reads the
/// live one from [`Settings::active_bank`](crate::Settings::active_bank). A
/// `cordon policy apply` fills the other bank and [`flip`](Bank::flip)s to it in one
/// `SETTINGS` write (the daemon's `Maps::seed`). Only `active_bank` changes in that record
/// after startup, so a flip moves just these 4 bytes, which cannot tear, and the kernel
/// never sees a half-filled table.
///
/// Only `0` and `1` are valid. It is a `repr(transparent)` integer rather than an enum
/// because it is read out of map memory, where every bit pattern must be a sound value.
/// [`masked`](Bank::masked) says what a garbage read does.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Bank(pub u32);

// `index` masks with `& 1` and `flip` toggles with `^ 1`, so both assume two banks.
const _: () = assert!(crate::NUM_BANKS == 2);

impl Bank {
    /// The bank that a zero-initialized `SETTINGS` reads as, so the first apply fills bank
    /// `1`.
    pub const ZERO: Bank = Bank(0);

    /// Returns the other generation.
    pub const fn flip(self) -> Bank {
        Bank(self.index() ^ 1)
    }

    /// Returns the bank as an array index, masked to `0` or `1`. A stray value read from
    /// map memory therefore cannot push a [`BankedObj::rule_slot`](crate::BankedObj::rule_slot)
    /// index out of range.
    pub const fn index(self) -> u32 {
        self.0 & 1
    }

    /// Returns this bank normalized to `0` or `1`. When the kernel keys the banked maps
    /// with a garbage `active_bank` read, it finds an empty bucket and allows the access,
    /// instead of making a wild lookup.
    pub const fn masked(self) -> Bank {
        Bank(self.index())
    }
}

// ---- userspace only, for use as aya map keys and values --------------------

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: each is a `repr(transparent)` wrapper over an integer, so every bit pattern
    // is valid, and each is `Copy`. That is aya's `Pod` contract.
    unsafe impl aya::Pod for Dev {}
    unsafe impl aya::Pod for Ino {}
    unsafe impl aya::Pod for Pid {}
    unsafe impl aya::Pod for Uid {}
    unsafe impl aya::Pod for CgroupId {}
    unsafe impl aya::Pod for Suppressed {}
    unsafe impl aya::Pod for Nanos {}
    unsafe impl aya::Pod for Bank {}
}
