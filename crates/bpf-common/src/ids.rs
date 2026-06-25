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

/// An owner-group id. Wraps `i64` to match the store's `owners.id` (SQLite
/// `INTEGER` → `i64`) exactly — the kernel only byte-compares it as a map key, so
/// its signedness is irrelevant there and matching the source avoids a cast.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct OwnerId(pub i64);

/// An FNV-1a hash of an executable path — the identity key (see [`crate::hash`]).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ExeHash(pub u64);

/// A process id (thread-group id). Wraps `u32` to match the natural width on both
/// sides — `std::process::id()` and the kernel's `bpf_get_current_pid_tgid() >> 32`
/// — distinct from core's `Pid(i32)`, which mirrors `/proc`/`nix`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Pid(pub u32);

/// Enforcement mode, stored in `Settings`. A `repr(transparent)` `u32` rather than
/// an enum *on purpose*: aya map values must be `Pod` (valid for any bit pattern),
/// which an enum is not — reading a stray discriminant out of map memory would be
/// UB. Named values live as associated consts.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mode(pub u32);

impl Mode {
    /// Block a protected non-owner open in-kernel (`-EPERM`).
    pub const ENFORCE: Mode = Mode(0);
    /// Allow it, but still report the would-be denial on the ring buffer.
    pub const AUDIT: Mode = Mode(1);

    pub fn enforces(self) -> bool {
        self == Mode::ENFORCE
    }
}

/// A mediated decision, stored in `LearnEvent`. Same `repr(transparent)`-not-enum
/// rationale as [`Mode`].
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Decision(pub u32);

impl Decision {
    /// Protected, non-owner, enforce mode → denied.
    pub const DENY: Decision = Decision(0);
    /// Same, but audit mode → allowed; logged as a would-be denial.
    pub const WOULD_DENY: Decision = Decision(1);
}

// ---- userspace-only: usable as aya map keys/values ------------------------

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: each is a `repr(transparent)` wrapper over a `u64`, so every bit
    // pattern is valid and the type is `Copy` — aya's `Pod` contract.
    unsafe impl aya::Pod for Dev {}
    unsafe impl aya::Pod for Ino {}
    unsafe impl aya::Pod for OwnerId {}
    unsafe impl aya::Pod for ExeHash {}
    unsafe impl aya::Pod for Pid {}
    unsafe impl aya::Pod for Mode {}
    unsafe impl aya::Pod for Decision {}
}
