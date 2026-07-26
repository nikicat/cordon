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

/// A **real** user id — always kernel-attested, never client-asserted. Two capture
/// sites, one type: the eBPF program reads `bpf_get_current_uid_gid()` (low 32 bits) into
/// [`crate::DecisionEvent`], so the daemon can name the user on the audit line and
/// collapse a path under that user's home to `~`; the IPC server reads `SO_PEERCRED` to
/// authorize a request. `u32` to match the kernel/passwd width. `Ord` so a uid can be
/// range-checked against the regular-account window (`cordon_core`'s `REGULAR_UID_RANGE`).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Uid(pub u32);

/// Render the bare number — for the journal's `user=` fallback when passwd has no name for
/// the uid, and for the `owner=` field on a minted blessing (recorded through `Display` via
/// the `%` sigil — see [`SuppressedTotal`]'s note on `tracing`'s sealed `Value`). Having it
/// is what keeps callers from reaching past the newtype with `.0` just to log one.
impl core::fmt::Display for Uid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A cgroup-v2 id, as returned by `bpf_get_current_cgroup_id()` — the kernel-assigned,
/// per-directory unique handle for a cgroup. The `cgroup` subject predicate
/// ([`crate::SubjectMatch::cgroup`], M2) matches it directly, and it is the key of
/// [`crate::policy_maps::MAP_BLESSED`] (`cgroup → ClassId`, DESIGN §16.3): a
/// **per-invocation** blessed cgroup's id resolves to the [`ClassId`](crate::ClassId) it
/// was minted with. `u64` to match the helper's width; a newtype so it can't be confused
/// with an [`Ino`]/[`Nanos`]/raw count.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CgroupId(pub u64);

/// How many identical opens the in-kernel suppressor folded into one emit since the last
/// ring record for a `(exe, leaf, action)` key (M1 §1g): `0` on a first occurrence,
/// nonzero when a repeat burst was collapsed. Carried on the wire in
/// [`crate::DecisionEvent`] and held in [`crate::SuppressVal`] so the daemon can surface
/// the *true* volume a single line stands for. `u32` to match the per-key kernel counter;
/// the daemon widens to `u64` only when summing many of these across a drain batch.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Suppressed(pub u32);

/// The daemon's running total of folded opens across one drain batch: it sums one wire
/// [`Suppressed`] per coalesced `(exe, leaf, action)` key. A single per-window count fits
/// `u32` ([`Suppressed`]); their *sum* over a whole batch wants the headroom, so the total
/// is its own `u64` type — the two are different quantities, not one widened. Userspace
/// only (never on the wire), but it lives here with [`Suppressed`] so the suppressor's
/// counters stay documented together.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SuppressedTotal(pub u64);

/// Seed a total from a single wire count — a lossless widen, so a typed `From` rather than
/// an `as` cast.
impl From<Suppressed> for SuppressedTotal {
    fn from(s: Suppressed) -> SuppressedTotal {
        SuppressedTotal(u64::from(s.0))
    }
}

/// Fold another wire count into the running total.
impl core::ops::AddAssign<Suppressed> for SuppressedTotal {
    fn add_assign(&mut self, s: Suppressed) {
        self.0 += u64::from(s.0);
    }
}

/// The scalar total — for summing into an [`Opens`] count without reaching for `.0`.
impl From<SuppressedTotal> for u64 {
    fn from(t: SuppressedTotal) -> u64 {
        t.0
    }
}

/// Render the bare number for the journal's `suppressed=` field (`tracing`'s `Value` is
/// sealed, so a typed field is recorded through `Display` via the `%` sigil).
impl core::fmt::Display for SuppressedTotal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The total opens a single coalesced journal record stands for: the opens that *surfaced*
/// as ring records (`events`) plus the [`SuppressedTotal`] the in-kernel suppressor held
/// back. Its own type because it's a **superset** of the suppressed count, not the same
/// quantity — calling it a `SuppressedTotal` would claim every open was suppressed.
/// Userspace only, alongside the other suppressor counters.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Opens(pub u64);

/// Render the bare number for the journal's `count=` field (recorded through `Display` via
/// the `%` sigil — see [`SuppressedTotal`]'s note on `tracing`'s sealed `Value`).
impl core::fmt::Display for Opens {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A monotonic nanosecond reading of the kernel's `bpf_ktime_get_ns()` clock — both an
/// instant (the suppressor's last-emit time, [`crate::SuppressVal::last_ns`]) and the
/// elapsed-since it's compared against. `Ord` for the window check; the elapsed gap is
/// [`wrapping_sub`](Nanos::wrapping_sub) so the math stays defined across the (practically
/// unreachable) wrap of a since-boot counter.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Nanos(pub u64);

impl Nanos {
    /// Nanoseconds elapsed from `earlier` to `self`, wrapping (so a counter wrap yields a
    /// defined small gap rather than a panic/UB).
    pub const fn wrapping_sub(self, earlier: Nanos) -> Nanos {
        Nanos(self.0.wrapping_sub(earlier.0))
    }
}

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
    unsafe impl aya::Pod for Uid {}
    unsafe impl aya::Pod for CgroupId {}
    unsafe impl aya::Pod for Suppressed {}
    unsafe impl aya::Pod for Nanos {}
    unsafe impl aya::Pod for Decision {}
    unsafe impl aya::Pod for Bank {}
}
