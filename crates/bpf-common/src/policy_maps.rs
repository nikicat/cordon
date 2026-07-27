//! The flat **rule model** schema (DESIGN §15) — the compiled, pre-resolved
//! decision table both sides agree on, byte-for-byte.
//!
//! The userspace compiler (`cordon_core::policy::compile`) lowers an expressive
//! text policy — groups, nesting, object precedence — into this dumb form: a set of
//! protected objects, each with a flat, **pre-sorted** list of [`CompiledRule`]s.
//! Object precedence and inheritance are resolved *there* (copy-down), so the eBPF
//! program only ever does: most-specific protected object → **first matching** rule
//! in its one bucket (DESIGN §15.3 — "expressive source, dumb-fast binary form").
//!
//! This module is the contract for that binary form — and the only enforcement schema
//! now that the v1 owner model (`SUBTREES`/`OWNER_IDS`) has been retired. The three
//! rule maps are **double-buffered** (see the map-name section): each holds two
//! generations, and `Settings.active_bank` picks the live one, so `cordon policy apply`
//! publishes a whole new table with one atomic flip (DESIGN §15.8).

use crate::ids::{Bank, CgroupId, Dev, Ino, Uid};
use crate::maps::FileId;
use bitflags::bitflags;

// ---- map names ------------------------------------------------------------
// The eBPF program defines these maps; the loader resolves them by name. Constants
// so a rename can't silently desync the two crates.
//
// ## Double-buffer (atomic apply)
// All three rule maps are **banked**: each holds two independent generations (banks
// `0` and `1`), and `Settings.active_bank` selects which the kernel reads. A
// `cordon policy apply` fills the *inactive* bank, then flips `active_bank` in one
// atomic `SETTINGS` write — an RCU-style generation flip (DESIGN §15.8). The kernel
// reads the active bank only; the inactive one is the next apply's scratch space, so
// a re-seed is never half-visible (no clear-then-insert window).

/// `HashMap<BankedFile, ObjId>` — every protected object's `(bank, dev, ino)` → its
/// object id. The deepest match in the dentry ancestor walk (keyed with the active
/// bank) is the most-specific object.
pub const MAP_PROTECTED: &str = "PROTECTED";
/// The packed per-(bank,object) rule table: bank `b`, object `o`'s rules occupy the
/// contiguous slot at [`rule_slot`]`(b, o, 0..RULE_COUNT[(b,o)])`. A single base +
/// index scan (cache-friendly) rather than a per-rule hash lookup.
pub const MAP_RULES: &str = "RULES";
/// `HashMap<BankedObj, u32>` — how many rules bank `b`, object `o` actually has in
/// [`MAP_RULES`] (its slot is otherwise zero-padded to `MAX_RULES_PER_OBJ`).
pub const MAP_RULE_COUNT: &str = "RULE_COUNT";

/// `HashMap<u64 /*cgroup_id*/, ClassId>` — the runtime **blessing** indirection
/// (DESIGN §16.3): a live blessed cgroup's id → the [`ClassId`] it was minted with. The
/// kernel resolves the caller's class once per decision (`BLESSED[current_cgroup_id]`,
/// or [`ClassId::UNBLESSED`] when absent) and a rule's `blessing` predicate matches that.
///
/// **Not banked** (unlike the three rule maps): it is per-`cordon bless` runtime state,
/// single-writer (the daemon's backend thread writes at mint, clears at GC), so a bless
/// never recompiles policy and a `policy apply` never disturbs a live bless. Also **not
/// pinned** (M5): a pinned `BLESSED` with a dead daemon = grants that never expire — it
/// fails closed on daemon death and is rebuilt by startup reconciliation (PLAN-bless B1d).
pub const MAP_BLESSED: &str = "BLESSED";

/// The number of rule-table generations the maps hold for the atomic double-buffer
/// swap. Two: one active (the kernel reads it), one inactive (an apply fills it, then
/// flips). Sizes the banked [`MAP_RULES`] array and the `bank` dimension of every key.
pub const NUM_BANKS: usize = 2;

/// Per-object rule-list cap. Bounds the kernel's first-match scan and the verifier
/// loop, and fixes the [`MAP_RULES`] slot stride. Copy-down can lengthen a bucket
/// (a deep object inherits every ancestor's rules), so this is the ceiling the
/// compiler enforces — `cordon policy check` errors if a compiled bucket exceeds it.
/// Start at 32; raise toward 64 if the verifier log demands (DESIGN §15, M1 #1).
pub const MAX_RULES_PER_OBJ: usize = 32;

/// Maximum number of protected objects (distinct `where` targets). Sizes the packed
/// [`MAP_RULES`] array (`MAX_OBJECTS * MAX_RULES_PER_OBJ` slots) and bounds the dense
/// [`ObjId`] space; the daemon rejects a compiled policy with more objects than this.
pub const MAX_OBJECTS: usize = 1024;

/// Maximum number of live blessings ([`MAP_BLESSED`] entries) at once — one per active
/// `cordon bless` invocation. On a personal box concurrent blessings are few; the daemon
/// refuses a new mint past this. (Distinct from the policy-class *count*: many invocations
/// can share one [`ClassId`].)
pub const MAX_BLESSED: usize = 1024;

/// A protected object's id — a dense `u32` index assigned by the compiler, used to
/// address the object's slot in [`MAP_RULES`]/[`MAP_RULE_COUNT`]. Distinct from
/// [`FileId`]: the `(dev,ino)` is the *kernel's* key into [`MAP_PROTECTED`], the
/// `ObjId` is the *compiler's* dense handle for the rule table.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ObjId(pub u32);

/// A **blessing class** id — a dense `u32` the compiler assigns to each named blessing
/// class declared in policy (`[group.subject.*] blessing = "<name>"`, DESIGN §16.3), and
/// the value stored in [`MAP_BLESSED`] for a live blessed cgroup. A rule's
/// [`SubjectMatch::blessing`] names the class it requires; the kernel matches it against
/// the caller's resolved class.
///
/// [`UNBLESSED`](ClassId::UNBLESSED) (`0`) is the sentinel a process in *no* blessed
/// cgroup resolves to. The compiler never assigns it to a named class, so no concrete
/// `blessing` predicate ever equals it — an unblessed caller matches only blessing-wildcard
/// rules ([`SubjectFlags::BLESSING_ANY`]).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ClassId(pub u32);

impl ClassId {
    /// The "not in any blessed cgroup" sentinel (`0`). What `BLESSED.get(cgroup)` resolving
    /// to nothing means, and never a class the compiler assigns — so a concrete `blessing`
    /// predicate can't accidentally match an unblessed caller.
    pub const UNBLESSED: ClassId = ClassId(0);
}

/// The raw class id, for the journal's `blessing=` field (the daemon resolves it back to
/// the policy name; `0`/[`UNBLESSED`](ClassId::UNBLESSED) renders as no class). `no_std`.
impl core::fmt::Display for ClassId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

padded_pod! {
    /// A [`MAP_PROTECTED`] key: a protected object's inode identity within one bank. The
    /// trailing `_pad` is **load-bearing**: `FileId` is 8-aligned, so [`Bank`] (a `u32`)
    /// at offset 16 would leave 4 trailing *implicit* padding bytes — and a BPF `HashMap`
    /// hashes the whole key, padding included (uninitialized padding → mismatched lookups).
    /// `padded_pod!` makes the gap an explicit, always-zeroed field (and asserts no interior
    /// gap), keeping the 24-byte key padding-free.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct BankedFile {
        pub file: FileId,
        pub bank: Bank,
    }
}

impl BankedFile {
    pub const fn new(bank: Bank, file: FileId) -> Self {
        BankedFile {
            file,
            bank,
            _pad: [0; Self::PAD],
        }
    }
}

/// A [`MAP_RULE_COUNT`] key: an object id within one bank. `ObjId` + [`Bank`]
/// (`u32 + u32`) is naturally padding-free.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BankedObj {
    pub obj: ObjId,
    pub bank: Bank,
}

impl BankedObj {
    pub const fn new(bank: Bank, obj: ObjId) -> Self {
        BankedObj { obj, bank }
    }
}

/// The flat index of bank `bank`, object `obj`'s rule `i` in the banked [`MAP_RULES`]
/// array (sized `NUM_BANKS * MAX_OBJECTS * MAX_RULES_PER_OBJ`). The **one** definition
/// both sides use — the kernel to scan, the loader to fill — so the stride can't
/// desync. [`Bank::index`] masks the bank to `0`/`1` and `wrapping_*` keeps the math
/// total, so valid inputs (`obj < MAX_OBJECTS`, `i < MAX_RULES_PER_OBJ`) stay in range
/// (and `Array::get` bounds-checks regardless).
pub const fn rule_slot(bank: Bank, obj: ObjId, i: u32) -> u32 {
    (bank.index().wrapping_mul(MAX_OBJECTS as u32))
        .wrapping_add(obj.0)
        .wrapping_mul(MAX_RULES_PER_OBJ as u32)
        .wrapping_add(i)
}

bitflags! {
    /// The set of actions a rule covers, as a bitset — one bit per LSM-mediated
    /// operation (DESIGN §15.5). A rule carries a *mask* (not one action) so e.g.
    /// `action = ["read","write"]` is a single [`CompiledRule`]; the kernel matches
    /// when the requested action's bit is set (`intersects`). `READ`/`WRITE`/`CREATE`
    /// are derivable at `file_open` from `f_mode`/`f_flags`; `LINK`/`RENAME`/`UNLINK`/
    /// `RMDIR`/`MKDIR` fire at the mutation hooks and `EXECUTE` at `bprm_check_security`
    /// (§15.5). `LISTDIR` still compiles but doesn't fire — its hook hasn't landed.
    ///
    /// `#[repr(transparent)]` is load-bearing: it's read byte-for-byte out of the
    /// `RULES` map inside [`CompiledRule`] (`repr(C)`), so the ABI must be exactly the
    /// inner `u32`. bitflags' public type is `repr(Rust)` by default — this attribute
    /// makes it transparent over the (also-transparent) internal `u32`, and bitflags
    /// 2.x permits unknown bits, so every bit pattern is valid → the `aya::Pod` impl
    /// below is sound.
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct Action: u32 {
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const CREATE  = 1 << 2;
        const EXECUTE = 1 << 3;
        const LISTDIR = 1 << 4;
        const UNLINK  = 1 << 5;
        const MKDIR   = 1 << 6;
        const RMDIR   = 1 << 7;
        const RENAME  = 1 << 8;
        const LINK    = 1 << 9;
    }
}

/// The canonical human form: `read|write|create|…` (or `none`). The lower-case names
/// match the policy authoring vocabulary. `no_std`: `core::fmt`, no allocation.
impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        const NAMED: [(Action, &str); 10] = [
            (Action::READ, "read"),
            (Action::WRITE, "write"),
            (Action::CREATE, "create"),
            (Action::EXECUTE, "execute"),
            (Action::LISTDIR, "listdir"),
            (Action::UNLINK, "unlink"),
            (Action::MKDIR, "mkdir"),
            (Action::RMDIR, "rmdir"),
            (Action::RENAME, "rename"),
            (Action::LINK, "link"),
        ];
        if self.is_empty() {
            return write!(f, "none");
        }
        let mut first = true;
        for (bit, name) in NAMED {
            if self.contains(bit) {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
        }
        Ok(())
    }
}

/// A rule's effect = `{allow, deny} × {log, silent}` (DESIGN §15.2). This per-rule
/// policy is the *only* enforcement level — there is no global mode (§15.6): the kernel
/// blocks iff [`denies`](Policy::denies), so `audit` observes an object and `deny`
/// enforces it, per object.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy(pub u8);

impl Policy {
    /// Allow, don't log.
    pub const ALLOW: Policy = Policy(0);
    /// Allow, but log the access (preview a would-be rule's reach).
    pub const AUDIT: Policy = Policy(1);
    /// Deny, and log it.
    pub const DENY: Policy = Policy(2);
    /// Deny, silently (no learn record).
    pub const SILENCE: Policy = Policy(3);
    /// Synthetic effect the kernel applies when **no rule matched** (the default-deny,
    /// DESIGN §15.6.3). Never authored or stored in a [`CompiledRule`] — it exists only as
    /// the *cause* carried on a [`crate::DecisionEvent`], so the journal can tell a
    /// default-deny ("you have no rule for this") apart from an explicit `deny` rule ("you
    /// chose to block this"). Blocks + logs exactly like [`DENY`](Policy::DENY).
    pub const DEFAULT_DENY: Policy = Policy(4);
    /// Synthetic effect the kernel applies when a protected inode would acquire a name
    /// **outside its object** — a hardlink or rename out (DESIGN §15.5). Like
    /// [`DEFAULT_DENY`](Policy::DEFAULT_DENY) it is never authored or stored in a
    /// [`CompiledRule`]; unlike every other cause it comes from no rule *at all*, because
    /// the escape is refused unconditionally: a second name in an unprotected directory
    /// makes the inode readable by every subject, permanently, and silently (the ancestor
    /// walk stops finding the object, so nothing is ever logged again). A distinct cause
    /// so the journal reads "this was structurally refused", not "a rule of yours blocked
    /// it" — the two want very different fixes.
    pub const ESCAPE_DENY: Policy = Policy(5);

    /// Whether this policy blocks the access (the `deny` half of `{allow,deny}×{log,silent}`).
    pub const fn denies(self) -> bool {
        matches!(
            self,
            Policy::DENY | Policy::SILENCE | Policy::DEFAULT_DENY | Policy::ESCAPE_DENY
        )
    }
    /// Whether a decision under this policy emits a record (the `log` half) rather than
    /// staying silent.
    pub const fn logs(self) -> bool {
        matches!(
            self,
            Policy::AUDIT | Policy::DENY | Policy::DEFAULT_DENY | Policy::ESCAPE_DENY
        )
    }
}

/// The canonical human form (`allow`/`audit`/`deny`/`silence`/`default-deny`) — the policy
/// authoring vocabulary plus the synthetic default-deny cause. `no_std`: `core::fmt`.
impl core::fmt::Display for Policy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Policy::ALLOW => "allow",
            Policy::AUDIT => "audit",
            Policy::DENY => "deny",
            Policy::SILENCE => "silence",
            Policy::DEFAULT_DENY => "default-deny",
            Policy::ESCAPE_DENY => "escape-deny",
            _ => "unknown",
        })
    }
}

bitflags! {
    /// Which subject predicates are **wildcards** — a set bit means "match any, skip the
    /// compare." `who = "*"` sets all of them; a concrete predicate *clears* its bit. The
    /// kernel ANDs only the non-wildcard predicates (DESIGN §15.4 + the §16.3 `blessing`),
    /// and the compiler counts the *cleared* bits as the rule's subject specificity (§15.6),
    /// so a 5th predicate bit extends both for free.
    ///
    /// `#[repr(transparent)]` over `u32` (same rationale as [`Action`]): it's read
    /// byte-for-byte out of `RULES` inside [`CompiledRule`], and bitflags 2.x admits unknown
    /// bits so every pattern is valid → the `aya::Pod` impl below is sound.
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct SubjectFlags: u32 {
        /// `exe` is a wildcard (M1 default for `who = "*"`).
        const EXE_ANY      = 1 << 0;
        /// `uid` is a wildcard (always, until M2).
        const UID_ANY      = 1 << 1;
        /// `cgroup` is a wildcard (always, until M2).
        const CGROUP_ANY   = 1 << 2;
        /// `blessing` is a wildcard (the default; cleared only by a blessing rule, B1).
        const BLESSING_ANY = 1 << 3;
    }
}

padded_pod! {
    /// A subject predicate: a conjunction of cheap-to-check fields the kernel ANDs
    /// against the caller (DESIGN §15.4 + the §16.3 `blessing` predicate).
    /// [`flags`](Self::flags) ([`SubjectFlags`]) marks which fields are wildcards. M1 fills
    /// only `exe`; `uid`/`cgroup` are reserved (always wildcard) until M2; `blessing` is set
    /// only by a rule referencing a blessing class (PLAN-bless B1), wildcard otherwise. It is
    /// a map *value* (it rides inside [`CompiledRule`]), so its `_pad` is for initialization
    /// soundness, not key hashing — see the [`padded_pod!`]/`layout` module docs.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct SubjectMatch {
        /// The caller's executable identity `(dev,ino)`. Compared unless [`SubjectFlags::EXE_ANY`].
        pub exe: FileId,
        /// The caller's cgroup id. Compared unless [`SubjectFlags::CGROUP_ANY`] (M2).
        pub cgroup: CgroupId,
        /// The caller's uid. Compared unless [`SubjectFlags::UID_ANY`] (M2).
        pub uid: Uid,
        /// The blessing class this rule requires (DESIGN §16.3). Compared against the caller's
        /// resolved class (`BLESSED[cgroup]`, or [`ClassId::UNBLESSED`]) unless
        /// [`SubjectFlags::BLESSING_ANY`].
        pub blessing: ClassId,
        /// Which predicates are wildcards (skip the compare).
        pub flags: SubjectFlags,
    }
}

impl SubjectMatch {
    /// Matches any caller (`who = "*"`): every predicate is a wildcard — including
    /// `blessing`, so a `*` catch-all matches blessed and unblessed callers alike.
    pub const ANY: SubjectMatch = SubjectMatch {
        exe: FileId::new(Dev(0), Ino(0)),
        cgroup: CgroupId(0),
        uid: Uid(0),
        blessing: ClassId::UNBLESSED,
        flags: SubjectFlags::all(),
        _pad: [0; Self::PAD],
    };

    /// A subject that matches exactly one executable (by `(dev,ino)`), any uid/cgroup/blessing.
    pub const fn exe(exe: FileId) -> SubjectMatch {
        SubjectMatch {
            exe,
            cgroup: CgroupId(0),
            uid: Uid(0),
            blessing: ClassId::UNBLESSED,
            // Everything wildcard except the concrete `exe`.
            flags: SubjectFlags::all().difference(SubjectFlags::EXE_ANY),
            _pad: [0; Self::PAD],
        }
    }

    /// A subject that matches any caller in blessing class `class` (DESIGN §16.3) — the
    /// `@blessed-*` predicate: exe/uid/cgroup wildcard, `blessing` concrete. Composes with
    /// [`exe`](Self::exe) under conjunction in the compiler (PLAN-bless B1c).
    pub const fn blessed(class: ClassId) -> SubjectMatch {
        SubjectMatch {
            exe: FileId::new(Dev(0), Ino(0)),
            cgroup: CgroupId(0),
            uid: Uid(0),
            blessing: class,
            // Everything wildcard except the concrete `blessing`.
            flags: SubjectFlags::all().difference(SubjectFlags::BLESSING_ANY),
            _pad: [0; Self::PAD],
        }
    }
}

padded_pod! {
    /// One pre-resolved rule in an object's bucket: a subject predicate, the actions it
    /// covers, and the effect. The compiler sorts each bucket most-specific-object-first
    /// then `deny > allow`, so the kernel applies the **first** rule whose action and
    /// subject match. The `padded_pod!` `_pad` keeps the layout deterministic (no
    /// uninitialized bytes) when the loader memcpys these into the packed [`MAP_RULES`] array.
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct CompiledRule {
        pub subject: SubjectMatch,
        pub action_mask: Action,
        pub policy: Policy,
    }
}

impl CompiledRule {
    pub const fn new(subject: SubjectMatch, action_mask: Action, policy: Policy) -> CompiledRule {
        CompiledRule {
            subject,
            action_mask,
            policy,
            _pad: [0; Self::PAD],
        }
    }
}

// ---- userspace-only: mark the POD types usable as aya map keys/values -----

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: each is `repr(transparent)`/`repr(C)` over POD integer fields, so every
    // bit pattern is valid and the type is `Copy` with a fixed layout — aya's `Pod`
    // contract. (`Policy`/`Action` accept out-of-range discriminants in memory, like
    // `Decision`; that's a memory-safety statement, not a claim every value is
    // semantically meaningful.)
    unsafe impl aya::Pod for ObjId {}
    unsafe impl aya::Pod for ClassId {}
    unsafe impl aya::Pod for BankedFile {}
    unsafe impl aya::Pod for BankedObj {}
    unsafe impl aya::Pod for Action {}
    unsafe impl aya::Pod for SubjectFlags {}
    unsafe impl aya::Pod for Policy {}
    unsafe impl aya::Pod for SubjectMatch {}
    unsafe impl aya::Pod for CompiledRule {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_set_algebra() {
        let rw = Action::READ | Action::WRITE;
        assert!(rw.contains(Action::READ));
        assert!(rw.contains(Action::WRITE));
        assert!(!rw.contains(Action::CREATE));
        assert!(rw.intersects(Action::READ));
        assert!(!rw.intersects(Action::CREATE));
        assert!(Action::all().contains(rw));
        assert!(Action::all().contains(Action::RENAME));
        assert!(Action::all().contains(Action::LINK));
        assert!(Action::empty().is_empty());
        // `*` (all defined actions) is exactly the ten bits, no more.
        assert_eq!(Action::all().bits(), 0b11_1111_1111);
    }

    #[test]
    fn policy_semantics() {
        assert!(!Policy::ALLOW.denies() && !Policy::ALLOW.logs());
        assert!(!Policy::AUDIT.denies() && Policy::AUDIT.logs());
        assert!(Policy::DENY.denies() && Policy::DENY.logs());
        assert!(Policy::SILENCE.denies() && !Policy::SILENCE.logs());
        // The synthetic default-deny blocks and logs, like DENY.
        assert!(Policy::DEFAULT_DENY.denies() && Policy::DEFAULT_DENY.logs());
    }

    #[test]
    fn subject_wildcards() {
        // `*` is wildcard on every predicate, including blessing.
        assert!(SubjectMatch::ANY.flags.contains(SubjectFlags::EXE_ANY));
        assert!(SubjectMatch::ANY.flags.contains(SubjectFlags::BLESSING_ANY));

        // A concrete exe clears EXE_ANY but stays blessing-wildcard (an exe rule is
        // unconcerned with blessing) and unblessed-sentinel.
        let s = SubjectMatch::exe(FileId::new(Dev(7), Ino(9)));
        assert!(!s.flags.contains(SubjectFlags::EXE_ANY)); // exe is matched, not wildcard
        assert!(s.flags.contains(SubjectFlags::BLESSING_ANY));
        assert_eq!(s.exe, FileId::new(Dev(7), Ino(9)));
        assert_eq!(s.blessing, ClassId::UNBLESSED);

        // A blessing rule clears BLESSING_ANY and names a concrete class, exe stays wildcard.
        let b = SubjectMatch::blessed(ClassId(3));
        assert!(b.flags.contains(SubjectFlags::EXE_ANY));
        assert!(!b.flags.contains(SubjectFlags::BLESSING_ANY));
        assert_eq!(b.blessing, ClassId(3));
    }

    #[test]
    fn compiled_rule_layout_is_padded() {
        // SubjectMatch: 16 (exe) + 8 (cgroup) + 4 (uid) + 4 (blessing) + 4 (flags) +
        // 4 (pad) = 40, 8-aligned, no implicit padding.
        assert_eq!(core::mem::size_of::<SubjectMatch>(), 40);
        assert_eq!(core::mem::align_of::<SubjectMatch>(), 8);
        // CompiledRule: 40 (SubjectMatch) + 4 (Action) + 1 (Policy) + 3 (pad) = 48, 8-aligned.
        assert_eq!(core::mem::size_of::<CompiledRule>(), 48);
        assert_eq!(core::mem::align_of::<CompiledRule>(), 8);
    }

    #[test]
    fn banked_keys_are_padding_free() {
        // BPF hashes the whole key, padding included — these must have no implicit
        // padding bytes. BankedFile: 16 (FileId) + 4 (Bank) + 4 (explicit pad) = 24.
        assert_eq!(core::mem::size_of::<BankedFile>(), 24);
        assert_eq!(core::mem::align_of::<BankedFile>(), 8);
        // BankedObj: 4 (ObjId) + 4 (Bank) = 8, no padding.
        assert_eq!(core::mem::size_of::<BankedObj>(), 8);
        assert_eq!(core::mem::align_of::<BankedObj>(), 4);
    }

    #[test]
    fn rule_slot_banks_dont_overlap() {
        // Each bank occupies a disjoint MAX_OBJECTS*MAX_RULES_PER_OBJ window, and every
        // valid slot stays inside the NUM_BANKS-sized array.
        let span = (MAX_OBJECTS * MAX_RULES_PER_OBJ) as u32;
        assert_eq!(rule_slot(Bank(0), ObjId(0), 0), 0);
        assert_eq!(rule_slot(Bank(1), ObjId(0), 0), span);
        assert_eq!(
            rule_slot(
                Bank(1),
                ObjId(MAX_OBJECTS as u32 - 1),
                MAX_RULES_PER_OBJ as u32 - 1
            ),
            (NUM_BANKS * MAX_OBJECTS * MAX_RULES_PER_OBJ) as u32 - 1
        );
        // A garbage bank is masked back into range, never out the top of the array.
        assert!(
            rule_slot(Bank(u32::MAX), ObjId(0), 0)
                < (NUM_BANKS * MAX_OBJECTS * MAX_RULES_PER_OBJ) as u32
        );
    }
}
