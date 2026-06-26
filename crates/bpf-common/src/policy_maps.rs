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
//! This module is the contract for that binary form. It supersedes the v1 owner
//! schema in [`crate::maps`] (`SUBTREES`/`OWNER_IDS`), which the eBPF program and
//! loader still use until the rule-model backend lands; the two coexist during the
//! migration.

use crate::ids::{Dev, Ino};
use crate::maps::FileId;
use bitflags::bitflags;

// ---- map names ------------------------------------------------------------
// The eBPF program defines these maps; the loader resolves them by name. Constants
// so a rename can't silently desync the two crates.

/// `HashMap<FileId, ObjId>` — every protected object's `(dev,ino)` → its object id.
/// The deepest match in the dentry ancestor walk is the most-specific object.
pub const MAP_PROTECTED: &str = "PROTECTED";
/// The packed per-object rule table: object `o`'s rules occupy the contiguous slot
/// `[o * MAX_RULES_PER_OBJ .. o * MAX_RULES_PER_OBJ + RULE_COUNT[o]]`. A single base
/// + index scan (cache-friendly) rather than a per-rule hash lookup.
pub const MAP_RULES: &str = "RULES";
/// `HashMap<ObjId, u32>` — how many rules object `o` actually has in [`MAP_RULES`]
/// (its slot is otherwise zero-padded to `MAX_RULES_PER_OBJ`).
pub const MAP_RULE_COUNT: &str = "RULE_COUNT";

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

/// A protected object's id — a dense `u32` index assigned by the compiler, used to
/// address the object's slot in [`MAP_RULES`]/[`MAP_RULE_COUNT`]. Distinct from
/// [`FileId`]: the `(dev,ino)` is the *kernel's* key into [`MAP_PROTECTED`], the
/// `ObjId` is the *compiler's* dense handle for the rule table.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ObjId(pub u32);

bitflags! {
    /// The set of actions a rule covers, as a bitset — one bit per LSM-mediated
    /// operation (DESIGN §15.5). A rule carries a *mask* (not one action) so e.g.
    /// `action = ["read","write"]` is a single [`CompiledRule`]; the kernel matches
    /// when the requested action's bit is set (`intersects`). M1 enforces only
    /// `READ`/`WRITE`/`CREATE` (all derivable at `file_open` from `f_mode`/`f_flags`);
    /// the rest compile but don't fire until their hooks land (M3).
    ///
    /// `#[repr(transparent)]` is load-bearing: it's read byte-for-byte out of the
    /// `RULES` map inside [`CompiledRule`] (`repr(C)`), so the ABI must be exactly the
    /// inner `u32`. bitflags' public type is `repr(Rust)` by default — this attribute
    /// makes it transparent over the (also-transparent) internal `u32`, and bitflags
    /// 2.x permits unknown bits, so every bit pattern is valid → the `aya::Pod` impl
    /// below is sound.
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
    }
}

/// The canonical human form: `read|write|create|…` (or `none`). The lower-case names
/// match the policy authoring vocabulary. `no_std`: `core::fmt`, no allocation.
impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        const NAMED: [(Action, &str); 9] = [
            (Action::READ, "read"),
            (Action::WRITE, "write"),
            (Action::CREATE, "create"),
            (Action::EXECUTE, "execute"),
            (Action::LISTDIR, "listdir"),
            (Action::UNLINK, "unlink"),
            (Action::MKDIR, "mkdir"),
            (Action::RMDIR, "rmdir"),
            (Action::RENAME, "rename"),
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

/// A rule's effect = `{allow, deny} × {log, silent}` (DESIGN §15.2). The global
/// `permissive` mode (in `Settings`) downgrades every denying policy to a logged
/// allow at decision time — orthogonal to the value stored here, which is always the
/// policy *as authored*.
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

    /// Whether this policy blocks the access (`DENY` or `SILENCE`).
    pub const fn denies(self) -> bool {
        matches!(self.0, 2 | 3)
    }
    /// Whether a decision under this policy emits a learn record (`AUDIT` or `DENY`)
    /// rather than staying silent (`ALLOW` or `SILENCE`).
    pub const fn logs(self) -> bool {
        matches!(self.0, 1 | 2)
    }
}

/// A subject predicate: a conjunction of cheap-to-check fields the kernel ANDs
/// against the caller (DESIGN §15.4). `flags` marks which fields are wildcards
/// (`who = "*"` sets all three) — a wildcard field is skipped, never compared. M1
/// fills only `exe`; `uid`/`cgroup` are reserved (always wildcard) until M2.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SubjectMatch {
    /// The caller's executable identity `(dev,ino)`. Compared unless `FLAG_EXE_ANY`.
    pub exe: FileId,
    /// The caller's cgroup id. Compared unless `FLAG_CGROUP_ANY` (M2).
    pub cgroup: u64,
    /// The caller's uid. Compared unless `FLAG_UID_ANY` (M2).
    pub uid: u32,
    /// Which predicates are wildcards (skip the compare).
    pub flags: u32,
}

impl SubjectMatch {
    pub const FLAG_EXE_ANY: u32 = 1 << 0;
    pub const FLAG_UID_ANY: u32 = 1 << 1;
    pub const FLAG_CGROUP_ANY: u32 = 1 << 2;

    /// Matches any caller (`who = "*"`): every predicate is a wildcard.
    pub const ANY: SubjectMatch = SubjectMatch {
        exe: FileId::new(Dev(0), Ino(0)),
        cgroup: 0,
        uid: 0,
        flags: Self::FLAG_EXE_ANY | Self::FLAG_UID_ANY | Self::FLAG_CGROUP_ANY,
    };

    /// A subject that matches exactly one executable (by `(dev,ino)`), any uid/cgroup.
    pub const fn exe(exe: FileId) -> SubjectMatch {
        SubjectMatch {
            exe,
            cgroup: 0,
            uid: 0,
            flags: Self::FLAG_UID_ANY | Self::FLAG_CGROUP_ANY,
        }
    }
}

/// One pre-resolved rule in an object's bucket: a subject predicate, the actions it
/// covers, and the effect. The compiler sorts each bucket most-specific-object-first
/// then `deny > allow`, so the kernel applies the **first** rule whose action and
/// subject match. `_pad` keeps the layout deterministic (no uninitialized bytes) when
/// the loader memcpys these into the packed [`MAP_RULES`] array.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompiledRule {
    pub subject: SubjectMatch,
    pub action_mask: Action,
    pub policy: Policy,
    pub _pad: [u8; 3],
}

impl CompiledRule {
    pub const fn new(subject: SubjectMatch, action_mask: Action, policy: Policy) -> CompiledRule {
        CompiledRule {
            subject,
            action_mask,
            policy,
            _pad: [0; 3],
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
    // the existing `Mode`/`Decision`; that's a memory-safety statement, not a claim
    // every value is semantically meaningful.)
    unsafe impl aya::Pod for ObjId {}
    unsafe impl aya::Pod for Action {}
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
        assert!(Action::empty().is_empty());
        // `*` (all defined actions) is exactly the nine bits, no more.
        assert_eq!(Action::all().bits(), 0b1_1111_1111);
    }

    #[test]
    fn policy_semantics() {
        assert!(!Policy::ALLOW.denies() && !Policy::ALLOW.logs());
        assert!(!Policy::AUDIT.denies() && Policy::AUDIT.logs());
        assert!(Policy::DENY.denies() && Policy::DENY.logs());
        assert!(Policy::SILENCE.denies() && !Policy::SILENCE.logs());
    }

    #[test]
    fn subject_wildcards() {
        assert_eq!(
            SubjectMatch::ANY.flags & SubjectMatch::FLAG_EXE_ANY,
            SubjectMatch::FLAG_EXE_ANY
        );
        let s = SubjectMatch::exe(FileId::new(Dev(7), Ino(9)));
        assert_eq!(s.flags & SubjectMatch::FLAG_EXE_ANY, 0); // exe is matched, not wildcard
        assert_eq!(s.exe, FileId::new(Dev(7), Ino(9)));
    }

    #[test]
    fn compiled_rule_layout_is_padded() {
        // 32 (SubjectMatch) + 4 (Action) + 1 (Policy) + 3 (pad) = 40, 8-aligned.
        assert_eq!(core::mem::size_of::<SubjectMatch>(), 32);
        assert_eq!(core::mem::size_of::<CompiledRule>(), 40);
        assert_eq!(core::mem::align_of::<CompiledRule>(), 8);
    }
}
