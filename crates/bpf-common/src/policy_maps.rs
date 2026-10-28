//! The schema of the flat rule model (DESIGN §15), the compiled and pre-resolved decision
//! table that both sides read byte for byte.
//!
//! The userspace compiler (`cordon_core::policy::compile`) lowers an expressive text
//! policy, with groups, nesting and object precedence, into this simple form. The form is a
//! set of protected objects, each with a flat, pre-sorted list of [`CompiledRule`]s. The
//! compiler resolves object precedence and inheritance by copying rules down, so the eBPF
//! program only finds the most specific protected object and applies the first matching
//! rule in its one bucket (DESIGN §15.3, "expressive source, dumb-fast binary form").
//!
//! The three rule maps are double-buffered, and each holds [`NUM_BANKS`] generations (see
//! [`Bank`]).

use crate::ids::{Bank, CgroupId, Dev, Ino, Uid};
use crate::maps::FileId;
use bitflags::bitflags;

// ---- map names ------------------------------------------------------------
// The eBPF program defines these maps, and the loader resolves them by name. They are
// constants so that a rename cannot silently desync the two crates. The three rule maps
// are keyed or indexed by `Bank`, and `Settings.active_bank` selects the one the kernel
// reads.

/// The name of the `HashMap<BankedFile, ObjId>` that maps each protected object's bank,
/// device and inode to its object id. The deepest ancestor of a file that it holds under
/// the active bank is the most specific object covering that file.
pub const MAP_PROTECTED: &str = "PROTECTED";
/// The name of the packed rule table for every bank and object. The rules of one
/// [`BankedObj`] fill the contiguous slots from its [`rule_slot`](BankedObj::rule_slot)`(0)`
/// up to its `RULE_COUNT`, so the kernel scans them from one base index, which suits the cache better than a hash
/// lookup per rule.
pub const MAP_RULES: &str = "RULES";
/// The name of the `HashMap<BankedObj, u32>` that holds how many rules object `o` in bank
/// `b` has in [`MAP_RULES`]. The rest of that object's slot is zero-filled up to
/// `MAX_RULES_PER_OBJ`.
pub const MAP_RULE_COUNT: &str = "RULE_COUNT";

/// The name of the `HashMap<CgroupId, ClassId>` that maps each live blessed cgroup to the
/// [`ClassId`] it was minted with (DESIGN §16.3). The kernel resolves the caller's class as
/// `BLESSED[current_cgroup_id]`, or as [`ClassId::UNBLESSED`] when the cgroup is absent,
/// and a rule's `blessing` predicate matches that class.
///
/// Unlike the three rule maps, it is not banked. It holds per-`cordon bless` runtime state.
/// Only the daemon's backend thread writes it, adding an entry at mint and clearing it at
/// GC. So a bless never recompiles policy, and a `policy apply` never disturbs a live
/// bless.
///
/// It is not pinned either, because the daemon pins only the LSM links (its
/// `PinDir::pin_links`). A restarted daemon loads a fresh, empty `BLESSED`, and every
/// blessing fails closed until `Blessings::reconcile` re-registers the carriers whose class
/// is still declared.
pub const MAP_BLESSED: &str = "BLESSED";

/// The number of rule-table generations (see [`Bank`]). It sizes the banked [`MAP_RULES`]
/// array and the `bank` dimension of every key.
pub const NUM_BANKS: usize = 2;

/// The most rules that one object's bucket may hold. It bounds the kernel's first-match
/// scan and its verifier loop, and it fixes the [`MAP_RULES`] slot stride. Copying rules
/// down can lengthen a bucket, since a deep object inherits every ancestor's rules, so the
/// compiler enforces this ceiling, and `cordon policy check` errors on a bucket that
/// exceeds it. It can rise toward 64 if policies need more and the verifier still accepts
/// the scan.
pub const MAX_RULES_PER_OBJ: usize = 32;

/// The most protected objects, meaning distinct `where` targets, that a policy may have. It
/// sizes the packed [`MAP_RULES`] array (`MAX_OBJECTS * MAX_RULES_PER_OBJ` slots) and
/// bounds the dense [`ObjId`] space. The compiler reports more objects than this as an
/// error, and the daemon's `Maps::seed` refuses such a policy again before it does any slot
/// arithmetic.
pub const MAX_OBJECTS: usize = 1024;

/// The most live blessings, meaning [`MAP_BLESSED`] entries, at once. Each active
/// `cordon bless` invocation holds one, and on a personal machine few run at the same
/// time. The daemon refuses a new mint past this. It does not limit the number of policy
/// classes, since many invocations can share one [`ClassId`].
pub const MAX_BLESSED: usize = 1024;

/// The capacity of the banked object-keyed maps, [`MAP_PROTECTED`] and [`MAP_RULE_COUNT`].
pub const BANKED_OBJECTS: usize = NUM_BANKS * MAX_OBJECTS;
/// The capacity of [`MAP_RULES`], which [`BankedObj::rule_slot`] indexes.
pub const RULE_SLOTS: usize = BANKED_OBJECTS * MAX_RULES_PER_OBJ;

/// A protected object's dense id, which the compiler assigns to address the object's slot
/// in [`MAP_RULES`] and [`MAP_RULE_COUNT`]. It differs from the object's [`FileId`], which
/// is the kernel's key into [`MAP_PROTECTED`].
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ObjId(pub u32);

/// A blessing class id. The compiler assigns a dense id to each named blessing class that
/// policy declares (`[group.subject.*] blessing = "<name>"`, DESIGN §16.3), and
/// [`MAP_BLESSED`] stores it for a live blessed cgroup. A rule's
/// [`SubjectMatch::blessing`] names the class it requires, and the kernel matches it
/// against the caller's resolved class.
///
/// [`UNBLESSED`](ClassId::UNBLESSED) (`0`) is the sentinel that a process in no blessed
/// cgroup resolves to. The compiler never assigns it to a named class, so no concrete
/// `blessing` predicate equals it. An unblessed caller therefore matches only the rules
/// that wildcard the blessing ([`SubjectFlags::BLESSING_ANY`]).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ClassId(pub u32);

impl ClassId {
    /// The sentinel `0` that a cgroup with no `BLESSED` entry resolves to (see
    /// [`ClassId`]).
    pub const UNBLESSED: ClassId = ClassId(0);
}

/// Writes the raw class id for the journal's `blessing=` field. The daemon resolves it back
/// to the class name.
impl core::fmt::Display for ClassId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

padded_pod! {
    /// A [`MAP_PROTECTED`] key, which is a protected object's inode identity within one
    /// bank. Its trailing `_pad` is load-bearing. `FileId` is 8-aligned, so a [`Bank`] (a
    /// `u32`) at offset 16 would leave 4 bytes of implicit trailing padding in a hashed key
    /// (see the `layout` module docs). `padded_pod!` turns that gap into an explicit field
    /// that is always zeroed, so the 24-byte key has no padding.
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

/// A [`MAP_RULE_COUNT`] key, which is an object id within one bank. `ObjId` and [`Bank`]
/// are both `u32`, so the key has no padding.
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

    /// Returns the flat index of this object's rule `i` within [`MAP_RULES`]. The kernel
    /// scans with it and the loader fills with it, so the stride has one definition. Any
    /// bank value is masked to `0` or `1`, and valid inputs (`obj < MAX_OBJECTS`,
    /// `i < MAX_RULES_PER_OBJ`) stay below [`RULE_SLOTS`].
    pub const fn rule_slot(self, i: u32) -> u32 {
        // `Bank::index` masks the bank, and wrapping arithmetic keeps the result defined
        // for any input. `Array::get` bounds-checks the index regardless.
        (self.bank.index().wrapping_mul(MAX_OBJECTS as u32))
            .wrapping_add(self.obj.0)
            .wrapping_mul(MAX_RULES_PER_OBJ as u32)
            .wrapping_add(i)
    }
}

bitflags! {
    /// The set of actions that a rule covers, with one bit per LSM-mediated operation
    /// (DESIGN §15.5). A rule carries a mask rather than one action, so
    /// `action = ["read","write"]` compiles to a single [`CompiledRule`], and the kernel
    /// matches when the mask intersects the requested actions. `file_open` requests
    /// `READ`, `WRITE` and `CREATE`, the mutation hooks request `LINK`, `RENAME`, `UNLINK`,
    /// `RMDIR` and `MKDIR`, and `bprm_check_security` requests `EXECUTE` (§15.5).
    ///
    /// `#[repr(transparent)]` is load-bearing. The type is read byte for byte out of the
    /// `RULES` map inside [`CompiledRule`], which is `repr(C)`, so its ABI must be exactly
    /// the inner `u32`. bitflags makes its public type `repr(Rust)` by default, and this
    /// attribute makes it transparent over the internal `u32`, which is transparent too.
    /// bitflags 2.x also permits unknown bits, so every bit pattern is valid and the
    /// `aya::Pod` impl below is sound.
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct Action: u32 {
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const CREATE  = 1 << 2;
        const EXECUTE = 1 << 3;
        /// An action that compiles but that no hook requests. A directory open requests
        /// `READ`, so a rule that grants only `listdir` never matches, and the read falls
        /// to default-deny.
        const LISTDIR = 1 << 4;
        const UNLINK  = 1 << 5;
        const MKDIR   = 1 << 6;
        const RMDIR   = 1 << 7;
        const RENAME  = 1 << 8;
        const LINK    = 1 << 9;
    }
}

impl Action {
    /// Each action bit with its name in the policy authoring vocabulary. The policy parser
    /// reads names through this table and [`Display`](core::fmt::Display) writes them, so
    /// the two cannot disagree.
    pub const NAMED: [(Action, &'static str); 10] = [
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

    /// Returns the single action that `name` names, or `None` for an unknown name.
    pub fn from_authored(name: &str) -> Option<Action> {
        Self::NAMED
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(bit, _)| *bit)
    }
}

/// Writes the actions as `read|write|create|…`, or `none` for the empty set.
impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_empty() {
            return write!(f, "none");
        }
        let mut first = true;
        for (bit, name) in Self::NAMED {
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

/// A rule's effect, one of `{allow, deny} × {log, silent}` (DESIGN §15.2). This per-rule
/// policy is the only enforcement level, and there is no global mode (§15.6). The kernel
/// blocks exactly when the policy [`denies`](Policy::denies), so `audit` observes an object
/// and `deny` enforces it, per object.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy(pub u8);

impl Policy {
    /// The effect that allows the access without logging it.
    pub const ALLOW: Policy = Policy(0);
    /// The effect that allows the access and logs it, to preview a would-be rule's reach.
    pub const AUDIT: Policy = Policy(1);
    /// The effect that denies the access and logs it.
    pub const DENY: Policy = Policy(2);
    /// The effect that denies the access silently, with no learn record.
    pub const SILENCE: Policy = Policy(3);
    /// The synthetic effect that the kernel applies when no rule matched on a protected
    /// object (the default-deny, DESIGN §15.6.3). Only a protected object can reach it. A
    /// path under no object is allowed, and `where = "*"` is rejected at resolve, so the
    /// filesystem as a whole is never default-denied. It is never authored or stored in a
    /// [`CompiledRule`]. It exists only as the cause carried on a [`crate::DecisionEvent`],
    /// so the journal can tell a default-deny ("you have no rule for this") apart from an
    /// explicit `deny` rule ("you chose to block this"). It blocks and logs exactly like
    /// [`DENY`](Policy::DENY).
    pub const DEFAULT_DENY: Policy = Policy(4);
    /// The synthetic effect that the kernel applies when a protected inode would acquire a
    /// name outside its object, through a hardlink or a rename out (DESIGN §15.5). Like
    /// [`DEFAULT_DENY`](Policy::DEFAULT_DENY), it is never authored or stored in a
    /// [`CompiledRule`]. Unlike every other cause, it comes from no rule at all, because
    /// the escape is refused unconditionally (see the program's `decide_reparent`). It is a
    /// distinct cause so that the journal reads "this was structurally refused" rather than
    /// "a rule of yours blocked it", since the two need very different fixes.
    pub const ESCAPE_DENY: Policy = Policy(5);

    /// Checks whether this policy blocks the access, which is the `deny` half of
    /// `{allow,deny}×{log,silent}`.
    pub const fn denies(self) -> bool {
        matches!(
            self,
            Policy::DENY | Policy::SILENCE | Policy::DEFAULT_DENY | Policy::ESCAPE_DENY
        )
    }
    /// Checks whether a decision under this policy emits a record, which is the `log` half,
    /// rather than staying silent.
    pub const fn logs(self) -> bool {
        matches!(
            self,
            Policy::AUDIT | Policy::DENY | Policy::DEFAULT_DENY | Policy::ESCAPE_DENY
        )
    }

    /// Each policy with its name. The first four are the authoring vocabulary, which
    /// [`Policy::from_authored`] accepts. The last two name the synthetic causes, which only
    /// the journal writes.
    pub const NAMED: [(Policy, &'static str); 6] = [
        (Policy::ALLOW, "allow"),
        (Policy::DENY, "deny"),
        (Policy::AUDIT, "audit"),
        (Policy::SILENCE, "silence"),
        (Policy::DEFAULT_DENY, "default-deny"),
        (Policy::ESCAPE_DENY, "escape-deny"),
    ];
    /// The number of [`Policy::NAMED`] entries that a policy author may write.
    pub const AUTHORED: usize = 4;

    /// Returns the policy that an author's `name` names, or `None` for an unknown name or
    /// a synthetic cause.
    pub fn from_authored(name: &str) -> Option<Policy> {
        Self::NAMED[..Self::AUTHORED]
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(p, _)| *p)
    }
}

/// Writes the policy's name from [`Policy::NAMED`], or `unknown` for any other value.
impl core::fmt::Display for Policy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = Self::NAMED.iter().find(|(p, _)| p == self);
        f.write_str(name.map_or("unknown", |(_, n)| n))
    }
}

bitflags! {
    /// The subject predicates that are wildcards. A set bit means "match any caller and
    /// skip the compare". `who = "*"` sets every bit, and a concrete predicate clears its
    /// own bit. The kernel ANDs only the predicates that are not wildcards (DESIGN §15.4
    /// and the §16.3 `blessing`). The compiler counts the cleared bits as the rule's
    /// subject specificity (`subject_specificity`, §15.6), so a fifth predicate bit extends
    /// both for free.
    ///
    /// It is `#[repr(transparent)]` over `u32` for the same reason as [`Action`]. It is
    /// read byte for byte out of `RULES` inside [`CompiledRule`], and bitflags 2.x admits
    /// unknown bits, so every pattern is valid and the `aya::Pod` impl below is sound.
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct SubjectFlags: u32 {
        /// `exe` is a wildcard.
        const EXE_ANY      = 1 << 0;
        /// `uid` is a wildcard. It is always set, because the predicate is reserved.
        const UID_ANY      = 1 << 1;
        /// `cgroup` is a wildcard. It is always set, because the predicate is reserved.
        const CGROUP_ANY   = 1 << 2;
        /// `blessing` is a wildcard. Only a rule that names a blessing class clears it.
        const BLESSING_ANY = 1 << 3;
    }
}

padded_pod! {
    /// A subject predicate, which is a conjunction of cheap checks that the kernel ANDs
    /// against the caller (DESIGN §15.4 and the §16.3 `blessing` predicate). The compiler
    /// fills `exe` and `blessing`, while `uid` and `cgroup` are reserved and always
    /// wildcard. It rides inside [`CompiledRule`] as part of a map value, so its `_pad` is
    /// there for initialization soundness rather than key hashing (see the `layout` module
    /// docs).
    #[repr(C)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct SubjectMatch {
        /// The identity `(dev,ino)` of the caller's executable. It is compared unless
        /// [`SubjectFlags::EXE_ANY`] is set.
        pub exe: FileId,
        /// The caller's cgroup id. It is reserved, and [`SubjectFlags::CGROUP_ANY`] is
        /// always set.
        pub cgroup: CgroupId,
        /// The caller's uid. It is reserved, and [`SubjectFlags::UID_ANY`] is always set.
        pub uid: Uid,
        /// The blessing class that this rule requires (DESIGN §16.3). It is compared
        /// against the caller's resolved class, `BLESSED[cgroup]` or
        /// [`ClassId::UNBLESSED`], unless [`SubjectFlags::BLESSING_ANY`] is set.
        pub blessing: ClassId,
        /// The predicates that the kernel does not compare, because they are wildcards.
        pub flags: SubjectFlags,
    }
}

impl SubjectMatch {
    /// The subject that matches any caller (`who = "*"`). Every predicate is a wildcard,
    /// including `blessing`, so a `*` catch-all matches blessed and unblessed callers
    /// alike.
    pub const ANY: SubjectMatch = SubjectMatch {
        exe: FileId::new(Dev(0), Ino(0)),
        cgroup: CgroupId(0),
        uid: Uid(0),
        blessing: ClassId::UNBLESSED,
        flags: SubjectFlags::all(),
        _pad: [0; Self::PAD],
    };

    /// Returns a subject that matches exactly one executable, by `(dev,ino)`, with any uid,
    /// cgroup or blessing.
    pub const fn exe(exe: FileId) -> SubjectMatch {
        SubjectMatch {
            exe,
            // Every predicate is a wildcard except the concrete `exe`.
            flags: SubjectFlags::all().difference(SubjectFlags::EXE_ANY),
            ..Self::ANY
        }
    }

    /// Returns a subject that matches any caller in blessing class `class` (DESIGN §16.3),
    /// which is the `@blessed-*` predicate. The exe, uid and cgroup are wildcards. The
    /// compiler combines it with [`exe`](Self::exe) by conjunction.
    pub const fn blessed(class: ClassId) -> SubjectMatch {
        SubjectMatch {
            blessing: class,
            // Every predicate is a wildcard except the concrete `blessing`.
            flags: SubjectFlags::all().difference(SubjectFlags::BLESSING_ANY),
            ..Self::ANY
        }
    }
}

padded_pod! {
    /// One pre-resolved rule in an object's bucket. The compiler sorts each bucket into
    /// first-match order (`cordon_core`'s `sort_bucket`), so the kernel applies the first
    /// rule whose action and subject match. Its `padded_pod!` `_pad` leaves no byte
    /// uninitialized when the loader copies rules into the packed [`MAP_RULES`] array.
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

// ---- userspace only, so the POD types can be aya map keys and values -------

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: each type is `repr(transparent)` or `repr(C)` over POD integer fields, so
    // every bit pattern is valid, and each is `Copy` with a fixed layout. That is aya's
    // `Pod` contract. `Policy` and `Action` accept out-of-range values in memory, which is
    // a statement about memory safety, not a claim that every value means something.
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
    fn every_action_has_one_name() {
        let named = Action::NAMED.iter().fold(Action::empty(), |acc, (bit, _)| {
            assert!(!acc.intersects(*bit), "{bit:?} is named twice");
            acc | *bit
        });
        assert_eq!(named, Action::all());
        for (bit, name) in Action::NAMED {
            assert_eq!(Action::from_authored(name), Some(bit));
        }
        assert_eq!(Action::from_authored("nope"), None);
    }

    #[test]
    fn only_authored_policies_parse() {
        assert_eq!(Policy::from_authored("silence"), Some(Policy::SILENCE));
        assert_eq!(Policy::from_authored("default-deny"), None);
        assert_eq!(Policy::from_authored("escape-deny"), None);
        assert_eq!(Policy::from_authored("nope"), None);
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

        // A blessing rule clears BLESSING_ANY and names a concrete class, exe stays
        // wildcard.
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
        // CompiledRule: 40 (SubjectMatch) + 4 (Action) + 1 (Policy) + 3 (pad) = 48,
        // 8-aligned.
        assert_eq!(core::mem::size_of::<CompiledRule>(), 48);
        assert_eq!(core::mem::align_of::<CompiledRule>(), 8);
    }

    #[test]
    fn banked_keys_are_padding_free() {
        // Hashed keys must have no implicit padding bytes (see the `layout` module docs).
        // BankedFile: 16 (FileId) + 4 (Bank) + 4 (explicit pad) = 24.
        assert_eq!(core::mem::size_of::<BankedFile>(), 24);
        assert_eq!(core::mem::align_of::<BankedFile>(), 8);
        // BankedObj: 4 (ObjId) + 4 (Bank) = 8, no padding.
        assert_eq!(core::mem::size_of::<BankedObj>(), 8);
        assert_eq!(core::mem::align_of::<BankedObj>(), 4);
    }

    #[test]
    fn rule_slot_banks_dont_overlap() {
        // Each bank occupies a disjoint MAX_OBJECTS*MAX_RULES_PER_OBJ window, and every
        // valid slot stays inside the array.
        let slot = |bank, obj, i| BankedObj::new(Bank(bank), ObjId(obj)).rule_slot(i);
        let span = (MAX_OBJECTS * MAX_RULES_PER_OBJ) as u32;
        assert_eq!(slot(0, 0, 0), 0);
        assert_eq!(slot(1, 0, 0), span);
        assert_eq!(
            slot(1, MAX_OBJECTS as u32 - 1, MAX_RULES_PER_OBJ as u32 - 1),
            RULE_SLOTS as u32 - 1
        );
        // A garbage bank is masked back into range, never out the top of the array.
        assert!(slot(u32::MAX, 0, 0) < RULE_SLOTS as u32);
    }
}
