//! cordon's eBPF data plane: the `file_open` LSM hook that returns the access
//! verdict **in-kernel** (DESIGN §4, §15). The userspace daemon (`crates/daemon`,
//! `bpf-lsm` backend) compiles the text policy, loads this object, fills its maps,
//! and drains its ring buffer — but it is this program, not the daemon, that decides.
//!
//! ## The decision (rule model, M1)
//! For each `open` (reading the live double-buffer `bank` from `SETTINGS.active_bank`,
//! so a `policy apply` flips the whole table atomically — DESIGN §15.8):
//!   1. Fast-allow the daemon's own pid (never deadlock on our own opens).
//!   2. Walk the opened file's dentry ancestors; the first one whose **(bank, dev,
//!      ino)** is in `PROTECTED` is the most-specific protected object → its `ObjId`. No
//!      match ⇒ unprotected ⇒ allow (DESIGN §15.6.4 — the filesystem can't be
//!      default-denied).
//!   3. Derive the requested **action** from `f_mode`/`f_flags` (read/write/create). An
//!      open that is none of these (e.g. `O_PATH`) reads no content ⇒ allow.
//!   4. Scan the object's pre-sorted rule bucket (`RULE_COUNT[(bank,obj)]` entries in
//!      the packed `RULES` array, bounded by `MAX_RULES_PER_OBJ`) and apply the
//!      **first** rule whose action mask intersects and whose subject matches. Copy-down
//!      resolved all precedence in userspace, so first-match is correct (DESIGN §15.3).
//!   5. No matching rule ⇒ **default-deny** (DESIGN §15.6.3). The per-rule `policy` is
//!      the only enforcement level — there is no global mode (§15.6): a denying policy
//!      always blocks. When the matched policy logs (`audit`/`deny`), the in-kernel
//!      suppressor throttles a repeat burst to one `DecisionEvent` + a folded count
//!      (M1 §1g) before emitting.
//!
//! Anything we can't read fails **open** (a `None` becomes allow). All `unsafe`
//! (kernel reads, ring writes) lives in [`kernel`]; this file is the decision flow.
//! Field offsets come from the running kernel at load time (see [`kernel`]).

#![no_std]
#![no_main]

mod kernel;

use aya_ebpf::macros::{lsm, map};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::LsmContext;
use cordon_bpf_common::{
    rule_slot, Action, Bank, BankedFile, BankedObj, CgroupId, ClassId, CompiledRule, Decision,
    FileId, ObjId, Pid, Policy, Settings, SubjectFlags, SubjectMatch, MAX_BLESSED, MAX_OBJECTS,
    MAX_RULES_PER_OBJ, NUM_BANKS,
};

/// The hook's verdict. The kernel wants a raw return (`0` allow / negative errno
/// deny); the decision flow speaks `Verdict` and converts once, at the boundary.
#[derive(Clone, Copy)]
enum Verdict {
    Allow,
    Deny,
}

impl Verdict {
    /// The errno we deny with: `EPERM`.
    const EPERM: i32 = 1;

    fn to_lsm(self) -> i32 {
        match self {
            Verdict::Allow => 0,
            Verdict::Deny => -Self::EPERM,
        }
    }
}

/// Bound the dentry ancestor walk so a pathological chain can't spin the verifier.
const MAX_ANCESTORS: usize = 32;

// `f_mode` / `f_flags` bits we read at open time (stable kernel ABI constants).
const FMODE_READ: u32 = 0x1;
const FMODE_WRITE: u32 = 0x2;
const O_CREAT: u32 = 0o100;

// ---- policy maps (filled by the daemon from the compiled policy) ----------
// All three rule maps are double-buffered: keyed/indexed by `(bank, …)`, with
// `SETTINGS.active_bank` selecting the live generation. The kernel reads only the
// active bank; the daemon fills the inactive one and flips (DESIGN §15.8).

/// Every protected object's `(bank, dev, ino)` → its dense `ObjId`.
#[map]
static PROTECTED: HashMap<BankedFile, ObjId> =
    HashMap::with_max_entries((NUM_BANKS * MAX_OBJECTS) as u32, 0);
/// The packed per-(bank,object) rule table: bank `b`, object `o`'s rules occupy the
/// contiguous slot at `rule_slot(b, o, 0..RULE_COUNT[(b,o)])`.
#[map]
static RULES: Array<CompiledRule> =
    Array::with_max_entries((NUM_BANKS * MAX_OBJECTS * MAX_RULES_PER_OBJ) as u32, 0);
/// How many rules bank `b`, object `o` actually has in `RULES`.
#[map]
static RULE_COUNT: HashMap<BankedObj, u32> =
    HashMap::with_max_entries((NUM_BANKS * MAX_OBJECTS) as u32, 0);
/// The one-element control record (daemon pid + live bank).
#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

/// Live blessings (DESIGN §16.3): a blessed cgroup's id → its [`ClassId`]. Written by the
/// daemon at `cordon bless` mint, cleared at GC — **unbanked** runtime state, so a bless
/// never recompiles policy and a `policy apply` never disturbs a live bless. Empty until the
/// daemon writes it, so absent a bless every caller resolves to [`ClassId::UNBLESSED`].
#[map]
static BLESSED: HashMap<CgroupId, ClassId> = HashMap::with_max_entries(MAX_BLESSED as u32, 0);

/// The matched protected object, plus what leaf-path reconstruction needs: the opened
/// file's own identity (`leaf`, the suppressor/coalesce key) and the matched object's
/// dentry (the stop point of the `d_name` walk).
struct Match {
    obj: ObjId,
    object: FileId,
    /// The affected file's own `(dev,ino)` — equals `object` when the rule targets the file.
    leaf: FileId,
    /// The affected file's dentry: the start point of the `d_name` walk.
    leaf_dentry: kernel::Dentry,
    /// The matched object's dentry: the path walk stops here (pointer compare, cheap).
    object_dentry: kernel::Dentry,
}

/// Lower a decision to an LSM return value, clamped into the range the verifier demands.
///
/// An LSM hook must return a value in `[-4095, 0]`, and the verifier requires the exit
/// register to be *provably* in range. `to_lsm()` only ever yields `0` or `-EPERM`, but
/// codegen leaves R0 an untracked scalar that the stricter v6.12 verifier rejects ("R0 has
/// unknown scalar value should have been in [-4095, 0]") though the laxer host kernel
/// accepts it. `black_box` stops LLVM from proving the bound redundant and eliding it (it
/// knows `ret ∈ {0,-1}`), so the clamp survives in the object and gives the verifier the
/// range it needs.
///
/// Every program funnels through here — a new hook cannot forget the clamp and then fail
/// to load only on the pinned CI kernel.
fn clamped(verdict: Option<Verdict>) -> i32 {
    // `None` anywhere in a decision flow ⇒ couldn't decide ⇒ fail open.
    let ret = verdict.unwrap_or(Verdict::Allow).to_lsm();
    let ret = core::hint::black_box(ret);
    if ret < -4095 || ret > 0 { 0 } else { ret }
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    clamped(decide(&ctx))
}

// The mutation hooks. Argument positions come from the kernel's LSM prototypes and are
// **not** type-checked here: reading an `inode *` slot as a dentry yields a pointer whose
// field reads fail, which fails *open* and silently. `Dentry::from_arg` is called with a
// literal index at each entry point (never threaded through a shared fn) so the verifier
// sees a constant offset into the context, and the daemon's self-test exercises every hook
// so a wrong index fails loudly at startup rather than quietly forever.

/// `inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)`
#[lsm(hook = "inode_link")]
pub fn inode_link(ctx: LsmContext) -> i32 {
    clamped(decide_reparent(
        kernel::Dentry::from_arg(&ctx, 0),
        kernel::Dentry::from_arg(&ctx, 2),
        Action::LINK,
    ))
}

/// `inode_rename(struct inode *old_dir, struct dentry *old_dentry,
///               struct inode *new_dir, struct dentry *new_dentry)`
#[lsm(hook = "inode_rename")]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    clamped(decide_reparent(
        kernel::Dentry::from_arg(&ctx, 1),
        kernel::Dentry::from_arg(&ctx, 3),
        Action::RENAME,
    ))
}

/// `inode_unlink(struct inode *dir, struct dentry *dentry)`
#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    clamped(decide_remove(kernel::Dentry::from_arg(&ctx, 1), Action::UNLINK))
}

/// `inode_rmdir(struct inode *dir, struct dentry *dentry)`
#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
    clamped(decide_remove(kernel::Dentry::from_arg(&ctx, 1), Action::RMDIR))
}

/// Settings + the daemon's own-I/O fast path. `None` ⇒ the caller allows: either we can't
/// read settings (fail open) or this *is* the daemon (never deadlock on its own I/O).
fn live_bank(pid: Pid) -> Option<Bank> {
    let settings = settings()?;
    if pid == settings.daemon_pid {
        return None;
    }
    // Masked to a valid bank — a torn/garbage read can't escape the array, it just
    // resolves to an empty bucket → fail-open allow.
    Some(settings.active_bank.masked())
}

/// `inode_link` / `inode_rename`: a name is being created for an existing inode (and for
/// rename, the old name goes away). Two questions, in order:
///
/// 1. **Escape** — is a protected inode acquiring a name *outside* its object? Refused
///    unconditionally, with no rule lookup and no subject check. A second name in an
///    unprotected directory makes the inode readable by every subject, forever, and
///    silently: `find_object` stops finding the object, so no further event is ever
///    emitted. No subject is trusted with that — not an allowed exe, not a blessed
///    session. Blessing grants *read*, not re-parenting.
/// 2. **Clobber** — is an unprotected inode acquiring a name *inside* an object? That is
///    an ordinary create/write, so it takes the subject's verdict on the destination
///    object and honours `audit` (allow+log) exactly like any other write.
///
/// An internal shuffle (same object both sides) is neither, and returns early: that is the
/// atomic-save pattern (write a temp beside the target, rename over it), which has to keep
/// working inside a protected directory — `ssh` rewriting `known_hosts`, `git` in
/// `~/.password-store`. It is also why the clobber check can't simply fire on "destination
/// is protected".
fn decide_reparent(
    source: kernel::Dentry,
    new_dentry: kernel::Dentry,
    op: Action,
) -> Option<Verdict> {
    let pid = kernel::current_pid();
    let bank = live_bank(pid)?;

    let src = find_object(source, bank);
    // The destination *directory*. The new dentry is negative — it names a file that does
    // not exist yet, so `d_inode` is NULL and its own identity is unreadable. Its parent
    // is the directory receiving the name, which is what we must classify.
    let dst = find_object(new_dentry.parent()?, bank);

    match (src, dst) {
        // Nothing protected is moving.
        (None, None) => Some(Verdict::Allow),
        // Both sides inside the same object: an internal shuffle, not a re-parenting.
        (Some(s), Some(d)) if s.obj == d.obj => Some(Verdict::Allow),
        // ESCAPE. Covers dst unprotected *and* dst a different object (which may have
        // looser rules). Also catches the object's own directory being moved out, which
        // would otherwise strand the path unprotected for everything created afterwards.
        (Some(s), _) => Some(deny_escape(&s, op, pid, bank)),
        // CLOBBER: a foreign inode taking a name inside the object.
        (None, Some(d)) => consult(&d, Action::CREATE | Action::WRITE, op, pid, bank),
    }
}

/// `inode_unlink` / `inode_rmdir`: a name is being removed. There is no destination, so
/// this is an ordinary subject verdict — removing a name is a write to the object. Gating
/// it matters because destroying the object's own directory dangles its `PROTECTED` entry:
/// objects resolve once, at `policy apply`, and nothing re-checks them, so `rm -rf` +
/// `mkdir` would otherwise leave the path permanently unprotected.
fn decide_remove(dentry: kernel::Dentry, op: Action) -> Option<Verdict> {
    let pid = kernel::current_pid();
    let bank = live_bank(pid)?;
    let Some(matched) = find_object(dentry, bank) else {
        return Some(Verdict::Allow);
    };
    consult(&matched, Action::WRITE, op, pid, bank)
}

/// Refuse an escape, and journal it best-effort. The verdict deliberately does **not**
/// depend on being able to log: an unreadable exe or a full ring buffer costs the
/// observation, never the enforcement.
///
/// *Whether* to log still follows the object's own policy, so `{allow,deny}×{log,silent}`
/// holds here too — a `silence` object refuses the escape silently. The rule lookup
/// decides logging only; it can never make the escape allowed. Matching on `READ | op` is
/// what lets an ordinary read rule answer "does this object log?", since policies rarely
/// name `link`/`rename` explicitly.
fn deny_escape(matched: &Match, op: Action, pid: Pid, bank: Bank) -> Verdict {
    if let Some(exe) = kernel::caller_exe() {
        let policy = match_rule(matched.obj, Action::READ | op, exe, current_class(), bank)
            .unwrap_or(Policy::DEFAULT_DENY);
        if !policy.logs() {
            return Verdict::Deny;
        }
        if let Some(suppressed) = kernel::throttle(exe, matched.leaf, op) {
            kernel::emit(&kernel::Record {
                pid,
                uid: kernel::current_uid(),
                exe,
                object: matched.object,
                leaf: matched.leaf,
                obj: matched.obj,
                action: op,
                decision: Decision::DENY,
                policy: Policy::ESCAPE_DENY,
                suppressed,
                blessing: current_class(),
                leaf_dentry: matched.leaf_dentry,
                object_dentry: matched.object_dentry,
            });
        }
    }
    Verdict::Deny
}

fn decide(ctx: &LsmContext) -> Option<Verdict> {
    // (1) settings + our own I/O → allow (never deadlock on the daemon's own opens).
    let pid = kernel::current_pid();
    let bank = live_bank(pid)?;

    // file_open(struct file *file): arg 0.
    let file = kernel::File::from_arg(ctx, 0);

    // (2) most-specific protected object, or unprotected → allow.
    let Some(matched) = find_object(file.dentry()?, bank) else {
        return Some(Verdict::Allow);
    };

    // (3) requested action; an open that neither reads, writes, nor creates (e.g.
    // O_PATH) touches no content → allow, don't even scan.
    let requested = requested_action(file)?;
    if requested.is_empty() {
        return Some(Verdict::Allow);
    }

    // (4)/(5) subject match → verdict → journal. `file_open` logs exactly the action it
    // matched on; the mutation hooks pass a wider `requested` than they log (§15.5).
    consult(&matched, requested, requested, pid, bank)
}

/// The shared decision tail: caller subject → first matching rule → verdict → journal.
///
/// `requested` is the mask matched against rules; `logged` is what the journal and the
/// suppressor record. They differ only where an operation is gated by a broader capability
/// than the one it is named for. Keeping this in one place means deny/log semantics cannot
/// drift apart per hook.
///
/// **Five arguments is the ceiling**: BPF passes at most five in registers and has no
/// stack for the rest, so a sixth turns this from a subprogram call into a link error.
/// Fold anything further into [`Match`].
fn consult(
    matched: &Match,
    requested: Action,
    logged: Action,
    pid: Pid,
    bank: Bank,
) -> Option<Verdict> {
    // First matching rule, else default-deny (a distinct cause from an explicit `deny`, so
    // the journal can tell "no rule" apart from "you blocked it"). The subject is the exe
    // plus the caller's resolved blessing class (DESIGN §16.3), the latter read once here
    // from its cgroup; both are matched per-rule by `subject_matches`.
    let exe = kernel::caller_exe()?;
    let class = current_class();
    let policy =
        match_rule(matched.obj, requested, exe, class, bank).unwrap_or(Policy::DEFAULT_DENY);

    // The per-rule policy is the only enforcement level (no global mode): a denying
    // policy blocks outright.
    let blocked = policy.denies();
    // Emit only when the policy logs *and* the suppressor (keyed on the affected file, so
    // distinct leaves surface) lets this one through — a tight repeat-open burst collapses
    // to its first event + a folded `suppressed` count.
    if policy.logs() {
        if let Some(suppressed) = kernel::throttle(exe, matched.leaf, logged) {
            let decision = if blocked {
                Decision::DENY
            } else {
                Decision::AUDIT
            };
            // `emit` assembles the record off-stack (per-CPU scratch) and reconstructs the
            // affected file's path relative to the protected object (DESIGN §15.10 flow B)
            // — no `bpf_d_path` here, so it walks `d_name` from the leaf to
            // `object_dentry`. The uid is read only on the logged path, so the unprotected
            // majority pays nothing for it.
            kernel::emit(&kernel::Record {
                pid,
                uid: kernel::current_uid(),
                exe,
                object: matched.object,
                leaf: matched.leaf,
                obj: matched.obj,
                action: logged,
                decision,
                policy,
                suppressed,
                blessing: class,
                leaf_dentry: matched.leaf_dentry,
                object_dentry: matched.object_dentry,
            });
        }
    }
    Some(if blocked {
        Verdict::Deny
    } else {
        Verdict::Allow
    })
}

/// Walk `leaf_dentry`'s ancestors; return the first (deepest, hence most-specific) one
/// whose (dev, ino) is a protected object in the active `bank`. The leaf's own identity is
/// computed only on a match, so the unprotected majority pays nothing extra for it.
///
/// Entry is a dentry so every hook shares one resolver: `file_open` passes the opened
/// file's dentry, the mutation hooks pass the dentry their arguments carry directly. Note
/// the leaf is tested *first*, which is why a rule naming a file matches that inode by any
/// name, while a rule naming a directory protects children only by ancestry (DESIGN §15.5).
fn find_object(leaf_dentry: kernel::Dentry, bank: Bank) -> Option<Match> {
    let mut dentry = leaf_dentry;
    for _ in 0..MAX_ANCESTORS {
        let id = FileId::new(dentry.super_block()?.dev()?, dentry.inode()?.ino()?);
        if let Some(obj) = protected_obj(bank, id) {
            // The leaf's own id: reuse `id` if the leaf *is* the object, else read it.
            let leaf = if dentry == leaf_dentry {
                id
            } else {
                FileId::new(
                    leaf_dentry.super_block()?.dev()?,
                    leaf_dentry.inode()?.ino()?,
                )
            };
            return Some(Match {
                obj,
                object: id,
                leaf,
                leaf_dentry,
                object_dentry: dentry,
            });
        }
        let parent = dentry.parent()?;
        if parent == dentry {
            break; // mount root — d_parent points at itself
        }
        dentry = parent;
    }
    None
}

/// The requested action(s) for this open, from `f_mode` (read/write) + `f_flags`
/// (`O_CREAT` → create).
fn requested_action(file: kernel::File) -> Option<Action> {
    let mode = file.f_mode()?;
    let flags = file.f_flags()?;
    let mut a = Action::empty();
    if mode & FMODE_READ != 0 {
        a |= Action::READ;
    }
    if mode & FMODE_WRITE != 0 {
        a |= Action::WRITE;
    }
    if flags & O_CREAT != 0 {
        a |= Action::CREATE;
    }
    Some(a)
}

/// Scan object `obj`'s pre-sorted bucket in the active `bank` and return the first
/// rule's policy whose action mask intersects `requested` and whose subject matches the
/// caller (`exe` + blessing `class`). `None` ⇒ no matching rule (the caller applies
/// default-deny).
fn match_rule(
    obj: ObjId,
    requested: Action,
    exe: FileId,
    class: ClassId,
    bank: Bank,
) -> Option<Policy> {
    let count = rule_count(bank, obj).unwrap_or(0);
    for i in 0..MAX_RULES_PER_OBJ {
        if i as u32 >= count {
            break;
        }
        // `Array::get` is bounds-checked (safe in aya); a stray index yields `None`.
        let rule: CompiledRule = *RULES.get(rule_slot(bank, obj, i as u32))?;
        if rule.action_mask.intersects(requested) && subject_matches(rule.subject, exe, class) {
            return Some(rule.policy);
        }
    }
    None
}

/// Whether a subject predicate matches the caller: each non-wildcard predicate must equal
/// the caller's value (ANDed). M1 matches on `exe`; the `blessing` class (DESIGN §16.3) is
/// matched here too — a blessing rule clears `BLESSING_ANY` and names a class, so it fires
/// only for a caller in a blessed cgroup of that class. `uid`/`cgroup` matching is M2 (the
/// compiler never emits non-wildcard `uid`/`cgroup` yet, so they stay wildcard).
fn subject_matches(subject: SubjectMatch, exe: FileId, class: ClassId) -> bool {
    let exe_ok = subject.flags.contains(SubjectFlags::EXE_ANY) || subject.exe == exe;
    let blessing_ok =
        subject.flags.contains(SubjectFlags::BLESSING_ANY) || subject.blessing == class;
    exe_ok && blessing_ok
}

/// The caller's blessing class (DESIGN §16.3), resolved once per decision from its cgroup
/// via `BLESSED`, or [`ClassId::UNBLESSED`] when the cgroup is not a live blessing. Absent
/// any bless, `BLESSED` is empty so this is always `UNBLESSED` — every rule's blessing axis
/// is wildcard then, so the match is unchanged from M1.
fn current_class() -> ClassId {
    blessed_class(kernel::current_cgroup_id()).unwrap_or(ClassId::UNBLESSED)
}

/// The class a cgroup is blessed with, if it is a live blessing.
fn blessed_class(cgroup: CgroupId) -> Option<ClassId> {
    unsafe { BLESSED.get(&cgroup).copied() }
}

// ---- safe wrappers over the policy-map lookups ----------------------------
// aya's `HashMap::get` is `unsafe` (it hands back a reference into concurrently
// mutable map memory); copying the value out behind a safe fn keeps the decision flow
// `unsafe`-free. `Array::get` is already safe (bounds-checked).

/// The one-element settings record (daemon pid + live bank).
fn settings() -> Option<Settings> {
    SETTINGS.get(0).copied()
}

/// The `ObjId` of a protected object keyed by its `FileId` in `bank`, if any.
fn protected_obj(bank: Bank, key: FileId) -> Option<ObjId> {
    unsafe { PROTECTED.get(&BankedFile::new(bank, key)).copied() }
}

/// How many rules bank `bank`, object `obj` has in the packed table.
fn rule_count(bank: Bank, obj: ObjId) -> Option<u32> {
    unsafe { RULE_COUNT.get(&BankedObj::new(bank, obj)).copied() }
}

/// eBPF programs that call GPL-only helpers (`bpf_probe_read_kernel`) must declare a
/// GPL-compatible license, or the verifier rejects the load.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable in verified code (panics are optimized out under panic=abort);
    // present only to satisfy `no_std`.
    loop {}
}
