//! cordon's eBPF data plane. Its LSM hooks (`file_open`, the inode mutation hooks and
//! `bprm_check_security`) return the access verdict in the kernel (DESIGN §4, §15). The
//! userspace daemon (`crates/daemon`, `bpf-lsm` backend) compiles the text policy, loads
//! this object, fills its maps and drains its ring buffer, but this program makes the
//! decision, not the daemon.
//!
//! ## The decision
//! Each `open` is decided against the live bank in `SETTINGS.active_bank` (see [`Bank`]):
//!   1. The daemon itself is allowed at once (see [`live_bank`]).
//!   2. The first of the opened file's dentry ancestors whose bank, device and inode are
//!      in `PROTECTED` is the most specific protected object, and it yields an `ObjId`. A
//!      file with no such ancestor is unprotected, and its open is allowed.
//!   3. An open whose requested action ([`requested_action`]) is empty is allowed.
//!   4. The verdict comes from the first rule in the object's pre-sorted bucket whose
//!      action mask intersects and whose subject matches. The bucket is
//!      `RULE_COUNT[(bank,obj)]` entries of the packed `RULES` array, at most
//!      `MAX_RULES_PER_OBJ`. Copy-down resolved all precedence in userspace, so the first
//!      match is the right one (DESIGN §15.3).
//!   5. With no matching rule, the policy is default-deny. The open is blocked when the
//!      policy [`denies`](Policy::denies), and journaled through the suppressor
//!      (`kernel::throttle`) when it [`logs`](Policy::logs).
//!
//! Anything unreadable fails open (see [`clamped`]). All `unsafe` code, the kernel reads
//! and the ring writes, lives in [`kernel`], and this file holds the decision flow. Field
//! offsets come from the running kernel at load time (see [`kernel`]).

#![no_std]
#![no_main]

mod kernel;

use aya_ebpf::macros::{lsm, map};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::LsmContext;
use cordon_bpf_common::{
    rule_slot, Action, Bank, BankedFile, BankedObj, CgroupId, ClassId, CompiledRule, FileId, ObjId,
    Pid, Policy, Settings, SubjectFlags, SubjectMatch, MAX_BLESSED, MAX_OBJECTS, MAX_RULES_PER_OBJ,
    NUM_BANKS,
};

/// The verdict that the decision flow returns. It is converted once, at the hook boundary,
/// into the raw value the kernel wants, which is `0` to allow or a negative errno to deny.
#[derive(Clone, Copy)]
enum Verdict {
    Allow,
    Deny,
}

impl Verdict {
    /// The errno that a denied access gets.
    const EPERM: i32 = 1;

    fn to_lsm(self) -> i32 {
        match self {
            Verdict::Allow => 0,
            Verdict::Deny => -Self::EPERM,
        }
    }
}

/// The most ancestors that the dentry walk visits, so that a pathological chain cannot
/// exhaust the verifier.
const MAX_ANCESTORS: usize = 32;

// The `f_mode` and `f_flags` bits read at open time, which are stable kernel ABI constants.
const FMODE_READ: u32 = 0x1;
const FMODE_WRITE: u32 = 0x2;
const O_CREAT: u32 = 0o100;

// ---- policy maps (filled by the daemon from the compiled policy) ----------
// All three rule maps are banked. They are keyed or indexed by `(bank, …)`, and
// `SETTINGS.active_bank` selects the live generation (see `Bank`).

/// The protected objects of both banks (see `MAP_PROTECTED`).
#[map]
static PROTECTED: HashMap<BankedFile, ObjId> =
    HashMap::with_max_entries((NUM_BANKS * MAX_OBJECTS) as u32, 0);
/// The packed rule table of both banks (see `MAP_RULES`).
#[map]
static RULES: Array<CompiledRule> =
    Array::with_max_entries((NUM_BANKS * MAX_OBJECTS * MAX_RULES_PER_OBJ) as u32, 0);
/// The number of rules of each object in each bank (see `MAP_RULE_COUNT`).
#[map]
static RULE_COUNT: HashMap<BankedObj, u32> =
    HashMap::with_max_entries((NUM_BANKS * MAX_OBJECTS) as u32, 0);
/// The one-element control record ([`Settings`]).
#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

/// The live blessings (see `MAP_BLESSED`). The map is empty until the daemon writes it, so
/// with no bless every caller resolves to [`ClassId::UNBLESSED`].
#[map]
static BLESSED: HashMap<CgroupId, ClassId> = HashMap::with_max_entries(MAX_BLESSED as u32, 0);

/// The protected object that a hook matched, together with what leaf-path reconstruction
/// needs.
struct Match {
    obj: ObjId,
    object: FileId,
    /// The affected file's own `(dev,ino)`. It equals `object` when the rule targets the
    /// file.
    leaf: FileId,
    /// The affected file's dentry, where the `d_name` walk starts.
    leaf_dentry: kernel::Dentry,
    /// The matched object's dentry, where the path walk stops. The walk finds it by a cheap
    /// pointer compare.
    object_dentry: kernel::Dentry,
}

/// Returns the LSM return value for a verdict, clamped into the `[-4095, 0]` range that the
/// verifier demands of an LSM hook. A `None` verdict means that something in the decision
/// flow was unreadable, and it allows the access, so an unreadable kernel never blocks one.
///
/// Every hook returns through this function, so a new hook cannot forget the clamp and
/// then fail to load only on the pinned CI kernel.
fn clamped(verdict: Option<Verdict>) -> i32 {
    let ret = verdict.unwrap_or(Verdict::Allow).to_lsm();
    // The verifier needs the exit register provably in range. `to_lsm()` only yields `0`
    // or `-EPERM`, but codegen leaves R0 an untracked scalar, which the stricter v6.12
    // verifier rejects ("R0 has unknown scalar value should have been in [-4095, 0]")
    // though the laxer host kernel accepts it. LLVM knows that `ret` is 0 or -1 and would
    // drop the clamp as redundant, so `black_box` hides that and the clamp survives.
    let ret = core::hint::black_box(ret);
    if ret < -4095 || ret > 0 {
        0
    } else {
        ret
    }
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    clamped(decide(&ctx))
}

// The mutation hooks. Argument positions come from the kernel's LSM prototypes, and
// nothing type-checks them (see `Dentry::from_arg`). Each entry point calls
// `Dentry::from_arg` with a literal index, never one threaded through a shared fn, so that
// the verifier sees a constant offset into the context.

/// Gates a new hard link. The kernel prototype is
/// `inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)`.
#[lsm(hook = "inode_link")]
pub fn inode_link(ctx: LsmContext) -> i32 {
    clamped(decide_reparent(
        kernel::Dentry::from_arg(&ctx, 0),
        kernel::Dentry::from_arg(&ctx, 2),
        Action::LINK,
    ))
}

/// Gates a rename. The kernel prototype is `inode_rename(struct inode *old_dir,
/// struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)`.
#[lsm(hook = "inode_rename")]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    clamped(decide_reparent(
        kernel::Dentry::from_arg(&ctx, 1),
        kernel::Dentry::from_arg(&ctx, 3),
        Action::RENAME,
    ))
}

/// Gates removing a name. The kernel prototype is
/// `inode_unlink(struct inode *dir, struct dentry *dentry)`.
#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    clamped(decide_remove(
        kernel::Dentry::from_arg(&ctx, 1),
        Action::UNLINK,
    ))
}

/// Gates removing a directory. The kernel prototype is
/// `inode_rmdir(struct inode *dir, struct dentry *dentry)`.
#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
    clamped(decide_remove(
        kernel::Dentry::from_arg(&ctx, 1),
        Action::RMDIR,
    ))
}

/// Gates creating a directory. The kernel prototype is
/// `inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)`.
#[lsm(hook = "inode_mkdir")]
pub fn inode_mkdir(ctx: LsmContext) -> i32 {
    clamped(decide_create(
        kernel::Dentry::from_arg(&ctx, 1),
        Action::MKDIR,
    ))
}

/// Gates executing a binary. The kernel prototype is
/// `bprm_check_security(struct linux_binprm *bprm)`.
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    clamped(decide_exec(&ctx))
}

/// Returns the live bank for a decision on behalf of caller `pid`. Returns `None`, which
/// the caller turns into an allow, when the settings are unreadable or when the caller is
/// the daemon itself, so the daemon never deadlocks on its own I/O.
///
/// The daemon is identified by its pid and its exe together, never by the pid alone. The
/// LSM links are pinned in bpffs, so `SETTINGS`, and the bypass it grants, outlives the
/// process that wrote it, and a pid is a recyclable name. A pid-only test would hand a
/// total, unlogged bypass of every protected object to whatever process lands on that pid
/// while the daemon is down. The exe compare narrows the bypass to a process that also
/// runs cordond.
fn live_bank(pid: Pid) -> Option<Bank> {
    let settings = settings()?;
    // The exe read is the same `mm->exe_file` read that every subject match makes, and
    // `&&` skips it for every caller whose pid is not the daemon's.
    if pid == settings.daemon_pid && kernel::caller_exe() == Some(settings.daemon_exe) {
        return None;
    }
    // See `Bank::masked`.
    Some(settings.active_bank.masked())
}

/// Returns the verdict for `inode_link` and `inode_rename`, where an existing inode gets a
/// new name and, for a rename, loses its old one. The verdict answers three questions, and
/// the first refusal decides it:
///
/// 1. Destroy. Is the destination name already taken by an inode inside a protected
///    object? Only a rename can find one. The VFS resolves a `link` target with
///    `LOOKUP_CREATE`, so an existing name fails with `EEXIST` before this hook runs.
///    `vfs_rename` then unlinks that inode, and this hook is the only one the kernel fires
///    for it, for two reasons: `inode_unlink` is reachable only from `vfs_unlink`, and
///    `do_renameat2`'s own target check is the DAC-only `may_delete()`. Without this
///    check, `mv anything secret` would do exactly what `rm secret` is refused, and the
///    `PROTECTED` entry it leaves dangling is permanent, since objects resolve once. The
///    destroyed side gets its own `write` verdict, from the most specific object in play
///    on the destination (§15.6). This question comes before the internal-shuffle check
///    below, because that check would otherwise swallow a more specific object nested
///    inside the one being shuffled within.
/// 2. Escape. Is a protected inode acquiring a name outside its object? That is refused
///    unconditionally, with no rule lookup and no subject check. A second name in an
///    unprotected directory makes the inode readable by every subject, forever and
///    silently, because `find_object` stops finding the object and no further event is
///    emitted. No subject is trusted with that, neither an allowed exe nor a blessed
///    session. A blessing grants reading, not re-parenting.
/// 3. Clobber. Is an unprotected inode acquiring a name inside an object? That is an
///    ordinary create and write, so it gets the subject's verdict on the destination
///    object and honours `audit` (allow and log) like any other write.
///
/// An internal shuffle, with the same object on both sides, is none of the three and is
/// allowed. It is the atomic-save pattern of writing a temp file beside the target and
/// renaming it over the target. That pattern has to keep working inside a protected
/// directory, for example when `ssh` rewrites `known_hosts` or `git` writes in
/// `~/.password-store`. It is also why the clobber check cannot simply fire whenever the
/// destination is protected. The destroy check does not break the pattern. An atomic save
/// renames over a name in an object that the subject may already write, so the destroy
/// verdict is that same `allow`, and the shuffle proceeds. The check bites only where the
/// destination carries a tighter rule of its own, which is the case worth biting on.
fn decide_reparent(
    source: kernel::Dentry,
    new_dentry: kernel::Dentry,
    op: Action,
) -> Option<Verdict> {
    let pid = kernel::current_pid();
    let bank = live_bank(pid)?;

    // (1) DESTROY. `find_object` runs on the destination itself. It yields `None` for every
    // `link` and for a rename onto a free name, because both destinations are negative and
    // `Dentry::inode` yields `None` on the first step of the walk. It yields `Some` exactly
    // when this rename is about to unlink something that a protected object covers. A
    // refusal ends the operation here.
    if let Some(target) = find_object(new_dentry, bank) {
        if let Verdict::Deny = consult(&target, Action::WRITE, op, pid, bank)? {
            return Some(Verdict::Deny);
        }
    }

    let src = find_object(source, bank);
    // The escape and clobber questions are about the destination directory, which receives
    // the name. It differs from the destination dentry classified above, because
    // `~/.ssh/authorized_keys` and `~/.ssh` can be protected by different rules, or only
    // one of them can be protected at all.
    let dst = find_object(new_dentry.parent()?, bank);

    match (src, dst) {
        // Nothing protected is moving.
        (None, None) => Some(Verdict::Allow),
        // Both sides inside the same object: an internal shuffle, not a re-parenting.
        (Some(s), Some(d)) if s.obj == d.obj => Some(Verdict::Allow),
        // ESCAPE. This covers an unprotected `dst` and a `dst` in a different object, which
        // may have looser rules. It also catches the object's own directory being moved
        // out, which would otherwise leave the path unprotected for everything created
        // there afterwards.
        (Some(s), _) => Some(deny_escape(&s, op, pid, bank)),
        // CLOBBER. A foreign inode is taking a name inside the object.
        (None, Some(d)) => consult(&d, Action::CREATE | Action::WRITE, op, pid, bank),
    }
}

/// Returns the verdict for `inode_unlink` and `inode_rmdir`, where a name is being removed.
/// There is no destination, so the subject gets an ordinary verdict, and removing a name
/// counts as a write to the object. The gate matters because destroying the object's own
/// directory leaves its `PROTECTED` entry dangling. Objects resolve once, at
/// `policy apply`, and nothing re-checks them, so `rm -rf` followed by `mkdir` would
/// otherwise leave the path permanently unprotected.
fn decide_remove(dentry: kernel::Dentry, op: Action) -> Option<Verdict> {
    let pid = kernel::current_pid();
    let bank = live_bank(pid)?;
    let Some(matched) = find_object(dentry, bank) else {
        return Some(Verdict::Allow);
    };
    consult(&matched, Action::WRITE, op, pid, bank)
}

/// Returns the verdict for `bprm_check_security`, where a binary is being executed. The
/// subject is the process that performs the exec. At this hook the caller still runs its
/// old image, so `caller_exe()` names the launcher, not the binary being launched.
///
/// `execute` is a distinct capability, not implied by `read`. The exec's own open already
/// passes through `file_open`, since it is a real open with `FMODE_EXEC | FMODE_READ`, so
/// an object that denies reads already refuses to run its contents. This hook adds the
/// converse, so an object may be readable and still not runnable. A rule that grants only
/// `read` does not let a subject execute the object's contents. That falls to
/// default-deny, and a policy that wants both must say `["read", "execute"]`.
fn decide_exec(ctx: &LsmContext) -> Option<Verdict> {
    let pid = kernel::current_pid();
    let bank = live_bank(pid)?;
    let dentry = kernel::Binprm::from_arg(ctx, 0).file()?.dentry()?;
    let Some(matched) = find_object(dentry, bank) else {
        return Some(Verdict::Allow);
    };
    consult(&matched, Action::EXECUTE, Action::EXECUTE, pid, bank)
}

/// Returns the verdict for `inode_mkdir`, where a new directory name appears inside a
/// parent that may be protected. Adding a name inside an object is an ordinary create and
/// write on it, so the subject gets its verdict, and `audit` is honoured.
///
/// The dentry is negative, since no inode exists yet, so `find_object` on it would miss on
/// the first step of the walk. The object comes from the parent instead, just as the
/// clobber arm of [`decide_reparent`] takes `new_dentry.parent()`.
///
/// The hook is gated for symmetry with `inode_rmdir`. Removing a directory inside the
/// object is a write, and so is adding one. Leaving it ungated would let a subject that may
/// not touch the object grow structure inside it. This is not the
/// `rm -rf ~/.ssh && mkdir ~/.ssh` case. `inode_rmdir` closes that one by refusing the
/// removal, since once the object's own directory is gone, this hook finds no protected
/// ancestor.
fn decide_create(dentry: kernel::Dentry, op: Action) -> Option<Verdict> {
    let pid = kernel::current_pid();
    let bank = live_bank(pid)?;
    let Some(matched) = find_object(dentry.parent()?, bank) else {
        return Some(Verdict::Allow);
    };
    consult(&matched, Action::CREATE | Action::WRITE, op, pid, bank)
}

/// Refuses an escape, always returning [`Verdict::Deny`], and journals it on a best-effort
/// basis. The verdict never depends on logging, so an unreadable exe or a full ring buffer
/// costs the observation, never the enforcement.
///
/// Whether to log still follows the object's own policy, so `{allow,deny}×{log,silent}`
/// holds here too, and a `silence` object refuses the escape silently. The rule lookup
/// decides logging only and can never allow the escape. It matches on `READ | op`, so an
/// ordinary read rule decides whether the object logs, since policies rarely name `link`
/// or `rename`.
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
                action: op,
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
    // (1) Settings. The daemon itself is allowed (see `live_bank`).
    let pid = kernel::current_pid();
    let bank = live_bank(pid)?;

    // The file is arg 0 of `file_open(struct file *file)`.
    let file = kernel::File::from_arg(ctx, 0);

    // (2) The most specific protected object. An unprotected file is allowed.
    let Some(matched) = find_object(file.dentry()?, bank) else {
        return Some(Verdict::Allow);
    };

    // (3) The requested action. An open that neither reads, writes nor creates, such as
    // `O_PATH`, touches no content and is allowed without a rule scan.
    let requested = requested_action(file)?;
    if requested.is_empty() {
        return Some(Verdict::Allow);
    }

    // (4) and (5) The subject match, the verdict and the journal. `file_open` logs exactly
    // the action it matched on, while the mutation hooks pass a wider `requested` than
    // they log (§15.5).
    consult(&matched, requested, requested, pid, bank)
}

/// Returns the verdict of the first rule of `matched` that covers `requested` and matches
/// the caller, or default-deny when no rule does, and journals the decision when its policy
/// logs. Returns `None` when the caller's exe is unreadable.
///
/// `requested` is the mask matched against rules, and `logged` is what the journal and the
/// suppressor record. The two differ only where an operation is gated by a broader
/// capability than the one it is named for. Every hook shares this tail, so deny and log
/// semantics cannot drift apart per hook.
///
/// Five arguments is the ceiling (see [`kernel::Record`]), because a sixth turns this
/// subprogram call into a link error. Anything further belongs in [`Match`].
fn consult(
    matched: &Match,
    requested: Action,
    logged: Action,
    pid: Pid,
    bank: Bank,
) -> Option<Verdict> {
    // The subject is the exe plus the caller's resolved blessing class, which is read once
    // here from its cgroup. `subject_matches` compares both for each rule.
    let exe = kernel::caller_exe()?;
    let class = current_class();
    let policy =
        match_rule(matched.obj, requested, exe, class, bank).unwrap_or(Policy::DEFAULT_DENY);

    let blocked = policy.denies();
    if policy.logs() {
        if let Some(suppressed) = kernel::throttle(exe, matched.leaf, logged) {
            // The uid is read only on the logged path, so the unprotected majority pays
            // nothing for it.
            kernel::emit(&kernel::Record {
                pid,
                uid: kernel::current_uid(),
                exe,
                object: matched.object,
                leaf: matched.leaf,
                action: logged,
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

/// Returns the most specific protected object in `bank` that covers `leaf_dentry`. That is
/// the deepest of its ancestors, counting the dentry itself, that is a protected object.
/// Returns `None` when no ancestor is protected or a dentry on the way is unreadable.
///
/// The leaf itself is tested first, so a rule that names a file matches that inode under
/// any name, while a rule that names a directory protects its children only by ancestry
/// (DESIGN §15.5). It takes a dentry so that every hook shares one resolver.
fn find_object(leaf_dentry: kernel::Dentry, bank: Bank) -> Option<Match> {
    let mut dentry = leaf_dentry;
    for _ in 0..MAX_ANCESTORS {
        let id = FileId::new(dentry.super_block()?.dev()?, dentry.inode()?.ino()?);
        if let Some(obj) = protected_obj(bank, id) {
            // The leaf's own id is read only on a match, so the unprotected majority pays
            // nothing for it. When the leaf is the object, `id` already holds it.
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
            break; // the mount root is its own parent
        }
        dentry = parent;
    }
    None
}

/// Returns the actions that opening `file` requests, which are `READ` for `FMODE_READ`,
/// `WRITE` for `FMODE_WRITE` and `CREATE` for `O_CREAT`. An `O_PATH` open sets none of
/// them and requests nothing. A directory open requests `READ`, so the result never holds
/// `Action::LISTDIR`. Returns `None` when the mode or the flags are unreadable.
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

/// Returns the policy of the first rule in the pre-sorted bucket of object `obj` in `bank`
/// that covers `requested` and matches the caller's `exe` and blessing `class`. Returns
/// `None` when no rule matches or a rule slot is unreadable.
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
        // `Array::get` is bounds-checked and safe in aya, so a stray index yields `None`.
        let rule: CompiledRule = *RULES.get(rule_slot(bank, obj, i as u32))?;
        if rule.action_mask.intersects(requested) && subject_matches(rule.subject, exe, class) {
            return Some(rule.policy);
        }
    }
    None
}

/// Checks whether `subject` matches the caller, meaning that every predicate that is not a
/// wildcard equals the caller's value. It compares `exe` and the `blessing` class (DESIGN
/// §16.3), so a blessing rule fires only for a caller in a blessed cgroup of its class. It
/// does not compare `uid` and `cgroup`, because they are reserved and the compiler always
/// leaves them wildcard.
fn subject_matches(subject: SubjectMatch, exe: FileId, class: ClassId) -> bool {
    let exe_ok = subject.flags.contains(SubjectFlags::EXE_ANY) || subject.exe == exe;
    let blessing_ok =
        subject.flags.contains(SubjectFlags::BLESSING_ANY) || subject.blessing == class;
    exe_ok && blessing_ok
}

/// Returns the caller's blessing class (DESIGN §16.3), looked up from its cgroup in
/// `BLESSED`, or [`ClassId::UNBLESSED`] when the cgroup is not a live blessing.
fn current_class() -> ClassId {
    blessed_class(kernel::current_cgroup_id()).unwrap_or(ClassId::UNBLESSED)
}

/// Returns the class that `cgroup` is blessed with, or `None` when it is not a live
/// blessing.
fn blessed_class(cgroup: CgroupId) -> Option<ClassId> {
    unsafe { BLESSED.get(&cgroup).copied() }
}

// ---- safe wrappers over the policy-map lookups ----------------------------
// aya's `HashMap::get` is `unsafe` because it hands back a reference into map memory that
// can change concurrently. Copying the value out behind a safe fn keeps the decision flow
// free of `unsafe`. `Array::get` is already safe, since it is bounds-checked.

/// Returns the [`Settings`] record, or `None` when it is unreadable.
fn settings() -> Option<Settings> {
    SETTINGS.get(0).copied()
}

/// Returns the `ObjId` of the protected object `key` in `bank`, or `None` when `key` is not
/// protected there.
fn protected_obj(bank: Bank, key: FileId) -> Option<ObjId> {
    unsafe { PROTECTED.get(&BankedFile::new(bank, key)).copied() }
}

/// Returns how many rules object `obj` has in `bank`, or `None` when it has no entry.
fn rule_count(bank: Bank, obj: ObjId) -> Option<u32> {
    unsafe { RULE_COUNT.get(&BankedObj::new(bank, obj)).copied() }
}

/// The program's license. The verifier rejects a program that calls GPL-only helpers, such
/// as `bpf_probe_read_kernel`, unless it declares a GPL-compatible license.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Verified code never reaches this, because panics are optimized out under
    // panic=abort. It exists only because `no_std` requires a panic handler.
    loop {}
}
