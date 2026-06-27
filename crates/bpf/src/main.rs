//! cordon's eBPF data plane: the `file_open` LSM hook that returns the access
//! verdict **in-kernel** (DESIGN §4, §15). The userspace daemon (`crates/daemon`,
//! `bpf-lsm` backend) compiles the text policy, loads this object, fills its maps,
//! and drains its ring buffer — but it is this program, not the daemon, that decides.
//!
//! ## The decision (rule model, M1)
//! For each `open` (reading the live double-buffer `bank` from `SETTINGS.active_bank`,
//! so a `policy apply` flips the whole table atomically — DESIGN §15.8):
//!   1. Global mode `off` ⇒ allow; fast-allow the daemon's own pid.
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
//!   5. No matching rule ⇒ **default-deny** (DESIGN §15.6.3). A denying policy blocks
//!      only in `enforce`; `permissive` downgrades it to a logged allow. When the
//!      matched policy logs (`audit`/`deny`), the in-kernel suppressor throttles a
//!      repeat burst to one `DecisionEvent` + a folded count (M1 §1g) before emitting.
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
    Action, Bank, BankedFile, BankedObj, CompiledRule, Decision, DecisionEvent, FileId, MAX_OBJECTS,
    MAX_RULES_PER_OBJ, NUM_BANKS, ObjId, Policy, Settings, SubjectMatch, rule_slot,
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
/// The one-element control record (daemon pid + global mode + live bank).
#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

/// The matched protected object.
struct Match {
    obj: ObjId,
    object: FileId,
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    // `None` anywhere in the flow ⇒ couldn't decide ⇒ fail open.
    decide(&ctx).unwrap_or(Verdict::Allow).to_lsm()
}

fn decide(ctx: &LsmContext) -> Option<Verdict> {
    let settings = settings()?;

    // (1) boundary off, or our own I/O → allow.
    if settings.mode.is_off() {
        return Some(Verdict::Allow);
    }
    let pid = kernel::current_pid();
    if pid == settings.daemon_pid {
        return Some(Verdict::Allow);
    }
    // The live double-buffer generation, masked to a valid bank (a torn/garbage read
    // can't escape the array — it just resolves to an empty bucket → fail-open allow).
    let bank = settings.active_bank.masked();

    // file_open(struct file *file): arg 0.
    let file = kernel::File::from_arg(ctx, 0);

    // (2) most-specific protected object, or unprotected → allow.
    let Some(matched) = find_object(file, bank) else {
        return Some(Verdict::Allow);
    };

    // (3) requested action; an open that neither reads, writes, nor creates (e.g.
    // O_PATH) touches no content → allow, don't even scan.
    let requested = requested_action(file)?;
    if requested.is_empty() {
        return Some(Verdict::Allow);
    }

    // (4)/(5) caller exe → first matching rule, else default-deny.
    let exe = kernel::caller_exe()?;
    let policy = match_rule(matched.obj, requested, exe, bank).unwrap_or(Policy::DENY);

    let blocked = policy.denies() && settings.mode.enforces();
    // Emit only when the policy logs *and* the suppressor lets this one through (a tight
    // repeat-open burst collapses to its first event + a folded `suppressed` count).
    if policy.logs() {
        if let Some(suppressed) = kernel::throttle(exe, matched.obj, requested) {
            let decision = if !policy.denies() {
                Decision::AUDIT
            } else if blocked {
                Decision::DENY
            } else {
                Decision::WOULD_DENY
            };
            kernel::emit(DecisionEvent::new(
                pid,
                exe,
                matched.object,
                matched.obj,
                requested,
                decision,
                policy,
                suppressed,
            ));
        }
    }
    Some(if blocked { Verdict::Deny } else { Verdict::Allow })
}

/// Walk the opened file's dentry ancestors; return the first (deepest, hence
/// most-specific) one whose (dev, ino) is a protected object in the active `bank`.
fn find_object(file: kernel::File, bank: Bank) -> Option<Match> {
    let mut dentry = file.dentry()?;
    for _ in 0..MAX_ANCESTORS {
        let id = FileId::new(dentry.super_block()?.dev()?, dentry.inode()?.ino()?);
        if let Some(obj) = protected_obj(bank, id) {
            return Some(Match { obj, object: id });
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
/// rule's policy whose action mask intersects `requested` and whose subject matches
/// `exe`. `None` ⇒ no matching rule (the caller applies default-deny).
fn match_rule(obj: ObjId, requested: Action, exe: FileId, bank: Bank) -> Option<Policy> {
    let count = rule_count(bank, obj).unwrap_or(0);
    for i in 0..MAX_RULES_PER_OBJ {
        if i as u32 >= count {
            break;
        }
        // `Array::get` is bounds-checked (safe in aya); a stray index yields `None`.
        let rule: CompiledRule = *RULES.get(rule_slot(bank, obj, i as u32))?;
        if rule.action_mask.intersects(requested) && subject_matches(rule.subject, exe) {
            return Some(rule.policy);
        }
    }
    None
}

/// Whether a subject predicate matches the caller. M1 matches on `exe` only (honoring
/// the wildcard flag); `uid`/`cgroup` matching is M2 (DESIGN §15.4) — the compiler
/// never emits non-wildcard `uid`/`cgroup` yet, so exe-or-any is complete for M1.
fn subject_matches(subject: SubjectMatch, exe: FileId) -> bool {
    subject.flags & SubjectMatch::FLAG_EXE_ANY != 0 || subject.exe == exe
}

// ---- safe wrappers over the policy-map lookups ----------------------------
// aya's `HashMap::get` is `unsafe` (it hands back a reference into concurrently
// mutable map memory); copying the value out behind a safe fn keeps the decision flow
// `unsafe`-free. `Array::get` is already safe (bounds-checked).

/// The one-element settings record (daemon pid + mode).
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
