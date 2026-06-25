//! cordon's eBPF data plane: the `file_open` LSM hook that returns the access
//! verdict **in-kernel** (DESIGN §4). The userspace daemon (`crates/daemon`,
//! `bpf-lsm` backend) loads this object, fills its maps from the store, and drains
//! its ring buffer — but it is this program, not the daemon, that decides.
//!
//! ## The decision (increment 1 — `fanotify` parity, in-kernel)
//! For each `open`:
//!   1. Fast-allow the daemon's own pid (never deadlock on our own I/O).
//!   2. Walk the opened file's dentry ancestors; the first one whose **(dev, ino)**
//!      is in `SUBTREES` is the most-specific protected subtree → its owner id.
//!      No match ⇒ unprotected ⇒ allow.
//!   3. Resolve the caller's exe path (`bpf_d_path`) and hash it; if `(owner, hash)`
//!      is in `OWNER_IDS` the caller is an owner ⇒ allow.
//!   4. Otherwise push a `LearnEvent` and return `-EPERM` (enforce) or allow (audit).
//!
//! Anything we can't read fails **open** — `None` from a [`kernel`] handle becomes
//! an allow. All `unsafe` (kernel reads, `d_path`, ring writes) lives in [`kernel`];
//! this file is the decision flow only.
//!
//! NOTE: this compiles against the running kernel's BTF to a valid object, but
//! load/verify/enforce is validated in a virtme-ng VM booted with `lsm=…,bpf` (the
//! host kernel omits `bpf` from its active LSM list). Points for the verifier/
//! allowlist to confirm there: `bpf_d_path` on `file_open`, and the bounded
//! exe-hash loop.

#![no_std]
#![no_main]

mod kernel;
// Generated from the kernel BTF by `aya-tool` and committed (so building needs no
// libclang). These lints are exempted *for this module only* — our hand-written
// code is still linted. `unnecessary_transmutes` fires inside bindgen's bitfield
// accessors, which we never call; there's nothing to fix short of hand-editing
// generated output, which regenerating for another kernel would wipe.
#[allow(
    nonstandard_style,
    dead_code,
    unnecessary_transmutes,
    improper_ctypes_definitions,
    clippy::all
)]
mod vmlinux;

use aya_ebpf::macros::{lsm, map};
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::LsmContext;
use cordon_bpf_common::{OwnerId, OwnerKey, Settings, SubtreeKey};

/// The hook's verdict. The kernel wants a raw return (`0` allow / negative errno
/// deny), but only the LSM ABI at the `file_open` signature does — the decision
/// flow speaks `Verdict` and converts once, at that boundary.
#[derive(Clone, Copy)]
enum Verdict {
    Allow,
    Deny,
}

impl Verdict {
    /// The errno we deny with: `EPERM`.
    const EPERM: i32 = 1;

    /// Into the LSM return convention.
    fn to_lsm(self) -> i32 {
        match self {
            Verdict::Allow => 0,
            Verdict::Deny => -Self::EPERM,
        }
    }
}

/// Bound the dentry ancestor walk so a pathological chain can't spin the verifier
/// (and to keep the program within the instruction budget).
const MAX_ANCESTORS: usize = 32;

// ---- policy maps (filled by the daemon from the store) --------------------

#[map]
static SUBTREES: HashMap<SubtreeKey, OwnerId> = HashMap::with_max_entries(4096, 0);
#[map]
static OWNER_IDS: HashMap<OwnerKey, u8> = HashMap::with_max_entries(4096, 0);
#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

/// The matched protected subtree.
struct Match {
    owner: OwnerId,
    dev: cordon_bpf_common::Dev,
    ino: cordon_bpf_common::Ino,
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    // `None` anywhere in the flow ⇒ couldn't decide ⇒ fail open.
    decide(&ctx).unwrap_or(Verdict::Allow).to_lsm()
}

fn decide(ctx: &LsmContext) -> Option<Verdict> {
    let settings = settings()?;

    // (1) fast-allow ourselves.
    let pid = kernel::current_pid();
    if pid == settings.daemon_pid {
        return Some(Verdict::Allow);
    }

    // file_open(struct file *file): arg 0.
    let file = kernel::File::from_arg(ctx, 0);

    // (2) most-specific protected subtree, or unprotected → allow.
    let Some(matched) = find_subtree(file) else {
        return Some(Verdict::Allow);
    };

    // (3) owner identity: hash the caller's exe and look up membership.
    let exe = kernel::caller_exe_hash()?;
    if is_owner(OwnerKey::new(matched.owner, exe)) {
        return Some(Verdict::Allow);
    }

    // (4) protected, non-owner → learn + deny (or would-deny in audit mode).
    kernel::emit(
        file,
        pid,
        matched.owner,
        matched.dev,
        matched.ino,
        exe,
        settings.mode,
    );
    Some(if settings.mode.enforces() {
        Verdict::Deny
    } else {
        Verdict::Allow
    })
}

/// Walk the opened file's dentry ancestors; return the first (deepest, hence
/// most-specific) one whose (dev, ino) is a protected subtree root.
fn find_subtree(file: kernel::File) -> Option<Match> {
    let mut dentry = file.dentry()?;
    for _ in 0..MAX_ANCESTORS {
        let dev = dentry.super_block()?.dev()?;
        let ino = dentry.inode()?.ino()?;
        if let Some(owner) = subtree_owner(SubtreeKey::new(dev, ino)) {
            return Some(Match { owner, dev, ino });
        }
        let parent = dentry.parent()?;
        if parent == dentry {
            break; // mount root — d_parent points at itself
        }
        dentry = parent;
    }
    None
}

// ---- safe wrappers over the policy-map lookups ----------------------------
// aya's `HashMap::get`/`Array::get` are `unsafe` (they hand back a reference into
// concurrently-mutable map memory); copying the value out behind a safe fn keeps
// the decision flow `unsafe`-free.

/// The one-element settings record (daemon pid + mode). `Array::get` is safe in
/// aya (bounds-checked); only `HashMap::get` hands back a reference into mutable
/// map memory and is `unsafe`.
fn settings() -> Option<Settings> {
    SETTINGS.get(0).copied()
}

/// The owner of a protected subtree keyed by (dev, ino), if any.
fn subtree_owner(key: SubtreeKey) -> Option<OwnerId> {
    unsafe { SUBTREES.get(&key).copied() }
}

/// Whether (owner, exe-hash) is a known owner identity.
fn is_owner(key: OwnerKey) -> bool {
    unsafe { OWNER_IDS.get(&key).is_some() }
}

/// eBPF programs that call GPL-only helpers (`bpf_d_path`, `bpf_probe_read_kernel`)
/// must declare a GPL-compatible license, or the verifier rejects the load.
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
