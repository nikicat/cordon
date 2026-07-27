//! Linux **BPF-LSM** enforcement backend — the hardened boundary (DESIGN §4, §15).
//!
//! Control-plane / data-plane split:
//!   - **Data plane (in-kernel):** an eBPF program (`crates/bpf`) on the `file_open`
//!     LSM hook returns the verdict *in-kernel* by reading the flat rule table from
//!     BPF maps. It is the boundary; this Rust code never sees an individual open.
//!   - **Control plane (this module):** load + attach the program, **compile the text
//!     policy** (`cordon_core::policy`) and seed the maps from it ([`seed`]), and drain
//!     the ring buffer of logged decisions into the journal ([`events`]). The daemon is
//!     still required (for logging) but the verdict no longer depends on it.
//!
//! This root holds the lifecycle (load → attach → self-test → seed → drain). The work
//! lives in submodules: [`seed`] (map writes — the atomic double-buffer swap; fail-safe
//! pinning lands there next) and [`events`] (ring drain + event coalescing).
//!
//! Requires **root** with `CAP_BPF` + `CAP_MAC_ADMIN`, `CONFIG_BPF_LSM=y`, **and**
//! `bpf` in the active LSM list (`lsm=…,bpf`).
//!
//! ## Scope (M1)
//! Open-time actions (`read`/`write`/`create`): deepest protected object → first
//! matching rule in its copy-down bucket → allow/deny/audit. The per-rule `policy` is
//! the only enforcement level (no global mode, DESIGN §15.6). The policy is compiled +
//! seeded at startup and re-seeded by `cordon policy apply` via an **atomic
//! double-buffer swap** ([`seed`]).
//! Fail-safe **pinning** (enforcement surviving daemon death) is the next increment.

mod bless;
mod events;
mod seed;

use crate::btf::KernelBtf;
use crate::proc;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};
use cordon_bpf_common::offsets::GLOBAL_OFFSETS;
use cordon_bpf_common::{
    Action, Bank, ClassId, CompiledRule, FileId, ObjId, Offsets, Pid, Policy, SubjectMatch,
    rule_slot,
};
use cordon_core::backend::{Backend, PolicyControl, Shutdown};
use cordon_core::policy::{self, ClassName, CompiledPolicy, PolicySource, Severity};
use cordon_core::proto::{ObjectView, PolicyView};
use cordon_core::{Error, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

/// The LSM hooks we attach to. Each name does double duty: aya keys programs by their
/// **function symbol**, and the same string is the **kernel hook name** resolved from BTF
/// as `bpf_lsm_<hook>` — the eBPF side keeps them equal by naming each `#[lsm(hook = …)]`
/// fn after its hook.
///
/// `file_open` decides reads/writes/creates; the four mutation hooks make a *directory*
/// object sound, since a directory protects its children only by ancestry and a second
/// name (hardlink or rename) is an ancestry that avoids it (DESIGN §15.5).
const HOOKS: [&str; 5] = [
    "file_open",
    "inode_link",
    "inode_rename",
    "inode_unlink",
    "inode_rmdir",
];

/// Test-only env var: forces deliberately wrong field offsets so the self-test's
/// failure path can be exercised end-to-end.
const POISON_OFFSETS_ENV: &str = "CORDON_SELFTEST_POISON_OFFSETS";

pub struct BpfLsmBackend {
    /// The compiled eBPF object (`just build-ebpf` output / packaged install).
    object: PathBuf,
    /// bpffs directory for fail-safe pinning (reserved; see module scope note).
    #[allow(dead_code)]
    pin_dir: PathBuf,
    /// The root-owned text policy compiled + seeded at startup.
    policy: PathBuf,
}

impl BpfLsmBackend {
    pub fn new(object: PathBuf, pin_dir: PathBuf, policy: PathBuf) -> Self {
        BpfLsmBackend {
            object,
            pin_dir,
            policy,
        }
    }
}

impl Backend for BpfLsmBackend {
    fn name(&self) -> &str {
        "bpf-lsm"
    }

    fn run(self: Box<Self>, control: PolicyControl, shutdown: Arc<Shutdown>) -> Result<()> {
        // Compile the policy *before* loading anything — a bad startup policy fails
        // fast, without touching the kernel.
        let compiled = self.compile_policy()?;

        // Kernel BTF resolves the hook's BTF id for attach (and sanitizes the program's
        // own BTF). The object carries no struct layout (rustc can't emit CO-RE
        // relocations); resolve the running kernel's field offsets and inject them.
        let btf =
            Btf::from_sys_fs().map_err(|e| Error::msg(format!("bpf-lsm: kernel BTF: {e}")))?;
        let mut offsets = KernelBtf::from_running_kernel()?.offsets()?;
        maybe_poison_offsets(&mut offsets);

        let mut ebpf = EbpfLoader::new()
            .verifier_log_level(aya::VerifierLogLevel::VERBOSE)
            .btf(Some(&btf))
            .override_global(GLOBAL_OFFSETS, &offsets, true)
            .load_file(&self.object)
            .map_err(|e| {
                Error::msg(format!(
                    "bpf-lsm: load {}: {e} (build it with `just build-ebpf`)",
                    self.object.display()
                ))
            })?;

        // Attach (maps still empty ⇒ allow-all, transient), then PROVE they enforce
        // before trusting them — a wrong-offset silent no-op must abort loudly.
        for hook in HOOKS {
            let program: &mut Lsm = ebpf
                .program_mut(hook)
                .ok_or_else(|| {
                    Error::msg(format!("bpf-lsm: program '{hook}' missing from object"))
                })?
                .try_into()
                .map_err(|e| Error::msg(format!("bpf-lsm: '{hook}' is not an LSM program: {e}")))?;
            program
                .load(hook, &btf)
                .map_err(|e| Error::msg(format!("bpf-lsm: load program {hook}: {e}")))?;
            program
                .attach()
                .map_err(|e| Error::msg(format!("bpf-lsm: attach {hook}: {e}")))?;
        }
        self_test(&mut ebpf)?;

        // Seed the real, compiled policy and publish it for `cordon policy show`.
        seed::seed_policy(&mut ebpf, &compiled)?;
        *control.current.lock().unwrap() = Some(build_view(&compiled));

        // The message text is load-bearing beyond readability: the VM smoke's readiness
        // gate greps "active on the file_open hook", and every scenario waits on it. Extra
        // context goes in *fields*, which tracing renders after the message.
        info!(
            objects = compiled.objects.len(),
            hooks = HOOKS.len(),
            policy = %self.policy.display(),
            object = %self.object.display(),
            "bpf-lsm active on the file_open hook (self-test passed)",
        );

        // The per-run state beside the Ebpf handle (journal naming maps, class
        // registry, blessings table), then adopt any carrier cgroups a previous
        // daemon run left behind (its map entries died with it).
        let mut runtime = events::Runtime::new(&compiled);
        runtime.blessings.reconcile(&mut ebpf, &runtime.registry);

        // Drain the ring buffer + honor control requests (applies, bless ops) until
        // shutdown; the apply path refreshes the runtime's maps on each re-seed.
        events::serve(&mut ebpf, &control, &shutdown, runtime)
    }
}

impl BpfLsmBackend {
    /// Startup: read + compile the policy source (a file, or a conf.d directory of
    /// fragments). Returns an error (refusing to seed) if it has any error-severity
    /// finding — a bad startup policy must not silently run.
    fn compile_policy(&self) -> Result<CompiledPolicy> {
        let sources = policy::load_policy(&self.policy)?;
        let compiled = compile_sources(&sources);
        if compiled.has_errors() {
            return Err(Error::msg(format!(
                "bpf-lsm: policy {} has errors; refusing to seed",
                self.policy.display()
            )));
        }
        Ok(compiled)
    }
}

/// Resolve (each fragment's own `user =` home, else the daemon `$HOME`) → merge →
/// compile a set of policy fragments, logging diagnostics. Always returns a
/// `CompiledPolicy`: a per-fragment parse/resolve failure is folded in as an error
/// diagnostic naming the fragment (so `policy apply` reports it instead of the daemon
/// crashing). The caller decides whether to seed via [`CompiledPolicy::has_errors`].
pub(super) fn compile_sources(sources: &[PolicySource]) -> CompiledPolicy {
    let compiled = policy::compile_fragments(sources, &policy_home(), proc::file_id);
    for d in &compiled.diagnostics {
        match d.severity {
            Severity::Error => error!("policy: {d}"),
            Severity::Warning => warn!("policy: {d}"),
        }
    }
    compiled
}

/// A human-facing view of a compiled policy for `cordon policy show`.
pub(super) fn build_view(c: &CompiledPolicy) -> PolicyView {
    PolicyView {
        objects: c
            .objects
            .iter()
            .map(|o| ObjectView {
                path: o.path.clone(),
                rules: o.rules.len(),
            })
            .collect(),
        pending: c.pending.clone(),
    }
}

/// The protected objects' `inode → path` map, for naming objects in the journal. The
/// kernel can't resolve paths at `file_open` (`bpf_d_path` is disallowed there), so a
/// `DecisionEvent` carries the object's `FileId`; this is the reverse of the path→inode
/// resolution the daemon did at seed time. Rebuilt on every apply (inodes are stable, but
/// the *set* of protected objects changes).
pub(super) fn object_paths(c: &CompiledPolicy) -> HashMap<FileId, PathBuf> {
    c.objects.iter().map(|o| (o.file, o.path.clone())).collect()
}

/// The blessing classes' `id → name` map, for naming a blessed caller's class in the
/// journal (a `DecisionEvent` carries only the dense [`ClassId`]). The reverse of the
/// compiler's registry. Rebuilt on every apply — ids are renumbered per compile
/// (dense, name-sorted), so a stale map would name the wrong class.
pub(super) fn class_names(c: &CompiledPolicy) -> HashMap<ClassId, ClassName> {
    c.blessing_classes
        .iter()
        .map(|(name, id)| (*id, name.clone()))
        .collect()
}

/// The compile's blessing-class registry (`name → ClassId`) — what `cordon bless`
/// resolves `--class` against and what an apply remaps live blessings with. A
/// `BTreeMap` so error messages list the classes in stable (name) order.
pub(super) fn class_registry(c: &CompiledPolicy) -> std::collections::BTreeMap<ClassName, ClassId> {
    c.blessing_classes.iter().cloned().collect()
}

/// Where `~` in the (system-wide, root-owned) policy expands to. M1 uses the daemon's
/// `$HOME` (so a user-session dev daemon resolves its own home); multi-user `~` is a
/// later refinement — system policies can always use absolute paths.
fn policy_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}

/// Test hook for the self-test's *failure* path: throw away the BTF-resolved offsets
/// and inject [`Offsets::POISON`] for the fields read out of kernel memory, so the dentry
/// walk reads garbage, matches nothing, and would silently allow — exactly the
/// kernel-mismatch no-op the self-test must catch.
fn maybe_poison_offsets(offsets: &mut Offsets) {
    if std::env::var_os(POISON_OFFSETS_ENV).is_some() {
        warn!(
            "{POISON_OFFSETS_ENV} set — injecting poison offsets; the self-test MUST now \
             abort (test-only failure-path hook)"
        );
        // Keep real every offset applied to a **trusted ctx pointer**: the verifier
        // bounds-checks that math against `.rodata` and rejects an out-of-range value at
        // *load*, which is a different (also loud) guard — but one that would abort before
        // the self-test could run, turning this failure-path test into a load failure.
        // The trusted arg is `file` at `file_open` and a *dentry* at the mutation hooks,
        // so the `dentry_d_*` offsets are trusted-pointer math too and must stay real.
        //
        // Poisoning `sb_s_dev`/`inode_i_*` alone still yields a complete silent no-op:
        // `find_object`'s very first read is `dentry.super_block()?.dev()?`, so every walk
        // faults out and matches nothing.
        *offsets = Offsets {
            file_f_path_dentry: offsets.file_f_path_dentry,
            file_f_inode: offsets.file_f_inode,
            file_f_mode: offsets.file_f_mode,
            file_f_flags: offsets.file_f_flags,
            dentry_d_inode: offsets.dentry_d_inode,
            dentry_d_sb: offsets.dentry_d_sb,
            dentry_d_parent: offsets.dentry_d_parent,
            dentry_d_name_name: offsets.dentry_d_name_name,
            ..Offsets::POISON
        };
    }
}

/// Prove the boundary actually enforces before trusting it. Protect a throwaway probe
/// directory with a single deny-all rule, make ourselves not-fast-allowed, and confirm
/// that **every** attached hook refuses. A wrong-offset attach — or a hook reading the
/// wrong context argument — matches nothing, the operation is *allowed*, and we abort
/// instead of pretending to protect.
///
/// Each hook is exercised separately because "loaded and attached" is not "mediating":
/// the argument index a mutation hook reads is not type-checked, and getting it wrong
/// fails open in complete silence. This is the only thing that catches that.
fn self_test(ebpf: &mut Ebpf) -> Result<()> {
    let probe = std::env::temp_dir().join(format!("cordon-selftest.{}", std::process::id()));
    std::fs::create_dir_all(&probe)
        .map_err(|e| Error::msg(format!("bpf-lsm self-test: mkdir probe: {e}")))?;
    // Seeded *before* the object goes live, or creating them would be denied by our own
    // rule. `over` is the rename-over target: a *positive* destination dentry, which is the
    // one shape `link` can never produce.
    for name in ["src", "over"] {
        std::fs::write(probe.join(name), b"x")
            .map_err(|e| Error::msg(format!("bpf-lsm self-test: seed probe {name}: {e}")))?;
    }
    let outcome = run_self_test(ebpf, &probe);
    let _ = std::fs::remove_dir_all(&probe);
    outcome
}

/// One hook's expectation: the operation must have been refused with `EPERM`.
fn expect_denied(what: &str, result: std::io::Result<()>) -> Result<()> {
    match result {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Ok(()) => Err(Error::msg(format!(
            "bpf-lsm self-test FAILED: a protected {what} was ALLOWED — the program is \
             attached but not enforcing (wrong hook argument index, or eBPF object vs \
             running-kernel struct-layout mismatch?). Refusing to run as a silent no-op."
        ))),
        Err(e) => Err(Error::msg(format!(
            "bpf-lsm self-test: probe {what} failed unexpectedly (not a deny): {e}"
        ))),
    }
}

fn run_self_test(ebpf: &mut Ebpf, probe: &Path) -> Result<()> {
    let id = proc::file_id(probe)
        .ok_or_else(|| Error::msg("bpf-lsm self-test: cannot resolve probe FileId"))?;
    let obj = ObjId(0);
    // Seed bank 0 and point `active_bank` at it (the zero-initialized default), so the
    // probe is live; the real `seed_policy` then fills bank 1 and flips away from this.
    let bank = Bank::ZERO;
    // A *silent* deny-all rule (any subject, any action) on the probe object; u32::MAX
    // pid so we are *not* fast-allowed (a denying policy always blocks — there is no
    // global mode). SILENCE (deny + no log) not DENY: the self-test only needs the open
    // *blocked*, and a logged probe-deny would spam a spurious record on every startup.
    seed::set_settings(ebpf, Pid(u32::MAX), bank)?;
    seed::protected_insert(ebpf, bank, id, obj)?;
    seed::rules_set(
        ebpf,
        rule_slot(bank, obj, 0),
        CompiledRule::new(SubjectMatch::ANY, Action::all(), Policy::SILENCE),
    )?;
    seed::rule_count_insert(ebpf, bank, obj, 1)?;

    // One operation per attached hook. `outside` is in the same directory as the probe so
    // link/rename really reach the LSM hook instead of failing `EXDEV` at the VFS layer.
    // Ordered so each still has something to act on: link is non-destructive, rename would
    // consume `src`, unlink would remove it.
    let src = probe.join("src");
    let outside = std::env::temp_dir().join(format!("cordon-selftest-out.{}", std::process::id()));
    let opened = std::fs::File::open(probe).map(drop);
    let linked = std::fs::hard_link(&src, &outside);
    let renamed = std::fs::rename(&src, &outside);
    let unlinked = std::fs::remove_file(&src);
    // Rename *over* an existing name, both sides inside the object. The pair-of-directories
    // classification calls this an internal shuffle and allows it, so only the destination
    // dentry's own lookup refuses — which is the whole point of the case. Last, because if
    // it is wrongly allowed it consumes `src`.
    let clobbered = std::fs::rename(&src, probe.join("over"));

    // Clean up the probe entries (the real seed also clears, but don't rely on it).
    let _ = seed::protected_remove(ebpf, bank, id);
    let _ = seed::rule_count_remove(ebpf, bank, obj);
    // Only exists if a hook let us through, i.e. if we are about to abort anyway.
    let _ = std::fs::remove_file(&outside);

    expect_denied("open (file_open)", opened)?;
    expect_denied("hardlink out (inode_link)", linked)?;
    expect_denied("rename out (inode_rename)", renamed)?;
    expect_denied("unlink (inode_unlink)", unlinked)?;
    expect_denied(
        "rename over a protected name (inode_rename, destroy)",
        clobbered,
    )?;
    Ok(())
}

/// `ebpf.map_mut(name)` with a uniform error. Private to this module; the `seed` and
/// `events` submodules reach it via `super::map_mut` (a child sees its ancestor's
/// private items).
fn map_mut<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut aya::maps::Map> {
    ebpf.map_mut(name)
        .ok_or_else(|| Error::msg(format!("bpf-lsm: map '{name}' missing from object")))
}
