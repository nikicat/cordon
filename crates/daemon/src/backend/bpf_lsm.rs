//! The Linux BPF-LSM enforcement backend (DESIGN §4, §15).
//!
//! The eBPF program (`crates/bpf`) returns every verdict in-kernel from the rule table in
//! BPF maps, so this Rust code never sees an individual open. This module is the control
//! plane. It compiles the text policy (`cordon_core::policy`) and loads, attaches and
//! self-tests the program. Its submodules own the rest: [`seed`] writes the maps, [`pin`]
//! keeps the boundary up without a daemon, [`events`] drains logged decisions into the
//! journal, and [`bless`] owns the live blessings.
//!
//! A run (`BpfLsmBackend::run`) loads, attaches, self-tests, seeds, pins and drains, in
//! that order. The kernel and privilege requirements are listed in the README.

mod bless;
mod events;
// `pub(super)` for `PinDir::teardown`, which `backend::teardown` reaches without a backend.
pub(super) mod pin;
mod seed;

use pin::PinDir;
use seed::Maps;

use crate::btf::KernelBtf;
use crate::proc;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};
use cordon_bpf_common::offsets::GLOBAL_OFFSETS;
use cordon_bpf_common::{
    Action, Bank, CompiledRule, FileId, ObjId, Offsets, Policy, Settings, SubjectMatch,
};
use cordon_core::backend::{Backend, PolicyControl, Shutdown};
use cordon_core::policy::{self, CompiledPolicy, PolicySource, Severity};
use cordon_core::{Context, Error, Result};
use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

/// The test-only environment variable that forces deliberately wrong field offsets, so
/// that the self-test's failure path can be exercised end to end.
const POISON_OFFSETS_ENV: &str = "CORDON_SELFTEST_POISON_OFFSETS";

pub struct BpfLsmBackend {
    /// The path of the compiled eBPF object, which `just build-ebpf` or the package puts
    /// there.
    object: PathBuf,
    /// The bpffs directory that the LSM links are pinned under, with one subdirectory per
    /// run ([`pin`]).
    pin_dir: PinDir,
    /// The root-owned text policy that is compiled and seeded at startup.
    policy: PathBuf,
}

impl BpfLsmBackend {
    pub fn new(object: PathBuf, pin_dir: PathBuf, policy: PathBuf) -> Self {
        BpfLsmBackend {
            object,
            pin_dir: PinDir(pin_dir),
            policy,
        }
    }
}

impl Backend for BpfLsmBackend {
    fn run(self: Box<Self>, control: PolicyControl, shutdown: Arc<Shutdown>) -> Result<()> {
        // Compile the policy before loading anything, so a bad startup policy fails fast
        // without touching the kernel.
        let compiled = self.compile_policy()?;

        // Kernel BTF resolves each hook's BTF id for attach, and it sanitizes the
        // program's own BTF. The object carries no struct layout, so resolve the running
        // kernel's field offsets and inject them (see `Offsets`).
        let btf = Btf::from_sys_fs().context("bpf-lsm: kernel BTF")?;
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

        // Attach while the maps are still empty, so the hooks allow everything until the
        // seed. Then prove that the hooks enforce before trusting them (see `self_test`).
        //
        // Keep the `LsmLinkId`s, because they are the handle `PinDir::pin_links` takes. A
        // link left inside its `Program` detaches when `ebpf` drops, and enforcement would
        // end with the daemon.
        //
        // Every program in the object is an LSM program named after its hook, because aya
        // keys programs by their function symbol, and BTF resolves the same string as
        // `bpf_lsm_<hook>`. The object is the one list of hooks, and the self-test proves
        // each one mediates.
        let mut links = Vec::new();
        for (hook, program) in ebpf.programs_mut() {
            let program: &mut Lsm = program
                .try_into()
                .with_context(|| format!("bpf-lsm: '{hook}' is not an LSM program"))?;
            program
                .load(hook, &btf)
                .with_context(|| format!("bpf-lsm: load program {hook}"))?;
            let id = program
                .attach()
                .with_context(|| format!("bpf-lsm: attach {hook}"))?;
            links.push((hook.to_owned(), id));
        }
        self_test(&mut ebpf).inspect_err(|e| {
            error!(event = "self_test_failed", error = %e, "bpf-lsm self-test failed");
        })?;

        // Seed the real, compiled policy and publish it for `cordon policy show`.
        Maps(&mut ebpf).seed(&compiled)?;
        control.publish(&compiled);

        // Pinned last, with `pinned` held for the run. `PinDir::pin_links` says why.
        let pinned = self.pin_dir.pin_links(&mut ebpf, links)?;

        // The message is a fixed phrase that marks readiness, so it can be grepped for.
        // Context goes in fields, which tracing renders after the message.
        info!(
            event = "ready",
            objects = compiled.objects.len(),
            hooks = pinned.len(),
            policy = %self.policy.display(),
            object = %self.object.display(),
            "bpf-lsm active (self-test passed)",
        );

        // Build the per-run state that sits beside the `Ebpf` handle, and adopt the
        // carrier cgroups that a previous daemon run left behind (see
        // `Blessings::reconcile`).
        let mut runtime = events::Runtime::new(&compiled);
        runtime
            .blessings
            .reconcile(&mut Maps(&mut ebpf), &runtime.classes);

        // Drain the ring buffer and serve control requests until shutdown. The apply path
        // refreshes the runtime's maps on each re-seed.
        events::serve(&mut ebpf, &control, &shutdown, runtime)
    }
}

impl BpfLsmBackend {
    /// Returns the startup policy, compiled from its file or its conf.d directory of
    /// fragments.
    ///
    /// Errors when the policy cannot be read or has any error-severity finding, because a
    /// bad startup policy must not silently run.
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

/// Compiles the policy fragments `sources` and logs every diagnostic. A `~` in a fragment
/// with no `user =` header expands against [`policy_home`]. The result comes back even
/// when it has errors, and the caller decides by [`CompiledPolicy::has_errors`] whether to
/// seed it.
pub(super) fn compile_sources(sources: &[PolicySource]) -> CompiledPolicy {
    let compiled = policy::compile_fragments(sources, &policy::fallback_home(), proc::file_id);
    for d in &compiled.diagnostics {
        match d.severity {
            Severity::Error => error!("policy: {d}"),
            Severity::Warning => warn!("policy: {d}"),
        }
    }
    compiled
}

/// Returns the path of each protected object by its inode, which names objects in the
/// journal. A `DecisionEvent` carries only the object's [`FileId`], so this map reverses
/// the path-to-inode resolution done at seed time.
pub(super) fn object_paths(c: &CompiledPolicy) -> HashMap<FileId, PathBuf> {
    c.objects.iter().map(|o| (o.file, o.path.clone())).collect()
}

/// Replaces the offsets of the fields read out of kernel memory with [`Offsets::POISON`]
/// when [`POISON_OFFSETS_ENV`] is set. The dentry walk then reads garbage, matches nothing
/// and would silently allow, which is exactly the kernel-mismatch no-op that the self-test
/// must catch.
fn maybe_poison_offsets(offsets: &mut Offsets) {
    if std::env::var_os(POISON_OFFSETS_ENV).is_some() {
        warn!(
            "{POISON_OFFSETS_ENV} set — injecting poison offsets; the self-test MUST now \
             abort (test-only failure-path hook)"
        );
        // Keep every offset that is applied to a trusted ctx pointer real. The verifier
        // bounds-checks that math against `.rodata` and rejects an out-of-range value at
        // load. That is a different guard, and a loud one too, but it would abort before
        // the self-test could run and turn this failure-path test into a load failure. The
        // trusted arg is `file` at `file_open`, a dentry at the mutation hooks, and the
        // `linux_binprm` at `bprm_check_security`. So `dentry_d_*` and `binprm_file` are
        // trusted-pointer math too, and they must stay real.
        //
        // Poisoning only `sb_s_dev` and `inode_i_*` still yields a complete silent no-op.
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
            binprm_file: offsets.binprm_file,
            ..Offsets::POISON
        };
    }
}

/// Checks that every attached hook refuses an operation on a protected probe directory,
/// so the boundary is proven to enforce before it is trusted. Writes the probe's rules
/// into bank 0 of the maps, which the real seed then replaces.
///
/// Errors when any hook allows its operation, which is what a wrong-offset attach or a
/// hook that reads the wrong context argument does, or when the probe cannot be set up.
///
/// Each hook is exercised separately because "loaded and attached" is not "mediating".
/// The argument index a mutation hook reads is not type-checked, and getting it wrong
/// fails open in complete silence. This is the only thing that catches that.
fn self_test(ebpf: &mut Ebpf) -> Result<()> {
    let probe = make_probe(Path::new(PROBE_DIR))?;
    let outcome = run_self_test(&mut Maps(ebpf), &probe);
    let _ = std::fs::remove_dir_all(&probe);
    outcome
}

/// The root-only scratch directory for the self-test probe. It is deliberately not
/// `TMPDIR`, because the daemon is uid 0 and the self-test runs before `Maps::seed`, so
/// cordon is not yet enforcing on itself. In a world-writable directory a local user could
/// pre-create `cordon-selftest.<pid>/` holding `src -> /etc/cordon/policy.toml`, and pids
/// are sequential, so guessing is cheap. Root would then truncate the policy on the next
/// start, the daemon would fail to compile it, and the boundary would be off entirely.
/// `create_dir_all` accepts a pre-existing directory of any owner, and `fs::write` is
/// `O_WRONLY|O_CREAT|O_TRUNC` with no `O_NOFOLLOW`. `fs.protected_symlinks` does not help
/// either. It keys on the symlink's immediate parent being sticky and world-writable, and
/// the attacker's own plain directory is not.
///
/// `/run` is root-owned `0755`, so nothing unprivileged can plant any component of this path.
/// That removes the shared namespace outright rather than hardening each open against it.
const PROBE_DIR: &str = "/run/cordon";

/// Creates a fresh probe directory under `base` with its seed files, and returns its
/// path. `base` is [`PROBE_DIR`] outside tests.
///
/// Errors when the directory or a seed file cannot be created.
///
/// It never reuses a directory it finds. The probe is removed and recreated with
/// `create_dir`, so anything already on the path, and any symlink inside it, is gone before
/// the seed writes, which have no `O_NOFOLLOW`. Under [`PROBE_DIR`] nothing unprivileged
/// could have put it there in the first place, so this is the second line of defence, not
/// the first.
fn make_probe(base: &Path) -> Result<PathBuf> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(base)
        .with_context(|| format!("bpf-lsm self-test: mkdir {}", base.display()))?;
    let probe = base.join(format!("selftest.{}", std::process::id()));
    // A previous run that died before its cleanup leaves this behind, and pids are reused.
    let _ = std::fs::remove_dir_all(&probe);
    std::fs::create_dir(&probe).context("bpf-lsm self-test: mkdir probe")?;
    // Seed the files before the probe's rules go live, or the daemon's own rule would deny
    // creating them. `over` is the rename-over target. It is a positive destination dentry,
    // which is the one shape `link` can never produce.
    for name in ["src", "over", "exe"] {
        std::fs::write(probe.join(name), b"x")
            .with_context(|| format!("bpf-lsm self-test: seed probe {name}"))?;
    }
    // `exe` must carry the x bit or `do_open_execat`'s `may_open(MAY_EXEC)` refuses with
    // EACCES *before* `bprm_check_security` runs, and the probe would prove nothing.
    std::fs::set_permissions(probe.join("exe"), std::fs::Permissions::from_mode(0o755))
        .context("bpf-lsm self-test: chmod probe exe")?;
    Ok(probe)
}

/// Checks that the probe operation `what` was refused as permission denied.
///
/// Errors when the operation was allowed or failed for another reason.
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

fn run_self_test(maps: &mut Maps, probe: &Path) -> Result<()> {
    let id = proc::file_id(probe)
        .ok_or_else(|| Error::msg("bpf-lsm self-test: cannot resolve probe FileId"))?;
    let obj = ObjId(0);
    // Seed bank 0, which `active_bank` points at as its zero-initialized default, so the
    // probe is live. The real `Maps::seed` then fills bank 1 and flips away from this one.
    let bank = Bank::ZERO;
    // A silent deny-all rule (any subject, any action) on the probe object, with no
    // daemon fast-allowed, so this process is refused too. The rule is SILENCE (deny with
    // no log) rather than DENY, because the self-test only needs the open blocked, and a
    // logged probe deny would add a spurious record on every startup.
    maps.set_settings(Settings::no_daemon(bank))?;
    maps.seed_object(
        bank,
        id,
        obj,
        &[CompiledRule::new(
            SubjectMatch::ANY,
            Action::all(),
            Policy::SILENCE,
        )],
    )?;

    // A second object, for `execute` alone. It cannot be proven under the deny-all rule
    // above, because an exec opens the file first. `file_open` would refuse it, the
    // verdict would never reach `bprm_check_security`, and the probe would pass with that
    // hook detached. So this object allows the read and denies the rest, and only the
    // bprm hook itself can then refuse the exec. It nests inside the probe directory, and
    // `find_object` takes the deepest match, so this file's own rules win.
    let exec_obj = ObjId(1);
    let exec_path = probe.join("exe");
    let exec_id = proc::file_id(&exec_path)
        .ok_or_else(|| Error::msg("bpf-lsm self-test: cannot resolve exec probe FileId"))?;
    maps.seed_object(
        bank,
        exec_id,
        exec_obj,
        &[
            CompiledRule::new(SubjectMatch::ANY, Action::READ, Policy::ALLOW),
            CompiledRule::new(SubjectMatch::ANY, Action::all(), Policy::SILENCE),
        ],
    )?;

    // One operation per attached hook. `outside` is in the same directory as the probe, so
    // link and rename really reach the LSM hook instead of failing with `EXDEV` at the VFS
    // layer. The order leaves each operation something to act on. A link is
    // non-destructive, a rename would consume `src`, and an unlink would remove it.
    let src = probe.join("src");
    let outside = Path::new(PROBE_DIR).join(format!("selftest-out.{}", std::process::id()));
    let opened = std::fs::File::open(probe).map(drop);
    let linked = std::fs::hard_link(&src, &outside);
    let renamed = std::fs::rename(&src, &outside);
    let unlinked = std::fs::remove_file(&src);
    // Rename over an existing name, with both sides inside the object. The
    // pair-of-directories classification calls this an internal shuffle and allows it, so
    // only the destination dentry's own lookup refuses, which is the whole point of the
    // case. It comes last, because if it is wrongly allowed it consumes `src`.
    let clobbered = std::fs::rename(&src, probe.join("over"));
    // A negative dentry inside the object. `inode_mkdir` classifies by the parent, which no
    // other probe here exercises, because every other one starts from a positive dentry.
    let made = std::fs::create_dir(probe.join("sub"));
    // The exec probe: its object allows `read`, so reaching a refusal here means the verdict
    // came from `bprm_check_security` and not from the open.
    let executed = std::process::Command::new(&exec_path).status().map(drop);

    // Remove the probe entries. The first real seed fills bank 1 and leaves bank 0 alone, so
    // nothing else clears them until a later seed flips back here.
    let _ = maps.unseed_object(bank, id, obj);
    let _ = maps.unseed_object(bank, exec_id, exec_obj);
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
    expect_denied("mkdir inside the object (inode_mkdir)", made)?;
    expect_denied("exec of a protected binary (bprm_check_security)", executed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards against the planted-directory attack described at [`PROBE_DIR`].
    /// `make_probe` must recreate the probe directory and never reuse one it finds, or the
    /// seed writes follow a planted symlink.
    ///
    /// It drives a writable `base` because the test is unprivileged. That is the second
    /// line of defence. The first, the root-only location, is pinned below.
    #[test]
    fn the_probe_never_reuses_a_directory_it_found() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();

        // Stands in for /etc/cordon/policy.toml — a file outside the probe that root can write.
        let victim = base.join("policy.toml");
        std::fs::write(&victim, b"the live policy").unwrap();

        // Plant the probe directory, with `src` aimed at the victim. `src` is the name the
        // seed loop writes, so a reused directory redirects that write.
        let planted = base.join(format!("selftest.{}", std::process::id()));
        std::fs::create_dir_all(&planted).unwrap();
        std::os::unix::fs::symlink(&victim, planted.join("src")).unwrap();

        let probe = make_probe(&base).expect("probe creation");

        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "the live policy",
            "the seed write followed a planted symlink and truncated the victim"
        );
        assert!(
            !std::fs::symlink_metadata(probe.join("src"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the probe reused the planted directory instead of recreating it"
        );
    }

    /// Pins [`PROBE_DIR`] under the root-only `/run`. It checks the constant because an
    /// unprivileged test cannot write `/run`, and moving the probe under `TMPDIR` would
    /// reopen the hole with every other line intact.
    #[test]
    fn the_probe_lives_where_only_root_can_write() {
        assert!(
            PROBE_DIR.starts_with("/run/"),
            "the probe must sit in a root-only directory, got {PROBE_DIR}"
        );
    }
}
