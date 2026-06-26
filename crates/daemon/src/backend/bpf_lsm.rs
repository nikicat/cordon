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
//! This root holds the lifecycle (load → attach → self-test → seed → drain). The two
//! growth areas live in submodules: [`seed`] (map writes — atomic double-buffer swap +
//! pinning land there) and [`events`] (ring drain — coalescing lands there).
//!
//! Requires **root** with `CAP_BPF` + `CAP_MAC_ADMIN`, `CONFIG_BPF_LSM=y`, **and**
//! `bpf` in the active LSM list (`lsm=…,bpf`).
//!
//! ## Scope (M1)
//! Open-time actions (`read`/`write`/`create`): deepest protected object → first
//! matching rule in its copy-down bucket → allow/deny/audit, with the global
//! `enforce`/`permissive`/`off` mode. The policy is compiled + seeded **once at
//! startup**; live `cordon policy apply` (atomic re-seed) and fail-safe **pinning** are
//! the next increments.

mod events;
mod seed;

use crate::btf::KernelBtf;
use crate::proc;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};
use cordon_bpf_common::offsets::GLOBAL_OFFSETS;
use cordon_bpf_common::{
    Action, CompiledRule, Mode as BpfMode, ObjId, Offsets, Pid, Policy, SubjectMatch,
};
use cordon_core::backend::{Backend, PolicyControl, Shutdown};
use cordon_core::policy::{self, CompiledPolicy, Diagnostic, Mode as PolicyMode, Severity};
use cordon_core::proto::{ObjectView, PolicyView};
use cordon_core::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

/// The LSM hook we attach to (the eBPF fn is `#[lsm(hook = "file_open")]`).
const HOOK: &str = "file_open";

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
        let mode = bpf_mode(compiled.mode);

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

        // Attach (maps still empty ⇒ allow-all, transient), then PROVE it enforces
        // before trusting it — a wrong-offset silent no-op must abort loudly.
        let program: &mut Lsm = ebpf
            .program_mut(HOOK)
            .ok_or_else(|| Error::msg(format!("bpf-lsm: program '{HOOK}' missing from object")))?
            .try_into()
            .map_err(|e| Error::msg(format!("bpf-lsm: '{HOOK}' is not an LSM program: {e}")))?;
        program
            .load(HOOK, &btf)
            .map_err(|e| Error::msg(format!("bpf-lsm: load program: {e}")))?;
        program
            .attach()
            .map_err(|e| Error::msg(format!("bpf-lsm: attach {HOOK}: {e}")))?;
        self_test(&mut ebpf)?;

        // Seed the real, compiled policy and publish it for `cordon policy show`.
        seed::seed_policy(&mut ebpf, &compiled, mode)?;
        *control.current.lock().unwrap() = Some(build_view(&compiled));

        info!(
            mode = mode_str(mode),
            objects = compiled.objects.len(),
            policy = %self.policy.display(),
            object = %self.object.display(),
            "bpf-lsm active on the file_open hook (self-test passed)",
        );

        // Drain the ring buffer + honor `policy apply` requests until shutdown.
        events::serve(&mut ebpf, &control, &shutdown)
    }
}

impl BpfLsmBackend {
    /// Startup: read + compile the policy file. Returns an error (refusing to seed) if
    /// it has any error-severity finding — a bad startup policy must not silently run.
    fn compile_policy(&self) -> Result<CompiledPolicy> {
        let text = std::fs::read_to_string(&self.policy).map_err(|e| {
            Error::msg(format!(
                "bpf-lsm: read policy {}: {e}",
                self.policy.display()
            ))
        })?;
        let compiled = compile_text(&text);
        if compiled.has_errors() {
            return Err(Error::msg(format!(
                "bpf-lsm: policy {} has errors; refusing to seed",
                self.policy.display()
            )));
        }
        Ok(compiled)
    }
}

/// Parse → resolve → compile policy text, logging diagnostics. Always returns a
/// `CompiledPolicy`: a structural parse/resolve failure becomes a single error
/// diagnostic (so `policy apply` can report it instead of the daemon crashing). The
/// caller decides whether to seed via [`CompiledPolicy::has_errors`].
pub(super) fn compile_text(text: &str) -> CompiledPolicy {
    let parsed = match policy::parse(text) {
        Ok(p) => p,
        Err(e) => return error_policy(e),
    };
    let resolved = match policy::resolve(&parsed, &policy_home()) {
        Ok(r) => r,
        Err(e) => return error_policy(e),
    };
    let compiled = policy::compile(&resolved, proc::file_id);
    for d in &compiled.diagnostics {
        match d.severity {
            Severity::Error => error!("policy: {d}"),
            Severity::Warning => warn!("policy: {d}"),
        }
    }
    compiled
}

/// Wrap a structural parse/resolve error as an otherwise-empty compiled policy
/// carrying it as one error diagnostic (its message already includes `line:col`).
fn error_policy(e: Error) -> CompiledPolicy {
    error!("policy: {e}");
    CompiledPolicy {
        mode: PolicyMode::Enforce,
        objects: Vec::new(),
        pending: Vec::new(),
        diagnostics: vec![Diagnostic {
            severity: Severity::Error,
            message: e.to_string(),
            pos: None,
        }],
    }
}

/// A human-facing view of a compiled policy for `cordon policy show`.
pub(super) fn build_view(c: &CompiledPolicy) -> PolicyView {
    PolicyView {
        mode: mode_str(bpf_mode(c.mode)).to_string(),
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

/// Map the policy's global mode to the kernel `Settings` mode.
fn bpf_mode(mode: PolicyMode) -> BpfMode {
    match mode {
        PolicyMode::Enforce => BpfMode::ENFORCE,
        PolicyMode::Permissive => BpfMode::PERMISSIVE,
        PolicyMode::Off => BpfMode::OFF,
    }
}

fn mode_str(mode: BpfMode) -> &'static str {
    match mode {
        BpfMode::PERMISSIVE => "permissive",
        BpfMode::OFF => "off",
        _ => "enforce",
    }
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
/// and inject [`Offsets::POISON`] for the fields read *after* the trusted `file`
/// pointer, so the dentry walk reads garbage, matches nothing, and would silently
/// allow — exactly the kernel-mismatch no-op the self-test must catch.
fn maybe_poison_offsets(offsets: &mut Offsets) {
    if std::env::var_os(POISON_OFFSETS_ENV).is_some() {
        warn!(
            "{POISON_OFFSETS_ENV} set — injecting poison offsets; the self-test MUST now \
             abort (test-only failure-path hook)"
        );
        // Keep the offsets applied to the *trusted* `file` ctx pointer real (the
        // verifier bounds-checks trusted-pointer math against `.rodata`, rejecting an
        // out-of-range value at load — a different, also-loud guard). Poison only the
        // downstream offsets (read out of kernel memory, no verifier constraint).
        *offsets = Offsets {
            file_f_path_dentry: offsets.file_f_path_dentry,
            file_f_inode: offsets.file_f_inode,
            file_f_mode: offsets.file_f_mode,
            file_f_flags: offsets.file_f_flags,
            ..Offsets::POISON
        };
    }
}

/// Prove the boundary actually enforces before trusting it. Protect a throwaway probe
/// directory with a single deny-all rule, make ourselves not-fast-allowed in enforce
/// mode, and confirm our own open of it is denied. A wrong-offset attach matches
/// nothing, the open is *allowed*, and we abort instead of pretending to protect.
fn self_test(ebpf: &mut Ebpf) -> Result<()> {
    let probe = std::env::temp_dir().join(format!("cordon-selftest.{}", std::process::id()));
    std::fs::create_dir_all(&probe)
        .map_err(|e| Error::msg(format!("bpf-lsm self-test: mkdir probe: {e}")))?;
    let outcome = run_self_test(ebpf, &probe);
    let _ = std::fs::remove_dir_all(&probe);
    outcome
}

fn run_self_test(ebpf: &mut Ebpf, probe: &Path) -> Result<()> {
    let id = proc::file_id(probe)
        .ok_or_else(|| Error::msg("bpf-lsm self-test: cannot resolve probe FileId"))?;
    let obj = ObjId(0);
    // A *silent* deny-all rule (any subject, any action) on the probe object; u32::MAX
    // pid so we are *not* fast-allowed; enforce so the deny actually blocks. SILENCE
    // (deny + no log) not DENY: the self-test only needs the open *blocked*, and a
    // logged probe-deny would spam a spurious record into the ring on every startup.
    seed::set_settings(ebpf, Pid(u32::MAX), BpfMode::ENFORCE)?;
    seed::protected_insert(ebpf, id, obj)?;
    seed::rules_set(
        ebpf,
        seed::rule_index(obj, 0),
        CompiledRule::new(SubjectMatch::ANY, Action::all(), Policy::SILENCE),
    )?;
    seed::rule_count_insert(ebpf, obj, 1)?;

    let opened = std::fs::File::open(probe);

    // Clean up the probe entries (the real seed also clears, but don't rely on it).
    let _ = seed::protected_remove(ebpf, id);
    let _ = seed::rule_count_remove(ebpf, obj);

    match opened {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Ok(_) => Err(Error::msg(
            "bpf-lsm self-test FAILED: a protected open was ALLOWED — the program is \
             attached but not enforcing (eBPF object vs running-kernel struct-layout \
             mismatch?). Refusing to run as a silent no-op.",
        )),
        Err(e) => Err(Error::msg(format!(
            "bpf-lsm self-test: probe open failed unexpectedly (not a deny): {e}"
        ))),
    }
}

/// `ebpf.map_mut(name)` with a uniform error. Private to this module; the `seed` and
/// `events` submodules reach it via `super::map_mut` (a child sees its ancestor's
/// private items).
fn map_mut<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut aya::maps::Map> {
    ebpf.map_mut(name)
        .ok_or_else(|| Error::msg(format!("bpf-lsm: map '{name}' missing from object")))
}
