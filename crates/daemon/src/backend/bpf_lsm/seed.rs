//! The control plane → BPF maps: seed the flat rule table (`PROTECTED` / `RULES` /
//! `RULE_COUNT`) and `SETTINGS` from a compiled policy, plus the typed map-write
//! helpers.
//!
//! ## Atomic apply — the double-buffer (DESIGN §15.8)
//! The three rule maps are **banked**: each holds two generations, and
//! `Settings.active_bank` selects the live one. [`Maps::seed`] fills the *inactive*
//! bank (the kernel never reads it) and then flips `active_bank` in one `SETTINGS`
//! write — an RCU-style publish, so a re-seed is never half-visible (no clear-then-
//! insert window). The flip hinges on the 4-byte `active_bank`, which can't tear; since the
//! daemon identity (`daemon_pid` + `daemon_exe`) never changes after startup, `active_bank`
//! is the only moving field, so a concurrent reader always observes a fully-populated bank
//! — never a torn pointer.
//!
//! ## Single writer
//! Every map write goes through [`Maps`], over the `&mut Ebpf` that the backend thread
//! alone owns; the CLI has no handle and `apply` requests are serialized through one mpsc channel. So
//! there is exactly one writer by construction — no userspace write/write race.
//!
//! M5's pinning does **not** change that, deliberately: it pins the LSM *links*, never the
//! maps, and adopts nothing on startup, so every daemon still creates its own private maps
//! (see [`super::pin`]). Sharing maps across processes is what would reintroduce a
//! cross-process writer — one daemon's bank fill interleaving another's flip into a torn
//! table — which is why adopt-existing-pins was dropped rather than guarded.

use aya::maps::{Array, HashMap as BpfHashMap, MapData};
use aya::{Ebpf, Pod};
use cordon_bpf_common::{
    Bank, BankedFile, BankedObj, CgroupId, ClassId, CompiledRule, FileId, MAP_BLESSED,
    MAP_PROTECTED, MAP_RULE_COUNT, MAP_RULES, MAP_SETTINGS, MAX_OBJECTS, ObjId, Pid, Settings,
    rule_slot,
};
use cordon_core::policy::CompiledPolicy;
use cordon_core::{Context, Error, Result};
use std::path::Path;
use std::sync::OnceLock;
use tracing::{info, warn};

/// The maps of one loaded program, for writing. The backend thread builds one over its
/// `Ebpf` wherever it writes, so there is a single writer (see the module doc).
pub(super) struct Maps<'a>(pub(super) &'a mut Ebpf);

impl Maps<'_> {
    /// Atomically seed a compiled policy: fill the inactive bank from `compiled`, then flip
    /// `active_bank` so the kernel switches to it in one update. Used both at startup (from
    /// the zero-initialized `SETTINGS`, so the first fill targets bank 1) and on every
    /// `cordon policy apply`.
    pub(super) fn seed(&mut self, compiled: &CompiledPolicy) -> Result<()> {
        // Compile already reports this as an error, which refuses the apply; this guards
        // the slot arithmetic against a caller that seeds anyway.
        if compiled.objects.len() > MAX_OBJECTS {
            return Err(Error::msg(format!(
                "bpf-lsm: {} protected objects exceed MAX_OBJECTS ({MAX_OBJECTS})",
                compiled.objects.len()
            )));
        }

        let target = self.current_bank()?.flip();

        // Drop the target bank's previous generation first, so removed objects/paths don't
        // linger once we flip to it. (RULES needs no clearing — RULE_COUNT gates the scan,
        // and every live slot is overwritten below.)
        self.clear_bank(target)?;

        for obj in &compiled.objects {
            self.protected_insert(target, obj.file, obj.id)?;
            self.rule_count_insert(target, obj.id, obj.rules.len() as u32)?;
            for (i, rule) in obj.rules.iter().enumerate() {
                self.rules_set(rule_slot(target, obj.id, i as u32), *rule)?;
            }
        }

        // The flip: publish the freshly-filled bank in one write.
        self.set_settings(Pid(std::process::id()), daemon_exe()?, target)?;

        info!(
            objects = compiled.objects.len(),
            pending = compiled.pending.len(),
            bank = target.index(),
            "bpf-lsm seeded compiled policy (atomic bank flip)"
        );
        if !compiled.pending.is_empty() {
            warn!(
                count = compiled.pending.len(),
                "bpf-lsm: some policy paths don't exist yet and aren't enforced until re-apply"
            );
        }
        Ok(())
    }

    /// The live bank, read from `SETTINGS`. A zero-initialized (never-seeded) `SETTINGS`
    /// reads as [`Bank::ZERO`], so the first [`seed`](Self::seed) targets bank 1.
    fn current_bank(&mut self) -> Result<Bank> {
        let s = self
            .array::<Settings>(MAP_SETTINGS)?
            .get(&0, 0)
            .context("bpf-lsm: read settings")?;
        Ok(s.active_bank.masked())
    }

    pub(super) fn protected_insert(&mut self, bank: Bank, file: FileId, obj: ObjId) -> Result<()> {
        self.hash::<BankedFile, ObjId>(MAP_PROTECTED)?
            .insert(BankedFile::new(bank, file), obj, 0)
            .context("bpf-lsm: insert protected")
    }

    pub(super) fn protected_remove(&mut self, bank: Bank, file: FileId) -> Result<()> {
        self.hash::<BankedFile, ObjId>(MAP_PROTECTED)?
            .remove(&BankedFile::new(bank, file))
            .context("bpf-lsm: remove protected")
    }

    pub(super) fn rule_count_insert(&mut self, bank: Bank, obj: ObjId, count: u32) -> Result<()> {
        self.hash::<BankedObj, u32>(MAP_RULE_COUNT)?
            .insert(BankedObj::new(bank, obj), count, 0)
            .context("bpf-lsm: insert rule count")
    }

    pub(super) fn rule_count_remove(&mut self, bank: Bank, obj: ObjId) -> Result<()> {
        self.hash::<BankedObj, u32>(MAP_RULE_COUNT)?
            .remove(&BankedObj::new(bank, obj))
            .context("bpf-lsm: remove rule count")
    }

    /// Register a live blessing: the carrier cgroup's id → its class. `MAP_BLESSED` is
    /// **unbanked** (blessings are runtime state, not policy — an apply remaps values in
    /// place by class name rather than re-seeding a generation).
    pub(super) fn blessed_insert(&mut self, cgroup: CgroupId, class: ClassId) -> Result<()> {
        self.hash::<CgroupId, ClassId>(MAP_BLESSED)?
            .insert(cgroup, class, 0)
            .context("bpf-lsm: insert blessed")
    }

    pub(super) fn blessed_remove(&mut self, cgroup: CgroupId) -> Result<()> {
        self.hash::<CgroupId, ClassId>(MAP_BLESSED)?
            .remove(&cgroup)
            .context("bpf-lsm: remove blessed")
    }

    pub(super) fn rules_set(&mut self, index: u32, rule: CompiledRule) -> Result<()> {
        self.array::<CompiledRule>(MAP_RULES)?
            .set(index, rule, 0)
            .with_context(|| format!("bpf-lsm: set rule[{index}]"))
    }

    /// Set the one-element `SETTINGS` record: the fast-allowed daemon identity and the live
    /// bank. Writing this with a flipped `bank` is the atomic policy publish.
    pub(super) fn set_settings(&mut self, pid: Pid, exe: FileId, bank: Bank) -> Result<()> {
        self.array::<Settings>(MAP_SETTINGS)?
            .set(0, Settings::new(pid, bank, exe), 0)
            .context("bpf-lsm: set settings")
    }

    /// Remove `bank`'s entries from the keyed rule maps (`PROTECTED`, `RULE_COUNT`), leaving
    /// the *other* bank — the live one during a re-seed — untouched.
    fn clear_bank(&mut self, bank: Bank) -> Result<()> {
        self.remove_where::<BankedFile, ObjId>(MAP_PROTECTED, |k| k.bank == bank)?;
        self.remove_where::<BankedObj, u32>(MAP_RULE_COUNT, |k| k.bank == bank)
    }

    /// Removes every key of the hash map `name` that `stale` picks.
    fn remove_where<K: Pod, V: Pod>(
        &mut self,
        name: &str,
        stale: impl Fn(&K) -> bool,
    ) -> Result<()> {
        let mut map = self.hash::<K, V>(name)?;
        let keys = map
            .keys()
            .collect::<std::result::Result<Vec<K>, _>>()
            .with_context(|| format!("bpf-lsm: list {name}"))?;
        for k in keys.iter().filter(|k| stale(k)) {
            map.remove(k)
                .with_context(|| format!("bpf-lsm: clear {name}"))?;
        }
        Ok(())
    }

    fn hash<K: Pod, V: Pod>(&mut self, name: &str) -> Result<BpfHashMap<&mut MapData, K, V>> {
        BpfHashMap::try_from(self.map(name)?).with_context(|| format!("bpf-lsm: {name}"))
    }

    fn array<V: Pod>(&mut self, name: &str) -> Result<Array<&mut MapData, V>> {
        Array::try_from(self.map(name)?).with_context(|| format!("bpf-lsm: {name}"))
    }

    fn map(&mut self, name: &str) -> Result<&mut aya::maps::Map> {
        self.0
            .map_mut(name)
            .ok_or_else(|| Error::msg(format!("bpf-lsm: map '{name}' missing from object")))
    }
}

/// This daemon's own executable identity, the other half of the fast-allow (the kernel
/// requires pid **and** exe, see [`Settings`]).
///
/// **Resolved once, then memoized — do not make this re-read `/proc/self/exe` per call.**
/// The kernel's side of the comparison is `mm->exe_file`, which is fixed for the life of the
/// process, so this value is a constant and re-deriving it can only introduce disagreement.
/// Concretely, a package upgrade replaces the binary underneath a *running* daemon, and from
/// that moment `/proc/self/exe` reads `…/cordond (deleted)`. Both outcomes of re-resolving
/// are bad:
///   - `fs::canonicalize` fails `ENOENT` on the `(deleted)` path (measured), so the next
///     `cordon policy apply` would be refused for no reason a user could act on; and
///   - if it *did* resolve, it would name the **new** inode, which this process never
///     exec'd — the fast-allow would silently stop matching and the daemon could deadlock
///     on its own I/O inside a protected object.
///
/// Memoizing pins the answer to the binary actually running, which is what the kernel
/// compares against, and makes an upgrade a non-event until the daemon restarts.
///
/// A hard error rather than a zero id: without it the daemon is subject to its own policy
/// and a protected object it needs at seed time would deny it, which reads as a mysterious
/// policy bug rather than the missing-identity it is.
pub(super) fn daemon_exe() -> Result<FileId> {
    static EXE: OnceLock<Option<FileId>> = OnceLock::new();
    (*EXE.get_or_init(|| crate::proc::file_id(Path::new("/proc/self/exe"))))
        .ok_or_else(|| Error::msg("bpf-lsm: cannot resolve /proc/self/exe for the daemon identity"))
}
