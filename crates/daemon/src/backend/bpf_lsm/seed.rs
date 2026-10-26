//! The only way the daemon writes the BPF maps. [`Maps::seed`] turns a compiled policy
//! into the flat rule table (`PROTECTED`, `RULES`, `RULE_COUNT`) and `SETTINGS` with an
//! atomic bank flip, and the live blessings reach `BLESSED` through the same type.
//!
//! ## Single writer
//! Every map write goes through [`Maps`], over the `&mut Ebpf` that the backend thread
//! alone owns. The CLI has no handle, and applies and bless ops reach that thread over one
//! channel (see `cordon_core::backend::ControlMsg`). No map is shared with another
//! process either (see [`super::pin`]), so there is exactly one writer by construction.

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

/// The write access to one loaded program's maps. The backend thread builds one over its
/// `Ebpf` wherever it writes, so there is a single writer (see the module doc).
pub(super) struct Maps<'a>(pub(super) &'a mut Ebpf);

impl Maps<'_> {
    /// Seeds a compiled policy atomically (DESIGN §15.8), so a re-seed is never
    /// half-visible. The three rule maps are banked, which means each holds two
    /// generations, and `Settings.active_bank` selects the live one (see [`Bank`]). This
    /// fills the inactive bank, which the kernel never reads, and then flips `active_bank`
    /// in one `SETTINGS` write that also records this process as the fast-allowed daemon.
    /// The 4-byte `active_bank` cannot tear, and the daemon identity beside it never
    /// changes after startup, so a concurrent reader always sees a fully populated bank.
    /// On a never-seeded `SETTINGS` the first fill targets bank 1.
    ///
    /// Errors when `compiled` holds more than `MAX_OBJECTS` objects, the daemon's own
    /// executable cannot be resolved, or a map write fails.
    pub(super) fn seed(&mut self, compiled: &CompiledPolicy) -> Result<()> {
        // Guards the slot arithmetic against a caller that seeds a policy compile refused.
        if compiled.objects.len() > MAX_OBJECTS {
            return Err(Error::msg(format!(
                "bpf-lsm: {} protected objects exceed MAX_OBJECTS ({MAX_OBJECTS})",
                compiled.objects.len()
            )));
        }

        let target = self.current_bank()?.flip();

        // Drop the target bank's previous generation, so removed objects and paths don't
        // linger once the flip makes it live. RULES needs no clearing, because RULE_COUNT
        // gates the scan and every live slot is overwritten below.
        self.clear_bank(target)?;

        for obj in &compiled.objects {
            self.protected_insert(target, obj.file, obj.id)?;
            self.rule_count_insert(target, obj.id, obj.rules.len() as u32)?;
            for (i, rule) in obj.rules.iter().enumerate() {
                self.rules_set(rule_slot(target, obj.id, i as u32), *rule)?;
            }
        }

        // The flip.
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

    /// Returns the live bank that `SETTINGS` records. A never-seeded, zero-initialized
    /// `SETTINGS` reads as [`Bank::ZERO`], so the first [`seed`](Self::seed) targets
    /// bank 1.
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

    /// Registers a live blessing by mapping the carrier cgroup's id to its class. The
    /// entry is written in place, never through a bank (see [`MAP_BLESSED`]).
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

    /// Sets the one-element `SETTINGS` record, which holds the fast-allowed daemon
    /// identity and the live bank.
    pub(super) fn set_settings(&mut self, pid: Pid, exe: FileId, bank: Bank) -> Result<()> {
        self.array::<Settings>(MAP_SETTINGS)?
            .set(0, Settings::new(pid, bank, exe), 0)
            .context("bpf-lsm: set settings")
    }

    /// Removes `bank`'s entries from the keyed rule maps (`PROTECTED`, `RULE_COUNT`). The
    /// other bank, which is the live one during a re-seed, stays untouched.
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

/// Returns this daemon's own executable identity, which is the other half of the
/// fast-allow beside its pid (the kernel requires both, see [`Settings`]).
///
/// Errors when `/proc/self/exe` cannot be resolved. A zero id instead would leave the
/// daemon subject to its own policy, and a protected object it needs at seed time would
/// deny it. That reads as a mysterious policy bug rather than the missing identity it is.
///
/// The value is resolved once and then memoized, so do not make this re-read
/// `/proc/self/exe` per call. The kernel's side of the comparison is `mm->exe_file`, which
/// is fixed for the life of the process, so this value is a constant and re-deriving it can
/// only introduce disagreement. A package upgrade replaces the binary underneath a running
/// daemon, and from that moment `/proc/self/exe` reads `…/cordond (deleted)`. Both
/// outcomes of re-resolving are bad:
///   - `fs::canonicalize` fails with `ENOENT` on the `(deleted)` path (measured), so the
///     next `cordon policy apply` would be refused for no reason a user could act on.
///   - If it did resolve, it would name the new inode, which this process never exec'd.
///     The fast-allow would silently stop matching, and the daemon could deadlock on its
///     own I/O inside a protected object.
///
/// Memoizing pins the answer to the binary actually running, which is what the kernel
/// compares against, and makes an upgrade a non-event until the daemon restarts.
pub(super) fn daemon_exe() -> Result<FileId> {
    static EXE: OnceLock<Option<FileId>> = OnceLock::new();
    (*EXE.get_or_init(|| crate::proc::file_id(Path::new("/proc/self/exe"))))
        .ok_or_else(|| Error::msg("bpf-lsm: cannot resolve /proc/self/exe for the daemon identity"))
}
