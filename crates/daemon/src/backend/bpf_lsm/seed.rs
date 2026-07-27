//! The control plane → BPF maps: seed the flat rule table (`PROTECTED` / `RULES` /
//! `RULE_COUNT`) and `SETTINGS` from a compiled policy, plus the typed map-write
//! helpers.
//!
//! ## Atomic apply — the double-buffer (DESIGN §15.8)
//! The three rule maps are **banked**: each holds two generations, and
//! `Settings.active_bank` selects the live one. [`seed_policy`] fills the *inactive*
//! bank (the kernel never reads it) and then flips `active_bank` in one `SETTINGS`
//! write — an RCU-style publish, so a re-seed is never half-visible (no clear-then-
//! insert window). The flip hinges on the 4-byte `active_bank`, which can't tear; since
//! `daemon_pid` never changes after startup, `active_bank` is the only moving field, so a
//! concurrent reader always observes a fully-populated bank — never a torn pointer.
//!
//! ## Single writer
//! Every map write goes through `&mut Ebpf`, owned solely by the backend thread; the
//! CLI has no handle and `apply` requests are serialized through one mpsc channel. So
//! there is exactly one writer by construction — no userspace write/write race. (Maps
//! are not pinned/shared yet; when pinning lands (M5), adopting shared pins must come
//! with a singleton guard, since *that* would reintroduce a cross-process writer.)
//!
//! Fail-safe **pinning** is the remaining growth area here.

use super::map_mut;
use aya::Ebpf;
use aya::maps::{Array, HashMap as BpfHashMap};
use cordon_bpf_common::{
    Bank, BankedFile, BankedObj, CgroupId, ClassId, CompiledRule, FileId, MAP_BLESSED,
    MAP_PROTECTED, MAP_RULE_COUNT, MAP_RULES, MAP_SETTINGS, MAX_OBJECTS, ObjId, Pid, Settings,
    rule_slot,
};
use cordon_core::policy::CompiledPolicy;
use cordon_core::{Error, Result};
use tracing::{info, warn};

/// Atomically seed a compiled policy: fill the inactive bank from `compiled`, then flip
/// `active_bank` so the kernel switches to it in one update. Used both at startup (from
/// the zero-initialized `SETTINGS`, so the first fill targets bank 1) and on every
/// `cordon policy apply`.
pub(super) fn seed_policy(ebpf: &mut Ebpf, compiled: &CompiledPolicy) -> Result<()> {
    if compiled.objects.len() > MAX_OBJECTS {
        return Err(Error::msg(format!(
            "bpf-lsm: {} protected objects exceed MAX_OBJECTS ({MAX_OBJECTS})",
            compiled.objects.len()
        )));
    }

    let target = current_bank(ebpf)?.flip();

    // Drop the target bank's previous generation first, so removed objects/paths don't
    // linger once we flip to it. (RULES needs no clearing — RULE_COUNT gates the scan,
    // and every live slot is overwritten below.)
    clear_bank(ebpf, target)?;

    for obj in &compiled.objects {
        protected_insert(ebpf, target, obj.file, obj.id)?;
        rule_count_insert(ebpf, target, obj.id, obj.rules.len() as u32)?;
        for (i, rule) in obj.rules.iter().enumerate() {
            rules_set(ebpf, rule_slot(target, obj.id, i as u32), *rule)?;
        }
    }

    // The flip: publish the freshly-filled bank in one write.
    set_settings(ebpf, Pid(std::process::id()), target)?;

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
/// reads as [`Bank::ZERO`], so the first [`seed_policy`] targets bank 1.
fn current_bank(ebpf: &mut Ebpf) -> Result<Bank> {
    let settings: Array<_, Settings> = Array::try_from(map_mut(ebpf, MAP_SETTINGS)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_SETTINGS}: {e}")))?;
    let s = settings
        .get(&0, 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: read settings: {e}")))?;
    Ok(s.active_bank.masked())
}

pub(super) fn protected_insert(
    ebpf: &mut Ebpf,
    bank: Bank,
    file: FileId,
    obj: ObjId,
) -> Result<()> {
    let mut map: BpfHashMap<_, BankedFile, ObjId> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_PROTECTED)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_PROTECTED}: {e}")))?;
    map.insert(BankedFile::new(bank, file), obj, 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: insert protected: {e}")))
}

pub(super) fn protected_remove(ebpf: &mut Ebpf, bank: Bank, file: FileId) -> Result<()> {
    let mut map: BpfHashMap<_, BankedFile, ObjId> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_PROTECTED)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_PROTECTED}: {e}")))?;
    map.remove(&BankedFile::new(bank, file))
        .map_err(|e| Error::msg(format!("bpf-lsm: remove protected: {e}")))
}

pub(super) fn rule_count_insert(ebpf: &mut Ebpf, bank: Bank, obj: ObjId, count: u32) -> Result<()> {
    let mut map: BpfHashMap<_, BankedObj, u32> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_RULE_COUNT)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_RULE_COUNT}: {e}")))?;
    map.insert(BankedObj::new(bank, obj), count, 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: insert rule count: {e}")))
}

pub(super) fn rule_count_remove(ebpf: &mut Ebpf, bank: Bank, obj: ObjId) -> Result<()> {
    let mut map: BpfHashMap<_, BankedObj, u32> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_RULE_COUNT)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_RULE_COUNT}: {e}")))?;
    map.remove(&BankedObj::new(bank, obj))
        .map_err(|e| Error::msg(format!("bpf-lsm: remove rule count: {e}")))
}

/// Register a live blessing: the carrier cgroup's id → its class. `MAP_BLESSED` is
/// **unbanked** (blessings are runtime state, not policy — an apply remaps values in
/// place by class name rather than re-seeding a generation).
pub(super) fn blessed_insert(ebpf: &mut Ebpf, cgroup: CgroupId, class: ClassId) -> Result<()> {
    let mut map: BpfHashMap<_, CgroupId, ClassId> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_BLESSED)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_BLESSED}: {e}")))?;
    map.insert(cgroup, class, 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: insert blessed: {e}")))
}

pub(super) fn blessed_remove(ebpf: &mut Ebpf, cgroup: CgroupId) -> Result<()> {
    let mut map: BpfHashMap<_, CgroupId, ClassId> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_BLESSED)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_BLESSED}: {e}")))?;
    map.remove(&cgroup)
        .map_err(|e| Error::msg(format!("bpf-lsm: remove blessed: {e}")))
}

pub(super) fn rules_set(ebpf: &mut Ebpf, index: u32, rule: CompiledRule) -> Result<()> {
    let mut map: Array<_, CompiledRule> = Array::try_from(map_mut(ebpf, MAP_RULES)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_RULES}: {e}")))?;
    map.set(index, rule, 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: set rule[{index}]: {e}")))
}

/// Set the one-element `SETTINGS` record: our pid (fast-allowed) and the live bank.
/// Writing this with a flipped `bank` is the atomic policy publish.
pub(super) fn set_settings(ebpf: &mut Ebpf, pid: Pid, bank: Bank) -> Result<()> {
    let mut settings: Array<_, Settings> = Array::try_from(map_mut(ebpf, MAP_SETTINGS)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_SETTINGS}: {e}")))?;
    settings
        .set(0, Settings::new(pid, bank), 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: set settings: {e}")))
}

/// Remove `bank`'s entries from the keyed rule maps (`PROTECTED`, `RULE_COUNT`), leaving
/// the *other* bank — the live one during a re-seed — untouched.
fn clear_bank(ebpf: &mut Ebpf, bank: Bank) -> Result<()> {
    {
        let mut map: BpfHashMap<_, BankedFile, ObjId> =
            BpfHashMap::try_from(map_mut(ebpf, MAP_PROTECTED)?)
                .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_PROTECTED}: {e}")))?;
        let stale: Vec<BankedFile> = map
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::msg(format!("bpf-lsm: list {MAP_PROTECTED}: {e}")))?
            .into_iter()
            .filter(|k| k.bank == bank)
            .collect();
        for k in stale {
            map.remove(&k)
                .map_err(|e| Error::msg(format!("bpf-lsm: clear {MAP_PROTECTED}: {e}")))?;
        }
    }
    {
        let mut map: BpfHashMap<_, BankedObj, u32> =
            BpfHashMap::try_from(map_mut(ebpf, MAP_RULE_COUNT)?)
                .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_RULE_COUNT}: {e}")))?;
        let stale: Vec<BankedObj> = map
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::msg(format!("bpf-lsm: list {MAP_RULE_COUNT}: {e}")))?
            .into_iter()
            .filter(|k| k.bank == bank)
            .collect();
        for k in stale {
            map.remove(&k)
                .map_err(|e| Error::msg(format!("bpf-lsm: clear {MAP_RULE_COUNT}: {e}")))?;
        }
    }
    Ok(())
}
