//! The control plane → BPF maps: seed the flat rule table (`PROTECTED` / `RULES` /
//! `RULE_COUNT`) and `SETTINGS` from a compiled policy, plus the typed map-write
//! helpers. This is the part that grows next — the atomic **double-buffer swap** (so a
//! live `cordon policy apply` re-seed has no visible window) and fail-safe **pinning**
//! land here.

use super::map_mut;
use aya::Ebpf;
use aya::maps::{Array, HashMap as BpfHashMap};
use cordon_bpf_common::{
    CompiledRule, FileId, MAP_PROTECTED, MAP_RULE_COUNT, MAP_RULES, MAP_SETTINGS, MAX_OBJECTS,
    MAX_RULES_PER_OBJ, Mode as BpfMode, ObjId, Pid, Settings,
};
use cordon_core::policy::CompiledPolicy;
use cordon_core::{Error, Result};
use tracing::{info, warn};

/// Seed `PROTECTED`, `RULES` (packed), `RULE_COUNT`, and `SETTINGS` from a compiled
/// policy. Clears the keyed maps first so a re-seed reflects removals (not yet atomic
/// — a brief window; the double-buffer swap is the next increment).
pub(super) fn seed_policy(ebpf: &mut Ebpf, compiled: &CompiledPolicy, mode: BpfMode) -> Result<()> {
    if compiled.objects.len() > MAX_OBJECTS {
        return Err(Error::msg(format!(
            "bpf-lsm: {} protected objects exceed MAX_OBJECTS ({MAX_OBJECTS})",
            compiled.objects.len()
        )));
    }

    clear_hashmap::<FileId, ObjId>(ebpf, MAP_PROTECTED)?;
    clear_hashmap::<ObjId, u32>(ebpf, MAP_RULE_COUNT)?;

    for obj in &compiled.objects {
        protected_insert(ebpf, obj.file, obj.id)?;
        rule_count_insert(ebpf, obj.id, obj.rules.len() as u32)?;
        for (i, rule) in obj.rules.iter().enumerate() {
            rules_set(ebpf, rule_index(obj.id, i), *rule)?;
        }
    }
    set_settings(ebpf, Pid(std::process::id()), mode)?;

    info!(
        objects = compiled.objects.len(),
        pending = compiled.pending.len(),
        "bpf-lsm seeded compiled policy"
    );
    if !compiled.pending.is_empty() {
        warn!(
            count = compiled.pending.len(),
            "bpf-lsm: some policy paths don't exist yet and aren't enforced until re-apply"
        );
    }
    Ok(())
}

/// The global index of object `obj`'s rule `i` in the packed `RULES` array.
pub(super) fn rule_index(obj: ObjId, i: usize) -> u32 {
    obj.0 * MAX_RULES_PER_OBJ as u32 + i as u32
}

pub(super) fn protected_insert(ebpf: &mut Ebpf, file: FileId, obj: ObjId) -> Result<()> {
    let mut map: BpfHashMap<_, FileId, ObjId> = BpfHashMap::try_from(map_mut(ebpf, MAP_PROTECTED)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_PROTECTED}: {e}")))?;
    map.insert(file, obj, 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: insert protected: {e}")))
}

pub(super) fn protected_remove(ebpf: &mut Ebpf, file: FileId) -> Result<()> {
    let mut map: BpfHashMap<_, FileId, ObjId> = BpfHashMap::try_from(map_mut(ebpf, MAP_PROTECTED)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_PROTECTED}: {e}")))?;
    map.remove(&file)
        .map_err(|e| Error::msg(format!("bpf-lsm: remove protected: {e}")))
}

pub(super) fn rule_count_insert(ebpf: &mut Ebpf, obj: ObjId, count: u32) -> Result<()> {
    let mut map: BpfHashMap<_, ObjId, u32> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_RULE_COUNT)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_RULE_COUNT}: {e}")))?;
    map.insert(obj, count, 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: insert rule count: {e}")))
}

pub(super) fn rule_count_remove(ebpf: &mut Ebpf, obj: ObjId) -> Result<()> {
    let mut map: BpfHashMap<_, ObjId, u32> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_RULE_COUNT)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_RULE_COUNT}: {e}")))?;
    map.remove(&obj)
        .map_err(|e| Error::msg(format!("bpf-lsm: remove rule count: {e}")))
}

pub(super) fn rules_set(ebpf: &mut Ebpf, index: u32, rule: CompiledRule) -> Result<()> {
    let mut map: Array<_, CompiledRule> = Array::try_from(map_mut(ebpf, MAP_RULES)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_RULES}: {e}")))?;
    map.set(index, rule, 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: set rule[{index}]: {e}")))
}

/// Set the one-element `SETTINGS` record: our pid (fast-allowed) and the global mode.
pub(super) fn set_settings(ebpf: &mut Ebpf, pid: Pid, mode: BpfMode) -> Result<()> {
    let mut settings: Array<_, Settings> = Array::try_from(map_mut(ebpf, MAP_SETTINGS)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_SETTINGS}: {e}")))?;
    settings
        .set(0, Settings::new(pid, mode), 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: set settings: {e}")))
}

/// Remove every entry from a keyed (HashMap) policy map.
fn clear_hashmap<K, V>(ebpf: &mut Ebpf, name: &str) -> Result<()>
where
    K: aya::Pod,
    V: aya::Pod,
{
    let mut map: BpfHashMap<_, K, V> = BpfHashMap::try_from(map_mut(ebpf, name)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {name}: {e}")))?;
    let stale: Vec<K> = map
        .keys()
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::msg(format!("bpf-lsm: list {name}: {e}")))?;
    for k in stale {
        map.remove(&k)
            .map_err(|e| Error::msg(format!("bpf-lsm: clear {name}: {e}")))?;
    }
    Ok(())
}
