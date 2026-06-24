//! The decision flow (DESIGN §6) — the heart of the policy core.
//!
//! `evaluate` is privilege-agnostic and deterministic: given an access event and
//! the store, it returns a verdict and performs the one side effect the flow
//! allows (a TOFU claim on create). Backends call it; tests call it directly.

use crate::decision::{Decision, Reason};
use crate::event::AccessEvent;
use crate::paths::{self, normalize};
use crate::store::Store;
use crate::{Result, now_secs};
use std::path::PathBuf;

pub struct Engine {
    store: Store,
    /// Cached zone roots, refreshed from the store on mutation. Read on every
    /// evaluate, so we keep them in memory rather than re-querying per event.
    zones: Vec<PathBuf>,
}

impl Engine {
    pub fn new(store: Store) -> Result<Engine> {
        let zones = store.zones()?;
        Ok(Engine { store, zones })
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Re-read the zone roots after a mutation (e.g. `cordon zone add`).
    pub fn reload_zones(&mut self) -> Result<()> {
        self.zones = self.store.zones()?;
        Ok(())
    }

    /// Decide a single access, following DESIGN §6 step-for-step. Phase 0 emits
    /// only Allow/Deny (step 5's default is deny; the interactive prompt is
    /// Phase 2).
    pub fn evaluate(&self, event: &AccessEvent) -> Result<Decision> {
        let path = normalize(&event.path);
        let now = now_secs();

        // Step 2 — explicit rules win (allow *or* deny, so revocation works).
        if let Some(rule) = self
            .store
            .matching_rule(&path, &event.caller, event.op, now)?
        {
            return Ok(if rule.allow {
                Decision::allow(Reason::ExplicitAllow)
            } else {
                Decision::deny(Reason::ExplicitDeny)
            });
        }

        // Steps 3 & 5 — an owned subtree most specifically covers this path.
        if let Some(subtree) = self.store.owning_subtree(&path)? {
            let owners = self.store.owner_identities(subtree.owner_id)?;
            let owner_match = event
                .caller
                .identity_chain()
                .any(|exe| owners.iter().any(|o| o == exe));
            if owner_match {
                return Ok(Decision::allow(Reason::OwnerMatch));
            }
            // Protected and the caller is not in the owner group. A Create here
            // does NOT re-claim an already-owned subtree (claim-on-create applies
            // only to *unclaimed* locations), so this is the step-5 default.
            return Ok(Decision::deny(Reason::DefaultDeny));
        }

        // Step 4 — TOFU creator-owns: a create of a new path in an unclaimed
        // zone subtree claims that subtree for its creator.
        if event.op.is_create()
            && let Some(claimable) = paths::claimable_subtree(&path, &self.zones)
        {
            let owner = self
                .store
                .ensure_owner(&zone_owner_name(&claimable), &event.caller.proc.exe)?;
            self.store.claim_subtree(&claimable, owner, now)?;
            return Ok(Decision::allow(Reason::TofuClaim));
        }

        // Step 1 (fall-through) — not under any owned subtree or rule; unmediated.
        Ok(Decision::allow(Reason::Unprotected))
    }
}

/// The auto-generated owner-group name for a TOFU claim: the subtree path itself,
/// which is unique (an already-owned subtree would have matched earlier).
fn zone_owner_name(subtree: &std::path::Path) -> String {
    subtree.to_string_lossy().into_owned()
}
