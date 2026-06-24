//! The verdict the engine returns, with a machine-readable reason tying it back
//! to a step of the decision flow (DESIGN §6).

use serde::{Deserialize, Serialize};

/// The engine's verdict for an access event. Phase 0 emits only `Allow`/`Deny`;
/// `Prompt` (deny-and-learn) arrives in Phase 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Decision {
    Allow { reason: Reason },
    Deny { reason: Reason },
}

/// Why the engine reached its verdict — one per branch of the decision flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Step 1 — not under any owned subtree or explicit rule; unmediated.
    Unprotected,
    /// Step 2 — an explicit allow rule matched (user rules win).
    ExplicitAllow,
    /// Step 2 — an explicit deny rule matched (revocation works).
    ExplicitDeny,
    /// Step 3 — caller or an ancestor is in the owning subtree's owner group.
    OwnerMatch,
    /// Step 4 — creator-owns: a new path was claimed for its creator.
    TofuClaim,
    /// Step 5 — protected, non-owner, not a create; the configured default.
    DefaultDeny,
}

impl Decision {
    pub fn allow(reason: Reason) -> Self {
        Decision::Allow { reason }
    }

    pub fn deny(reason: Reason) -> Self {
        Decision::Deny { reason }
    }

    pub fn allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    pub fn reason(&self) -> Reason {
        match self {
            Decision::Allow { reason } | Decision::Deny { reason } => *reason,
        }
    }
}
