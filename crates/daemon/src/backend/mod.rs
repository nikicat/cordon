//! Backend selection. Under the rule model the only backend is `bpf-lsm` (the hardened
//! Linux boundary), in the `bpf-lsm` cargo feature — **on by default**, so a stock Linux
//! build has it. The earlier owner-model backends were retired with the rule-model
//! migration (DESIGN §15). The feature is Linux-only, so `select` only hits the
//! no-backend error on a non-Linux target or a `--no-default-features` build.

use cordon_core::Result;
use cordon_core::backend::{Backend, BackendKind};
use cordon_core::config::Config;
use std::num::NonZeroUsize;

#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
mod bpf_lsm;

/// What a sweep of the pinned generations removed.
///
/// Deliberately not a bare count: **zero is a different event, not a small number**, and
/// both call sites have to say something different about it. A startup handover that
/// supersedes no predecessor is routine; a *teardown* that removed nothing means the box was
/// already unenforced, and reporting that as "enforcement torn down" is a lie about the
/// security posture. A `usize` lets a caller forget to draw that line; this does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Swept {
    /// No pinned generations were present.
    Nothing,
    /// Removed this many. Non-zero by construction, so [`Swept::Nothing`] is the only way
    /// to say "none" — the two can never disagree.
    Generations(NonZeroUsize),
}

impl Swept {
    /// Build from a raw count; `0` collapses to [`Swept::Nothing`]. Private to `backend`,
    /// so the invariant can only be established here (descendant modules may still call it).
    fn from_count(removed: usize) -> Self {
        NonZeroUsize::new(removed).map_or(Swept::Nothing, Swept::Generations)
    }
}

/// Disarm enforcement: drop whatever the backend left standing so it could outlive the
/// daemon.
///
/// Separate from `Backend` because it must work with **no backend loaded and no daemon
/// running** — that is the whole point of `cordond --teardown`.
pub fn teardown(cfg: &Config) -> Result<Swept> {
    match cfg.backend {
        BackendKind::BpfLsm => {
            #[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
            {
                bpf_lsm::pin::teardown(&cfg.bpf_pin_dir)
            }
            // This build never pinned anything, so there is nothing to remove — not an error.
            #[cfg(not(all(target_os = "linux", feature = "bpf-lsm")))]
            {
                let _ = cfg;
                Ok(Swept::Nothing)
            }
        }
    }
}

/// Build the configured backend from the resolved config.
pub fn select(cfg: &Config) -> Result<Box<dyn Backend>> {
    match cfg.backend {
        BackendKind::BpfLsm => {
            #[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
            {
                Ok(Box::new(bpf_lsm::BpfLsmBackend::new(
                    cfg.bpf_object.clone(),
                    cfg.bpf_pin_dir.clone(),
                    cfg.policy.clone(),
                )))
            }
            #[cfg(not(all(target_os = "linux", feature = "bpf-lsm")))]
            {
                Err(cordon_core::Error::msg(
                    "this build has no 'bpf-lsm' backend — it is Linux-only and on by \
                     default, so this is a non-Linux target or a `--no-default-features` \
                     build. Rebuild on Linux with default features (`cargo build -p \
                     cordon-daemon`, or `just build-bpf-daemon`)",
                ))
            }
        }
    }
}
