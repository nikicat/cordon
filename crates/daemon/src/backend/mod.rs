//! Turns the config's backend choice into a backend to run, or into a teardown of what it
//! pinned. The only backend is `bpf-lsm`, the hardened Linux boundary. Its cargo feature is
//! on by default but Linux-only, so `select` finds no backend only on a non-Linux target or
//! in a `--no-default-features` build.

use cordon_core::Result;
use cordon_core::backend::{Backend, BackendKind};
use cordon_core::config::Config;
use std::num::NonZeroUsize;

#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
mod bpf_lsm;

/// What a sweep of the pinned generations removed.
///
/// It is deliberately not a bare count, because zero is a different event and not a small
/// number, and both call sites must say something different about it. A startup handover
/// that supersedes no predecessor is routine. A teardown that removed nothing means the box
/// was already unenforced, and reporting that as "enforcement torn down" is a lie about the
/// security posture. A `usize` would let a caller forget to draw that line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Swept {
    /// No pinned generations were present.
    Nothing,
    /// The number of generations removed. It is non-zero by construction, so
    /// [`Swept::Nothing`] is the only way to say "none".
    Generations(NonZeroUsize),
}

impl Swept {
    /// Returns the sweep for `removed` generations, where zero becomes [`Swept::Nothing`].
    /// It is private so that only `backend` and its descendant modules can build a sweep.
    fn from_count(removed: usize) -> Self {
        NonZeroUsize::new(removed).map_or(Swept::Nothing, Swept::Generations)
    }
}

/// Disarms enforcement by removing what the backend pinned (see `PinDir::teardown`), and
/// returns what was removed.
///
/// It is separate from `Backend` because it runs with no backend loaded and no daemon
/// running.
pub fn teardown(cfg: &Config) -> Result<Swept> {
    match cfg.backend {
        BackendKind::BpfLsm => {
            #[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
            {
                bpf_lsm::pin::PinDir(cfg.bpf_pin_dir.clone()).teardown()
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

/// Returns the backend that `cfg` names, built but not yet running.
///
/// Errors when this build has no such backend.
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
                     cordon-daemon`, or `just build`)",
                ))
            }
        }
    }
}
