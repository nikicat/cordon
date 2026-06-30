//! Backend selection. Under the rule model the only backend is `bpf-lsm` (the hardened
//! Linux boundary), in the `bpf-lsm` cargo feature — **on by default**, so a stock Linux
//! build has it. The earlier owner-model backends were retired with the rule-model
//! migration (DESIGN §15). The feature is Linux-only, so `select` only hits the
//! no-backend error on a non-Linux target or a `--no-default-features` build.

use cordon_core::Result;
use cordon_core::backend::{Backend, BackendKind};
use cordon_core::config::Config;

#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
mod bpf_lsm;

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
