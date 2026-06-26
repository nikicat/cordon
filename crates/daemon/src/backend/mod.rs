//! Backend selection. Under the rule model the only backend is `bpf-lsm` (the
//! hardened Linux boundary), compiled in with the `bpf-lsm` cargo feature. The
//! owner-model `mock`/`fanotify` backends were retired with the rule-model migration
//! (DESIGN §15), so a stock build (without the feature) has no functional backend —
//! `select` returns a clear error pointing at `--features bpf-lsm`.

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
                    "the 'bpf-lsm' backend requires Linux and the `bpf-lsm` build \
                     feature — rebuild with `cargo build -p cordon-daemon --features bpf-lsm` \
                     (or `just build-bpf-daemon`)",
                ))
            }
        }
    }
}
