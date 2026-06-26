//! Backend selection: maps the configured [`BackendKind`] to a boxed
//! implementation. The mock backend (privilege-agnostic, in core) is always
//! available; the Linux `fanotify` backend (root) is compiled in on Linux; the
//! Linux `bpf-lsm` backend (root, hardened) is compiled in only with the
//! `bpf-lsm` cargo feature (it pulls the aya toolchain).

use cordon_core::Result;
use cordon_core::backend::{Backend, BackendKind, MockBackend};
use cordon_core::config::Config;

#[cfg(target_os = "linux")]
mod fanotify;

#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
mod bpf_lsm;

/// Build the configured backend from the resolved config. `mode` selects enforce
/// vs audit for the privileged backends (the mock backend doesn't actuate, so it
/// ignores it); the `bpf-lsm` backend additionally needs the eBPF object + pin
/// paths.
pub fn select(cfg: &Config) -> Result<Box<dyn Backend>> {
    match cfg.backend {
        BackendKind::Mock => Ok(Box::new(MockBackend)),
        BackendKind::Fanotify => {
            #[cfg(target_os = "linux")]
            {
                Ok(Box::new(fanotify::FanotifyBackend::new(cfg.mode)))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(cordon_core::Error::msg(
                    "the 'fanotify' backend is Linux-only",
                ))
            }
        }
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
