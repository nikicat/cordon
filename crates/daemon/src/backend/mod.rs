//! Backend selection: maps a [`BackendKind`] to a boxed implementation. The mock
//! backend (privilege-agnostic, in core) is always available; the Linux
//! `fanotify` backend (root) is compiled in only on Linux.

use cordon_core::Result;
use cordon_core::backend::{Backend, BackendKind, MockBackend};
use cordon_core::config::Mode;

#[cfg(target_os = "linux")]
mod fanotify;

/// Build the configured backend. `mode` selects enforce vs audit for the
/// privileged backends (the mock backend doesn't actuate, so it ignores it).
pub fn select(kind: BackendKind, mode: Mode) -> Result<Box<dyn Backend>> {
    match kind {
        BackendKind::Mock => Ok(Box::new(MockBackend)),
        BackendKind::Fanotify => {
            #[cfg(target_os = "linux")]
            {
                Ok(Box::new(fanotify::FanotifyBackend::new(mode)))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(cordon_core::Error::msg(
                    "the 'fanotify' backend is Linux-only",
                ))
            }
        }
    }
}
