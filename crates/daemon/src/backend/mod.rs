//! Backend selection: maps a backend name to a boxed implementation. The mock
//! backend (privilege-agnostic, in core) is always available; the Linux
//! `fanotify` backend (root) is compiled in only on Linux.

use cordon_core::backend::{Backend, MockBackend};
use cordon_core::{Error, Result};

#[cfg(target_os = "linux")]
mod fanotify;

pub fn select(name: &str) -> Result<Box<dyn Backend>> {
    match name {
        "mock" => Ok(Box::new(MockBackend)),
        #[cfg(target_os = "linux")]
        "fanotify" => Ok(Box::new(fanotify::FanotifyBackend::new())),
        other => Err(Error::msg(format!(
            "unknown backend '{other}' (available: {}). endpoint-security lands in Phase 4.",
            available()
        ))),
    }
}

fn available() -> &'static str {
    if cfg!(target_os = "linux") {
        "mock, fanotify"
    } else {
        "mock"
    }
}
