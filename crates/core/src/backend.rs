//! The enforcement-backend seam.
//!
//! A backend is the only privileged part of the system: it sources open-events
//! and carries out the engine's verdicts. Everything behind this trait (engine,
//! store, IPC) is privilege-agnostic. Phase 0 ships only [`MockBackend`]; Phase 1
//! adds a root `fanotify` backend implementing the same trait.

use crate::engine::Engine;
use crate::{Error, Result};
use std::sync::{Arc, Condvar, Mutex};

/// Which enforcement backend to run. The concrete implementations live where
/// their privilege/OS lands (`MockBackend` here; `fanotify` in the daemon crate;
/// macOS Endpoint Security in Phase 4) — this enum is just the selector that
/// flows from config/CLI to the daemon's backend factory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Unprivileged dev/CI backend; events injected over IPC. Not a boundary.
    #[default]
    Mock,
    /// Linux `fanotify FAN_OPEN_PERM` (root). The portable boundary (fail-open).
    Fanotify,
    /// Linux BPF-LSM (root, CAP_BPF + CAP_MAC_ADMIN). The hardened boundary:
    /// in-kernel verdicts, fail-safe via pinned programs (DESIGN §4). Built into
    /// the daemon only with the `bpf-lsm` cargo feature.
    #[serde(rename = "bpf-lsm")]
    BpfLsm,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Mock => "mock",
            BackendKind::Fanotify => "fanotify",
            BackendKind::BpfLsm => "bpf-lsm",
        }
    }
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for BackendKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<BackendKind> {
        match s {
            "mock" => Ok(BackendKind::Mock),
            "fanotify" => Ok(BackendKind::Fanotify),
            "bpf-lsm" => Ok(BackendKind::BpfLsm),
            other => Err(Error::msg(format!(
                "unknown backend '{other}' (expected 'mock', 'fanotify', or 'bpf-lsm')"
            ))),
        }
    }
}

/// A cooperative shutdown signal shared between the daemon and its backend
/// thread. A backend's run loop parks on / polls this and returns when tripped.
#[derive(Default)]
pub struct Shutdown {
    state: Mutex<bool>,
    cv: Condvar,
}

impl Shutdown {
    pub fn new() -> Arc<Shutdown> {
        Arc::new(Shutdown::default())
    }

    /// Request shutdown and wake any waiter.
    pub fn trigger(&self) {
        *self.state.lock().unwrap() = true;
        self.cv.notify_all();
    }

    pub fn is_triggered(&self) -> bool {
        *self.state.lock().unwrap()
    }

    /// Block until [`Shutdown::trigger`] is called.
    pub fn wait(&self) {
        let mut tripped = self.state.lock().unwrap();
        while !*tripped {
            tripped = self.cv.wait(tripped).unwrap();
        }
    }
}

/// A source of open-events and the actuator of verdicts.
pub trait Backend: Send {
    /// Short stable name shown in `cordon status` (e.g. `mock`, `fanotify`).
    fn name(&self) -> &str;

    /// Run the event loop until `shutdown` is tripped. The mock backend has no
    /// kernel event source — events arrive via IPC `Submit` and are evaluated on
    /// the IPC threads — so its loop simply parks. A real backend reads native
    /// events, calls `engine.lock().evaluate(..)`, and writes the verdict back to
    /// the kernel.
    fn run(self: Box<Self>, engine: Arc<Mutex<Engine>>, shutdown: Arc<Shutdown>) -> Result<()>;
}

/// The unprivileged development backend: no interception, events injected over
/// IPC. **Not a boundary** (DESIGN §4) — for logic/CI and local iteration.
pub struct MockBackend;

impl Backend for MockBackend {
    fn name(&self) -> &str {
        "mock"
    }

    fn run(self: Box<Self>, _engine: Arc<Mutex<Engine>>, shutdown: Arc<Shutdown>) -> Result<()> {
        shutdown.wait();
        Ok(())
    }
}
