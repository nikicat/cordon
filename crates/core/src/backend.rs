//! The enforcement-backend seam.
//!
//! A backend sources the verdict mechanism (in-kernel, for `bpf-lsm`) and is fed the
//! compiled policy by the control plane. Everything behind this trait — the policy
//! compiler, the IPC — is privilege-agnostic; only the backend needs root.
//!
//! Under the rule model the only backend is `bpf-lsm` (the hardened Linux boundary),
//! built into the daemon with the `bpf-lsm` cargo feature. The earlier owner-model
//! backends were retired with the rule-model migration (DESIGN §15).

use crate::policy::Diagnostic;
use crate::proto::PolicyView;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};

/// Which enforcement backend to run — the selector that flows from config to the
/// daemon's backend factory. Only `bpf-lsm` remains under the rule model.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Linux BPF-LSM (root, CAP_BPF + CAP_MAC_ADMIN). In-kernel verdicts from BPF
    /// maps the daemon seeds from the compiled policy (DESIGN §4, §15). Built into the
    /// daemon only with the `bpf-lsm` cargo feature.
    #[default]
    #[serde(rename = "bpf-lsm")]
    BpfLsm,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
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
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<BackendKind> {
        match s {
            "bpf-lsm" => Ok(BackendKind::BpfLsm),
            other => Err(crate::Error::msg(format!(
                "unknown backend '{other}' (the only backend is 'bpf-lsm')"
            ))),
        }
    }
}

/// A cooperative shutdown signal shared between the daemon and its backend thread.
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

/// The control-plane handle the daemon hands the backend thread: a channel of
/// `cordon policy apply` requests to honor, and a slot to publish the effective
/// policy into for `cordon policy show`. The IPC side holds the matching
/// [`ControlSender`].
pub struct PolicyControl {
    pub apply_rx: Receiver<ApplyRequest>,
    pub current: Arc<Mutex<Option<PolicyView>>>,
}

/// The IPC side of [`PolicyControl`]: send applies, read the current policy.
#[derive(Clone)]
pub struct ControlSender {
    pub apply_tx: Sender<ApplyRequest>,
    pub current: Arc<Mutex<Option<PolicyView>>>,
}

/// Create a connected [`PolicyControl`] / [`ControlSender`] pair.
pub fn control() -> (PolicyControl, ControlSender) {
    let (apply_tx, apply_rx) = std::sync::mpsc::channel();
    let current = Arc::new(Mutex::new(None));
    (
        PolicyControl {
            apply_rx,
            current: Arc::clone(&current),
        },
        ControlSender { apply_tx, current },
    )
}

/// One `policy apply`: the policy text + a one-shot reply channel for the outcome.
pub struct ApplyRequest {
    pub text: String,
    pub reply: Sender<ApplyOutcome>,
}

/// The result of an apply: the compile diagnostics and whether the live policy was
/// replaced (false ⇒ it had errors and was left unchanged).
pub struct ApplyOutcome {
    pub applied: bool,
    pub diagnostics: Vec<Diagnostic>,
}

/// A source of verdicts and the actuator of compiled policy.
pub trait Backend: Send {
    /// Short stable name shown in `cordon status` (e.g. `bpf-lsm`).
    fn name(&self) -> &str;

    /// Load + seed the compiled policy, then run until `shutdown` trips: drain the
    /// ring buffer to the journal and honor `policy apply` requests off `control`.
    fn run(self: Box<Self>, control: PolicyControl, shutdown: Arc<Shutdown>) -> crate::Result<()>;
}
