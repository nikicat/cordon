//! The enforcement-backend seam.
//!
//! A backend sources the verdict mechanism (in-kernel, for `bpf-lsm`) and is fed the
//! compiled policy by the control plane. Everything behind this trait — the policy
//! compiler, the IPC — is privilege-agnostic; only the backend needs root.
//!
//! Under the rule model the only backend is `bpf-lsm` (the hardened Linux boundary),
//! built into the daemon with the `bpf-lsm` cargo feature. The earlier owner-model
//! backends were retired with the rule-model migration (DESIGN §15).

use crate::Uid;
use crate::policy::{ClassName, Diagnostic, PolicySource};
use crate::proto::{BlessId, BlessingView, CarrierProcs, Pid, PolicyView};
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

/// The control-plane handle the daemon hands the backend thread: **one** channel of
/// control messages (`policy apply` + bless ops) to honor, and a slot to publish the
/// effective policy into for `cordon policy show`. One channel, not two, on purpose:
/// an apply renumbers `ClassId`s and remaps the live blessings, so strict ordering
/// between applies and bless ops is what keeps a mint from racing the remap. The IPC
/// side holds the matching [`ControlSender`].
pub struct PolicyControl {
    pub msg_rx: Receiver<ControlMsg>,
    pub current: Arc<Mutex<Option<PolicyView>>>,
}

/// The IPC side of [`PolicyControl`]: send control messages, read the current policy.
#[derive(Clone)]
pub struct ControlSender {
    pub msg_tx: Sender<ControlMsg>,
    pub current: Arc<Mutex<Option<PolicyView>>>,
}

/// Create a connected [`PolicyControl`] / [`ControlSender`] pair.
pub fn control() -> (PolicyControl, ControlSender) {
    let (msg_tx, msg_rx) = std::sync::mpsc::channel();
    let current = Arc::new(Mutex::new(None));
    (
        PolicyControl {
            msg_rx,
            current: Arc::clone(&current),
        },
        ControlSender { msg_tx, current },
    )
}

/// One control-plane message to the backend thread (which owns the BPF maps — every
/// map write funnels through this single channel, preserving the single-writer
/// discipline).
pub enum ControlMsg {
    Apply(ApplyRequest),
    Bless(BlessOp),
}

/// A blessing operation (DESIGN §16). Replies are `Result<_, String>`: the failure is
/// only ever shown to the human on the CLI end, and `String` keeps the backend's
/// error types out of the seam.
pub enum BlessOp {
    /// Mint a blessing: create + register a carrier cgroup for `class` (`None` → the
    /// sole declared class). The reply carries the carrier's `cgroup.procs` **opened by
    /// the (root) backend thread** — passing that fd is what lets an unprivileged client
    /// join, since the kernel checks migration permission against the opener's
    /// credentials, not the writer's (DESIGN §16.4).
    Mint {
        class: Option<ClassName>,
        /// The **requester's** kernel-attested uid, recorded on the blessing so they can
        /// later revoke what they minted without needing root ([`Self::Revoke`]).
        owner: Uid,
        /// The **requester's** kernel-attested pid. The daemon reads its cgroup to place
        /// the carrier in that process's own logind session scope, so the blessed command
        /// keeps a session polkit will resolve. Attested, never asserted: a client-supplied
        /// pid would let a caller aim the carrier at *another* user's session.
        requester: Pid,
        reply: Sender<std::result::Result<(BlessingView, CarrierProcs), String>>,
    },
    /// Snapshot the live blessings.
    List {
        reply: Sender<std::result::Result<Vec<BlessingView>, String>>,
    },
    /// Kill a blessing's carrier and unregister it. `by` is the caller's kernel-attested
    /// uid: root revokes anything, anyone else only what they minted. The check lives here
    /// rather than in the IPC `authorize` gate because it needs the live table — the gate
    /// answers "may this uid speak this verb", ownership answers "is this one yours".
    Revoke {
        id: BlessId,
        by: Uid,
        reply: Sender<std::result::Result<(), String>>,
    },
}

/// One `policy apply`: the policy fragments to compile + a one-shot reply channel for
/// the outcome.
pub struct ApplyRequest {
    pub sources: Vec<PolicySource>,
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
    /// Short stable name for the daemon's startup log (e.g. `bpf-lsm`).
    fn name(&self) -> &str;

    /// Load + seed the compiled policy, then run until `shutdown` trips: drain the
    /// ring buffer to the journal and honor `policy apply` requests off `control`.
    fn run(self: Box<Self>, control: PolicyControl, shutdown: Arc<Shutdown>) -> crate::Result<()>;
}
