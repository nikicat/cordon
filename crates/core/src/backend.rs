//! The seam between the unprivileged control plane and the enforcement backend.
//!
//! A backend owns the verdict mechanism, which is in-kernel for `bpf-lsm`, and the
//! control plane feeds it the compiled policy. Only the backend needs root. The policy
//! compiler and the IPC on the other side of the seam run unprivileged.
//!
//! The only backend is `bpf-lsm`, built into the daemon with the `bpf-lsm` cargo feature.

use crate::Uid;
use crate::policy::{ClassName, Diagnostic, PolicySource};
use crate::proto::{BlessId, BlessingView, CarrierProcs, Pid, PolicyView};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};

/// The enforcement backend to run. The config selects it, and the daemon's backend
/// factory builds the backend it names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Linux BPF-LSM: in-kernel verdicts from BPF maps the daemon seeds from the compiled
    /// policy (DESIGN §4, §15; kernel and capability requirements in the README).
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

    /// Requests shutdown and wakes every waiter.
    pub fn trigger(&self) {
        *self.state.lock().unwrap() = true;
        self.cv.notify_all();
    }

    pub fn is_triggered(&self) -> bool {
        *self.state.lock().unwrap()
    }

    /// Blocks until [`Shutdown::trigger`] is called.
    pub fn wait(&self) {
        let mut tripped = self.state.lock().unwrap();
        while !*tripped {
            tripped = self.cv.wait(tripped).unwrap();
        }
    }
}

/// The backend thread's end of the control plane. The backend takes every policy apply
/// and bless op from it, and publishes the effective policy through it for
/// `cordon policy show`. The IPC side holds the matching [`ControlSender`].
pub struct PolicyControl {
    pub msg_rx: Receiver<ControlMsg>,
    pub current: Arc<Mutex<Option<PolicyView>>>,
}

/// The IPC side of [`PolicyControl`]. It sends control messages to the backend thread
/// and reads the policy that the thread last published.
#[derive(Clone)]
pub struct ControlSender {
    pub msg_tx: Sender<ControlMsg>,
    pub current: Arc<Mutex<Option<PolicyView>>>,
}

/// Creates a connected [`PolicyControl`] / [`ControlSender`] pair.
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

/// One control-plane message to the backend thread, which owns the BPF maps.
///
/// Applies and bless ops share one channel on purpose. Every map write goes through it,
/// so the backend thread is the only writer of the maps. An apply also renumbers
/// `ClassId`s and remaps the live blessings (see
/// [`ClassRegistry`](crate::policy::ClassRegistry)), and the strict order of one channel
/// keeps a mint from racing that remap.
pub enum ControlMsg {
    Apply(ApplyRequest),
    Bless(BlessOp),
}

/// A blessing operation (DESIGN §16). Each reply carries its failure as a `String`,
/// because the failure is only ever shown to the human at the CLI end, and a string
/// keeps the backend's error types out of the seam.
pub enum BlessOp {
    /// Mints a blessing by creating and registering a carrier cgroup for `class`, or for
    /// the sole declared class when `class` is `None`. The reply carries the carrier's
    /// `cgroup.procs`, opened by the root backend thread ([`CarrierProcs`]).
    Mint {
        class: Option<ClassName>,
        /// The requester's uid ([`Conn::peer_uid`](crate::proto::Conn::peer_uid)),
        /// recorded on the blessing so that [`Self::Revoke`] can let the requester revoke
        /// it.
        owner: Uid,
        /// The requester's pid ([`Conn::peer_pid`](crate::proto::Conn::peer_pid)). The
        /// carrier is placed in that process's logind session scope, so the blessed
        /// command keeps a session that polkit can resolve.
        requester: Pid,
        reply: Sender<std::result::Result<(BlessingView, CarrierProcs), String>>,
    },
    /// Lists the live blessings.
    List {
        reply: Sender<std::result::Result<Vec<BlessingView>, String>>,
    },
    /// Kills a blessing's carrier and unregisters it. `by` holds the caller's
    /// [`Conn::peer_uid`](crate::proto::Conn::peer_uid), and the daemon's `may_revoke`
    /// decides whether that caller may revoke this blessing. The check runs behind this
    /// channel rather than in the IPC `authorize` gate because it needs the live table.
    /// The gate only answers whether a uid may use the verb at all.
    Revoke {
        id: BlessId,
        by: Uid,
        reply: Sender<std::result::Result<(), String>>,
    },
}

/// One `policy apply`, sent from the IPC side to the backend thread. The backend compiles
/// the sources and sends the outcome back on `reply`.
pub struct ApplyRequest {
    pub sources: Vec<PolicySource>,
    pub reply: Sender<ApplyOutcome>,
}

/// The result of one apply, which the backend sends back to the IPC side. When `applied`
/// is false, the live policy is unchanged and `diagnostics` holds at least one error that
/// says why.
pub struct ApplyOutcome {
    pub applied: bool,
    pub diagnostics: Vec<Diagnostic>,
}

/// An enforcement mechanism that the daemon drives. An implementor makes the verdicts,
/// puts the compiled policy into effect, and is the only part of cordon that needs root.
pub trait Backend: Send {
    /// Enforces the compiled policy until `shutdown` is triggered. While it runs, it
    /// carries out every message from `control` and logs audit events to the journal.
    fn run(self: Box<Self>, control: PolicyControl, shutdown: Arc<Shutdown>) -> crate::Result<()>;
}
