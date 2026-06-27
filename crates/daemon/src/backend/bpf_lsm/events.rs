//! The data plane → journal: drain the ring buffer of logged decisions and write
//! them out. The verdict already happened in-kernel; this is the audit/observability
//! path.
//!
//! **Event coalescing** (M1 §1g): tools re-open the same config hundreds of times per
//! run. The in-kernel suppressor already throttles the ring to ~one record per `(exe,
//! object, action)` per second (carrying a folded `suppressed` count); here we collapse
//! whatever a single drain *does* surface — one journal line per `(exe, object,
//! action)` with the folded counts — so a burst never becomes a wall of identical log
//! lines. Both layers together turn the audit's ~hundreds-of-opens floods into a line.

use crate::proc;
use aya::Ebpf;
use aya::maps::RingBuf;
use cordon_bpf_common::{Action, Decision, DecisionEvent, FileId, MAP_EVENTS, Pid, Policy};
use cordon_core::backend::{ApplyOutcome, PolicyControl, Shutdown};
use cordon_core::{Error, Result};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::collections::HashMap;
use std::fmt;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Poll wakeup cadence so the reader re-checks shutdown + the apply channel.
const POLL_TIMEOUT_MS: u16 = 500;

/// Drain the ring buffer into the journal and honor `policy apply` requests until
/// shutdown. The ring poll's timeout doubles as the apply-channel tick: each wakeup
/// (event or `POLL_TIMEOUT_MS`) we also service any pending apply, so a `cordon policy
/// apply` lands within one poll interval.
pub(super) fn serve(
    ebpf: &mut Ebpf,
    control: &PolicyControl,
    shutdown: &Arc<Shutdown>,
    mut object_paths: HashMap<FileId, PathBuf>,
) -> Result<()> {
    let mut ring = RingBuf::try_from(
        ebpf.take_map(MAP_EVENTS)
            .ok_or_else(|| Error::msg(format!("bpf-lsm: {MAP_EVENTS} missing from object")))?,
    )
    .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_EVENTS}: {e}")))?;
    let raw = ring.as_raw_fd();

    while !shutdown.is_triggered() {
        // SAFETY: `raw` is the ring buffer's fd, owned by `ring` for this scope.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(POLL_TIMEOUT_MS)) {
            Ok(0) => {} // timeout → re-check shutdown + apply channel
            Ok(_) => {
                // Drain the whole ready batch, then coalesce identical decisions into
                // one journal line each (the in-kernel suppressor already thinned it).
                let mut batch: Vec<DecisionEvent> = Vec::new();
                while let Some(item) = ring.next() {
                    match parse_event(&item) {
                        Some(event) => batch.push(event),
                        None => warn!(
                            len = item.len(),
                            "bpf-lsm: short ring-buffer record; dropped"
                        ),
                    }
                }
                for record in coalesce(&batch) {
                    record.log(&object_paths);
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::msg(format!("bpf-lsm: poll: {e}"))),
        }
        // Service any `policy apply` requests that arrived since the last tick.
        while let Ok(req) = control.apply_rx.try_recv() {
            apply(ebpf, control, &req.text, &req.reply, &mut object_paths);
        }
    }
    Ok(())
}

/// Handle one `policy apply`: recompile the text, and if it has no errors re-seed the
/// maps via the atomic double-buffer swap ([`super::seed::seed_policy`]) and republish
/// the effective view. Always replies with the diagnostics so the CLI can show them
/// whether or not it applied.
fn apply(
    ebpf: &mut Ebpf,
    control: &PolicyControl,
    text: &str,
    reply: &std::sync::mpsc::Sender<ApplyOutcome>,
    object_paths: &mut HashMap<FileId, PathBuf>,
) {
    let compiled = super::compile_text(text);
    let applied = if compiled.has_errors() {
        false
    } else {
        match super::seed::seed_policy(ebpf, &compiled) {
            Ok(()) => {
                *control.current.lock().unwrap() = Some(super::build_view(&compiled));
                *object_paths = super::object_paths(&compiled);
                info!(objects = compiled.objects.len(), "policy applied");
                true
            }
            Err(e) => {
                error!(error = %e, "policy apply: seeding the maps failed; live policy unchanged");
                false
            }
        }
    };
    let _ = reply.send(ApplyOutcome {
        applied,
        diagnostics: compiled.diagnostics,
    });
}

/// A drain batch's worth of ring events sharing one `(exe, object, action)` identity,
/// folded into a single journal record. `events` is how many ring records were folded
/// (each one open that passed the in-kernel suppressor); `suppressed` is the sum of
/// their in-kernel folded counts. `count` (their sum) is the true number of opens the
/// burst represents.
struct Coalesced {
    exe: FileId,
    object: FileId,
    action: Action,
    /// Representative decision/policy/pid (the first occurrence; identical across the group
    /// in practice — the policy is fixed within a single drain batch).
    decision: Decision,
    /// The matched policy — `audit`/`deny`, or `default-deny` (no rule matched). Lets the
    /// journal distinguish a default-deny from an explicit `deny` (DESIGN §15.6).
    policy: Policy,
    pid: Pid,
    events: u32,
    suppressed: u64,
}

impl Coalesced {
    /// Total opens this record stands for: the ring records folded plus the opens the
    /// in-kernel suppressor held back.
    fn count(&self) -> u64 {
        self.events as u64 + self.suppressed
    }

    /// Journal it at the level its decision warrants. The fields are typed (`object` via
    /// [`ObjectName`], `action` via its own `Display`, `exe` via [`CallerExe`]); `tracing`
    /// renders them lazily — no eager `String`s.
    fn log(&self, object_paths: &HashMap<FileId, PathBuf>) {
        let exe = CallerExe::resolve(self.pid, self.exe);
        let object = ObjectName::resolve(self.object, object_paths);
        let action = self.action;
        let policy = self.policy;
        let (count, suppressed) = (self.count(), self.suppressed);
        match self.decision {
            Decision::DENY => {
                info!(pid = self.pid.0, %exe, %object, %action, %policy, count, suppressed, "deny")
            }
            _ => {
                info!(pid = self.pid.0, %exe, %object, %action, %policy, count, suppressed, "audit")
            }
        }
    }
}

/// Collapse a drain batch to one [`Coalesced`] record per `(exe, object, action)`,
/// summing the ring-record count and the in-kernel suppressed totals. Insertion order
/// is preserved (first occurrence wins the representative decision/pid). Pure — the
/// `/proc` resolution and logging happen later, per record.
fn coalesce(events: &[DecisionEvent]) -> Vec<Coalesced> {
    let mut records: Vec<Coalesced> = Vec::new();
    let mut index: HashMap<(FileId, FileId, Action), usize> = HashMap::new();
    for e in events {
        match index.get(&(e.exe, e.object, e.action)) {
            Some(&i) => {
                records[i].events += 1;
                records[i].suppressed += e.suppressed as u64;
            }
            None => {
                index.insert((e.exe, e.object, e.action), records.len());
                records.push(Coalesced {
                    exe: e.exe,
                    object: e.object,
                    action: e.action,
                    decision: e.decision,
                    policy: e.policy,
                    pid: e.pid,
                    events: 1,
                    suppressed: e.suppressed as u64,
                });
            }
        }
    }
    records
}

/// The caller's executable in the journal: a resolved path when `/proc/<pid>/exe` still
/// points at the inode the kernel recorded, else the raw inode (the pid exited or was
/// recycled, so a path would misattribute). The kernel's `FileId` is the race-free
/// anchor; modelling "path *or* inode" as a type keeps the distinction visible instead
/// of collapsing both into a `String`.
enum CallerExe {
    Resolved(PathBuf),
    Inode(FileId),
}

impl CallerExe {
    fn resolve(pid: Pid, exe: FileId) -> CallerExe {
        let link = format!("/proc/{}/exe", pid.0);
        if proc::file_id(Path::new(&link)) == Some(exe)
            && let Ok(path) = std::fs::read_link(&link)
        {
            return CallerExe::Resolved(path);
        }
        CallerExe::Inode(exe)
    }
}

impl fmt::Display for CallerExe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallerExe::Resolved(p) => write!(f, "{}", p.display()),
            CallerExe::Inode(id) => write!(f, "{id}"),
        }
    }
}

/// The protected object in the journal: its policy **path** when the daemon knows the
/// inode (it seeded the object from that path), else the raw inode. Same "path *or* inode,
/// kept distinct" modelling as [`CallerExe`] — there's no path at the `file_open` hook, so
/// the kernel only ever hands us the `FileId`.
enum ObjectName {
    Path(PathBuf),
    Inode(FileId),
}

impl ObjectName {
    fn resolve(object: FileId, object_paths: &HashMap<FileId, PathBuf>) -> ObjectName {
        match object_paths.get(&object) {
            Some(p) => ObjectName::Path(p.clone()),
            None => ObjectName::Inode(object),
        }
    }
}

impl fmt::Display for ObjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectName::Path(p) => write!(f, "{}", p.display()),
            ObjectName::Inode(id) => write!(f, "{id}"),
        }
    }
}

/// Reinterpret a ring-buffer record as a [`DecisionEvent`]. `None` if too short.
fn parse_event(bytes: &[u8]) -> Option<DecisionEvent> {
    if bytes.len() < std::mem::size_of::<DecisionEvent>() {
        return None;
    }
    // SAFETY: length checked; `DecisionEvent` is `repr(C)` POD and the kernel reserved
    // exactly `size_of::<DecisionEvent>()` bytes.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const DecisionEvent) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordon_bpf_common::{Dev, Ino, ObjId, Policy};

    /// A `DecisionEvent` with the given exe/object inodes, action, and in-kernel
    /// suppressed count — enough to exercise coalescing (the rest is fixed).
    fn ev(exe_ino: u64, obj_ino: u64, action: Action, suppressed: u32) -> DecisionEvent {
        DecisionEvent::new(
            Pid(1),
            FileId::new(Dev(1), Ino(exe_ino)),
            FileId::new(Dev(1), Ino(obj_ino)),
            ObjId(0),
            action,
            Decision::DENY,
            Policy::DENY,
            suppressed,
        )
    }

    #[test]
    fn folds_identical_events_summing_counts() {
        let batch = vec![
            ev(10, 20, Action::READ, 0),
            ev(10, 20, Action::READ, 5),
            ev(10, 20, Action::READ, 3),
        ];
        let out = coalesce(&batch);
        assert_eq!(out.len(), 1, "one (exe,object,action) → one record");
        assert_eq!(out[0].events, 3, "three ring records folded");
        assert_eq!(out[0].suppressed, 8, "in-kernel suppressed counts summed");
        assert_eq!(out[0].count(), 11, "total opens = events + suppressed");
    }

    #[test]
    fn distinct_keys_stay_separate() {
        let batch = vec![
            ev(10, 20, Action::READ, 0),
            ev(11, 20, Action::READ, 0),  // different exe
            ev(10, 21, Action::READ, 0),  // different object
            ev(10, 20, Action::WRITE, 0), // different action
            ev(10, 20, Action::READ, 2),  // dup of the first → folds in
        ];
        let out = coalesce(&batch);
        assert_eq!(out.len(), 4, "four distinct identities");
        // Insertion order preserved; the first key folded the trailing dup.
        assert_eq!(out[0].action, Action::READ);
        assert_eq!(out[0].events, 2);
        assert_eq!(out[0].suppressed, 2);
    }

    #[test]
    fn empty_batch_yields_nothing() {
        assert!(coalesce(&[]).is_empty());
    }
}
