//! The data plane → journal: drain the ring buffer of logged decisions and write
//! them out. The verdict already happened in-kernel; this is the audit/observability
//! path. **Event coalescing** (M1 §1g — collapse the hundreds of repeat opens a tool
//! makes into one record + a count) lands here next.

use crate::proc;
use aya::Ebpf;
use aya::maps::RingBuf;
use cordon_bpf_common::{Decision, DecisionEvent, FileId, MAP_EVENTS, Pid};
use cordon_core::backend::Shutdown;
use cordon_core::{Error, Result};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::fmt;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

/// Poll wakeup cadence so the ring-buffer reader re-checks the shutdown flag.
const POLL_TIMEOUT_MS: u16 = 500;

/// Drain the ring buffer into the journal until shutdown.
pub(super) fn serve(ebpf: &mut Ebpf, shutdown: &Arc<Shutdown>) -> Result<()> {
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
            Ok(0) => {} // timeout → re-check shutdown
            Ok(_) => {
                while let Some(item) = ring.next() {
                    log_event(&item);
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::msg(format!("bpf-lsm: poll: {e}"))),
        }
    }
    Ok(())
}

/// Parse one ring-buffer record and journal it at the level its decision warrants.
/// The fields are typed (`object`/`action` format via their own `Display`, `exe` via
/// [`CallerExe`]); `tracing` renders them lazily — no eager `String`s.
fn log_event(bytes: &[u8]) {
    let Some(event) = parse_event(bytes) else {
        warn!(
            len = bytes.len(),
            "bpf-lsm: short ring-buffer record; dropped"
        );
        return;
    };
    let exe = CallerExe::resolve(event.pid, event.exe);
    let object = event.object;
    let action = event.action;
    match event.decision {
        Decision::DENY => info!(pid = event.pid.0, %exe, %object, %action, "deny"),
        Decision::WOULD_DENY => {
            warn!(pid = event.pid.0, %exe, %object, %action, "would deny (permissive)")
        }
        _ => info!(pid = event.pid.0, %exe, %object, %action, "audit"),
    }
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

/// Reinterpret a ring-buffer record as a [`DecisionEvent`]. `None` if too short.
fn parse_event(bytes: &[u8]) -> Option<DecisionEvent> {
    if bytes.len() < std::mem::size_of::<DecisionEvent>() {
        return None;
    }
    // SAFETY: length checked; `DecisionEvent` is `repr(C)` POD and the kernel reserved
    // exactly `size_of::<DecisionEvent>()` bytes.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const DecisionEvent) })
}
