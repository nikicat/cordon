//! Linux `fanotify` enforcement backend — the real boundary (DESIGN §4/§9).
//!
//! Requires **root / CAP_SYS_ADMIN**: `FAN_OPEN_PERM` is a system-wide
//! interception/veto power the kernel guards behind that capability. We mark the
//! *filesystems* backing the zone roots and owned subtrees (per-directory marks
//! don't recurse; filesystem marks do), receive a permission event per open
//! beneath them, resolve who/what, run the §6 decision flow, and answer
//! ALLOW/DENY before the kernel's deadline.
//!
//! All `fanotify`/`poll` syscalls go through the `nix` crate, so there is no
//! hand-written `unsafe` here — `nix` owns the bindings and the event-fd
//! lifecycle (each [`FanotifyEvent`] closes its fd on drop).
//!
//! ## Deadlock safety
//! With a filesystem mark, *every* open on that fs is routed to us — including
//! the daemon's own. Two things keep us from blocking ourselves:
//!   1. The engine's hot path performs **no `open(2)`**: the SQLite connection is
//!      established at startup (before marking) and reused (queries `read`/`mmap`
//!      already-open fds; `FAN_OPEN_PERM` fires only on `open`). Identity lookups
//!      touch `/proc`, a different (unmarked) filesystem.
//!   2. We still **fast-allow our own pid** unconditionally — all daemon threads
//!      share it — so a stray daemon open can never wait on a verdict we are too
//!      busy to give.
//!
//! On any resolution error we **fail open** (DESIGN §4) rather than hang a
//! legitimate process.
//!
//! ## Scope (Phase 1)
//! `FAN_OPEN_PERM` carries no `O_CREAT`/`O_WRONLY` bit, so we map every event to
//! `Op::Read` — which is the threat (non-owner *reads* of secrets). Write/create
//! distinction and **TOFU-on-create** need the separate `FAN_CREATE` notify group
//! (FID-based); deferred. Until then ownership is established with `cordon adopt`.
//! Ancestry is the best-effort `/proc` snapshot (DESIGN §8.2 upgrades it to an
//! event-sourced lineage cache).

use crate::proc;
use cordon_core::backend::{Backend, Shutdown};
use cordon_core::engine::Engine;
use cordon_core::event::{AccessEvent, Op};
use cordon_core::identity::Caller;
use cordon_core::{Error, Result};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyEvent, FanotifyResponse, InitFlags, MarkFlags, MaskFlags,
    Response,
};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{error, info, trace, warn};

/// Poll wakeup cadence so the loop re-checks the shutdown flag between events.
const POLL_TIMEOUT_MS: u16 = 500;

pub struct FanotifyBackend;

impl FanotifyBackend {
    pub fn new() -> Self {
        FanotifyBackend
    }
}

impl Backend for FanotifyBackend {
    fn name(&self) -> &str {
        "fanotify"
    }

    fn run(self: Box<Self>, engine: Arc<Mutex<Engine>>, shutdown: Arc<Shutdown>) -> Result<()> {
        // FAN_CLASS_CONTENT enables permission events; NONBLOCK so we drive reads
        // from poll(); CLOEXEC so children don't inherit the veto fd.
        let group = Fanotify::init(
            InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC | InitFlags::FAN_NONBLOCK,
            EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC,
        )
        .map_err(init_err)?;

        // Base dir fd for mark(); ignored because our marked paths are absolute.
        let root = File::open("/")?;

        // Mark the filesystem behind every zone root and owned subtree. A runtime
        // adopt on an already-marked fs is covered automatically (the mark is
        // fs-wide; ownership is read live from the store on each event).
        let mut targets = Vec::new();
        {
            let e = engine.lock().unwrap();
            targets.extend(e.store().zones()?);
            targets.extend(e.store().subtrees()?.into_iter().map(|s| s.path));
        }
        let mut marked = 0usize;
        for path in &targets {
            match group.mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
                MaskFlags::FAN_OPEN_PERM,
                root.as_fd(),
                Some(path.as_path()),
            ) {
                Ok(()) => marked += 1,
                Err(e) => warn!(path = %path.display(), error = %e, "cannot mark filesystem"),
            }
        }
        if marked == 0 {
            return Err(Error::msg(
                "fanotify: marked no filesystems (no zones/subtrees exist yet) — nothing to enforce",
            ));
        }
        info!(filesystems = marked, "enforcing FAN_OPEN_PERM");

        let me = std::process::id() as i32;
        while !shutdown.is_triggered() {
            let mut fds = [PollFd::new(group.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, PollTimeout::from(POLL_TIMEOUT_MS)) {
                Ok(0) => continue, // timeout → re-check shutdown
                Ok(_) => drain(&group, &engine, me),
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(Error::msg(format!("fanotify: poll: {e}"))),
            }
        }
        Ok(())
    }
}

/// Read and dispatch all currently-pending events (NONBLOCK → until EAGAIN).
fn drain(group: &Fanotify, engine: &Arc<Mutex<Engine>>, me: i32) {
    loop {
        match group.read_events() {
            Ok(events) if events.is_empty() => break,
            Ok(events) => {
                for ev in events {
                    handle_event(group, ev, engine, me);
                }
            }
            Err(Errno::EAGAIN) => break, // drained
            Err(e) => {
                error!(error = %e, "read_events failed");
                break;
            }
        }
    }
}

/// Decide and answer one event. The `FanotifyEvent` owns its object fd and closes
/// it on drop, so we respond (kernel matches by fd) *before* `ev` goes out of
/// scope at the end of this function.
fn handle_event(group: &Fanotify, ev: FanotifyEvent, engine: &Arc<Mutex<Engine>>, me: i32) {
    if !ev.check_version() {
        return;
    }
    if !ev.mask().contains(MaskFlags::FAN_OPEN_PERM) {
        return;
    }
    let Some(fd) = ev.fd() else {
        return; // FAN_NOFD (e.g. queue overflow) — nothing to act on
    };

    let allow = decide(fd, ev.pid(), engine, me);
    let response = if allow {
        Response::FAN_ALLOW
    } else {
        Response::FAN_DENY
    };
    if let Err(e) = group.write_response(FanotifyResponse::new(fd, response)) {
        error!(error = %e, "write_response failed");
    }
}

/// Run the decision flow for one permission event. Fails **open** on any
/// resolution error so a legitimate process is never hung by our own bugs.
fn decide(fd: BorrowedFd<'_>, pid: i32, engine: &Arc<Mutex<Engine>>, me: i32) -> bool {
    // Never gate the daemon's own opens (all our threads share this pid).
    if pid == me {
        return true;
    }
    // The opener is suspended in the kernel awaiting our verdict, so resolving
    // its path (via the event fd) and exe (via /proc) is race-free for *this*
    // access. Ancestors are not blocked → best-effort (DESIGN §8.1).
    let Some(path) = read_link_fd(fd.as_raw_fd()) else {
        return true;
    };
    let Some(exe) = proc::exe_of(pid) else {
        return true;
    };
    let caller = Caller::new(pid, exe).with_ancestors(proc::ancestry(pid));
    let event = AccessEvent::new(path, Op::Read, caller);

    let decision = match engine.lock().unwrap().evaluate(&event) {
        Ok(d) => d,
        Err(e) => {
            error!(error = %e, "evaluate error; failing open");
            return true;
        }
    };
    // Denials are the security-relevant events → log at info; allows are noisy
    // (every open on the marked fs) → trace.
    if decision.allowed() {
        trace!(pid, exe = %event.caller.proc.exe.display(), path = %event.path.display(), reason = ?decision.reason(), "allow");
    } else {
        info!(pid, exe = %event.caller.proc.exe.display(), path = %event.path.display(), reason = ?decision.reason(), "deny");
    }
    decision.allowed()
}

/// The absolute path behind an event fd, via `/proc/self/fd/<fd>`.
fn read_link_fd(fd: RawFd) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

fn init_err(e: Errno) -> Error {
    if e == Errno::EPERM {
        Error::msg(
            "fanotify_init: permission denied — the fanotify backend needs root / CAP_SYS_ADMIN",
        )
    } else {
        Error::msg(format!("fanotify_init: {e}"))
    }
}
