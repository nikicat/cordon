//! Best-effort caller-identity resolution from `/proc` (Linux).
//!
//! For the *immediate* caller this is race-free: a process triggering a
//! `FAN_OPEN_PERM` event is suspended in the kernel awaiting our verdict, so it
//! cannot exit or exec while we read `/proc/<pid>/exe`. The parent chain is
//! genuinely best-effort — double-fork launders ancestry, and we never trust
//! argv (DESIGN §5/§8). It raises cost; it is not a boundary.

use cordon_core::event::Op;
use cordon_core::identity::Process;
use nix::unistd::Pid;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use tracing::warn;

/// Bound the parent-chain walk so a pathological/looping `/proc` can't spin us.
const MAX_HOPS: usize = 32;

/// Infer the abstract [`Op`] from the caller's *in-flight* open syscall.
///
/// `FAN_OPEN_PERM` does not expose the open flags, but the caller is suspended
/// in the kernel awaiting our verdict, so its syscall arguments are stable and
/// readable from `/proc/<pid>/syscall` — a **safe** create signal (no FID /
/// `open_by_handle_at` / `unsafe`). This drives TOFU (`Op::Create`) and gives
/// write-detection for free.
///
/// ## Coverage and why a miss is safe
/// We recognize `creat`, `open`, and `openat`. `openat2` (flags behind a
/// `struct open_how` pointer) and any other obscure path fall back to `Read`.
/// A miss is *never* a security problem — the op only selects the **convenience**
/// branch (TOFU) and explicit-rule *mode* matching; the boundary itself ("deny a
/// non-owner under an owned subtree") is op-independent. So a process making a
/// raw syscall we don't decode just doesn't get auto-TOFU (use `cordon adopt`),
/// and a scraper *reading* a secret is `O_RDONLY` regardless — it can never be
/// mistaken for a creator.
///
/// Caveat: `/proc/<pid>/syscall` reflects the thread-group-leader; a create from
/// a non-main thread reads the wrong thread → falls back to `Read`. Degrades to
/// `adopt`, never to a wrong verdict.
pub fn access_op(pid: Pid) -> Op {
    const O_CREAT: u64 = 0o100;
    const O_ACCMODE: u64 = 0o3;
    match open_flags(pid) {
        OpenSyscall::Create => Op::Create, // creat(2) is inherently a create
        OpenSyscall::Flags(f) if f & O_CREAT != 0 => Op::Create,
        OpenSyscall::Flags(f) if f & O_ACCMODE != 0 => Op::Write,
        OpenSyscall::Openat2 => {
            // Flags live behind a struct pointer; reading them from another
            // process's memory is racy (a sibling thread can rewrite it) and only
            // drives the convenience layer, so we deliberately don't. Surface it
            // rather than hide it — if this fires, a real creator may not get
            // auto-TOFU (it can still use `cordon adopt`). May be chatty under a
            // busy openat2 user (container runtimes); rate-limit if it becomes so.
            warn!(
                pid = %pid,
                "openat2 flags not decoded (behind a struct pointer); treating as read — TOFU/write-detection skipped for this access"
            );
            Op::Read
        }
        _ => Op::Read,
    }
}

enum OpenSyscall {
    /// Flags decoded from the syscall's argument register.
    Flags(u64),
    /// `creat(2)` — no flags needed; it always creates.
    Create,
    /// `openat2` — flags are behind a `struct open_how` pointer (see `access_op`).
    Openat2,
    /// Not a recognized open, or unreadable.
    Other,
}

/// Decode the caller's in-flight open from `/proc/<pid>/syscall` (format:
/// `nr arg0 arg1 … sp pc`, nr decimal, args hex). The flags argument index
/// differs by syscall: `open(path, flags, …)` → arg1; `openat(dfd, path, flags,
/// …)` → arg2.
fn open_flags(pid: Pid) -> OpenSyscall {
    let Ok(line) = std::fs::read_to_string(format!("/proc/{pid}/syscall")) else {
        return OpenSyscall::Other;
    };
    let mut fields = line.split_whitespace();
    let Some(nr) = fields.next().and_then(|n| n.parse::<i64>().ok()) else {
        return OpenSyscall::Other;
    };

    // `creat(2)` is always O_CREAT|O_WRONLY|O_TRUNC.
    #[cfg(target_arch = "x86_64")]
    if nr == nix::libc::SYS_creat {
        return OpenSyscall::Create;
    }

    // `openat2` carries flags behind a struct pointer — flagged, not decoded.
    if nr == nix::libc::SYS_openat2 {
        return OpenSyscall::Openat2;
    }

    let flags_index = if nr == nix::libc::SYS_openat {
        2
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            if nr == nix::libc::SYS_open {
                1
            } else {
                return OpenSyscall::Other;
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            return OpenSyscall::Other;
        }
    };

    // Skip arg0..arg(flags_index-1), then read the flags argument (hex).
    match fields
        .nth(flags_index)
        .and_then(|f| u64::from_str_radix(f.strip_prefix("0x").unwrap_or(f), 16).ok())
    {
        Some(flags) => OpenSyscall::Flags(flags),
        None => OpenSyscall::Other,
    }
}

/// Resolve a pid's executable path via `/proc/<pid>/exe`. Strips the trailing
/// " (deleted)" the kernel appends when the binary was unlinked/replaced.
pub fn exe_of(pid: Pid) -> Option<PathBuf> {
    let link = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(strip_deleted(link))
}

fn strip_deleted(p: PathBuf) -> PathBuf {
    let bytes = p.as_os_str().as_bytes();
    const SUFFIX: &[u8] = b" (deleted)";
    if let Some(head) = bytes.strip_suffix(SUFFIX) {
        PathBuf::from(std::ffi::OsStr::from_bytes(head))
    } else {
        p
    }
}

/// Best-effort parent chain (nearest-first), bounded at init (`ppid <= 1`) and a
/// hop cap. Each hop is validated only by readability; a hole in the chain stops
/// the walk.
pub fn ancestry(pid: Pid) -> Vec<Process> {
    let mut out = Vec::new();
    let mut cur = pid;
    for _ in 0..MAX_HOPS {
        let Some(ppid) = parent_of(cur) else { break };
        if ppid.as_raw() <= 1 {
            break; // reached init / session root
        }
        match exe_of(ppid) {
            Some(exe) => out.push(Process::new(ppid.as_raw(), exe)),
            None => break,
        }
        cur = ppid;
    }
    out
}

fn parent_of(pid: Pid) -> Option<Pid> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_ppid(&stat).map(Pid::from_raw)
}

/// Parse the ppid (4th field) from a `/proc/<pid>/stat` line. The `comm` field
/// (2nd) is wrapped in parens and may itself contain spaces and `)`, so we split
/// *after the last* `)`: the remaining fields are `state ppid pgrp …`.
pub fn parse_ppid(stat: &str) -> Option<i32> {
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 1..)?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_simple() {
        assert_eq!(parse_ppid("42 (cat) R 7 42 7 0 -1 4194304 100 0"), Some(7));
    }

    #[test]
    fn ppid_with_nasty_comm() {
        // comm contains spaces and a stray ')': must split after the *last* ')'.
        assert_eq!(
            parse_ppid("1234 (weird )name) S 1000 1234 1234 0 -1"),
            Some(1000)
        );
    }

    #[test]
    fn ppid_garbage_is_none() {
        assert_eq!(parse_ppid("no parens here"), None);
        assert_eq!(parse_ppid("123 (x) S"), None); // missing ppid field
    }

    #[test]
    fn strip_deleted_suffix() {
        assert_eq!(
            strip_deleted(PathBuf::from("/usr/bin/foo (deleted)")),
            PathBuf::from("/usr/bin/foo")
        );
        assert_eq!(
            strip_deleted(PathBuf::from("/usr/bin/foo")),
            PathBuf::from("/usr/bin/foo")
        );
    }
}
