//! Best-effort caller-identity resolution from `/proc` (Linux).
//!
//! For the *immediate* caller this is race-free: a process triggering a
//! `FAN_OPEN_PERM` event is suspended in the kernel awaiting our verdict, so it
//! cannot exit or exec while we read `/proc/<pid>/exe`. The parent chain is
//! genuinely best-effort — double-fork launders ancestry, and we never trust
//! argv (DESIGN §5/§8). It raises cost; it is not a boundary.

use cordon_core::identity::Process;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Bound the parent-chain walk so a pathological/looping `/proc` can't spin us.
const MAX_HOPS: usize = 32;

/// Resolve a pid's executable path via `/proc/<pid>/exe`. Strips the trailing
/// " (deleted)" the kernel appends when the binary was unlinked/replaced.
pub fn exe_of(pid: i32) -> Option<PathBuf> {
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
pub fn ancestry(pid: i32) -> Vec<Process> {
    let mut out = Vec::new();
    let mut cur = pid;
    for _ in 0..MAX_HOPS {
        let Some(ppid) = parent_of(cur) else { break };
        if ppid <= 1 {
            break; // reached init / session root
        }
        match exe_of(ppid) {
            Some(exe) => out.push(Process::new(ppid, exe)),
            None => break,
        }
        cur = ppid;
    }
    out
}

fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_ppid(&stat)
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
