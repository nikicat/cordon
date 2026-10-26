//! The few privileged operations `policy edit` and `bless` need, isolated here. Every
//! one is a safe `nix` wrapper except the two inherently-unsafe `Command::pre_exec`
//! registrations — so the whole crate's `unsafe` surface is those two *calls*, one line
//! each. The hooks they register are ordinary safe code, hoisted into `let` bindings so
//! the `unsafe` block covers only the operation that is actually unsound to get wrong.

use cordon_core::policy::UserName;
use cordon_core::proto::CarrierProcs;
use nix::unistd::{Gid, Uid, User};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Returns the login name and home directory of `uid` from the passwd database, or `None`
/// if the uid isn't in passwd or has no home set.
pub fn user_identity(uid: Uid) -> Option<(UserName, PathBuf)> {
    let user = User::from_uid(uid).ok().flatten()?;
    if user.dir.as_os_str().is_empty() {
        return None;
    }
    Some((UserName::new(user.name), user.dir))
}

/// `chown(2)` a path to `uid:gid`. Used only for the temp directory, a root-created entry
/// in the sticky tmpdir whose own path can't be swapped out from under us; anything inside
/// it goes through [`fchown`].
pub fn chown(path: &Path, uid: Uid, gid: Gid) -> io::Result<()> {
    nix::unistd::chown(path, Some(uid), Some(gid)).map_err(io::Error::from)
}

/// `fchown(2)` an open fd to `uid:gid`; hands the temp edit copy to the invoking user so
/// the dropped editor can read and write it. Acting on the open inode is symlink-safe: a
/// path `chown` follows symlinks, so once the temp dir is the invoking user's, a same-uid
/// attacker could plant one and redirect the chown to an arbitrary file (a TOCTOU). An fd
/// has no name to redirect.
pub fn fchown(fd: impl AsFd, uid: Uid, gid: Gid) -> io::Result<()> {
    nix::unistd::fchown(fd, Some(uid), Some(gid)).map_err(io::Error::from)
}

/// Arranges for `cmd` to drop to `uid:gid`, shedding all supplementary groups, in the
/// forked child before exec; the parent keeps its privilege.
pub fn drop_to_on_exec(cmd: &mut Command, uid: Uid, gid: Gid) {
    // The order is load-bearing: shed supplementary groups and the gid *before* the uid —
    // once root is surrendered the earlier two would be refused.
    let hook = move || -> io::Result<()> {
        nix::unistd::setgroups(&[])?;
        nix::unistd::setgid(gid)?;
        nix::unistd::setuid(uid)?;
        Ok(())
    };
    // SAFETY: `hook` runs post-fork / pre-exec in the child, where only async-signal-safe
    // operations are sound. setgroups/setgid/setuid are raw syscalls over values captured
    // before the fork (nix adds errno translation, no allocation), so they qualify.
    unsafe { cmd.pre_exec(hook) };
}

/// Arranges for `cmd`, in the forked child, to join the bless carrier cgroup by writing
/// its own pid through `procs`, the carrier's `cgroup.procs` descriptor the root daemon
/// opened and handed over.
///
/// Joining before `exec` means the target runs zero instructions unblessed. The caller
/// needs no privilege: the kernel checks the descriptor's opener, not the writer (see
/// [`CarrierProcs`]).
pub fn join_cgroup_on_exec(cmd: &mut Command, procs: CarrierProcs) {
    let hook = move || -> io::Result<()> {
        let mut buf = [0u8; U32_DECIMAL_MAX];
        let text = format_u32(std::process::id(), &mut buf);
        if nix::unistd::write(&procs.0, text)? != text.len() {
            return Err(io::Error::from(nix::errno::Errno::EIO));
        }
        Ok(())
    };
    // SAFETY: `hook` runs post-fork / pre-exec in the child, where only async-signal-safe
    // operations are sound. getpid(2) and write(2) are raw syscalls and the pid is
    // formatted into a stack buffer — no allocation, which could otherwise deadlock on an
    // allocator lock another thread held at fork time.
    unsafe { cmd.pre_exec(hook) };
}

/// Decimal digits of `u32::MAX` — the buffer a [`format_u32`] caller provides.
pub(crate) const U32_DECIMAL_MAX: usize = 10;

/// Format `n` in decimal into the tail of `buf`, returning the used slice. No
/// allocation, no `core::fmt` machinery — async-signal-safe for the `pre_exec` join.
pub(crate) fn format_u32(mut n: u32, buf: &mut [u8; U32_DECIMAL_MAX]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The passwd lookup resolves the test runner's own uid (no root needed) — the path the
    /// editor's `$HOME`/`$USER` ride on.
    #[test]
    fn user_identity_resolves_current_user() {
        let (name, home) = user_identity(Uid::current()).expect("current uid is in passwd");
        assert!(!name.as_str().is_empty());
        assert!(home.is_absolute(), "home should be absolute, got {home:?}");
    }

    /// The no-alloc formatter behind the async-signal-safe cgroup join: exact digits,
    /// no leading zeros, both extremes.
    #[test]
    fn format_u32_renders_decimal() {
        let mut buf = [0u8; U32_DECIMAL_MAX];
        assert_eq!(format_u32(0, &mut buf), b"0");
        assert_eq!(format_u32(7, &mut buf), b"7");
        assert_eq!(format_u32(1234, &mut buf), b"1234");
        assert_eq!(format_u32(u32::MAX, &mut buf), b"4294967295");
    }

    /// Exercises the fd-based [`fchown`] end to end; a no-op self-chown needs no root.
    #[test]
    fn fchown_by_fd_chowns_an_owned_file() {
        use std::os::unix::fs::MetadataExt;
        let f = tempfile::tempfile().expect("create temp file");
        let meta = f.metadata().expect("stat");
        // Re-assert the file's own uid:gid — allowed without CAP_CHOWN (owner unchanged),
        // so the test runs unprivileged while still exercising the real `fchown` path.
        fchown(&f, Uid::from_raw(meta.uid()), Gid::from_raw(meta.gid())).expect("fchown by fd");
    }
}
