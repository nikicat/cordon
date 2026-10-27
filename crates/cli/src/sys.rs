//! The process-identity and file-ownership operations that `policy edit` and `bless`
//! need, kept in one place so that the crate's `unsafe` lives here. Every one is a safe
//! `nix` wrapper except the two `Command::pre_exec` registrations, so the crate's whole
//! `unsafe` surface is those two one-line calls. The hooks they register are ordinary safe
//! code, bound with `let` first so that each `unsafe` block covers only the registration.

use cordon_core::proto::CarrierProcs;
use nix::unistd::{Gid, Uid};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// Changes the owner of `path` to `uid:gid`, following symlinks. It is safe only on a path
/// that nobody else can swap, such as the root-created temp directory in the sticky
/// tmpdir. Anything inside that directory goes through [`fchown`] instead.
pub fn chown(path: &Path, uid: Uid, gid: Gid) -> io::Result<()> {
    nix::unistd::chown(path, Some(uid), Some(gid)).map_err(io::Error::from)
}

/// Changes the owner of the open file `fd` to `uid:gid`. Acting on the open inode is
/// symlink-safe, because an fd has no name to redirect. A path-based [`chown`] follows
/// symlinks, so once a directory belongs to another user, that user could plant a link
/// and redirect the chown to any file.
pub fn fchown(fd: impl AsFd, uid: Uid, gid: Gid) -> io::Result<()> {
    nix::unistd::fchown(fd, Some(uid), Some(gid)).map_err(io::Error::from)
}

/// Arranges for the child of `cmd` to drop to `uid:gid` with no supplementary groups
/// before it execs. The calling process keeps its privilege.
pub fn drop_to_on_exec(cmd: &mut Command, uid: Uid, gid: Gid) {
    // The groups and the gid must go before the uid, because once root is given up the
    // kernel refuses the other two.
    let hook = move || -> io::Result<()> {
        nix::unistd::setgroups(&[])?;
        nix::unistd::setgid(gid)?;
        nix::unistd::setuid(uid)?;
        Ok(())
    };
    // SAFETY: `hook` runs in the child between fork and exec, where only async-signal-safe
    // operations are sound. setgroups, setgid and setuid qualify. They are raw syscalls on
    // values captured before the fork, and nix adds only errno translation, not allocation.
    unsafe { cmd.pre_exec(hook) };
}

/// Arranges for the child of `cmd` to join the bless carrier cgroup before it execs, so
/// the target runs no instruction outside the blessing. The child writes its own pid
/// through `procs`, which is the carrier's `cgroup.procs` descriptor as the root daemon
/// opened it.
///
/// The caller needs no privilege, because the kernel checks who opened the descriptor,
/// not who writes to it (see [`CarrierProcs`]).
pub fn join_cgroup_on_exec(cmd: &mut Command, procs: CarrierProcs) {
    let hook = move || -> io::Result<()> {
        let mut buf = [0u8; U32_DECIMAL_MAX];
        let text = format_u32(std::process::id(), &mut buf);
        if nix::unistd::write(&procs.0, text)? != text.len() {
            return Err(io::Error::from(nix::errno::Errno::EIO));
        }
        Ok(())
    };
    // SAFETY: `hook` runs in the child between fork and exec, where only async-signal-safe
    // operations are sound. getpid(2) and write(2) are raw syscalls, and the pid is
    // formatted into a stack buffer. Nothing allocates, which matters because an
    // allocation could deadlock on an allocator lock that another thread held at fork.
    unsafe { cmd.pre_exec(hook) };
}

/// The number of decimal digits in `u32::MAX`, which sizes the buffer for [`format_u32`].
pub(crate) const U32_DECIMAL_MAX: usize = 10;

/// Writes `n` in decimal into the tail of `buf` and returns the written slice. It neither
/// allocates nor uses `core::fmt`, so it is async-signal-safe for the `pre_exec` join.
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

    /// Checks that the formatter writes exact digits with no leading zeros, at both
    /// extremes too.
    #[test]
    fn format_u32_renders_decimal() {
        let mut buf = [0u8; U32_DECIMAL_MAX];
        assert_eq!(format_u32(0, &mut buf), b"0");
        assert_eq!(format_u32(7, &mut buf), b"7");
        assert_eq!(format_u32(1234, &mut buf), b"1234");
        assert_eq!(format_u32(u32::MAX, &mut buf), b"4294967295");
    }

    /// Exercises the real [`fchown`] path end to end without root.
    #[test]
    fn fchown_by_fd_chowns_an_owned_file() {
        use std::os::unix::fs::MetadataExt;
        let f = tempfile::tempfile().expect("create temp file");
        let meta = f.metadata().expect("stat");
        // Setting the owner the file already has needs no CAP_CHOWN.
        fchown(&f, Uid::from_raw(meta.uid()), Gid::from_raw(meta.gid())).expect("fchown by fd");
    }
}
