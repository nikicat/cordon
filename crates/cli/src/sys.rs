//! The few privileged operations `policy edit` needs, isolated here. Every one is a safe
//! `nix` wrapper except the single inherently-unsafe `Command::pre_exec` registration — so
//! the whole crate's `unsafe` surface is the one block below. All serve the sudoedit-style
//! boundary: the parent stays root to validate/apply/write while the editor child runs
//! fully as the invoking user.

use cordon_core::policy::UserName;
use nix::unistd::{Gid, Uid, User};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The login name and home directory of `uid` from the passwd database. Used to hand the
/// dropped editor *its own* `$HOME`/`$USER`: under `sudo` the inherited `HOME` is still
/// `/root`, so an editor running as the invoking user would try to write its state/config
/// under root's home and be denied. `None` if the uid isn't in passwd or has no home set.
pub fn user_identity(uid: Uid) -> Option<(UserName, PathBuf)> {
    let user = User::from_uid(uid).ok().flatten()?;
    if user.dir.as_os_str().is_empty() {
        return None;
    }
    Some((UserName::new(user.name), user.dir))
}

/// `chown(2)` a path to `uid:gid`. Used only for the temp *directory* — a root-created
/// entry in the sticky tmpdir, so its own path can't be swapped out from under us. For the
/// temp *file* use [`fchown`] instead: a path `chown` follows symlinks, so once the dir is
/// handed to the invoking user a same-uid attacker could redirect it through a planted
/// symlink (an arbitrary-`chown` TOCTOU).
pub fn chown(path: &Path, uid: Uid, gid: Gid) -> io::Result<()> {
    nix::unistd::chown(path, Some(uid), Some(gid)).map_err(io::Error::from)
}

/// `fchown(2)` an **open fd** to `uid:gid` — hands the temp edit copy to the invoking user
/// so the dropped editor can read and write it. Acting on the already-open inode (not a
/// path) is symlink-safe: there is no name to redirect, so a same-uid attacker who owns the
/// temp dir can't reroute the chown to an arbitrary file the way a path `chown` would.
pub fn fchown(fd: impl AsFd, uid: Uid, gid: Gid) -> io::Result<()> {
    nix::unistd::fchown(fd, Some(uid), Some(gid)).map_err(io::Error::from)
}

/// Arrange for `cmd` to drop to `uid:gid` — shedding *all* supplementary groups — in the
/// forked child, before exec, so the editor keeps none of root's authority while the parent
/// does.
pub fn drop_to_on_exec(cmd: &mut Command, uid: Uid, gid: Gid) {
    // SAFETY: the closure runs post-fork / pre-exec in the child. setgroups/setgid/setuid
    // are async-signal-safe syscalls (nix adds only errno translation, no allocation), so
    // they're sound in that window. The order is load-bearing: shed supplementary groups and
    // the gid *before* the uid — once root is surrendered the earlier two would be refused.
    unsafe {
        cmd.pre_exec(move || {
            nix::unistd::setgroups(&[])?;
            nix::unistd::setgid(gid)?;
            nix::unistd::setuid(uid)?;
            Ok(())
        });
    }
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

    /// The temp-file chown is done through an **fd** (`fchown`), the symlink-safe primitive
    /// that replaced the old path `chown` (which a same-uid attacker could redirect via a
    /// planted symlink once the dir was theirs). A no-op self-chown needs no root and proves
    /// the fd path works end to end.
    #[test]
    fn fchown_by_fd_chowns_an_owned_file() {
        use std::os::unix::fs::MetadataExt;
        let path = std::env::temp_dir().join(format!("cordon-fchown-{}", std::process::id()));
        let f = std::fs::File::create(&path).expect("create temp file");
        let meta = f.metadata().expect("stat");
        // Re-assert the file's own uid:gid — allowed without CAP_CHOWN (owner unchanged),
        // so the test runs unprivileged while still exercising the real `fchown` path.
        fchown(&f, Uid::from_raw(meta.uid()), Gid::from_raw(meta.gid())).expect("fchown by fd");
        std::fs::remove_file(&path).ok();
    }
}
