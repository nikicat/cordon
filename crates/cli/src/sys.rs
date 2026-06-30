//! The few privileged operations `policy edit` needs, isolated here. Every one is a safe
//! `nix` wrapper except the single inherently-unsafe `Command::pre_exec` registration — so
//! the whole crate's `unsafe` surface is the one block below. All serve the sudoedit-style
//! boundary: the parent stays root to validate/apply/write while the editor child runs
//! fully as the invoking user.

use cordon_core::policy::UserName;
use nix::unistd::{Gid, Uid, User};
use std::io;
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

/// `chown(2)` a path to `uid:gid` — hands the temp edit copy to the invoking user so the
/// dropped editor can read and write it.
pub fn chown(path: &Path, uid: Uid, gid: Gid) -> io::Result<()> {
    nix::unistd::chown(path, Some(uid), Some(gid)).map_err(io::Error::from)
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
}
