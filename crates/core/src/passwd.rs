//! Reads user accounts from `/etc/passwd`, which is the one place cordon reads them. The
//! journal names a caller by uid through the cached [`Passwd`], and the policy expands a
//! user's `~` through [`home_of`]. Both go through the same parser, so the `~` that the
//! journal renders is the same `~` that the user's policy expands to.

use crate::Context;
use crate::policy::UserName;
use cordon_bpf_common::Uid;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const PASSWD: &str = "/etc/passwd";

/// The conventional uid range of human login accounts, which matches the `UID_MIN` and
/// `UID_MAX` defaults of `useradd` and `login.defs`. System accounts sit below it (`root`
/// is 0, and daemons are under 1000), and `nobody` sits above it at 65534. Only a uid in
/// this range has its home collapsed to `~` on the audit line, because a regular user's
/// home maps to a `~`-relative user policy, while root and system access stays absolute
/// for the system policy.
const REGULAR_UID_RANGE: std::ops::RangeInclusive<Uid> = Uid(1000)..=Uid(60000);

/// Checks whether `uid` names a regular (human) login account, as
/// `REGULAR_UID_RANGE` defines it.
pub fn is_regular_uid(uid: Uid) -> bool {
    REGULAR_UID_RANGE.contains(&uid)
}

/// A caller resolved for the audit line. It borrows from the [`Passwd`] cache, so naming a
/// caller costs no allocation.
pub struct Identity<'a> {
    pub name: &'a UserName,
    /// The home to collapse to `~`, present only for a uid in `REGULAR_UID_RANGE`.
    pub home: Option<&'a Path>,
}

/// A cache of `/etc/passwd` keyed by uid, kept for the daemon's life so that naming a
/// caller does not reread the file. [`refresh`](Passwd::refresh) keeps it current.
#[derive(Default)]
pub struct Passwd {
    by_uid: HashMap<Uid, Entry>,
    mtime: Option<SystemTime>,
}

impl Passwd {
    /// Creates an empty cache. The first [`refresh`](Passwd::refresh) fills it.
    pub fn new() -> Passwd {
        Passwd::default()
    }

    /// Reloads the cache from `/etc/passwd` when the cache is empty or the file's mtime
    /// changed since the last load. A failed read keeps the previous entries, so that a
    /// transient error heals on the next call instead of emptying the cache.
    pub fn refresh(&mut self) {
        let mtime = std::fs::metadata(PASSWD).and_then(|m| m.modified()).ok();
        if mtime == self.mtime && !self.by_uid.is_empty() {
            return;
        }
        if let Ok(text) = std::fs::read_to_string(PASSWD) {
            self.by_uid = entries(&text).map(|e| (e.uid, e)).collect();
            self.mtime = mtime;
        }
    }

    /// Returns the [`Identity`] of `uid` from the entries that
    /// [`refresh`](Passwd::refresh) last loaded, without any I/O. Returns `None` when `uid`
    /// has no passwd entry, as for a deleted or NSS-only account.
    pub fn lookup(&self, uid: Uid) -> Option<Identity<'_>> {
        let entry = self.by_uid.get(&uid)?;
        Some(Identity {
            name: &entry.name,
            home: is_regular_uid(uid).then_some(entry.home.as_path()),
        })
    }
}

/// Returns the home of the login `user`, or `None` when `/etc/passwd` has no entry for
/// it. Errors when `/etc/passwd` can't be read.
pub fn home_of(user: &UserName) -> crate::Result<Option<PathBuf>> {
    let text = std::fs::read_to_string(PASSWD).with_context(|| format!("read {PASSWD}"))?;
    Ok(home_in(&text, user))
}

fn home_in(passwd: &str, user: &UserName) -> Option<PathBuf> {
    entries(passwd).find(|e| e.name == *user).map(|e| e.home)
}

/// The fields of one passwd line that cordon reads.
struct Entry {
    name: UserName,
    uid: Uid,
    home: PathBuf,
}

/// Returns the entries of the passwd text `passwd`, skipping any malformed line.
fn entries(passwd: &str) -> impl Iterator<Item = Entry> + '_ {
    passwd.lines().filter_map(|line| {
        // name(0):passwd(1):uid(2):gid(3):gecos(4):home(5):shell(6).
        let mut fields = line.split(':');
        let name = fields.next()?;
        let uid = fields.nth(1)?.parse().ok()?; // skip passwd(1), take uid(2)
        let home = fields.nth(2)?; // skip gid(3), gecos(4), take home(5)
        Some(Entry {
            name: UserName::new(name),
            uid: Uid(uid),
            home: PathBuf::from(home),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "root:x:0:0:root:/root:/bin/bash\n\
                          alice:x:1000:1000:Alice,,,:/home/alice:/usr/bin/fish\n";

    /// Returns a cache filled from the passwd text `passwd`, without reading a file.
    fn db(passwd: &str) -> Passwd {
        Passwd {
            by_uid: entries(passwd).map(|e| (e.uid, e)).collect(),
            mtime: None,
        }
    }

    #[test]
    fn home_in_finds_a_login_by_name() {
        let home = |name| home_in(SAMPLE, &UserName::new(name));
        assert_eq!(home("alice"), Some("/home/alice".into()));
        assert_eq!(home("root"), Some("/root".into()));
        assert_eq!(home("ghost"), None);
    }

    #[test]
    fn lookup_names_caller_and_gates_home_on_regular() {
        let p = db(SAMPLE);
        // alice is regular → home present for the `~` collapse.
        let alice = p.lookup(Uid(1000)).unwrap();
        assert_eq!(alice.name.as_str(), "alice");
        assert_eq!(alice.home, Some(Path::new("/home/alice")));
        // root resolves its name but is not regular → no home, so its paths stay absolute.
        let root = p.lookup(Uid::ROOT).unwrap();
        assert_eq!(root.name.as_str(), "root");
        assert_eq!(root.home, None);
        // A uid with no passwd line → None (the caller shows the bare number).
        assert!(p.lookup(Uid(4242)).is_none());
    }

    #[test]
    fn regular_uid_excludes_system_and_overflow() {
        assert!(!is_regular_uid(Uid::ROOT)); // root
        assert!(!is_regular_uid(Uid(999))); // a system daemon
        assert!(is_regular_uid(Uid(1000))); // first human account
        assert!(is_regular_uid(Uid(60000))); // login.defs UID_MAX default
        assert!(!is_regular_uid(Uid(65534))); // nobody / overflow
    }

    #[test]
    fn malformed_lines_are_dropped() {
        // A non-numeric uid and a too-short line are skipped, not panicked on.
        let p = db("garbage\nbob:x:notanumber:1:b:/home/bob:/bin/sh\n");
        assert!(p.lookup(Uid(1)).is_none());
    }
}
