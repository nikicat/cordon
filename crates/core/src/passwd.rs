//! `/etc/passwd` for the audit log: a cached uid → (login name, home) lookup so the
//! journal can name the caller and collapse a *regular* user's home to `~` without
//! rereading the file on every event.
//!
//! The [`Passwd`] map is reparsed only when the file's mtime changes (a user added or
//! removed), so a long-lived daemon parses once and then does O(1) lookups while still
//! reflecting a passwd edit without a restart. Resolved the same way the policy expands
//! `~` ([`crate::policy::home_for`] also reads `/etc/passwd`), so a rendered `~` matches
//! what that user's policy expands to.

use crate::policy::UserName;
use cordon_bpf_common::Uid;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The file backing the lookup. A constant so the parser tests can target a string instead.
const PASSWD: &str = "/etc/passwd";

/// The conventional uid range for human login accounts — the `useradd`/`login.defs`
/// `UID_MIN`/`UID_MAX` defaults. System accounts sit below it (`root` = 0, daemons < 1000)
/// and `nobody`/overflow above it (65534). Only a uid in this range has its home collapsed
/// to `~` on the audit line: a regular user's home access maps to a user-tier policy
/// (`~`-relative), while root/system access stays absolute for the system policy.
const REGULAR_UID_RANGE: std::ops::RangeInclusive<Uid> = Uid(1000)..=Uid(60000);

/// Whether `uid` names a regular (human) login account — see [`REGULAR_UID_RANGE`].
pub fn is_regular_uid(uid: Uid) -> bool {
    REGULAR_UID_RANGE.contains(&uid)
}

/// A resolved caller for the audit line: the login name, plus — only for a *regular*
/// account, so root/system paths stay absolute — the home to collapse to `~`. Borrows the
/// [`Passwd`] cache, so naming a caller costs no allocation.
pub struct Identity<'a> {
    pub name: &'a UserName,
    pub home: Option<&'a Path>,
}

/// A cached view of `/etc/passwd`, keyed by uid. Construct once ([`Passwd::new`]) and keep
/// it for the daemon's life; [`refresh`](Passwd::refresh) before a batch of lookups reloads
/// it only when the file changed.
#[derive(Default)]
pub struct Passwd {
    by_uid: HashMap<Uid, (UserName, PathBuf)>,
    mtime: Option<SystemTime>,
}

impl Passwd {
    /// An empty cache; the first [`refresh`](Passwd::refresh) populates it.
    pub fn new() -> Passwd {
        Passwd::default()
    }

    /// Reload from `/etc/passwd` iff its mtime changed since the last load — cheap (one
    /// `stat`) when unchanged, a full parse only on first call or after an edit. A failed
    /// read leaves the previous map (and mtime) in place, so a transient error self-heals
    /// on the next call rather than blanking the cache.
    pub fn refresh(&mut self) {
        let mtime = std::fs::metadata(PASSWD).and_then(|m| m.modified()).ok();
        if mtime == self.mtime && !self.by_uid.is_empty() {
            return;
        }
        if let Ok(text) = std::fs::read_to_string(PASSWD) {
            self.by_uid = parse(&text);
            self.mtime = mtime;
        }
    }

    /// Resolve a uid to its [`Identity`] (name + regular-user home), or `None` when the uid
    /// has no passwd entry (a deleted or NSS-only account) — the caller then shows the bare
    /// number. Pure (no I/O): looks up the map [`refresh`](Passwd::refresh) last loaded.
    pub fn lookup(&self, uid: Uid) -> Option<Identity<'_>> {
        let (name, home) = self.by_uid.get(&uid)?;
        Some(Identity {
            name,
            home: is_regular_uid(uid).then_some(home.as_path()),
        })
    }
}

/// Parse `name:passwd:uid:gid:gecos:home:shell` lines into a uid → (name, home) map,
/// dropping any malformed line. Split out so it unit-tests without the real file.
fn parse(passwd: &str) -> HashMap<Uid, (UserName, PathBuf)> {
    passwd
        .lines()
        .filter_map(|line| {
            // name(0):passwd(1):uid(2):gid(3):gecos(4):home(5):shell(6).
            let mut fields = line.split(':');
            let name = fields.next()?;
            let uid = fields.nth(1)?.parse().ok()?; // skip passwd(1), take uid(2)
            let home = fields.nth(2)?; // skip gid(3), gecos(4), take home(5)
            Some((Uid(uid), (UserName::new(name), PathBuf::from(home))))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "root:x:0:0:root:/root:/bin/bash\n\
                          alice:x:1000:1000:Alice,,,:/home/alice:/usr/bin/fish\n";

    /// A cache populated from a literal passwd (no real file) — `parse` + private fields.
    fn db(passwd: &str) -> Passwd {
        Passwd {
            by_uid: parse(passwd),
            mtime: None,
        }
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
