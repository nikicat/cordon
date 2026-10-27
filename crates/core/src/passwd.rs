//! Looks up user accounts through NSS, so an LDAP or sssd account resolves like a local
//! one. The journal names a caller by uid through the cached [`Passwd`], and the policy
//! expands a user's `~` through [`home_of`]. Both ask NSS, so the `~` that the journal
//! renders is the same `~` that the user's policy expands to.

use crate::Context;
use crate::policy::UserName;
use cordon_bpf_common::Uid;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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

/// One user account as NSS reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub name: UserName,
    pub uid: Uid,
    pub home: PathBuf,
}

impl Account {
    /// Returns the account of `uid`, or `None` when NSS has no such account. Errors when
    /// the lookup itself fails.
    pub fn by_uid(uid: Uid) -> crate::Result<Option<Account>> {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid.0))
            .with_context(|| format!("look up uid {uid}"))?;
        Ok(user.map(Account::from))
    }

    /// Returns the account named `name`, or `None` when NSS has no such account. Errors
    /// when the lookup itself fails.
    pub fn by_name(name: &UserName) -> crate::Result<Option<Account>> {
        let user = nix::unistd::User::from_name(name.as_str())
            .with_context(|| format!("look up user {name}"))?;
        Ok(user.map(Account::from))
    }
}

impl From<nix::unistd::User> for Account {
    fn from(user: nix::unistd::User) -> Account {
        Account {
            name: UserName::new(user.name),
            uid: Uid(user.uid.as_raw()),
            home: user.dir,
        }
    }
}

/// A caller resolved for the audit line. It borrows from the [`Passwd`] cache, so naming a
/// caller costs no allocation.
pub struct Identity<'a> {
    pub name: &'a UserName,
    /// The home to collapse to `~`, present only for a uid in `REGULAR_UID_RANGE`.
    pub home: Option<&'a Path>,
}

/// A cache of NSS accounts by uid, kept for the daemon's life so that naming a caller does
/// not ask NSS on every journal line. A miss is cached too.
// ponytail: an account changed only in a network directory (LDAP, sssd) is seen after the
// next /etc/passwd change or a daemon restart. Add a TTL if renames there matter.
#[derive(Default)]
pub struct Passwd {
    by_uid: HashMap<Uid, Option<Account>>,
    mtime: Option<SystemTime>,
}

impl Passwd {
    /// Creates an empty cache. Each uid is looked up on first use.
    pub fn new() -> Passwd {
        Passwd::default()
    }

    /// Empties the cache when `/etc/passwd` changed since the last call, so a local
    /// account change shows on the next journal line.
    pub fn refresh(&mut self) {
        let mtime = std::fs::metadata("/etc/passwd")
            .and_then(|m| m.modified())
            .ok();
        if mtime != self.mtime {
            self.by_uid.clear();
            self.mtime = mtime;
        }
    }

    /// Returns the [`Identity`] of `uid`, asking NSS only on the first lookup of that uid
    /// since the last [`refresh`](Passwd::refresh) that emptied the cache. Returns `None`
    /// when `uid` has no account or the lookup failed.
    pub fn lookup(&mut self, uid: Uid) -> Option<Identity<'_>> {
        let account = self
            .by_uid
            .entry(uid)
            .or_insert_with(|| Account::by_uid(uid).ok().flatten())
            .as_ref()?;
        Some(Identity {
            name: &account.name,
            home: is_regular_uid(uid).then_some(account.home.as_path()),
        })
    }
}

/// Returns the home of the login `user`, or `None` when NSS has no such account. Errors
/// when the lookup fails.
pub fn home_of(user: &UserName) -> crate::Result<Option<PathBuf>> {
    Ok(Account::by_name(user)?.map(|a| a.home))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks both lookups against the account running the tests, which NSS always knows,
    /// and that they agree with each other.
    #[test]
    fn looks_up_the_current_account_both_ways() {
        let uid = Uid(nix::unistd::getuid().as_raw());
        let me = Account::by_uid(uid)
            .unwrap()
            .expect("the test user has an account");
        assert_eq!(me.uid, uid);
        assert_eq!(Account::by_name(&me.name).unwrap(), Some(me.clone()));
        assert_eq!(home_of(&me.name).unwrap(), Some(me.home));
        assert_eq!(
            home_of(&UserName::new("cordon-no-such-user")).unwrap(),
            None
        );
    }

    #[test]
    fn lookup_names_caller_and_gates_home_on_regular() {
        let alice = Account {
            name: UserName::new("alice"),
            uid: Uid(1000),
            home: PathBuf::from("/home/alice"),
        };
        let root = Account {
            name: UserName::new("root"),
            uid: Uid::ROOT,
            home: PathBuf::from("/root"),
        };
        let mut p = Passwd {
            by_uid: HashMap::from([
                (alice.uid, Some(alice)),
                (root.uid, Some(root)),
                (Uid(4242), None),
            ]),
            mtime: None,
        };
        // alice is regular, so her home is present for the `~` collapse.
        let id = p.lookup(Uid(1000)).unwrap();
        assert_eq!(id.name.as_str(), "alice");
        assert_eq!(id.home, Some(Path::new("/home/alice")));
        // root resolves its name but is not regular, so its paths stay absolute.
        let id = p.lookup(Uid::ROOT).unwrap();
        assert_eq!(id.name.as_str(), "root");
        assert_eq!(id.home, None);
        // A cached miss stays a miss, and the caller shows the bare number.
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
}
