//! End-to-end decision-flow tests against the real `Engine` + SQLite store
//! (in-memory). These assert the locked safety rules from DESIGN §5/§6:
//! claim-on-create-never-on-read, owner-or-ancestor match, cross-owner denial,
//! explicit-rule precedence, and TTL expiry.

use cordon_core::decision::Reason;
use cordon_core::{AccessEvent, Caller, Engine, Op, Process, Store};
use std::path::{Path, PathBuf};

/// Throwaway $HOME with `~` and `~/.config` as zone roots, matching the fixture
/// layout in DESIGN §11.
fn engine() -> Engine {
    let store = Store::open_in_memory().unwrap();
    store
        .seed_zones(&[PathBuf::from("/home/u"), PathBuf::from("/home/u/.config")])
        .unwrap();
    Engine::new(store).unwrap()
}

fn caller(exe: &str) -> Caller {
    Caller::new(1000, exe)
}

fn ev(path: &str, op: Op, caller: Caller) -> AccessEvent {
    AccessEvent::new(path, op, caller)
}

const XDG: &str = "/usr/bin/testtool-xdg";
const OLD: &str = "/usr/bin/testtool-oldstyle";
const SCRAPER: &str = "/tmp/testscraper";

#[test]
fn tofu_claim_then_owner_reads_then_scraper_denied() {
    let e = engine();

    // testtool-xdg creates its config under the ~/.config zone → claims it.
    let d = e
        .evaluate(&ev(
            "/home/u/.config/ctest-xdg/secret",
            Op::Create,
            caller(XDG),
        ))
        .unwrap();
    assert_eq!(
        d.reason(),
        Reason::TofuClaim,
        "create should claim the subtree"
    );
    assert!(d.allowed());

    // Same tool reads it back on a later run → owner match.
    let d = e
        .evaluate(&ev(
            "/home/u/.config/ctest-xdg/secret",
            Op::Read,
            caller(XDG),
        ))
        .unwrap();
    assert_eq!(d.reason(), Reason::OwnerMatch);
    assert!(d.allowed());

    // A scraper reading the same file → denied (protected, non-owner).
    let d = e
        .evaluate(&ev(
            "/home/u/.config/ctest-xdg/secret",
            Op::Read,
            caller(SCRAPER),
        ))
        .unwrap();
    assert_eq!(d.reason(), Reason::DefaultDeny);
    assert!(!d.allowed());
}

#[test]
fn oldstyle_dotfile_in_home_zone() {
    let e = engine();
    let d = e
        .evaluate(&ev("/home/u/.ctest-old/secret", Op::Create, caller(OLD)))
        .unwrap();
    assert_eq!(d.reason(), Reason::TofuClaim);

    assert!(
        e.evaluate(&ev("/home/u/.ctest-old/secret", Op::Read, caller(OLD)))
            .unwrap()
            .allowed()
    );
    assert!(
        !e.evaluate(&ev("/home/u/.ctest-old/secret", Op::Read, caller(SCRAPER)))
            .unwrap()
            .allowed()
    );
}

#[test]
fn unprotected_paths_pass_through() {
    let e = engine();
    // Under a zone but unclaimed, and not a create → unmediated allow.
    let d = e
        .evaluate(&ev(
            "/home/u/.config/unowned/file",
            Op::Read,
            caller(SCRAPER),
        ))
        .unwrap();
    assert_eq!(d.reason(), Reason::Unprotected);
    assert!(d.allowed());

    // Entirely outside every zone → unmediated allow.
    let d = e
        .evaluate(&ev("/etc/hosts", Op::Read, caller(SCRAPER)))
        .unwrap();
    assert_eq!(d.reason(), Reason::Unprotected);
    assert!(d.allowed());
}

#[test]
fn cross_owner_read_denied() {
    let e = engine();
    e.evaluate(&ev(
        "/home/u/.config/a/secret",
        Op::Create,
        caller("/bin/tool-a"),
    ))
    .unwrap();
    e.evaluate(&ev(
        "/home/u/.config/b/secret",
        Op::Create,
        caller("/bin/tool-b"),
    ))
    .unwrap();
    // tool-b may read its own...
    assert!(
        e.evaluate(&ev(
            "/home/u/.config/b/secret",
            Op::Read,
            caller("/bin/tool-b")
        ))
        .unwrap()
        .allowed()
    );
    // ...but not tool-a's.
    let d = e
        .evaluate(&ev(
            "/home/u/.config/a/secret",
            Op::Read,
            caller("/bin/tool-b"),
        ))
        .unwrap();
    assert_eq!(d.reason(), Reason::DefaultDeny);
}

#[test]
fn ancestor_in_owner_group_is_allowed() {
    let e = engine();
    // The real tool creates the config.
    e.evaluate(&ev(
        "/home/u/.config/pytool/secret",
        Op::Create,
        caller("/usr/bin/pytool"),
    ))
    .unwrap();

    // Later it runs as an interpreter: caller exe is python3, but pytool is an
    // ancestor within the session → owner match via the chain (DESIGN §5).
    let interp = Caller::new(2000, "/usr/bin/python3")
        .with_ancestors(vec![Process::new(1999, "/usr/bin/pytool")]);
    let d = e
        .evaluate(&ev("/home/u/.config/pytool/secret", Op::Read, interp))
        .unwrap();
    assert_eq!(d.reason(), Reason::OwnerMatch);

    // A python3 with no such ancestor is still denied (interpreter alone ≠ owner).
    let bare = Caller::new(2001, "/usr/bin/python3");
    let d = e
        .evaluate(&ev("/home/u/.config/pytool/secret", Op::Read, bare))
        .unwrap();
    assert_eq!(d.reason(), Reason::DefaultDeny);
}

#[test]
fn explicit_deny_revokes_owner() {
    let e = engine();
    e.evaluate(&ev(
        "/home/u/.config/x/secret",
        Op::Create,
        caller("/bin/x"),
    ))
    .unwrap();
    // Owner would normally be allowed...
    assert!(
        e.evaluate(&ev("/home/u/.config/x/secret", Op::Read, caller("/bin/x")))
            .unwrap()
            .allowed()
    );
    // ...but an explicit deny rule wins (revocation works, DESIGN §6 step 2).
    e.store()
        .add_rule("/bin/x", Path::new("/home/u/.config/x"), "rw", false, None)
        .unwrap();
    let d = e
        .evaluate(&ev("/home/u/.config/x/secret", Op::Read, caller("/bin/x")))
        .unwrap();
    assert_eq!(d.reason(), Reason::ExplicitDeny);
    assert!(!d.allowed());
}

#[test]
fn explicit_allow_without_ownership() {
    let e = engine();
    // No ownership anywhere, but an explicit allow lets this identity read.
    e.store()
        .add_rule(
            "/bin/reader",
            Path::new("/home/u/.config/shared"),
            "r",
            true,
            None,
        )
        .unwrap();
    // Establish ownership by someone else so the path is protected.
    e.evaluate(&ev(
        "/home/u/.config/shared/k",
        Op::Create,
        caller("/bin/owner"),
    ))
    .unwrap();

    let d = e
        .evaluate(&ev(
            "/home/u/.config/shared/k",
            Op::Read,
            caller("/bin/reader"),
        ))
        .unwrap();
    assert_eq!(d.reason(), Reason::ExplicitAllow);

    // A write is *not* covered by the read-only ('r') rule → falls through to the
    // owner check, where /bin/reader is not the owner → denied.
    let d = e
        .evaluate(&ev(
            "/home/u/.config/shared/k",
            Op::Write,
            caller("/bin/reader"),
        ))
        .unwrap();
    assert_eq!(d.reason(), Reason::DefaultDeny);
}

#[test]
fn expired_ttl_rule_is_ignored() {
    let e = engine();
    e.evaluate(&ev(
        "/home/u/.config/x/secret",
        Op::Create,
        caller("/bin/owner"),
    ))
    .unwrap();
    // An allow rule for the scraper that expired in 1970 must not apply.
    e.store()
        .add_rule(SCRAPER, Path::new("/home/u/.config/x"), "rw", true, Some(1))
        .unwrap();
    let d = e
        .evaluate(&ev("/home/u/.config/x/secret", Op::Read, caller(SCRAPER)))
        .unwrap();
    assert_eq!(
        d.reason(),
        Reason::DefaultDeny,
        "expired allow must not rescue the scraper"
    );
}

#[test]
fn read_never_claims_ownership() {
    let e = engine();
    // A scraper *reads* a pre-existing path in an unclaimed zone subtree. This
    // must NOT make the scraper an owner (claim-on-create-never-on-read).
    let d = e
        .evaluate(&ev(
            "/home/u/.config/preexisting/secret",
            Op::Read,
            caller(SCRAPER),
        ))
        .unwrap();
    assert_eq!(d.reason(), Reason::Unprotected);
    assert_eq!(
        e.store().subtrees().unwrap().len(),
        0,
        "a read must create no ownership"
    );

    // The legitimate tool can still later adopt/own it via a create elsewhere;
    // here we just confirm the scraper gained nothing.
    let d = e
        .evaluate(&ev(
            "/home/u/.config/preexisting/secret",
            Op::Read,
            caller(SCRAPER),
        ))
        .unwrap();
    assert!(d.allowed()); // still just unprotected, not owned-by-scraper
    assert_eq!(e.store().subtrees().unwrap().len(), 0);
}
