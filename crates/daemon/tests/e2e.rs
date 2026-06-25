//! End-to-end test: spawn the real `cordond` with a hermetic `$HOME` and drive
//! the three DESIGN §11 fixtures (testtool-oldstyle, testtool-xdg, testscraper)
//! plus `adopt`/`disown` over the actual IPC socket. This exercises the daemon,
//! the IPC server, the engine, and the SQLite store together as a real boundary
//! would — minus the kernel interception, which the `mock` backend stands in for.

use cordon_core::decision::Reason;
use cordon_core::event::Op;
use cordon_core::proto::{Request, Response, read_msg, write_msg};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A spawned daemon bound to a throwaway socket/store; killed on drop.
struct Daemon {
    child: Child,
    sock: PathBuf,
    _dir: tempfile::TempDir,
    home: PathBuf,
}

impl Daemon {
    fn start() -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("cordon.sock");
        let store = dir.path().join("store.db");
        let home = dir.path().join("home");
        let config = dir.path().join("config.toml");
        // Hermetic config file, serialized properly (no hand-rolled TOML).
        #[derive(serde::Serialize)]
        struct DaemonConfig {
            backend: String,
            socket: PathBuf,
            store: PathBuf,
            zones: Vec<PathBuf>,
        }
        let toml = toml::to_string(&DaemonConfig {
            backend: "mock".into(),
            socket: sock.clone(),
            store: store.clone(),
            zones: vec![home.clone(), home.join(".config")],
        })
        .unwrap();
        std::fs::write(&config, toml).unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_cordond"))
            .arg("--config")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cordond");

        let d = Daemon {
            child,
            sock,
            _dir: dir,
            home,
        };
        d.wait_ready();
        d
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if UnixStream::connect(&self.sock).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("cordond did not start listening on {}", self.sock.display());
    }

    fn connect(&self) -> Conn {
        let stream = UnixStream::connect(&self.sock).expect("connect");
        Conn {
            writer: BufWriter::new(stream.try_clone().unwrap()),
            reader: BufReader::new(stream),
        }
    }

    fn p(&self, rel: &str) -> String {
        self.home.join(rel).display().to_string()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One IPC connection; the daemon handles many requests per connection.
struct Conn {
    writer: BufWriter<UnixStream>,
    reader: BufReader<UnixStream>,
}

impl Conn {
    fn call(&mut self, req: Request) -> Response {
        write_msg(&mut self.writer, &req).expect("write request");
        read_msg(&mut self.reader)
            .expect("read response")
            .expect("a response")
    }

    fn submit(&mut self, path: &str, exe: &str, op: Op) -> Reason {
        let resp = self.call(Request::Submit {
            path: path.to_string(),
            exe: exe.to_string(),
            ancestors: vec![],
            op,
            pid: None,
        });
        match resp {
            Response::Decision(d) => d.reason(),
            other => panic!("expected Decision, got {other:?}"),
        }
    }
}

const XDG: &str = "/usr/bin/testtool-xdg";
const OLD: &str = "/usr/bin/testtool-oldstyle";
const SCRAPER: &str = "/tmp/testscraper";

#[test]
fn fixtures_tofu_and_denial_over_ipc() {
    let d = Daemon::start();
    let mut c = d.connect();

    let xdg_secret = d.p(".config/ctest-xdg/secret");
    let old_secret = d.p(".ctest-old/secret");

    // TOFU: each tool creates its own config and becomes its owner.
    assert_eq!(c.submit(&xdg_secret, XDG, Op::Create), Reason::TofuClaim);
    assert_eq!(c.submit(&old_secret, OLD, Op::Create), Reason::TofuClaim);

    // Each tool reads its own secret back across "runs".
    assert_eq!(c.submit(&xdg_secret, XDG, Op::Read), Reason::OwnerMatch);
    assert_eq!(c.submit(&old_secret, OLD, Op::Read), Reason::OwnerMatch);

    // The scraper is denied on both.
    assert_eq!(
        c.submit(&xdg_secret, SCRAPER, Op::Read),
        Reason::DefaultDeny
    );
    assert_eq!(
        c.submit(&old_secret, SCRAPER, Op::Read),
        Reason::DefaultDeny
    );

    // Cross-owner: xdg may not read old's secret.
    assert_eq!(c.submit(&old_secret, XDG, Op::Read), Reason::DefaultDeny);

    // The store reflects two owners.
    match c.call(Request::Owners) {
        Response::Owners(owners) => assert_eq!(owners.len(), 2, "two TOFU owners expected"),
        other => panic!("expected Owners, got {other:?}"),
    }
}

#[test]
fn adopt_then_disown_a_preexisting_subtree() {
    let d = Daemon::start();
    let mut c = d.connect();

    let aws = d.p(".aws/credentials");
    let aws_dir = d.p(".aws");

    // Pre-existing & unclaimed: a read just passes through (and claims nothing).
    assert_eq!(c.submit(&aws, SCRAPER, Op::Read), Reason::Unprotected);

    // Adopt ~/.aws for the aws CLI → now it's protected.
    assert!(matches!(
        c.call(Request::Adopt {
            path: aws_dir.clone(),
            identity: "/usr/bin/aws".into()
        }),
        Response::Done { changed: true }
    ));
    assert_eq!(c.submit(&aws, "/usr/bin/aws", Op::Read), Reason::OwnerMatch);
    assert_eq!(c.submit(&aws, SCRAPER, Op::Read), Reason::DefaultDeny);

    // Disown it → back to unprotected.
    assert!(matches!(
        c.call(Request::Disown { subtree: aws_dir }),
        Response::Done { changed: true }
    ));
    assert_eq!(c.submit(&aws, SCRAPER, Op::Read), Reason::Unprotected);
}

#[test]
fn explicit_deny_rule_revokes_via_ipc() {
    let d = Daemon::start();
    let mut c = d.connect();
    let secret = d.p(".config/tool/secret");

    assert_eq!(
        c.submit(&secret, "/bin/tool", Op::Create),
        Reason::TofuClaim
    );
    assert_eq!(c.submit(&secret, "/bin/tool", Op::Read), Reason::OwnerMatch);

    // Add a deny rule revoking the owner.
    match c.call(Request::AddRule {
        identity: "/bin/tool".into(),
        path: d.p(".config/tool"),
        mode: "rw".into(),
        allow: false,
        ttl_secs: None,
    }) {
        Response::RuleAdded { .. } => {}
        other => panic!("expected RuleAdded, got {other:?}"),
    }
    assert_eq!(
        c.submit(&secret, "/bin/tool", Op::Read),
        Reason::ExplicitDeny
    );
}
