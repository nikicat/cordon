//! The data plane → journal: drain the ring buffer of logged decisions and write
//! them out. The verdict already happened in-kernel; this is the audit/observability
//! path.
//!
//! **Event coalescing** (M1 §1g): tools re-open the same config hundreds of times per
//! run. The in-kernel suppressor already throttles the ring to ~one record per `(exe,
//! object, action)` per second (carrying a folded `suppressed` count); here we collapse
//! whatever a single drain *does* surface — one journal line per `(exe, object,
//! action)` with the folded counts — so a burst never becomes a wall of identical log
//! lines. Both layers together turn the audit's ~hundreds-of-opens floods into a line.

use crate::proc;
use aya::Ebpf;
use aya::maps::RingBuf;
use cordon_bpf_common::{
    Action, Decision, DecisionEvent, FileId, MAP_EVENTS, Opens, PATH_MAX_DEPTH, PathComp, Pid,
    Policy, SuppressedTotal, Uid,
};
use cordon_core::backend::{ApplyOutcome, PolicyControl, Shutdown};
use cordon_core::passwd::Passwd;
use cordon_core::policy::{PolicySource, UserName};
use cordon_core::{Error, Result};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Poll wakeup cadence so the reader re-checks shutdown + the apply channel.
const POLL_TIMEOUT_MS: u16 = 500;

/// Drain the ring buffer into the journal and honor `policy apply` requests until
/// shutdown. The ring poll's timeout doubles as the apply-channel tick: each wakeup
/// (event or `POLL_TIMEOUT_MS`) we also service any pending apply, so a `cordon policy
/// apply` lands within one poll interval.
pub(super) fn serve(
    ebpf: &mut Ebpf,
    control: &PolicyControl,
    shutdown: &Arc<Shutdown>,
    mut object_paths: HashMap<FileId, PathBuf>,
) -> Result<()> {
    let mut ring = RingBuf::try_from(
        ebpf.take_map(MAP_EVENTS)
            .ok_or_else(|| Error::msg(format!("bpf-lsm: {MAP_EVENTS} missing from object")))?,
    )
    .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_EVENTS}: {e}")))?;
    let raw = ring.as_raw_fd();
    // Names callers on the audit line; reloaded only when /etc/passwd changes (per drain).
    let mut passwd = Passwd::new();

    while !shutdown.is_triggered() {
        // SAFETY: `raw` is the ring buffer's fd, owned by `ring` for this scope.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(POLL_TIMEOUT_MS)) {
            Ok(0) => {} // timeout → re-check shutdown + apply channel
            Ok(_) => {
                // Drain the whole ready batch, then coalesce identical decisions into
                // one journal line each (the in-kernel suppressor already thinned it).
                let mut batch: Vec<DecisionEvent> = Vec::new();
                while let Some(item) = ring.next() {
                    match parse_event(&item) {
                        Some(event) => batch.push(event),
                        None => warn!(
                            len = item.len(),
                            "bpf-lsm: short ring-buffer record; dropped"
                        ),
                    }
                }
                // Refresh once per drain (cheap unless /etc/passwd changed), then name each
                // record's caller from the cache.
                passwd.refresh();
                for record in coalesce(&batch) {
                    record.log(&object_paths, &passwd);
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::msg(format!("bpf-lsm: poll: {e}"))),
        }
        // Service any `policy apply` requests that arrived since the last tick.
        while let Ok(req) = control.apply_rx.try_recv() {
            apply(ebpf, control, &req.sources, &req.reply, &mut object_paths);
        }
    }
    Ok(())
}

/// Handle one `policy apply`: recompile the text, and if it has no errors re-seed the
/// maps via the atomic double-buffer swap ([`super::seed::seed_policy`]) and republish
/// the effective view. Always replies with the diagnostics so the CLI can show them
/// whether or not it applied.
fn apply(
    ebpf: &mut Ebpf,
    control: &PolicyControl,
    sources: &[PolicySource],
    reply: &std::sync::mpsc::Sender<ApplyOutcome>,
    object_paths: &mut HashMap<FileId, PathBuf>,
) {
    let compiled = super::compile_sources(sources);
    let applied = if compiled.has_errors() {
        false
    } else {
        match super::seed::seed_policy(ebpf, &compiled) {
            Ok(()) => {
                *control.current.lock().unwrap() = Some(super::build_view(&compiled));
                *object_paths = super::object_paths(&compiled);
                info!(objects = compiled.objects.len(), "policy applied");
                true
            }
            Err(e) => {
                error!(error = %e, "policy apply: seeding the maps failed; live policy unchanged");
                false
            }
        }
    };
    let _ = reply.send(ApplyOutcome {
        applied,
        diagnostics: compiled.diagnostics,
    });
}

/// A drain batch's worth of ring events sharing one `(exe, leaf, action)` identity,
/// folded into a single journal record. `events` is how many ring records were folded
/// (each one open that passed the in-kernel suppressor); `suppressed` is the sum of
/// their in-kernel folded counts. `count` (their sum) is the true number of opens the
/// burst represents.
struct Coalesced {
    exe: FileId,
    /// The matched protected object (the rule's `where`) — for the `object=` field.
    object: FileId,
    action: Action,
    /// Representative decision/policy/pid/path (the first occurrence; identical across the
    /// group — same `(exe, leaf, action)` ⇒ same matched rule + reconstructed path).
    decision: Decision,
    /// The matched policy — `audit`/`deny`, or `default-deny` (no rule matched). Lets the
    /// journal distinguish a default-deny from an explicit `deny` (DESIGN §15.6).
    policy: Policy,
    pid: Pid,
    /// The caller's real uid (representative, like `pid` — the in-kernel suppressor keys on
    /// `(exe, leaf, action)` regardless of uid, so a group can only carry one).
    uid: Uid,
    /// The opened file's path components (leaf-first) + how many are valid + truncation,
    /// for the `path=` field. Carried verbatim from the representative event.
    comps: [PathComp; PATH_MAX_DEPTH],
    depth: u8,
    trunc: u8,
    events: u32,
    suppressed: SuppressedTotal,
}

impl Coalesced {
    /// Total opens this record stands for: the ring records folded plus the opens the
    /// in-kernel suppressor held back.
    fn count(&self) -> Opens {
        Opens(u64::from(self.events) + u64::from(self.suppressed))
    }

    /// Journal it at the level its decision warrants. The fields are typed (`user` via
    /// [`CallerUser`], `object`/`path` via [`AuditPath`], `action`/`exe` via their own
    /// `Display`); `tracing` renders them lazily — no eager `String`s. For a regular user
    /// (DESIGN §15.8) a path under their home renders as `~/…`, so a `deny` line drops
    /// straight into that user's policy.
    fn log(&self, object_paths: &HashMap<FileId, PathBuf>, passwd: &Passwd) {
        let user = CallerUser::resolve(self.uid, passwd);
        let home = user.home();
        let exe = CallerExe::resolve(self.pid, self.exe);
        let object = ObjectName::resolve(self.object, object_paths).into_audit(home);
        let path = OpenedPath::resolve(self, object_paths).into_audit(home);
        let action = self.action;
        let policy = self.policy;
        let (count, suppressed) = (self.count(), self.suppressed);
        match self.decision {
            Decision::DENY => {
                info!(pid = self.pid.0, %user, %exe, %object, %path, %action, %policy, %count, %suppressed, "deny")
            }
            _ => {
                info!(pid = self.pid.0, %user, %exe, %object, %path, %action, %policy, %count, %suppressed, "audit")
            }
        }
    }
}

/// Collapse a drain batch to one [`Coalesced`] record per `(exe, leaf, action)`, summing
/// the ring-record count and the in-kernel suppressed totals. Keyed on the opened file
/// (`leaf`), matching the in-kernel suppressor, so distinct files under one audited root
/// each get their own journal line (DESIGN §15.10 flow B). Insertion order is preserved
/// (first occurrence wins the representative decision/pid/path). Pure — the `/proc`
/// resolution and logging happen later, per record.
fn coalesce(events: &[DecisionEvent]) -> Vec<Coalesced> {
    let mut records: Vec<Coalesced> = Vec::new();
    let mut index: HashMap<(FileId, FileId, Action), usize> = HashMap::new();
    for e in events {
        match index.get(&(e.exe, e.leaf, e.action)) {
            Some(&i) => {
                records[i].events += 1;
                records[i].suppressed += e.suppressed;
            }
            None => {
                index.insert((e.exe, e.leaf, e.action), records.len());
                records.push(Coalesced {
                    exe: e.exe,
                    object: e.object,
                    action: e.action,
                    decision: e.decision,
                    policy: e.policy,
                    pid: e.pid,
                    uid: e.uid,
                    comps: e.comps,
                    depth: e.depth,
                    trunc: e.trunc,
                    events: 1,
                    suppressed: e.suppressed.into(),
                });
            }
        }
    }
    records
}

/// The caller's user in the journal: the login name resolved from the kernel-captured uid
/// (via the [`Passwd`] cache), plus — when it's a *regular* account (DESIGN §15.8) — that
/// user's home, so a path under it collapses to `~` and the line drops into the user's
/// policy. Falls back to the bare uid when passwd has no entry (a deleted or NSS-only
/// account). Borrows the cache, so naming a caller costs no allocation.
enum CallerUser<'a> {
    Named {
        name: &'a UserName,
        home: Option<&'a Path>,
    },
    Uid(Uid),
}

impl<'a> CallerUser<'a> {
    fn resolve(uid: Uid, passwd: &'a Passwd) -> CallerUser<'a> {
        match passwd.lookup(uid) {
            Some(id) => CallerUser::Named {
                name: id.name,
                home: id.home,
            },
            None => CallerUser::Uid(uid),
        }
    }

    /// The home whose prefix collapses to `~` on this caller's audit paths, if any.
    fn home(&self) -> Option<&Path> {
        match self {
            CallerUser::Named { home, .. } => *home,
            CallerUser::Uid(_) => None,
        }
    }
}

impl fmt::Display for CallerUser<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallerUser::Named { name, .. } => write!(f, "{name}"),
            CallerUser::Uid(uid) => write!(f, "{}", uid.0),
        }
    }
}

/// The caller's executable in the journal: a resolved path when `/proc/<pid>/exe` still
/// points at the inode the kernel recorded, else the raw inode (the pid exited or was
/// recycled, so a path would misattribute). The kernel's `FileId` is the race-free
/// anchor; modelling "path *or* inode" as a type keeps the distinction visible instead
/// of collapsing both into a `String`.
enum CallerExe {
    Resolved(PathBuf),
    Inode(FileId),
}

impl CallerExe {
    fn resolve(pid: Pid, exe: FileId) -> CallerExe {
        let link = format!("/proc/{}/exe", pid.0);
        if proc::file_id(Path::new(&link)) == Some(exe)
            && let Ok(path) = std::fs::read_link(&link)
        {
            return CallerExe::Resolved(path);
        }
        CallerExe::Inode(exe)
    }
}

impl fmt::Display for CallerExe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallerExe::Resolved(p) => write!(f, "{}", p.display()),
            CallerExe::Inode(id) => write!(f, "{id}"),
        }
    }
}

/// The protected object in the journal: its policy **path** when the daemon knows the
/// inode (it seeded the object from that path), else the raw inode. Same "path *or* inode,
/// kept distinct" modelling as [`CallerExe`] — there's no path at the `file_open` hook, so
/// the kernel only ever hands us the `FileId`.
enum ObjectName {
    Path(PathBuf),
    Inode(FileId),
}

impl ObjectName {
    fn resolve(object: FileId, object_paths: &HashMap<FileId, PathBuf>) -> ObjectName {
        match object_paths.get(&object) {
            Some(p) => ObjectName::Path(p.clone()),
            None => ObjectName::Inode(object),
        }
    }

    /// Lower to the journal renderer, collapsing `home` (if a regular user's) to `~`.
    fn into_audit(self, home: Option<&Path>) -> AuditPath<'_> {
        match self {
            ObjectName::Path(path) => AuditPath::Path { path, home },
            ObjectName::Inode(id) => AuditPath::Inode(id),
        }
    }
}

/// The **actual opened file** in the journal (DESIGN §15.10 flow B): the protected
/// object's known path with the kernel-reconstructed relative path joined on
/// (`object=~/.aws` + `config` → `path=~/.aws/config`). The kernel walks `d_name` since
/// `bpf_d_path` is unavailable at `file_open`. Falls back to the relative path alone (then
/// the inode) when the object's base path is unknown — same "best identity we have" stance
/// as [`ObjectName`].
enum OpenedPath {
    Path(PathBuf),
    Inode(FileId),
}

impl OpenedPath {
    fn resolve(c: &Coalesced, object_paths: &HashMap<FileId, PathBuf>) -> OpenedPath {
        let rel = relative_path(&c.comps, c.depth, c.trunc != 0);
        match (object_paths.get(&c.object), rel) {
            (Some(base), Some(rel)) => OpenedPath::Path(base.join(rel)),
            (Some(base), None) => OpenedPath::Path(base.clone()),
            (None, Some(rel)) => OpenedPath::Path(rel),
            (None, None) => OpenedPath::Inode(c.object),
        }
    }

    /// Lower to the journal renderer, collapsing `home` (if a regular user's) to `~`.
    fn into_audit(self, home: Option<&Path>) -> AuditPath<'_> {
        match self {
            OpenedPath::Path(path) => AuditPath::Path { path, home },
            OpenedPath::Inode(id) => AuditPath::Inode(id),
        }
    }
}

/// A resolved audit path as it prints in the journal, with a *regular* user's home
/// collapsed to `~` (DESIGN §15.8) so `object=`/`path=` read exactly as that user's policy
/// would author them — copy-paste from a `deny` line straight into the user's policy.
/// Both [`ObjectName`] and [`OpenedPath`] lower to this, so the two fields collapse
/// identically; the inode fallback (no known path) passes through. `home` is `None` for
/// root/system callers and unresolvable uids, leaving their paths absolute.
enum AuditPath<'a> {
    Path {
        path: PathBuf,
        home: Option<&'a Path>,
    },
    Inode(FileId),
}

impl fmt::Display for AuditPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // `strip_prefix` is component-wise, so `/home/alice` never matches a peer like
            // `/home/alicia` — only a true home prefix collapses.
            AuditPath::Path { path, home } => match home.and_then(|h| path.strip_prefix(h).ok()) {
                Some(rest) if rest.as_os_str().is_empty() => f.write_str("~"),
                Some(rest) => write!(f, "~/{}", rest.display()),
                None => write!(f, "{}", path.display()),
            },
            AuditPath::Inode(id) => write!(f, "{id}"),
        }
    }
}

/// Rebuild the opened file's path *relative to the matched object* from the leaf-first
/// components: `comps[depth-1]/…/comps[0]` (reversed). `None` when `depth == 0` (the object
/// *is* the opened file). A truncated walk (`trunc`) prefixes `…/` so a partial path never
/// reads as exact. Component bytes are raw kernel names → [`OsStr`] (not lossy UTF-8).
fn relative_path(comps: &[PathComp; PATH_MAX_DEPTH], depth: u8, trunc: bool) -> Option<PathBuf> {
    let depth = (depth as usize).min(PATH_MAX_DEPTH);
    if depth == 0 {
        return None;
    }
    let mut rel = PathBuf::new();
    if trunc {
        rel.push("…");
    }
    for slot in comps[..depth].iter().rev() {
        rel.push(OsStr::from_bytes(slot.name()));
    }
    Some(rel)
}

/// Reinterpret a ring-buffer record as a [`DecisionEvent`]. `None` if too short.
fn parse_event(bytes: &[u8]) -> Option<DecisionEvent> {
    if bytes.len() < std::mem::size_of::<DecisionEvent>() {
        return None;
    }
    // SAFETY: length checked; `DecisionEvent` is `repr(C)` POD and the kernel reserved
    // exactly `size_of::<DecisionEvent>()` bytes.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const DecisionEvent) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordon_bpf_common::{Dev, Ino, ObjId, Policy, Suppressed, SuppressedTotal};

    /// A protected root shared by the test events (the `object`); `leaf` is what varies.
    const OBJECT: FileId = FileId::new(Dev(1), Ino(100));

    /// A `DecisionEvent` for the given exe + **opened file (leaf)** inodes, action, and
    /// in-kernel suppressed count — the coalesce key is `(exe, leaf, action)`.
    fn ev(exe: Ino, leaf: Ino, action: Action, suppressed: Suppressed) -> DecisionEvent {
        DecisionEvent::new(
            Pid(1),
            Uid(1000),
            FileId::new(Dev(1), exe),
            OBJECT,
            FileId::new(Dev(1), leaf),
            ObjId(0),
            action,
            Decision::DENY,
            Policy::DENY,
            suppressed,
        )
    }

    /// A NUL-padded path component from a short name.
    fn comp(s: &str) -> PathComp {
        let mut c = PathComp::EMPTY;
        c.0[..s.len()].copy_from_slice(s.as_bytes());
        c
    }

    #[test]
    fn folds_identical_events_summing_counts() {
        let batch = vec![
            ev(Ino(10), Ino(20), Action::READ, Suppressed(0)),
            ev(Ino(10), Ino(20), Action::READ, Suppressed(5)),
            ev(Ino(10), Ino(20), Action::READ, Suppressed(3)),
        ];
        let out = coalesce(&batch);
        assert_eq!(out.len(), 1, "one (exe,leaf,action) → one record");
        assert_eq!(out[0].events, 3, "three ring records folded");
        assert_eq!(
            out[0].suppressed,
            SuppressedTotal(8),
            "in-kernel suppressed counts summed"
        );
        assert_eq!(
            out[0].count(),
            Opens(11),
            "total opens = events + suppressed"
        );
    }

    #[test]
    fn distinct_keys_stay_separate() {
        let batch = vec![
            ev(Ino(10), Ino(20), Action::READ, Suppressed(0)),
            ev(Ino(11), Ino(20), Action::READ, Suppressed(0)), // different exe
            ev(Ino(10), Ino(21), Action::READ, Suppressed(0)), // different leaf (a different opened file)
            ev(Ino(10), Ino(20), Action::WRITE, Suppressed(0)), // different action
            ev(Ino(10), Ino(20), Action::READ, Suppressed(2)), // dup of the first → folds in
        ];
        let out = coalesce(&batch);
        assert_eq!(out.len(), 4, "four distinct identities");
        // Insertion order preserved; the first key folded the trailing dup.
        assert_eq!(out[0].action, Action::READ);
        assert_eq!(out[0].events, 2);
        assert_eq!(out[0].suppressed, SuppressedTotal(2));
    }

    /// The discovery property (DESIGN §15.10 flow B): two files under the *same* protected
    /// object must NOT coalesce — they have distinct leaves, so each surfaces its own path.
    #[test]
    fn distinct_leaves_under_one_object_stay_separate() {
        let batch = vec![
            ev(Ino(10), Ino(20), Action::READ, Suppressed(0)),
            ev(Ino(10), Ino(21), Action::READ, Suppressed(0)), // same exe + object, different opened file
        ];
        assert_eq!(coalesce(&batch).len(), 2);
    }

    #[test]
    fn empty_batch_yields_nothing() {
        assert!(coalesce(&[]).is_empty());
    }

    #[test]
    fn relative_path_reverses_leaf_first_components() {
        let mut comps = [PathComp::EMPTY; PATH_MAX_DEPTH];
        comps[0] = comp("config"); // leaf
        comps[1] = comp(".aws"); // its parent
        assert_eq!(
            relative_path(&comps, 2, false).unwrap(),
            PathBuf::from(".aws/config")
        );
        // depth 0 ⇒ the object *is* the opened file ⇒ no relative path.
        assert!(relative_path(&comps, 0, false).is_none());
        // truncation prefixes `…/` so a partial path never reads as exact.
        assert_eq!(
            relative_path(&comps, 2, true).unwrap(),
            PathBuf::from("…/.aws/config")
        );
    }

    #[test]
    fn opened_path_joins_object_base() {
        let mut object_paths = HashMap::new();
        object_paths.insert(OBJECT, PathBuf::from("/home/u"));
        let mut e = ev(Ino(10), Ino(20), Action::READ, Suppressed(0));
        e.comps[0] = comp("config");
        e.comps[1] = comp(".aws");
        e.depth = 2;
        let record = coalesce(&[e]).pop().unwrap();
        match OpenedPath::resolve(&record, &object_paths) {
            OpenedPath::Path(p) => assert_eq!(p, PathBuf::from("/home/u/.aws/config")),
            OpenedPath::Inode(_) => panic!("expected a joined path"),
        }
    }

    #[test]
    fn audit_path_collapses_regular_home_to_tilde() {
        let home = PathBuf::from("/home/alice");
        let render = |p: &str| {
            AuditPath::Path {
                path: PathBuf::from(p),
                home: Some(&home),
            }
            .to_string()
        };
        // A child of the home → `~/rest`; the home itself → `~`.
        assert_eq!(render("/home/alice/.aws/config"), "~/.aws/config");
        assert_eq!(render("/home/alice"), "~");
        // Outside the home → absolute, untouched.
        assert_eq!(render("/etc/passwd"), "/etc/passwd");
        // A peer that only shares a textual prefix must NOT collapse (component-wise strip).
        assert_eq!(render("/home/alicia/.aws"), "/home/alicia/.aws");
        // No home (root/system/unresolved caller) → absolute, untouched.
        assert_eq!(
            AuditPath::Path {
                path: PathBuf::from("/home/alice/.aws"),
                home: None,
            }
            .to_string(),
            "/home/alice/.aws"
        );
        // The inode fallback prints the raw identity regardless of home.
        assert_eq!(
            AuditPath::Inode(FileId::new(Dev(1), Ino(7))).to_string(),
            "dev=1 ino=7"
        );
    }

    #[test]
    fn caller_user_renders_name_or_bare_uid() {
        // A regular user: name shown, home kept for `~` collapse. (`CallerUser` borrows the
        // cache, so the owned name/home outlive it here.)
        let (alice, alice_home) = (UserName::new("alice"), PathBuf::from("/home/alice"));
        let u = CallerUser::Named {
            name: &alice,
            home: Some(&alice_home),
        };
        assert_eq!(u.to_string(), "alice");
        assert_eq!(u.home(), Some(Path::new("/home/alice")));
        // Resolved but not regular (root/system): name shown, no home → paths stay absolute.
        let root = UserName::new("root");
        let u = CallerUser::Named {
            name: &root,
            home: None,
        };
        assert_eq!(u.to_string(), "root");
        assert_eq!(u.home(), None);
        // No passwd entry → the bare uid, no home.
        let u = CallerUser::Uid(Uid(4242));
        assert_eq!(u.to_string(), "4242");
        assert_eq!(u.home(), None);
    }
}
