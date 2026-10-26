//! Turns the decisions that the eBPF program logs into journal lines, inside the backend
//! thread's loop that also serves control requests. The verdict already happened
//! in-kernel, so this is only the audit path.
//!
//! Tools re-open the same config hundreds of times per run. The in-kernel suppressor
//! (keyed by [`SuppressKey`](cordon_bpf_common::SuppressKey)) thins the ring, and
//! [`coalesce`] folds whatever one drain still surfaces, so a burst becomes one line.

use super::bless::Blessings;
use super::seed::Maps;
use crate::proc;
use aya::Ebpf;
use aya::maps::RingBuf;
use cordon_bpf_common::{
    Action, ClassId, DecisionEvent, FileId, MAP_EVENTS, Opens, PATH_MAX_DEPTH, PathComp, Pid,
    Policy, SuppressedTotal, Uid,
};
use cordon_core::backend::{ApplyOutcome, BlessOp, ControlMsg, PolicyControl, Shutdown};
use cordon_core::passwd::Passwd;
use cordon_core::policy::{ClassName, ClassRegistry, CompiledPolicy, PolicySource, UserName};
use cordon_core::{Context, Error, Result};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

/// The longest the reader sleeps in one poll, in milliseconds. Each wakeup re-checks
/// shutdown and the control channel, and ticks the blessing GC.
const POLL_TIMEOUT_MS: u16 = 500;

/// The backend thread's per-run state that sits beside the `Ebpf` handle. Only that
/// thread touches it, and each successful apply refreshes it from the new compile.
pub(super) struct Runtime {
    /// The path of each protected object by inode, which names objects in the journal.
    pub object_paths: HashMap<FileId, PathBuf>,
    /// The class registry of the live compile. Mints resolve against it, an apply remaps
    /// live blessings with it, and the journal names a blessed caller's class from it.
    pub classes: ClassRegistry,
    pub blessings: Blessings,
}

impl Runtime {
    pub(super) fn new(compiled: &CompiledPolicy) -> Runtime {
        Runtime {
            object_paths: super::object_paths(compiled),
            classes: compiled.classes.clone(),
            blessings: Blessings::new(),
        }
    }

    /// Replaces the object paths and the class registry with those of `compiled`. The
    /// class ids have just been renumbered, so live blessings carry stale ids until
    /// `blessings.remap` runs.
    fn refresh(&mut self, compiled: &CompiledPolicy) {
        self.object_paths = super::object_paths(compiled);
        self.classes = compiled.classes.clone();
    }
}

/// Writes logged decisions to the journal and serves control requests until shutdown.
/// Applies land, and dead blessing carriers are reaped, within one poll interval
/// ([`POLL_TIMEOUT_MS`]).
///
/// Errors when the object has no events ring buffer or polling it fails.
pub(super) fn serve(
    ebpf: &mut Ebpf,
    control: &PolicyControl,
    shutdown: &Arc<Shutdown>,
    mut runtime: Runtime,
) -> Result<()> {
    let mut ring = RingBuf::try_from(
        ebpf.take_map(MAP_EVENTS)
            .ok_or_else(|| Error::msg(format!("bpf-lsm: {MAP_EVENTS} missing from object")))?,
    )
    .with_context(|| format!("bpf-lsm: {MAP_EVENTS}"))?;
    let mut maps = Maps(ebpf);
    let raw = ring.as_raw_fd();
    // Names callers on the audit line. It reloads at most once per drain, and only when
    // /etc/passwd has changed.
    let mut passwd = Passwd::new();

    // The ring poll's timeout doubles as the control tick. Every wakeup, by an event or by
    // the timeout, also serves pending control messages and runs the blessing GC.
    while !shutdown.is_triggered() {
        // SAFETY: `raw` is the ring buffer's fd, owned by `ring` for this scope.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(POLL_TIMEOUT_MS)) {
            Ok(0) => {} // A timeout only re-checks shutdown and the control channel.
            Ok(_) => {
                // Drain the whole ready batch, then coalesce it.
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
                // Refresh once per drain, which is cheap unless /etc/passwd changed, and
                // name each record's caller from the cache.
                passwd.refresh();
                for record in coalesce(&batch) {
                    record.log(&runtime.object_paths, &runtime.classes, &passwd);
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::msg(format!("bpf-lsm: poll: {e}"))),
        }
        // Service the control messages that arrived since the last tick, in order (see
        // `ControlMsg` for why applies and bless ops share one channel).
        while let Ok(msg) = control.msg_rx.try_recv() {
            match msg {
                ControlMsg::Apply(req) => {
                    apply(&mut maps, control, &req.sources, &req.reply, &mut runtime)
                }
                ControlMsg::Bless(op) => bless_op(&mut maps, &mut runtime, op),
            }
        }
        // Reap dead blessing carriers (`populated 0`) each tick.
        runtime.blessings.gc(&mut maps);
    }
    Ok(())
}

/// Applies one bless op to the blessings table and the maps, and sends the outcome on the
/// op's reply channel. The op takes effect even when the requester no longer waits for it.
fn bless_op(maps: &mut Maps, runtime: &mut Runtime, op: BlessOp) {
    match op {
        BlessOp::Mint {
            class,
            owner,
            requester,
            reply,
        } => {
            let outcome = runtime
                .blessings
                .mint(maps, class, owner, requester, &runtime.classes)
                .map_err(|e| e.to_string());
            let _ = reply.send(outcome);
        }
        BlessOp::List { reply } => {
            let _ = reply.send(Ok(runtime.blessings.list()));
        }
        BlessOp::Revoke { id, by, reply } => {
            let _ = reply.send(runtime.blessings.revoke(id, by).map_err(|e| e.to_string()));
        }
    }
}

/// Recompiles the policy fragments `sources`. When they have no errors, it re-seeds the
/// maps ([`Maps::seed`]), republishes the effective view, refreshes `runtime` and remaps
/// live blessings. Always sends the diagnostics on `reply`, with whether the policy was
/// applied.
fn apply(
    maps: &mut Maps,
    control: &PolicyControl,
    sources: &[PolicySource],
    reply: &std::sync::mpsc::Sender<ApplyOutcome>,
    runtime: &mut Runtime,
) {
    let compiled = super::compile_sources(sources);
    let applied = if compiled.has_errors() {
        false
    } else {
        match maps.seed(&compiled) {
            Ok(()) => {
                *control.current.lock().unwrap() = Some(super::build_view(&compiled));
                runtime.refresh(&compiled);
                // This compile renumbered the ClassIds (see `Blessings::remap`).
                runtime.blessings.remap(maps, &runtime.classes);
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

/// The decisions in one drain batch that share a [`coalesce`] key, folded into a single
/// journal record.
struct Coalesced {
    exe: FileId,
    /// The matched protected object (the rule's `where`), which the `object=` field names.
    object: FileId,
    action: Action,
    /// The matched rule's policy, taken from the first occurrence. It is the same across
    /// the group, because the same `(exe, leaf, action)` hits the same rule. It decides
    /// between the `deny` and `audit` message words, and it names the cause (DESIGN §15.6).
    policy: Policy,
    pid: Pid,
    /// The caller's real uid, taken from the first occurrence like `pid`. The uid is not
    /// part of the [`coalesce`] key, so a group can carry only one.
    uid: Uid,
    /// The caller's resolved blessing class, or [`ClassId::UNBLESSED`] when it has none. It
    /// is part of the [`coalesce`] key, and [`BlessingName`] renders it.
    blessing: ClassId,
    /// The opened file's path components, leaf first, for the `path=` field. `depth` says
    /// how many are valid and `trunc` whether the walk was cut short. All three come
    /// verbatim from the first occurrence.
    comps: [PathComp; PATH_MAX_DEPTH],
    depth: u8,
    trunc: u8,
    /// How many ring records were folded. Each one is an open that passed the in-kernel
    /// suppressor.
    events: u32,
    /// The sum of the folded records' in-kernel suppressed counts.
    suppressed: SuppressedTotal,
}

impl Coalesced {
    /// Returns the total opens that this record stands for. They are the folded ring
    /// records plus the opens that the in-kernel suppressor held back.
    fn count(&self) -> Opens {
        Opens(u64::from(self.events) + u64::from(self.suppressed))
    }

    /// Writes this record to the journal as a `deny` or an `audit` line. An unblessed
    /// line carries no `blessing` field.
    fn log(
        &self,
        object_paths: &HashMap<FileId, PathBuf>,
        classes: &ClassRegistry,
        passwd: &Passwd,
    ) {
        // Every field is a typed value with its own `Display`, so `tracing` renders it
        // lazily, with no eager `String`s.
        let user = CallerUser::resolve(self.uid, passwd);
        let home = user.home();
        let exe = CallerExe::resolve(self.pid, self.exe);
        let object = ObjectName::resolve(self.object, object_paths).into_audit(home);
        let path = OpenedPath::resolve(self, object_paths).into_audit(home);
        let action = self.action;
        let policy = self.policy;
        let (count, suppressed) = (self.count(), self.suppressed);
        match (
            policy.denies(),
            BlessingName::resolve(self.blessing, classes),
        ) {
            (true, Some(blessing)) => {
                info!(pid = self.pid.0, %user, %exe, %object, %path, %action, %policy, %count, %suppressed, %blessing, "deny")
            }
            (true, None) => {
                info!(pid = self.pid.0, %user, %exe, %object, %path, %action, %policy, %count, %suppressed, "deny")
            }
            (_, Some(blessing)) => {
                info!(pid = self.pid.0, %user, %exe, %object, %path, %action, %policy, %count, %suppressed, %blessing, "audit")
            }
            (_, None) => {
                info!(pid = self.pid.0, %user, %exe, %object, %path, %action, %policy, %count, %suppressed, "audit")
            }
        }
    }
}

/// Folds a drain batch into one [`Coalesced`] record per `(exe, leaf, action, blessing)`,
/// in the order each key first occurs. The first occurrence supplies the record's
/// decision, pid and path, and [`Coalesced::count`] gives the record's true volume.
///
/// The key is the opened file (`leaf`), as in the in-kernel suppressor, so distinct files
/// under one audited root each get their own journal line (DESIGN §15.10 flow B). The
/// blessing is part of the key because bless is loud (DESIGN §16.3), and a blessed access
/// must never fold into, or hide behind, an unblessed one.
fn coalesce(events: &[DecisionEvent]) -> Vec<Coalesced> {
    let mut records: Vec<Coalesced> = Vec::new();
    let mut index: HashMap<(FileId, FileId, Action, ClassId), usize> = HashMap::new();
    for e in events {
        match index.get(&(e.exe, e.leaf, e.action, e.blessing)) {
            Some(&i) => {
                records[i].events += 1;
                records[i].suppressed += e.suppressed;
            }
            None => {
                index.insert((e.exe, e.leaf, e.action, e.blessing), records.len());
                records.push(Coalesced {
                    exe: e.exe,
                    object: e.object,
                    action: e.action,
                    policy: e.policy,
                    pid: e.pid,
                    uid: e.uid,
                    blessing: e.blessing,
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

/// The caller as the journal names it. That is the login name for the kernel-captured
/// uid, or the bare uid when passwd has no entry (a deleted or NSS-only account). A
/// regular account also carries the home that [`AuditPath`] collapses to `~`. It borrows
/// the [`Passwd`] cache, so naming a caller costs no allocation.
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

    /// Returns the home that collapses to `~` on this caller's audit paths, if it has one.
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
            CallerUser::Uid(uid) => write!(f, "{uid}"),
        }
    }
}

/// The caller's blessing class as the journal names it. That is the policy name when the
/// live registry knows the id, or else the raw id. The raw id shows up when an apply
/// renumbered the registry between the kernel's verdict and this drain. That is rare, but
/// a blessed access must never render as unblessed. It borrows the registry, like
/// [`CallerUser`].
enum BlessingName<'a> {
    Named(&'a ClassName),
    Id(ClassId),
}

impl<'a> BlessingName<'a> {
    /// Returns the name of `class`, or `None` for [`ClassId::UNBLESSED`], so an unblessed
    /// line carries no `blessing=` field at all.
    fn resolve(class: ClassId, classes: &'a ClassRegistry) -> Option<BlessingName<'a>> {
        if class == ClassId::UNBLESSED {
            return None;
        }
        Some(match classes.name(class) {
            Some(name) => BlessingName::Named(name),
            None => BlessingName::Id(class),
        })
    }
}

impl fmt::Display for BlessingName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlessingName::Named(name) => write!(f, "{name}"),
            BlessingName::Id(id) => write!(f, "{id}"),
        }
    }
}

/// The caller's executable as the journal names it. That is its path when
/// `/proc/<pid>/exe` still points at the inode the kernel recorded. Otherwise it is the
/// raw inode, because the pid exited or was recycled and a path would misattribute. The
/// kernel's `FileId` is the race-free anchor, and the two variants keep a path and an
/// inode distinct instead of collapsing both into a `String`.
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

/// The protected object as the journal names it. That is its policy path when the daemon
/// knows the inode, because it seeded the object from that path, or else the raw inode.
/// The kernel only ever hands over the `FileId`.
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

    /// Returns the journal rendering of this name, with `home` collapsed to `~`.
    fn into_audit(self, home: Option<&Path>) -> AuditPath<'_> {
        match self {
            ObjectName::Path(path) => AuditPath::Path { path, home },
            ObjectName::Inode(id) => AuditPath::Inode(id),
        }
    }
}

/// The file that was actually opened, as the journal names it (DESIGN §15.10 flow B). It
/// is the protected object's known path with the relative path that the kernel rebuilt
/// joined on, so `object=~/.aws` and `config` give `path=~/.aws/config` (see
/// [`DecisionEvent::comps`]). When the object's path is unknown, it is the relative path
/// alone, and when that is missing too, it is the inode.
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

    /// Returns the journal rendering of this path, with `home` collapsed to `~`.
    fn into_audit(self, home: Option<&Path>) -> AuditPath<'_> {
        match self {
            OpenedPath::Path(path) => AuditPath::Path { path, home },
            OpenedPath::Inode(id) => AuditPath::Inode(id),
        }
    }
}

/// An audit path as the journal prints it, with a regular user's home collapsed to `~`
/// (DESIGN §15.8). `object=` and `path=` then read exactly as that user's policy would
/// write them, so a `deny` line copies straight into the policy. Both [`ObjectName`] and
/// [`OpenedPath`] render through this, so the two fields collapse the same way.
enum AuditPath<'a> {
    Path {
        path: PathBuf,
        /// The caller's home, or `None` for root, system callers and unresolvable uids,
        /// whose paths stay absolute. `cordon_core::passwd` decides which uids count.
        home: Option<&'a Path>,
    },
    Inode(FileId),
}

impl fmt::Display for AuditPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // `strip_prefix` is component-wise, so `/home/alice` never matches a peer like
            // `/home/alicia`. Only a true home prefix collapses.
            AuditPath::Path { path, home } => match home.and_then(|h| path.strip_prefix(h).ok()) {
                Some(rest) if rest.as_os_str().is_empty() => f.write_str("~"),
                Some(rest) => write!(f, "~/{}", rest.display()),
                None => write!(f, "{}", path.display()),
            },
            AuditPath::Inode(id) => write!(f, "{id}"),
        }
    }
}

/// Returns the opened file's path relative to the matched object, built from the
/// leaf-first components `comps`. Returns `None` when `depth` is 0, because the object is
/// then the opened file. A truncated walk (`trunc`) starts with `…/`, so a partial path
/// never reads as exact. The components are raw kernel names, kept as [`OsStr`] rather
/// than lossy UTF-8.
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

/// Returns the [`DecisionEvent`] that a ring-buffer record holds, or `None` when the
/// record is too short.
fn parse_event(bytes: &[u8]) -> Option<DecisionEvent> {
    if bytes.len() < std::mem::size_of::<DecisionEvent>() {
        return None;
    }
    // SAFETY: the length is checked, `DecisionEvent` is `repr(C)` POD, and the kernel
    // reserved exactly `size_of::<DecisionEvent>()` bytes.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const DecisionEvent) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordon_bpf_common::{ClassId, Dev, Ino, Policy, Suppressed, SuppressedTotal};

    /// The protected root (the `object`) that the test events share. Their `leaf` is what
    /// varies.
    const OBJECT: FileId = FileId::new(Dev(1), Ino(100));

    /// Returns an unblessed `DecisionEvent` with the given exe and opened-file (`leaf`)
    /// inodes, action and in-kernel suppressed count.
    fn ev(exe: Ino, leaf: Ino, action: Action, suppressed: Suppressed) -> DecisionEvent {
        DecisionEvent::new(
            Pid(1),
            Uid(1000),
            FileId::new(Dev(1), exe),
            OBJECT,
            FileId::new(Dev(1), leaf),
            action,
            Policy::DENY,
            suppressed,
            ClassId::UNBLESSED,
        )
    }

    /// Returns [`ev`] with the caller resolved to the blessing `class`, which is the fourth
    /// part of the coalesce key.
    fn ev_blessed(exe: Ino, leaf: Ino, action: Action, class: ClassId) -> DecisionEvent {
        let mut e = ev(exe, leaf, action, Suppressed(0));
        e.blessing = class;
        e
    }

    /// Returns a NUL-padded path component that holds the short name `s`.
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

    /// Checks the discovery property (DESIGN §15.10 flow B). Two files under the same
    /// protected object must not coalesce, because their leaves differ and each one
    /// surfaces its own path.
    #[test]
    fn distinct_leaves_under_one_object_stay_separate() {
        let batch = vec![
            ev(Ino(10), Ino(20), Action::READ, Suppressed(0)),
            ev(Ino(10), Ino(21), Action::READ, Suppressed(0)), // same exe + object, different opened file
        ];
        assert_eq!(coalesce(&batch).len(), 2);
    }

    /// Checks that a blessed access never folds into, or hides behind, an unblessed one
    /// with the same `(exe, leaf, action)`. The blessing is part of the coalesce identity.
    #[test]
    fn distinct_blessings_stay_separate_identical_ones_fold() {
        let batch = vec![
            ev(Ino(10), Ino(20), Action::READ, Suppressed(0)), // unblessed
            ev_blessed(Ino(10), Ino(20), Action::READ, ClassId(1)),
            ev_blessed(Ino(10), Ino(20), Action::READ, ClassId(2)), // different class
            ev_blessed(Ino(10), Ino(20), Action::READ, ClassId(1)), // dup → folds into the first
        ];
        let out = coalesce(&batch);
        assert_eq!(out.len(), 3, "unblessed + class 1 + class 2");
        assert_eq!(out[0].blessing, ClassId::UNBLESSED);
        assert_eq!(out[1].blessing, ClassId(1));
        assert_eq!(out[1].events, 2, "same class folded");
        assert_eq!(out[2].blessing, ClassId(2));
    }

    #[test]
    fn empty_batch_yields_nothing() {
        assert!(coalesce(&[]).is_empty());
    }

    #[test]
    fn blessing_name_renders_name_or_raw_id_and_nothing_when_unblessed() {
        let names = ClassRegistry::new([ClassName::new("ro")]);
        // A registered class renders its policy name.
        let named = BlessingName::resolve(ClassId(1), &names).expect("blessed → Some");
        assert_eq!(named.to_string(), "ro");
        // An id the registry doesn't know, because an apply renumbered it mid-flight,
        // falls back to the raw id. A blessed access must never render as unblessed.
        let raw = BlessingName::resolve(ClassId(7), &names).expect("blessed → Some");
        assert_eq!(raw.to_string(), "7");
        // UNBLESSED resolves to nothing, so the journal line carries no `blessing=` field.
        assert!(BlessingName::resolve(ClassId::UNBLESSED, &names).is_none());
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
        // At depth 0 the object is the opened file, so there is no relative path.
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
        // A child of the home renders as `~/rest`, and the home itself as `~`.
        assert_eq!(render("/home/alice/.aws/config"), "~/.aws/config");
        assert_eq!(render("/home/alice"), "~");
        // A path outside the home stays absolute.
        assert_eq!(render("/etc/passwd"), "/etc/passwd");
        // A peer that only shares a textual prefix must NOT collapse (component-wise strip).
        assert_eq!(render("/home/alicia/.aws"), "/home/alicia/.aws");
        // With no home (a root, system or unresolved caller), the path stays absolute.
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
        // A regular user shows the name and keeps the home for the `~` collapse.
        // `CallerUser` borrows the cache, so the owned name and home outlive it here.
        let (alice, alice_home) = (UserName::new("alice"), PathBuf::from("/home/alice"));
        let u = CallerUser::Named {
            name: &alice,
            home: Some(&alice_home),
        };
        assert_eq!(u.to_string(), "alice");
        assert_eq!(u.home(), Some(Path::new("/home/alice")));
        // A resolved user that is not regular (root or a system account) shows the name
        // and has no home, so its paths stay absolute.
        let root = UserName::new("root");
        let u = CallerUser::Named {
            name: &root,
            home: None,
        };
        assert_eq!(u.to_string(), "root");
        assert_eq!(u.home(), None);
        // With no passwd entry, the bare uid shows and there is no home.
        let u = CallerUser::Uid(Uid(4242));
        assert_eq!(u.to_string(), "4242");
        assert_eq!(u.home(), None);
    }
}
