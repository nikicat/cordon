//! The live blessings table (DESIGN §16): carrier cgroups + the `BLESSED` map.
//!
//! A blessing is a **carrier cgroup** (`cordon-bless-<id>.<class>` under the daemon's
//! own cgroup) whose kernel id is registered in `MAP_BLESSED` → the class's dense
//! [`ClassId`]. The CLI (root, via sudo) execs the target into the carrier; membership
//! is the boundary — the dirs are root-owned, so a non-root process can't join.
//!
//! Backend-thread state, like the rule maps: every mutation (mint / revoke / GC /
//! remap / reconcile) runs on the backend thread via the one control channel, so the
//! single-writer discipline holds for `MAP_BLESSED` too.
//!
//! Lifecycle: **mint** (mkdir + register) → the CLI joins the target → … → the last
//! member exits (`cgroup.events populated 0`) → **GC** (unregister + rmdir). A mint
//! grace window covers the gap where a fresh carrier is still empty because the CLI
//! hasn't joined the target yet; `revoke` kills the whole carrier tree (`cgroup.kill`)
//! and lets the same GC finish. At startup, **reconcile** adopts leftover carriers
//! from a previous daemon run (its map entries died with it — a blessing only ever
//! grants again if its class is still declared).

use super::seed;
use aya::Ebpf;
use cordon_bpf_common::{CgroupId, ClassId, MAX_BLESSED};
use cordon_core::policy::ClassName;
use cordon_core::proto::{BlessId, BlessingView, CarrierProcs, Pid};
use cordon_core::{Error, Result, Uid};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// How long a fresh, never-populated carrier is left alone before GC may reap it.
/// Load-bearing: a carrier is empty from mint until the CLI's `pre_exec` writes the
/// target pid into it — without the grace, the 500ms GC tick would reap it first.
/// Generous because the cost of a leak is one empty cgroup dir for 30s; a CLI that
/// died before joining is cleaned up right after.
const MINT_GRACE: Duration = Duration::from_secs(30);

/// The cgroup2 mount. Both the daemon's own cgroup and a requester's session scope are
/// resolved against it, since `/proc/<pid>/cgroup` gives a path *relative* to the root.
///
/// A function rather than a `const`, only because `Path::new` is not const-stable yet
/// (rust-lang#143874); the point is that callers get a `Path` instead of re-wrapping a
/// `&str` at each use.
fn cgroup_root() -> &'static Path {
    Path::new("/sys/fs/cgroup")
}

/// The live blessings table — backend-thread state beside the `Ebpf` handle.
pub(super) struct Blessings {
    /// Where carrier cgroups live: the daemon's own cgroup directory, resolved once at
    /// startup. `None` ⇒ unresolvable (no cgroup2) — minting errors, everything else
    /// (the 17 pre-bless scenarios) is unaffected.
    root: Option<PathBuf>,
    /// The next [`BlessId`]; monotonic per run, bumped past adopted ids at reconcile.
    next: BlessId,
    live: Vec<Blessing>,
}

/// One live blessing.
struct Blessing {
    /// The daemon-assigned handle (`bless list`/`revoke <id>`); also embedded in the
    /// carrier's directory name, which is how it survives a daemon restart.
    id: BlessId,
    /// The blessing class it was minted for — the *name* is the durable identity: an
    /// apply renumbers `ClassId`s, and [`Blessings::remap`] re-resolves this name.
    class: ClassName,
    /// The carrier cgroup directory (root-owned; membership is the boundary).
    dir: PathBuf,
    /// Who asked for it — the requester's kernel-attested uid. Only they and root may
    /// revoke it. A blessing adopted from a previous daemon run has no recorded owner
    /// (`None`): the requester is long gone, so revoking it is root's call.
    owner: Option<Uid>,
    /// The carrier's kernel cgroup id — the `MAP_BLESSED` key.
    cgroup: CgroupId,
    /// Whether a `MAP_BLESSED` entry currently exists for it. `false` when the class
    /// vanished on an apply: the entry is inert (grants nothing) but kept for GC —
    /// never kill a tree just because policy changed under it.
    registered: bool,
    /// The carrier has had a member at some point — from then on, `populated 0` means
    /// "everything exited", not "the CLI hasn't joined yet".
    saw_populated: bool,
    /// `cordon bless revoke` hit it (`cgroup.kill` written): GC may reap it the moment
    /// it reads empty, mint grace notwithstanding.
    revoked: bool,
    /// When it was minted (or adopted by reconcile) — starts the mint grace window and
    /// feeds the view's `age`.
    minted: Instant,
}

impl Blessings {
    /// Resolve the carrier root from the daemon's own cgroup. Failure is not fatal:
    /// minting reports "unavailable", the rest of the daemon runs unaffected.
    pub(super) fn new() -> Blessings {
        let root = match carrier_root() {
            Ok(root) => Some(root),
            Err(e) => {
                warn!(error = %e, "bless: carrier root unresolved; minting unavailable");
                None
            }
        };
        Blessings {
            root,
            next: BlessId(1),
            live: Vec::new(),
        }
    }

    /// Mint a blessing: create the carrier cgroup, register it in `MAP_BLESSED`, and
    /// return it together with its `cgroup.procs` opened for write. The caller execs the
    /// target into the carrier by writing the child's pid through that fd.
    pub(super) fn mint(
        &mut self,
        ebpf: &mut Ebpf,
        class: Option<ClassName>,
        owner: Uid,
        requester: Pid,
        registry: &BTreeMap<ClassName, ClassId>,
    ) -> Result<(BlessingView, CarrierProcs)> {
        let root = self.root.as_ref().ok_or_else(|| {
            Error::msg("blessing unavailable: the daemon's cgroup was unresolvable at startup")
        })?;
        let (class, class_id) = resolve_class(class, registry)?;
        if !valid_class_dirname(class.as_str()) {
            return Err(Error::msg(format!(
                "blessing class '{class}' has characters outside [A-Za-z0-9_-]; \
                 rename it in the policy"
            )));
        }
        if self.live.len() >= MAX_BLESSED {
            return Err(Error::msg(format!(
                "too many live blessings (max {MAX_BLESSED})"
            )));
        }

        let id = self.next;
        // In the requester's own session scope where possible, so the blessed process
        // keeps its logind session and polkit/run0 keep working inside it.
        let dir = carrier_parent(requester, root).join(dir_name(id, &class));
        std::fs::create_dir(&dir)
            .map_err(|e| Error::msg(format!("bless: mkdir {}: {e}", dir.display())))?;
        // The carrier's kernel cgroup id: cgroup2 (kernfs) guarantees st_ino == the id
        // `bpf_get_current_cgroup_id()` returns (kernel ≥5.5; BPF-LSM needs ≥5.7, and
        // st_ino is the full 64-bit id — no 32-bit truncation on a 64-bit kernel). The
        // smoke's scoped-grant scenario is the end-to-end proof of this equality.
        let cgroup = match std::fs::metadata(&dir) {
            Ok(meta) => CgroupId(std::os::unix::fs::MetadataExt::ino(&meta)),
            Err(e) => {
                let _ = std::fs::remove_dir(&dir);
                return Err(Error::msg(format!("bless: stat fresh carrier: {e}")));
            }
        };
        // Open `cgroup.procs` here, as root, before handing anything back: this fd *is*
        // the grant (DESIGN §16.4). cgroup-v2 checks migration permission against the
        // opener's credentials, so the unprivileged CLI can write its child's pid through
        // it without ever holding privilege — and never needs the path at all.
        let procs = match std::fs::File::options()
            .write(true)
            .open(dir.join("cgroup.procs"))
        {
            Ok(f) => CarrierProcs(f.into()),
            Err(e) => {
                let _ = std::fs::remove_dir(&dir);
                return Err(Error::msg(format!(
                    "bless: open {}/cgroup.procs: {e}",
                    dir.display()
                )));
            }
        };
        if let Err(e) = seed::blessed_insert(ebpf, cgroup, class_id) {
            let _ = std::fs::remove_dir(&dir);
            return Err(e);
        }

        self.next = id.successor();
        self.live.push(Blessing {
            id,
            class: class.clone(),
            dir: dir.clone(),
            owner: Some(owner),
            cgroup,
            registered: true,
            saw_populated: false,
            revoked: false,
            minted: Instant::now(),
        });
        info!(%id, %class, %owner, cgroup = %dir.display(), "blessing minted");
        Ok((
            BlessingView {
                id,
                class,
                cgroup: dir,
                pids: Vec::new(),
                age: Duration::ZERO,
            },
            procs,
        ))
    }

    /// Snapshot the live blessings (member pids read fresh from each carrier).
    pub(super) fn list(&self) -> Vec<BlessingView> {
        self.live
            .iter()
            .map(|b| BlessingView {
                id: b.id,
                class: b.class.clone(),
                cgroup: b.dir.clone(),
                pids: read_pids(&b.dir),
                age: b.minted.elapsed(),
            })
            .collect()
    }

    /// Kill a blessing's carrier tree (`cgroup.kill`); the regular GC observes the
    /// resulting `populated 0` and finishes (unregister + rmdir).
    ///
    /// `by` is the caller's kernel-attested uid — root, or the uid that minted it.
    pub(super) fn revoke(&mut self, id: BlessId, by: Uid) -> Result<()> {
        let b = self
            .live
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or_else(|| Error::msg(format!("no blessing with id {id}")))?;
        if !may_revoke(b.owner, by) {
            // Deliberately the same shape as "no such id": whether a blessing exists is
            // itself information, and `bless list` is the way to ask that question.
            return Err(Error::msg(format!("no blessing with id {id}")));
        }
        b.revoked = true;
        // A write error means the carrier is already gone or dying — `revoked` alone
        // lets GC reap it, so report success either way.
        if let Err(e) = std::fs::write(b.dir.join("cgroup.kill"), "1") {
            warn!(id = %b.id, error = %e, "bless: cgroup.kill write failed; GC will reap");
        }
        info!(id = %b.id, class = %b.class, "blessing revoked");
        Ok(())
    }

    /// Reap dead carriers — run on every serve tick (≤500ms cadence). A carrier is
    /// reaped once it reads `populated 0` *and* that emptiness is meaningful:
    /// something ran and exited, it was revoked, or the mint grace expired (the CLI
    /// died before joining). Reaping = `MAP_BLESSED` remove + rmdir + drop.
    pub(super) fn gc(&mut self, ebpf: &mut Ebpf) {
        self.live.retain_mut(|b| {
            match read_populated(&b.dir) {
                Some(true) => {
                    b.saw_populated = true;
                    true
                }
                Some(false) if should_reap(b.saw_populated, b.revoked, b.minted.elapsed()) => {
                    reap(ebpf, b);
                    false
                }
                Some(false) => true,
                // The carrier dir (or its cgroup.events) vanished under us — nothing
                // left to keep alive; drop the map entry and the table row.
                None => {
                    reap(ebpf, b);
                    false
                }
            }
        });
    }

    /// Re-point every live blessing at the new compile's `ClassId`s — **by class
    /// name**. Called from the apply path: `policy apply` renumbers ids (dense,
    /// name-sorted), so without this a live blessing silently changes meaning. A
    /// vanished class unregisters the map entry (the blessing grants nothing) but the
    /// carrier is left to GC — never kill the tree because policy changed under it.
    pub(super) fn remap(&mut self, ebpf: &mut Ebpf, registry: &BTreeMap<ClassName, ClassId>) {
        for b in &mut self.live {
            match remap_plan(b.registered, registry.get(&b.class).copied()) {
                Remap::Register(class_id) => match seed::blessed_insert(ebpf, b.cgroup, class_id) {
                    Ok(()) => b.registered = true,
                    Err(e) => {
                        // Fail closed: a stale entry would mean the *renumbered* id —
                        // a different class. Grant nothing rather than the wrong thing.
                        warn!(id = %b.id, error = %e, "bless: remap re-insert failed; unregistering");
                        let _ = seed::blessed_remove(ebpf, b.cgroup);
                        b.registered = false;
                    }
                },
                Remap::Unregister => {
                    warn!(
                        id = %b.id, class = %b.class,
                        "bless: class vanished on apply; blessing is now inert (GC reaps it when empty)"
                    );
                    if let Err(e) = seed::blessed_remove(ebpf, b.cgroup) {
                        warn!(id = %b.id, error = %e, "bless: remap remove failed");
                    }
                    b.registered = false;
                }
                Remap::Keep => {}
            }
        }
    }

    /// Adopt carriers left over from a previous daemon run (its `MAP_BLESSED` entries
    /// died with it — the map is not pinned). Empty leftovers are removed; a populated
    /// carrier whose class is still declared is re-registered (a blessing only ever
    /// *grants*, and its class was human-authorized); a populated carrier of a
    /// vanished class is adopted inert, for GC only. Never fails startup.
    ///
    /// **Only root-owned directories are adopted.** Re-registering is a *grant*, so this
    /// has to be at least as strict as [`carrier_parent`], which refuses to create a
    /// carrier under a parent it doesn't trust. Every legitimate carrier was created by
    /// this daemon and is root-owned; anything else in the search space was planted, and
    /// adopting it would register a cgroup whose membership someone else controls —
    /// self-bless. Unreachable on a default systemd (every scanned level is root-owned
    /// and unwritable), which is exactly why it is worth asserting rather than assuming:
    /// a `Delegate=yes` drop-in or a wider [`carrier_roots`] would make it reachable
    /// without anything here looking different.
    pub(super) fn reconcile(&mut self, ebpf: &mut Ebpf, registry: &BTreeMap<ClassName, ClassId>) {
        let Some(root) = self.root.clone() else {
            return;
        };
        for found in carrier_roots(&root, cgroup_root())
            .iter()
            .flat_map(|dir| scan(dir))
        {
            // One stat serves both checks: who owns it, and its inode — which on cgroup2
            // *is* the id `bpf_get_current_cgroup_id()` reports.
            let meta = match std::fs::metadata(&found.dir) {
                Ok(meta) => meta,
                Err(e) => {
                    warn!(dir = %found.dir.display(), error = %e, "bless: reconcile stat failed; skipped");
                    continue;
                }
            };
            let owner = Uid(std::os::unix::fs::MetadataExt::uid(&meta));
            if !adoptable(owner) {
                warn!(
                    dir = %found.dir.display(), %owner,
                    "bless: leftover carrier is not root-owned; ignored (not ours to adopt)"
                );
                continue;
            }
            if !found.populated {
                let _ = std::fs::remove_dir(&found.dir);
                info!(dir = %found.dir.display(), "bless: removed empty leftover carrier");
                continue;
            }
            let cgroup = CgroupId(std::os::unix::fs::MetadataExt::ino(&meta));
            let registered = match registry.get(&found.class) {
                Some(&class_id) => match seed::blessed_insert(ebpf, cgroup, class_id) {
                    Ok(()) => true,
                    Err(e) => {
                        warn!(dir = %found.dir.display(), error = %e, "bless: reconcile re-register failed; adopted inert");
                        false
                    }
                },
                None => {
                    warn!(
                        dir = %found.dir.display(), class = %found.class,
                        "bless: leftover carrier's class is no longer declared; adopted inert (GC only)"
                    );
                    false
                }
            };
            info!(id = %found.id, class = %found.class, registered, "bless: adopted leftover carrier");
            self.next = self.next.max(found.id.successor());
            self.live.push(Blessing {
                id: found.id,
                class: found.class,
                dir: found.dir,
                owner: None,
                cgroup,
                registered,
                // It has members *now*; when they exit, GC may reap without grace.
                saw_populated: true,
                revoked: false,
                minted: Instant::now(),
            });
        }
    }
}

/// Unregister + rmdir + log one dead blessing (the table row is dropped by the caller).
fn reap(ebpf: &mut Ebpf, b: &Blessing) {
    if b.registered
        && let Err(e) = seed::blessed_remove(ebpf, b.cgroup)
    {
        warn!(id = %b.id, error = %e, "bless: MAP_BLESSED remove failed");
    }
    if let Err(e) = std::fs::remove_dir(&b.dir) {
        warn!(id = %b.id, error = %e, "bless: carrier rmdir failed");
    }
    info!(id = %b.id, class = %b.class, revoked = b.revoked, "blessing reaped");
}

/// The pure GC predicate, given a carrier that currently reads `populated 0`: reap
/// once the emptiness is meaningful — it had members and they exited, it was revoked,
/// or the mint grace expired (a CLI that died before joining).
/// Who may revoke a blessing: root always, otherwise only the uid that minted it. A
/// blessing adopted by reconcile has no recorded owner — its requester died with the
/// previous daemon — so it is root's to tear down.
fn may_revoke(owner: Option<Uid>, by: Uid) -> bool {
    by == Uid(0) || owner == Some(by)
}

fn should_reap(saw_populated: bool, revoked: bool, age: Duration) -> bool {
    saw_populated || revoked || age > MINT_GRACE
}

/// The pure remap decision for one live blessing on `policy apply`: what its
/// (possibly renumbered / vanished) class name now means for its `MAP_BLESSED` entry.
enum Remap {
    /// Class still declared → (re-)insert with the new id. Unconditional: the insert
    /// is idempotent and also heals a previously-failed remove/insert.
    Register(ClassId),
    /// Class vanished and the entry is live → remove it (the blessing goes inert).
    Unregister,
    /// Class vanished but the entry is already gone → nothing to do.
    Keep,
}

fn remap_plan(registered: bool, new_id: Option<ClassId>) -> Remap {
    match (new_id, registered) {
        (Some(id), _) => Remap::Register(id),
        (None, true) => Remap::Unregister,
        (None, false) => Remap::Keep,
    }
}

/// Resolve the class a mint is for: an explicit `--class` must be declared; omitted
/// picks the sole declared class, anything else is an error naming the choices.
fn resolve_class(
    requested: Option<ClassName>,
    registry: &BTreeMap<ClassName, ClassId>,
) -> Result<(ClassName, ClassId)> {
    let declared = || {
        registry
            .keys()
            .map(ClassName::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    match requested {
        Some(name) => match registry.get(&name) {
            Some(&id) => Ok((name, id)),
            None if registry.is_empty() => Err(Error::msg(format!(
                "unknown blessing class '{name}': the policy declares no blessing classes"
            ))),
            None => Err(Error::msg(format!(
                "unknown blessing class '{name}' (declared: {})",
                declared()
            ))),
        },
        None => match registry.len() {
            0 => Err(Error::msg("the policy declares no blessing classes")),
            1 => {
                let (name, id) = registry.first_key_value().expect("len checked");
                Ok((name.clone(), *id))
            }
            _ => Err(Error::msg(format!(
                "multiple blessing classes declared ({}); pass --class",
                declared()
            ))),
        },
    }
}

/// A carrier directory found by the startup [`scan`].
struct Found {
    id: BlessId,
    class: ClassName,
    dir: PathBuf,
    populated: bool,
}

/// Find leftover carrier dirs under `root` (anything matching the
/// `cordon-bless-<id>.<class>` shape). Read errors are treated as "nothing found" —
/// reconcile must never fail startup.
fn scan(root: &Path) -> Vec<Found> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let (id, class) = parse_dir_name(name.to_str()?)?;
            let dir = entry.path();
            let populated = read_populated(&dir).unwrap_or(false);
            Some(Found {
                id,
                class,
                dir,
                populated,
            })
        })
        .collect()
}

/// `cordon-bless-<id>.<class>` — the carrier directory name. [`parse_dir_name`] is its
/// exact inverse; the class charset ([`valid_class_dirname`], enforced at mint) is
/// what keeps the encoding unambiguous (no `.` or `/` in a class).
fn dir_name(id: BlessId, class: &ClassName) -> String {
    format!("cordon-bless-{id}.{class}")
}

fn parse_dir_name(name: &str) -> Option<(BlessId, ClassName)> {
    let rest = name.strip_prefix("cordon-bless-")?;
    let (id, class) = rest.split_once('.')?;
    if !valid_class_dirname(class) {
        return None;
    }
    Some((BlessId(id.parse().ok()?), ClassName::new(class)))
}

/// The class-name charset a carrier dir may embed: `^[A-Za-z0-9_-]+$`. Policy allows
/// arbitrary strings as class names; the fs encoding does not.
fn valid_class_dirname(class: &str) -> bool {
    !class.is_empty()
        && class
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The daemon's own cgroup directory — the carrier root. From the unified-hierarchy
/// (`0::`) line of `/proc/self/cgroup`, joined under the standard cgroup2 mount.
fn carrier_root() -> Result<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| Error::msg(format!("/proc/self/cgroup: {e}")))?;
    let rel = cgroup_v2_path(&text)
        .ok_or_else(|| Error::msg("/proc/self/cgroup has no unified-hierarchy (0::) line"))?;
    Ok(under_cgroup_root(rel))
}

/// The unified-hierarchy path from a `/proc/<pid>/cgroup` listing: the `0::<path>`
/// line's path part. It is **relative to the cgroup2 mount** despite the leading slash —
/// `/` alone *is* the root — so joining it onto [`cgroup_root`] goes through
/// [`under_cgroup_root`] rather than `join`, which would discard the base.
fn cgroup_v2_path(text: &str) -> Option<&Path> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(Path::new)
}

/// Whether a leftover carrier directory may be adopted by [`Blessings::reconcile`] — the
/// same trust question [`usable_session_scope`] asks of a parent, asked of the carrier
/// itself. Root-owned only: this daemon creates carriers as root, so anything else was
/// planted by whoever owns it.
fn adoptable(owner: Uid) -> bool {
    owner == Uid(0)
}

/// Resolve a `/proc/<pid>/cgroup` path against the cgroup2 mount.
fn under_cgroup_root(rel: &Path) -> PathBuf {
    cgroup_root().join(rel.strip_prefix("/").unwrap_or(rel))
}

/// Where a blessing's carrier should live: **inside the requester's own user subtree**
/// ([`placement_rel`]), falling back to `fallback` (the daemon's cgroup) when there isn't a
/// usable parent.
///
/// This is what makes a blessed shell a usable shell. logind attributes a process to a user
/// — and thence to a session — purely from its cgroup path, and polkit needs that
/// attribution to find an authentication agent. A carrier under `cordond.service` has
/// neither a `session-N.scope` nor a `user-<uid>.slice` in its ancestry, so logind reports
/// *"Caller does not belong to any known session and doesn't own any suitable session"* and
/// every `run0`/`pkexec` inside it fails with "interactive authentication has not been
/// enabled". Created inside the requester's own subtree, the blessed process resolves
/// exactly as an unblessed one there would.
///
/// **Refuses any parent that is not root-owned**, which is a real check rather than
/// belt-and-braces. A user-writable parent lets the invoker `rmdir` an empty carrier and
/// `mkdir` a replacement — and a cgroup id *is* a recycled kernfs inode number, so within
/// the GC window that replacement could land on an id still registered in `BLESSED`, i.e.
/// self-bless. `session-N.scope` is `root:root`; `user@UID.service` is delegated to the
/// user and must never be used, which the ownership check rejects on its own.
fn carrier_parent(pid: Pid, fallback: &Path) -> PathBuf {
    match usable_session_scope(pid) {
        Ok(scope) => scope,
        Err(reason) => {
            debug!(pid = %pid, reason, "bless: carrier goes under the daemon's cgroup");
            fallback.to_path_buf()
        }
    }
}

/// The requester's session scope if a carrier may be created there, else **why not**.
///
/// The `Err` is a reason string rather than a typed error because no caller branches on
/// it — every failure means the same thing, "use the daemon's cgroup". Its only job is to
/// say which of the four ways that happened, on one `debug!` line, when someone is working
/// out why `run0` stopped working inside a blessed shell.
fn usable_session_scope(pid: Pid) -> std::result::Result<PathBuf, &'static str> {
    // A requester that exited between connecting and here has no cgroup to read. The mint
    // will fail on its own shortly; meanwhile the daemon's cgroup is the safe placement.
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| "requester's cgroup unreadable")?;
    let rel = cgroup_v2_path(&text)
        .and_then(placement_rel)
        .ok_or("requester's cgroup has no session scope or user slice")?;
    let scope = under_cgroup_root(rel);
    match std::fs::metadata(&scope) {
        Ok(meta) if std::os::unix::fs::MetadataExt::uid(&meta) == 0 => Ok(scope),
        Ok(_) => Err("chosen parent is not root-owned"),
        Err(_) => Err("chosen parent vanished"),
    }
}

/// Every directory a carrier could have been created in. Reconcile's search space, and it
/// must stay the exact mirror of what [`placement_rel`] can choose: the daemon's own
/// cgroup, plus **every `user-*.slice` and every `session-*.scope` within it**.
///
/// A carrier this misses is a carrier nothing ever reaps: it lingers with its members
/// running, a non-empty child keeps systemd from removing the enclosing slice or scope at
/// logout, and — worse — the id allocator never advances past it, so the *next* mint
/// computes the same `cordon-bless-<id>.<class>` name under the same parent and fails
/// `EEXIST` forever. That is not hypothetical: widening `placement_rel` to the user slice
/// without widening this function did exactly that.
fn carrier_roots(daemon_cgroup: &Path, cgroup_root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![daemon_cgroup.to_path_buf()];
    let children = |dir: PathBuf, keep: fn(&str) -> bool| -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_str().is_some_and(keep))
            .map(|e| e.path())
            .collect()
    };
    for per_user in children(cgroup_root.join("user.slice"), |n| {
        n.starts_with("user-") && n.ends_with(".slice")
    }) {
        // The slice itself is the desktop placement — a terminal has no session scope.
        roots.extend(children(per_user.clone(), |n| {
            n.starts_with("session-") && n.ends_with(".scope")
        }));
        roots.push(per_user);
    }
    // The daemon's own cgroup *is* a session scope when cordond is started from a login
    // shell rather than the unit, so it can turn up twice. A duplicate would adopt every
    // leftover carrier twice — two table rows with one id, and a confusing `bless list`.
    roots.sort();
    roots.dedup();
    roots
}

/// Where in the requester's ancestry a carrier may live so the blessed process stays
/// **attributable to its user** — the property polkit ultimately needs.
///
/// Two shapes, tried in that order, both `root:root` on systemd:
///
/// 1. **`session-N.scope`** — a tty or login session. Deepest and most precise: logind
///    reads an exact session id straight from the cgroup.
/// 2. **`user-<uid>.slice`** — a desktop session. On a modern systemd the terminal does
///    *not* live in the session scope; it lives under the **delegated**
///    `user@UID.service/app.slice/app-*.scope`, and there is no session scope anywhere in
///    its ancestry. What still works there is `cg_path_get_owner_uid`, which keys on this
///    `user-<uid>.slice` component to attribute the process to a user, from which logind
///    falls back to that user's *display* session. That is exactly how an ordinary
///    unblessed shell on such a desktop resolves, so matching it is the goal.
///
/// Anything below those two is out: `user@UID.service` and everything under it is
/// delegated to the user, so a carrier there would sit in a directory its own beneficiary
/// can `rmdir` — see [`carrier_parent`] for why that matters.
///
/// Pure path work so the rule is testable without a cgroup hierarchy; the ownership check
/// that makes it *safe* is [`carrier_parent`]'s.
fn placement_rel(cgroup_path: &Path) -> Option<&Path> {
    named_ancestor(cgroup_path, "session-", ".scope")
        .or_else(|| named_ancestor(cgroup_path, "user-", ".slice"))
}

/// The deepest ancestor whose final component matches `<prefix>…<suffix>`. Note
/// `user-1000.slice` matches `("user-", ".slice")` while the enclosing `user.slice` does
/// not — the hyphen is load-bearing.
fn named_ancestor<'a>(path: &'a Path, prefix: &str, suffix: &str) -> Option<&'a Path> {
    path.ancestors().find(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
    })
}

/// Whether the carrier currently has members, from its `cgroup.events` (`populated
/// 0|1`). `None` ⇒ the file (or the carrier itself) is gone.
fn read_populated(dir: &Path) -> Option<bool> {
    let text = std::fs::read_to_string(dir.join("cgroup.events")).ok()?;
    events_populated(&text)
}

/// Parse `cgroup.events` text for the `populated` key.
fn events_populated(text: &str) -> Option<bool> {
    text.lines()
        .find_map(|l| l.strip_prefix("populated "))
        .map(|v| v.trim() == "1")
}

/// The carrier's member pids, from its `cgroup.procs`. Best-effort: an unreadable or
/// vanished carrier reads as empty.
fn read_pids(dir: &Path) -> Vec<Pid> {
    std::fs::read_to_string(dir.join("cgroup.procs"))
        .map(|text| {
            text.lines()
                .filter_map(|l| l.trim().parse().ok())
                .map(Pid)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_name_round_trips() {
        let name = dir_name(BlessId(42), &ClassName::new("ro"));
        assert_eq!(name, "cordon-bless-42.ro");
        let (id, class) = parse_dir_name(&name).unwrap();
        assert_eq!(id, BlessId(42));
        assert_eq!(class, ClassName::new("ro"));
    }

    #[test]
    fn parse_dir_name_rejects_non_carriers() {
        // Not ours / malformed / bad charset / no id.
        assert!(parse_dir_name("system.slice").is_none());
        assert!(parse_dir_name("cordon-bless-").is_none());
        assert!(parse_dir_name("cordon-bless-7").is_none()); // no `.class`
        assert!(parse_dir_name("cordon-bless-x.ro").is_none()); // non-numeric id
        assert!(parse_dir_name("cordon-bless-7.").is_none()); // empty class
        assert!(parse_dir_name("cordon-bless-7.a/b").is_none()); // bad charset
        // The first `.` splits: a dotted suffix lands in the class and fails the charset.
        assert!(parse_dir_name("cordon-bless-7.ro.bak").is_none());
    }

    #[test]
    fn class_dirname_charset() {
        assert!(valid_class_dirname("ro"));
        assert!(valid_class_dirname("Aws_prod-2"));
        assert!(!valid_class_dirname(""));
        assert!(!valid_class_dirname("a.b"));
        assert!(!valid_class_dirname("a b"));
        assert!(!valid_class_dirname("a/b"));
        assert!(!valid_class_dirname("é"));
    }

    #[test]
    fn resolve_class_defaults_and_errors() {
        let ro = ClassName::new("ro");
        let rw = ClassName::new("rw");
        let one: BTreeMap<_, _> = [(ro.clone(), ClassId(1))].into();
        let two: BTreeMap<_, _> = [(ro.clone(), ClassId(1)), (rw.clone(), ClassId(2))].into();
        let none = BTreeMap::new();

        // Explicit + declared → that class.
        assert_eq!(resolve_class(Some(ro.clone()), &two).unwrap().1, ClassId(1));
        // Omitted + exactly one declared → the sole class.
        assert_eq!(resolve_class(None, &one).unwrap().0, ro);
        // Omitted + several → error listing the choices.
        let e = resolve_class(None, &two).unwrap_err().to_string();
        assert!(e.contains("ro, rw"), "{e}");
        // Unknown explicit → error listing the choices.
        let e = resolve_class(Some(ClassName::new("nope")), &two)
            .unwrap_err()
            .to_string();
        assert!(e.contains("ro, rw"), "{e}");
        // Nothing declared → both forms error.
        assert!(resolve_class(None, &none).is_err());
        assert!(resolve_class(Some(ro), &none).is_err());
    }

    #[test]
    fn gc_reaps_only_meaningful_emptiness() {
        let fresh = Duration::from_secs(1);
        let expired = MINT_GRACE + Duration::from_secs(1);
        // Fresh, never populated, not revoked → the CLI may still be about to join.
        assert!(!should_reap(false, false, fresh));
        // Had members and they exited → reap.
        assert!(should_reap(true, false, fresh));
        // Revoked → reap as soon as it reads empty.
        assert!(should_reap(false, true, fresh));
        // Never joined and the grace expired (CLI died pre-join) → reap.
        assert!(should_reap(false, false, expired));
    }

    #[test]
    fn remap_plan_covers_rename_renumber_vanish() {
        // Class still declared (same or new id) → always (re-)register.
        assert!(matches!(
            remap_plan(true, Some(ClassId(3))),
            Remap::Register(ClassId(3))
        ));
        assert!(matches!(
            remap_plan(false, Some(ClassId(1))),
            Remap::Register(ClassId(1))
        ));
        // Vanished + live entry → unregister (blessing goes inert, tree survives).
        assert!(matches!(remap_plan(true, None), Remap::Unregister));
        // Vanished + already inert → nothing.
        assert!(matches!(remap_plan(false, None), Remap::Keep));
    }

    #[test]
    fn cgroup_v2_path_finds_the_unified_line() {
        // Hybrid listing: v1 controllers + the unified line.
        let text =
            "12:pids:/user.slice\n1:name=systemd:/init.scope\n0::/system.slice/cordond.service\n";
        assert_eq!(
            cgroup_v2_path(text),
            Some(Path::new("/system.slice/cordond.service"))
        );
        // Pure v2 at the root — relative to the mount, so it resolves to the mount itself.
        assert_eq!(cgroup_v2_path("0::/\n"), Some(Path::new("/")));
        assert_eq!(under_cgroup_root(Path::new("/")), cgroup_root());
        assert_eq!(
            under_cgroup_root(Path::new("/user.slice/session-3.scope")),
            cgroup_root().join("user.slice/session-3.scope"),
            "the leading slash must not make `join` discard the mount"
        );
        // No unified hierarchy at all.
        assert_eq!(cgroup_v2_path("12:pids:/user.slice\n"), None);
    }

    /// Where a carrier goes, from the cgroup shapes that actually occur.
    ///
    /// The desktop row is the one that matters and the one an earlier version of this got
    /// wrong: on a modern systemd a terminal is **not** in the session scope — it is under
    /// the delegated `user@UID.service`, with no session scope anywhere above it. Placing
    /// only-if-session-scope sent those blessings to the daemon's cgroup, where logind
    /// cannot attribute the process to a user at all and polkit therefore refuses.
    #[test]
    fn placement_covers_the_cgroup_shapes_that_actually_occur() {
        // A `fn`, not a closure: the result borrows from the argument, and closure
        // lifetime elision can't express that.
        fn rel(p: &str) -> Option<&Path> {
            placement_rel(Path::new(p))
        }

        // tty / login session: the session scope is deepest and most precise.
        let scope = Path::new("/user.slice/user-1000.slice/session-3.scope");
        assert_eq!(
            rel("/user.slice/user-1000.slice/session-3.scope"),
            Some(scope)
        );
        assert_eq!(
            rel("/user.slice/user-1000.slice/session-3.scope/cordon-bless-1.ro"),
            Some(scope)
        );

        // Desktop: no session scope in the ancestry at all. The user slice is what keeps
        // the process attributable, and it is the *only* root-owned option here.
        let slice = Path::new("/user.slice/user-1000.slice");
        assert_eq!(
            rel("/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-term.scope"),
            Some(slice)
        );
        assert_eq!(rel("/user.slice/user-1000.slice"), Some(slice));

        // A session scope wins over the user slice when both are present (more precise).
        assert_eq!(
            rel("/user.slice/user-1000.slice/session-12.scope/app.slice/x.service"),
            Some(Path::new("/user.slice/user-1000.slice/session-12.scope"))
        );

        // Nothing user-attributable ⇒ no placement, so the carrier falls back.
        assert_eq!(rel("/system.slice/cordond.service"), None);
        assert_eq!(rel("/system.slice/cordond.service/cordon-bless-3.ro"), None);
        assert_eq!(rel("/"), None);

        // Near-misses. `user.slice` has no hyphen and must NOT match: it is the shared
        // parent of every user, so a carrier there would be attributable to nobody.
        assert_eq!(rel("/user.slice"), None);
        assert_eq!(rel("/user.slice/session-3.slice"), None);
        assert_eq!(rel("/user.slice/mysession-3.scope"), None);
    }

    /// Placement never returns somewhere unsafe. The security half is the ownership gate:
    /// a user-writable parent lets the invoker `rmdir` an empty carrier and `mkdir` a
    /// replacement, and a cgroup id is a recycled inode number, so that replacement could
    /// land on an id still live in `BLESSED`.
    ///
    /// Asserted as an **invariant** rather than a fixed path on purpose — where the test
    /// runner itself sits is environment-dependent (a GUI terminal lands under
    /// `user@1000.service/app.slice`, with no session scope at all; a tty login lands in a
    /// root-owned `session-N.scope`), and a test that only holds on one of those would
    /// pass here and fail on a login shell or in CI.
    #[test]
    fn placement_is_the_fallback_or_a_root_owned_scope() {
        let base = std::env::temp_dir().join(format!("cordon-parent-{}", std::process::id()));
        let fallback = base.join("daemon-cgroup");
        std::fs::create_dir_all(&fallback).unwrap();

        let chosen = carrier_parent(Pid(std::process::id()), &fallback);
        if chosen != fallback {
            let owner = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&chosen).unwrap());
            assert_eq!(
                owner, 0,
                "chose a parent that is not root-owned: {chosen:?}"
            );
            assert!(placement_rel(&chosen).is_some(), "chose {chosen:?}");
        }

        // A pid that cannot exist has no cgroup to read: fall back, with a reason, rather
        // than fail the mint.
        assert_eq!(carrier_parent(Pid(0), &fallback), fallback);
        assert_eq!(
            usable_session_scope(Pid(0)),
            Err("requester's cgroup unreadable")
        );

        std::fs::remove_dir_all(&base).ok();
    }

    /// **Regression test.** Reconcile's search space must cover every parent
    /// [`placement_rel`] can choose — they are two halves of one rule, and widening
    /// placement to the user slice without widening this left desktop carriers
    /// unreachable: never reaped, and the id allocator never advancing past them, so the
    /// next mint collided on the same directory name and failed `EEXIST` forever.
    ///
    /// Asserted as that pairing rather than as a list of paths, so the two cannot drift
    /// apart again: for each shape a requester can be in, whatever placement picks must be
    /// somewhere reconcile looks.
    #[test]
    fn reconcile_scans_every_parent_placement_can_choose() {
        let root = std::env::temp_dir().join(format!("cordon-roots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let user_slice = root.join("user.slice/user-1000.slice");
        std::fs::create_dir_all(user_slice.join("session-3.scope")).unwrap();
        std::fs::create_dir_all(user_slice.join("user@1000.service/app.slice")).unwrap();
        let daemon = root.join("system.slice/cordond.service");
        std::fs::create_dir_all(&daemon).unwrap();

        let roots = carrier_roots(&daemon, &root);

        // Every requester shape → its placement → must be covered.
        for requester in [
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-term.scope", // desktop
            "/user.slice/user-1000.slice/session-3.scope",                            // tty
            "/user.slice/user-1000.slice",
        ] {
            let rel = placement_rel(Path::new(requester)).expect("a placement");
            let parent = root.join(rel.strip_prefix("/").unwrap());
            assert!(
                roots.contains(&parent),
                "placement picks {parent:?} for a requester in {requester}, \
                 but reconcile never scans it — that carrier would leak and \
                 block the next mint. roots={roots:?}"
            );
        }
        // The fallback parent is covered too.
        assert!(roots.contains(&daemon));
        // …and nothing is scanned twice (the daemon's cgroup can also be a session scope).
        let mut unique = roots.clone();
        unique.dedup();
        assert_eq!(unique, roots, "reconcile would scan a directory twice");

        std::fs::remove_dir_all(&root).ok();
    }

    /// Adoption is a *grant*, so it is gated on the same trust question placement asks:
    /// a carrier this daemon did not create as root is not ours to re-register.
    #[test]
    fn only_root_owned_carriers_are_adoptable() {
        assert!(adoptable(Uid(0)));
        assert!(!adoptable(Uid(1000)));
        assert!(!adoptable(Uid(u32::MAX)));
    }

    #[test]
    fn events_populated_parses_both_states() {
        assert_eq!(events_populated("populated 1\nfrozen 0\n"), Some(true));
        assert_eq!(events_populated("populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(events_populated("frozen 0\n"), None);
    }

    /// Reconcile's fs half against a fake carrier root: `scan` finds exactly the
    /// well-formed carrier dirs and reads their populated state.
    #[test]
    fn scan_finds_carriers_in_a_fake_root() {
        let root = std::env::temp_dir().join(format!("cordon-bless-test.{}", std::process::id()));
        let mk = |name: &str, events: Option<&str>| {
            let dir = root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(text) = events {
                std::fs::write(dir.join("cgroup.events"), text).unwrap();
            }
        };
        mk("cordon-bless-3.ro", Some("populated 1\n"));
        mk("cordon-bless-9.rw", Some("populated 0\n"));
        mk("cordon-bless-4.ro", None); // no events file → treated as unpopulated
        mk("not-a-carrier", Some("populated 1\n"));

        let mut found = scan(&root);
        found.sort_by_key(|f| f.id.0);
        let brief: Vec<_> = found
            .iter()
            .map(|f| (f.id.0, f.class.as_str().to_string(), f.populated))
            .collect();
        assert_eq!(
            brief,
            vec![
                (3, "ro".to_string(), true),
                (4, "ro".to_string(), false),
                (9, "rw".to_string(), false),
            ]
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
