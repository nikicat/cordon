//! The live blessings table (DESIGN §16), which alone creates and removes the carrier
//! cgroups and their `BLESSED` entries. A blessing is a carrier cgroup
//! (`cordon-bless-<id>.<class>`, placed by [`carrier_parent`]). `MAP_BLESSED` maps the
//! carrier's kernel id to the class's dense [`ClassId`]. Every mutation runs on the backend
//! thread, through the same single writer as the rule maps (see [`Maps`]).
//!
//! [`Blessings::mint`] creates a carrier, and the CLI then moves the target into it. Once
//! the last member exits (`cgroup.events` reads `populated 0`), [`Blessings::gc`]
//! unregisters the carrier and removes it. [`Blessings::revoke`] kills the carrier tree
//! and lets the same GC finish. An apply re-points live blessings ([`Blessings::remap`]),
//! and at startup [`Blessings::reconcile`] adopts the carriers a previous run left behind.

use super::seed::Maps;
use cordon_bpf_common::{CgroupId, ClassId, MAX_BLESSED};
use cordon_core::policy::{ClassName, ClassRegistry};
use cordon_core::proto::{BlessId, BlessingView, CarrierProcs, Pid};
use cordon_core::{Context, Error, Result, Uid};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// How long a fresh, never-populated carrier is left alone before GC may reap it. A
/// carrier is empty from mint until the CLI's `pre_exec` writes the target pid into it,
/// and GC runs on every serve tick (`POLL_TIMEOUT_MS`, 500ms), so without this grace GC
/// would reap the carrier first. It is generous because a leak costs one empty cgroup
/// directory for 30s, and a CLI that died before joining is cleaned up right after.
const MINT_GRACE: Duration = Duration::from_secs(30);

/// Returns the cgroup2 mount. Both the daemon's own cgroup and a requester's session
/// scope are resolved against it, because `/proc/<pid>/cgroup` gives a path relative to
/// the root.
///
/// It is a function rather than a `const` only because `Path::new` is not const-stable
/// yet (rust-lang#143874). Callers get a `Path` instead of re-wrapping a `&str` at each
/// use.
fn cgroup_root() -> &'static Path {
    Path::new("/sys/fs/cgroup")
}

/// The live blessings table, which the backend thread keeps beside the `Ebpf` handle.
pub(super) struct Blessings {
    /// The daemon's own cgroup directory, resolved once at startup. A carrier goes here
    /// when the requester's own session scope or user slice can't hold it. `None` means
    /// there is no cgroup2, so minting errors and everything else is unaffected.
    root: Option<PathBuf>,
    /// The id the next mint gets. It only grows within a run, and reconcile moves it past
    /// every adopted id.
    next: BlessId,
    live: Vec<Blessing>,
}

/// A live blessing, as the table tracks it until GC reaps its carrier.
struct Blessing {
    /// The handle that `bless list` shows and `bless revoke` takes. The carrier's directory
    /// name embeds it, which is how it survives a daemon restart.
    id: BlessId,
    /// The blessing class it was minted for. The name, not the id, is the durable identity
    /// (see [`Blessings::remap`]).
    class: ClassName,
    dir: CarrierDir,
    /// The requester's kernel-attested uid, which [`may_revoke`] checks. It is `None` for a
    /// blessing adopted from a previous daemon run.
    owner: Option<Uid>,
    /// The carrier's kernel cgroup id, which is the `MAP_BLESSED` key.
    cgroup: CgroupId,
    /// Whether a `MAP_BLESSED` entry exists for it now. It is false once its class has
    /// vanished (see [`Remap`]), and the blessing then grants nothing but is kept for GC.
    registered: bool,
    /// Whether the carrier has ever had a member. From then on, `populated 0` means that
    /// everything exited, not that the CLI hasn't joined yet.
    saw_populated: bool,
    /// Whether the blessing was revoked and its `cgroup.kill` written. GC may then reap it
    /// the moment it reads empty, despite the mint grace.
    revoked: bool,
    /// When it was minted, or adopted by reconcile. It starts the mint grace window and
    /// gives the view its `age`.
    minted: Instant,
}

impl Blessings {
    /// Creates an empty table whose fallback carrier root is the daemon's own cgroup. When
    /// that cgroup cannot be resolved, minting reports itself unavailable and the rest of
    /// the daemon runs unaffected.
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

    /// Mints a blessing for `owner` by creating its carrier cgroup as root and registering
    /// it in `MAP_BLESSED`. Returns the blessing's view and the carrier's `cgroup.procs`,
    /// opened for write. A process joins the carrier when its pid is written through that
    /// descriptor. Membership is the boundary, and the carrier is root-owned, so a non-root
    /// process can write its `cgroup.procs` only through that descriptor.
    ///
    /// Errors when the carrier root is unknown, the class cannot be resolved
    /// ([`resolve_class`]), [`MAX_BLESSED`] blessings are already live, or the carrier
    /// cannot be created and registered.
    pub(super) fn mint(
        &mut self,
        maps: &mut Maps,
        class: Option<ClassName>,
        owner: Uid,
        requester: Pid,
        registry: &ClassRegistry,
    ) -> Result<(BlessingView, CarrierProcs)> {
        let root = self.root.as_ref().ok_or_else(|| {
            Error::msg("blessing unavailable: the daemon's cgroup was unresolvable at startup")
        })?;
        let (class, class_id) = resolve_class(class, registry)?;
        if self.live.len() >= MAX_BLESSED {
            return Err(Error::msg(format!(
                "too many live blessings (max {MAX_BLESSED})"
            )));
        }

        let id = self.next;
        // In the requester's own user subtree where possible (see `carrier_parent`).
        let dir = CarrierDir::create(carrier_parent(requester, root).join(dir_name(id, &class)))?;
        let registered = (|| -> Result<_> {
            let cgroup = dir.cgroup_id()?;
            // Open `cgroup.procs` here, as root, before handing anything back, because
            // this fd is the grant (see `CarrierProcs`).
            let procs = dir.open_procs()?;
            maps.blessed_insert(cgroup, class_id)?;
            Ok((cgroup, procs))
        })();
        let (cgroup, procs) = registered.inspect_err(|_| {
            let _ = dir.remove();
        })?;

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
        info!(%id, %class, %owner, cgroup = %dir, "blessing minted");
        Ok((
            BlessingView {
                id,
                class,
                cgroup: dir.0,
                pids: Vec::new(),
                age: Duration::ZERO,
            },
            procs,
        ))
    }

    /// Returns a view of every live blessing, with member pids read fresh from each
    /// carrier.
    pub(super) fn list(&self) -> Vec<BlessingView> {
        self.live
            .iter()
            .map(|b| BlessingView {
                id: b.id,
                class: b.class.clone(),
                cgroup: b.dir.0.clone(),
                pids: b.dir.pids(),
                age: b.minted.elapsed(),
            })
            .collect()
    }

    /// Kills the carrier tree of blessing `id` through `cgroup.kill`. The regular GC then
    /// sees the carrier empty, unregisters it and removes it.
    ///
    /// Errors when there is no such blessing or `by` (the caller's kernel-attested uid)
    /// may not revoke it ([`may_revoke`]). Both errors read the same.
    pub(super) fn revoke(&mut self, id: BlessId, by: Uid) -> Result<()> {
        let b = self
            .live
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or_else(|| Error::msg(format!("no blessing with id {id}")))?;
        if !may_revoke(b.owner, by) {
            // Deliberately the same shape as "no such id". Whether a blessing exists is
            // itself information, and `bless list` is the way to ask that question.
            return Err(Error::msg(format!("no blessing with id {id}")));
        }
        b.revoked = true;
        // A write error means the carrier is already gone or dying. `revoked` alone lets
        // GC reap it, so report success either way.
        if let Err(e) = b.dir.kill() {
            warn!(id = %b.id, error = %e, "bless: cgroup.kill write failed; GC will reap");
        }
        info!(id = %b.id, class = %b.class, "blessing revoked");
        Ok(())
    }

    /// Reaps every dead carrier ([`Blessing::check_dead`]). Reaping removes its
    /// `MAP_BLESSED` entry, its directory and its table row.
    pub(super) fn gc(&mut self, maps: &mut Maps) {
        for b in self.live.extract_if(.., Blessing::check_dead) {
            reap(maps, &b);
        }
    }

    /// Re-points every live blessing at the id that its class name has in `registry`.
    /// Every compile renumbers the ids (see `ClassRegistry`), so without this a live
    /// blessing would silently change meaning. A blessing whose class has vanished goes
    /// inert, and [`Blessing::remap_plan`] decides what each entry becomes.
    pub(super) fn remap(&mut self, maps: &mut Maps, registry: &ClassRegistry) {
        for b in &mut self.live {
            match b.remap_plan(registry.id(&b.class)) {
                Remap::Register(class_id) => match maps.blessed_insert(b.cgroup, class_id) {
                    Ok(()) => b.registered = true,
                    Err(e) => {
                        // Fail closed. A stale entry would carry the renumbered id, which
                        // now means a different class. Grant nothing rather than the
                        // wrong thing.
                        warn!(id = %b.id, error = %e, "bless: remap re-insert failed; unregistering");
                        let _ = maps.blessed_remove(b.cgroup);
                        b.registered = false;
                    }
                },
                Remap::Unregister => {
                    warn!(
                        id = %b.id, class = %b.class,
                        "bless: class vanished on apply; blessing is now inert (GC reaps it when empty)"
                    );
                    if let Err(e) = maps.blessed_remove(b.cgroup) {
                        warn!(id = %b.id, error = %e, "bless: remap remove failed");
                    }
                    b.registered = false;
                }
                Remap::Keep => {}
            }
        }
    }

    /// Adopts the root-owned carriers ([`adoptable`]) that a previous daemon run left
    /// behind in [`carrier_roots`]. This run's `MAP_BLESSED` starts empty (see
    /// `PinDir::pin_links`), so nothing grants until this re-registers it. Empty leftovers
    /// are removed. A populated carrier whose class is still declared is re-registered,
    /// because a blessing only ever grants and a human authorized its class. A populated
    /// carrier of a vanished class is adopted inert, for GC only. Problems are logged and
    /// never fail startup.
    pub(super) fn reconcile(&mut self, maps: &mut Maps, registry: &ClassRegistry) {
        let Some(root) = self.root.clone() else {
            return;
        };
        for found in carrier_roots(&root, cgroup_root())
            .iter()
            .flat_map(|dir| scan(dir))
        {
            // One stat serves both checks: who owns it, and its inode, which is the cgroup
            // id (see `Blessings::mint`).
            let meta = match std::fs::metadata(found.dir.path()) {
                Ok(meta) => meta,
                Err(e) => {
                    warn!(dir = %found.dir, error = %e, "bless: reconcile stat failed; skipped");
                    continue;
                }
            };
            let owner = Uid(std::os::unix::fs::MetadataExt::uid(&meta));
            if !adoptable(owner) {
                warn!(
                    event = "carrier_not_adopted",
                    dir = %found.dir, %owner,
                    "bless: leftover carrier is not root-owned; ignored (not ours to adopt)"
                );
                continue;
            }
            if !found.populated {
                let _ = found.dir.remove();
                info!(dir = %found.dir, "bless: removed empty leftover carrier");
                continue;
            }
            let cgroup = CgroupId(std::os::unix::fs::MetadataExt::ino(&meta));
            let registered = match registry.id(&found.class) {
                Some(class_id) => match maps.blessed_insert(cgroup, class_id) {
                    Ok(()) => true,
                    Err(e) => {
                        warn!(dir = %found.dir, error = %e, "bless: reconcile re-register failed; adopted inert");
                        false
                    }
                },
                None => {
                    warn!(
                        dir = %found.dir, class = %found.class,
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
                // It has members now, so GC may reap it without grace once they exit.
                saw_populated: true,
                revoked: false,
                minted: Instant::now(),
            });
        }
    }
}

/// Unregisters a dead blessing, removes its carrier directory and logs it. Dropping the
/// table row is left to the caller.
fn reap(maps: &mut Maps, b: &Blessing) {
    if b.registered
        && let Err(e) = maps.blessed_remove(b.cgroup)
    {
        warn!(id = %b.id, error = %e, "bless: MAP_BLESSED remove failed");
    }
    if let Err(e) = b.dir.remove() {
        warn!(id = %b.id, error = %e, "bless: carrier rmdir failed");
    }
    info!(id = %b.id, class = %b.class, revoked = b.revoked, "blessing reaped");
}

/// Checks whether `by` may revoke a blessing that `owner` minted. Root always may, and
/// otherwise only the minting uid. A blessing adopted by reconcile has no recorded owner,
/// because its requester is gone with the previous daemon, so only root may revoke it.
fn may_revoke(owner: Option<Uid>, by: Uid) -> bool {
    by == Uid::ROOT || owner == Some(by)
}

impl Blessing {
    /// Checks whether the carrier is dead, from a fresh read of its `cgroup.events`. It is
    /// dead once it reads `populated 0` and that emptiness counts ([`should_reap`](Self::should_reap)),
    /// or once its directory is gone. A first member is recorded on the way.
    fn check_dead(&mut self) -> bool {
        match self.dir.populated() {
            Some(true) => {
                self.saw_populated = true;
                false
            }
            Some(false) => self.should_reap(),
            // The carrier directory, or its cgroup.events, vanished. Nothing is left to
            // keep alive.
            None => true,
        }
    }

    /// Checks whether an empty carrier (`populated 0`) should be reaped. Its emptiness
    /// counts once it had members that exited, once it was revoked, or once the mint grace
    /// expired, which covers a CLI that died before joining.
    fn should_reap(&self) -> bool {
        self.saw_populated || self.revoked || self.minted.elapsed() > MINT_GRACE
    }

    /// Returns what an apply does to this blessing's entry, given its class's `new_id`.
    fn remap_plan(&self, new_id: Option<ClassId>) -> Remap {
        match (new_id, self.registered) {
            (Some(id), _) => Remap::Register(id),
            (None, true) => Remap::Unregister,
            (None, false) => Remap::Keep,
        }
    }
}

/// What a policy apply does to one live blessing's `MAP_BLESSED` entry, now that its
/// class may have been renumbered or removed. The carrier itself is never killed because
/// policy changed under it, and an inert one is left to GC.
enum Remap {
    /// The class is still declared, so the entry is inserted again with the new id. This
    /// is unconditional, because the insert is idempotent and also heals an earlier
    /// failed remove or insert.
    Register(ClassId),
    /// The class vanished and the entry is live, so the entry is removed and the blessing
    /// goes inert.
    Unregister,
    /// The class vanished and the entry is already gone, so nothing changes.
    Keep,
}

/// Returns the class a mint is for, with its id. When no class is requested, it is the
/// sole declared class.
///
/// Errors when the requested class is not declared, or when none is requested and the
/// policy declares no class or several. The message names the declared classes.
fn resolve_class(
    requested: Option<ClassName>,
    registry: &ClassRegistry,
) -> Result<(ClassName, ClassId)> {
    let declared = || {
        registry
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match requested {
        Some(name) => match registry.id(&name) {
            Some(id) => Ok((name, id)),
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
                let (name, id) = registry.iter().next().expect("len checked");
                Ok((name.clone(), id))
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
    dir: CarrierDir,
    populated: bool,
}

/// Returns the leftover carrier directories directly under `root`, which are those named
/// like `cordon-bless-<id>.<class>`. An unreadable `root` yields none, and a carrier with
/// no readable `cgroup.events` counts as unpopulated.
fn scan(root: &Path) -> Vec<Found> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let (id, class) = parse_dir_name(name.to_str()?)?;
            let dir = CarrierDir(entry.path());
            let populated = dir.populated().unwrap_or(false);
            Some(Found {
                id,
                class,
                dir,
                populated,
            })
        })
        .collect()
}

/// Returns the carrier directory name `cordon-bless-<id>.<class>`. [`parse_dir_name`] is
/// its exact inverse. The [`ClassName`] charset keeps the encoding unambiguous, because a
/// class has no `.` or `/`.
fn dir_name(id: BlessId, class: &ClassName) -> String {
    format!("cordon-bless-{id}.{class}")
}

fn parse_dir_name(name: &str) -> Option<(BlessId, ClassName)> {
    let rest = name.strip_prefix("cordon-bless-")?;
    let (id, class) = rest.split_once('.')?;
    Some((BlessId(id.parse().ok()?), class.parse().ok()?))
}

/// A process's unified-hierarchy cgroup, from the `0::<path>` line of
/// `/proc/<pid>/cgroup`, or an ancestor of it ([`CgroupPath::placement`]).
///
/// The path is relative to the cgroup2 mount despite its leading slash, and `/` alone is
/// the root. So it reaches the filesystem only through [`CgroupPath::under`], never a bare
/// `join`, which would discard the base. That is the whole reason this is a type, because
/// as a `&Path` it is indistinguishable from an absolute one.
#[derive(Debug, PartialEq, Eq)]
struct CgroupPath(PathBuf);

impl CgroupPath {
    fn new(path: impl Into<PathBuf>) -> CgroupPath {
        CgroupPath(path.into())
    }

    /// Returns the unified-hierarchy cgroup from a whole `/proc/<pid>/cgroup` listing, or
    /// `None` when the listing has no cgroup2 line, as on pure v1. A hybrid listing carries
    /// both kinds, and this takes the `0::` line. Parsing lives here so the multi-line
    /// `/proc` text never travels as a `&str` past its one reader.
    fn parse(listing: &str) -> Option<CgroupPath> {
        listing
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(CgroupPath::new)
    }

    /// Returns this cgroup's directory under the cgroup2 mount `mount`.
    fn under(&self, mount: &Path) -> PathBuf {
        mount.join(self.0.strip_prefix("/").unwrap_or(&self.0))
    }

    /// Returns the ancestor of this cgroup where a carrier may live so that the blessed
    /// process stays attributable to its user, which is the property polkit needs in the
    /// end. Returns `None` when no ancestor qualifies. The units in [`PLACEMENT`] qualify,
    /// and an earlier one wins when several are present.
    ///
    /// Anything below those units is out. `user@UID.service` and everything under it is
    /// delegated to the user, so a carrier there would sit in a directory its own
    /// beneficiary can `rmdir`. See [`carrier_parent`] for why that matters.
    ///
    /// This is pure path work, so the rule is testable without a cgroup hierarchy. The
    /// ownership check that makes it safe is [`carrier_parent`]'s.
    fn placement(&self) -> Option<CgroupPath> {
        PLACEMENT
            .iter()
            .find_map(|unit| unit.ancestor_of(&self.0))
            .map(CgroupPath::new)
    }
}

/// A systemd unit's cgroup directory name, `<prefix>…<suffix>`.
struct UnitDir {
    prefix: &'static str,
    suffix: &'static str,
}

/// A tty or login session, `session-N.scope`. It is the deepest and most precise carrier
/// parent, because logind reads an exact session id straight from the cgroup.
const SESSION_SCOPE: UnitDir = UnitDir {
    prefix: "session-",
    suffix: ".scope",
};

/// A user's slice, `user-<uid>.slice`, which is where a desktop session's carrier goes. On
/// a modern systemd the terminal does not live in the session scope. It lives under the
/// delegated `user@UID.service/app.slice/app-*.scope`, and there is no session scope
/// anywhere in its ancestry. What still works there is `cg_path_get_owner_uid`, which keys
/// on this `user-<uid>.slice` component to attribute the process to a user. logind then
/// falls back to that user's display session. That is exactly how an ordinary unblessed
/// shell on such a desktop resolves, and matching it is the goal.
///
/// The enclosing `user.slice` does not match, so the hyphen is load-bearing.
const USER_SLICE: UnitDir = UnitDir {
    prefix: "user-",
    suffix: ".slice",
};

/// The units that [`CgroupPath::placement`] may put a carrier in, most preferred first.
/// Both are `root:root` on systemd. [`carrier_roots`] searches exactly these.
const PLACEMENT: [UnitDir; 2] = [SESSION_SCOPE, USER_SLICE];

impl UnitDir {
    fn matches(&self, name: &str) -> bool {
        name.starts_with(self.prefix) && name.ends_with(self.suffix)
    }

    /// Returns the deepest ancestor of `path`, itself included, that is this unit.
    fn ancestor_of<'a>(&self, path: &'a Path) -> Option<&'a Path> {
        path.ancestors().find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| self.matches(n))
        })
    }
}

/// Returns the unified-hierarchy cgroup of `pid`, or a short reason why it is
/// unavailable. This is the one place `/proc/<pid>/cgroup` is read.
fn cgroup_of(pid: Pid) -> std::result::Result<CgroupPath, &'static str> {
    let listing =
        std::fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|_| "cgroup unreadable")?;
    CgroupPath::parse(&listing).ok_or("no unified-hierarchy (0::) line in the cgroup listing")
}

/// Returns the daemon's own cgroup directory, where a carrier goes when the requester
/// has no usable parent.
///
/// Errors when the daemon's cgroup cannot be read or has no cgroup2 line.
fn carrier_root() -> Result<PathBuf> {
    // The daemon's own pid rather than `self`, so the read goes through `cgroup_of`.
    // `/proc/<tgid>/cgroup` is `/proc/self/cgroup`.
    cgroup_of(Pid(std::process::id()))
        .map(|cgroup| cgroup.under(cgroup_root()))
        .map_err(|reason| Error::msg(format!("/proc/self/cgroup: {reason}")))
}

/// Checks whether [`Blessings::reconcile`] may adopt a leftover carrier directory that
/// `owner` owns. Adoption re-registers the carrier, which is a grant, so it is held to the
/// same trust check that [`carrier_parent`] applies to a parent, and only root passes.
/// This daemon creates carriers as root, so anything else in the search space was
/// planted. Adopting it would register a cgroup whose membership someone else controls,
/// which is self-bless.
///
/// A refusal cannot happen on a default systemd, where every scanned level is root-owned
/// and unwritable. That is why the check is asserted rather than assumed. A `Delegate=yes`
/// drop-in or a wider [`carrier_roots`] would make it reachable with nothing here looking
/// different.
fn adoptable(owner: Uid) -> bool {
    owner == Uid::ROOT
}

/// Returns the directory where the carrier for the requester `pid` should be created.
/// That is inside the requester's own user subtree ([`CgroupPath::placement`]) when a
/// usable parent exists there, and `fallback` (the daemon's cgroup) otherwise.
///
/// This is what makes a blessed shell a usable shell. logind attributes a process to a
/// user, and from there to a session, purely from its cgroup path, and polkit needs that
/// attribution to find an authentication agent. A carrier under `cordond.service` has
/// neither a `session-N.scope` nor a `user-<uid>.slice` in its ancestry. logind then
/// reports "Caller does not belong to any known session and doesn't own any suitable
/// session", and every `run0` or `pkexec` inside it fails with "interactive authentication
/// has not been enabled". A carrier inside the requester's own subtree makes the blessed
/// process resolve exactly as an unblessed one there would.
///
/// It refuses any parent that is not root-owned, and that is a real check rather than
/// belt and braces. A user-writable parent lets the invoker `rmdir` an empty carrier and
/// `mkdir` a replacement. A cgroup id is a recycled kernfs inode number, so within the GC
/// window that replacement could land on an id still registered in `BLESSED`, which is
/// self-bless. `session-N.scope` is `root:root`. `user@UID.service` is delegated to the
/// user and must never be used, and the ownership check rejects it on its own.
fn carrier_parent(pid: Pid, fallback: &Path) -> PathBuf {
    match usable_session_scope(pid) {
        Ok(scope) => scope,
        Err(reason) => {
            debug!(pid = %pid, reason, "bless: carrier goes under the daemon's cgroup");
            fallback.to_path_buf()
        }
    }
}

/// Returns the parent in the requester's own subtree where a carrier may be created, or
/// the reason why there is none.
///
/// The reason is a string rather than a typed error because no caller branches on it.
/// Every failure means the same thing, which is to use the daemon's cgroup. The reason
/// only says which way that happened, on one `debug!` line, for someone working out why
/// `run0` stopped working inside a blessed shell.
fn usable_session_scope(pid: Pid) -> std::result::Result<PathBuf, &'static str> {
    // A requester that exited between connecting and here has no cgroup to read. The mint
    // will fail on its own shortly, and until then the daemon's cgroup is the safe
    // placement.
    resolve_placement(&cgroup_of(pid)?, cgroup_root(), owner_uid)
}

/// Returns the carrier parent that [`CgroupPath::placement`] picks for `cgroup` under
/// `cgroup_mount`, or the reason it cannot be used. `owner` reports who owns a candidate
/// parent, and only a root-owned parent that still exists is accepted.
///
/// The mount and the owner are injected rather than probed, so the rule is testable
/// without a cgroup hierarchy or root. That includes the ownership refusal, which is the
/// security-relevant half. It is the same shape as `SocketPath::for_client`'s `exists`.
fn resolve_placement(
    cgroup: &CgroupPath,
    cgroup_mount: &Path,
    owner: impl Fn(&Path) -> Option<Uid>,
) -> std::result::Result<PathBuf, &'static str> {
    let parent = cgroup
        .placement()
        .ok_or("requester's cgroup has no session scope or user slice")?
        .under(cgroup_mount);
    match owner(&parent) {
        Some(Uid::ROOT) => Ok(parent),
        Some(_) => Err("chosen parent is not root-owned"),
        None => Err("chosen parent vanished"),
    }
}

fn owner_uid(path: &Path) -> Option<Uid> {
    std::fs::metadata(path)
        .ok()
        .map(|m| Uid(std::os::unix::fs::MetadataExt::uid(&m)))
}

/// Returns every directory that a carrier could have been created in, which is
/// reconcile's search space. That is the daemon's own cgroup, every `user-*.slice`, and
/// every `session-*.scope` within one, so it mirrors exactly what
/// [`CgroupPath::placement`] can choose.
///
/// A carrier this misses is a carrier nothing ever reaps. It lingers with its members
/// running, and a non-empty child keeps systemd from removing the enclosing slice or
/// scope at logout. Worse, the id allocator never advances past it, so the next mint
/// computes the same `cordon-bless-<id>.<class>` name under the same parent and fails
/// with `EEXIST` forever. Widening `CgroupPath::placement` without widening this function
/// is exactly how that happens.
fn carrier_roots(daemon_cgroup: &Path, cgroup_root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![daemon_cgroup.to_path_buf()];
    let children = |dir: PathBuf, unit: &UnitDir| -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_str().is_some_and(|n| unit.matches(n)))
            .map(|e| e.path())
            .collect()
    };
    for per_user in children(cgroup_root.join("user.slice"), &USER_SLICE) {
        // The slice itself is the desktop placement, because a desktop terminal has no
        // session scope.
        roots.extend(children(per_user.clone(), &SESSION_SCOPE));
        roots.push(per_user);
    }
    // The daemon's own cgroup is a session scope when cordond is started from a login
    // shell rather than the unit, so it can turn up twice. A duplicate would adopt every
    // leftover carrier twice, leaving two table rows with one id and a confusing
    // `bless list`.
    roots.sort();
    roots.dedup();
    roots
}

/// Returns the `populated` value in the `cgroup.events` text, or `None` when the key is
/// missing.
fn events_populated(text: &str) -> Option<bool> {
    text.lines()
        .find_map(|l| l.strip_prefix("populated "))
        .map(|v| v.trim() == "1")
}

/// A carrier cgroup directory, which this daemon creates as root (see [`Blessings::mint`]).
#[derive(Clone, Debug)]
struct CarrierDir(PathBuf);

impl CarrierDir {
    /// Creates the carrier at `path`. Errors when the directory cannot be created, which
    /// includes when it exists already.
    fn create(path: PathBuf) -> Result<CarrierDir> {
        std::fs::create_dir(&path).with_context(|| format!("bless: mkdir {}", path.display()))?;
        Ok(CarrierDir(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Returns the carrier's kernel cgroup id. cgroup2 (kernfs) guarantees that `st_ino`
    /// equals the id `bpf_get_current_cgroup_id()` returns from kernel 5.5 on, and BPF-LSM
    /// needs 5.7 anyway. `st_ino` is the full 64-bit id, with no 32-bit truncation on a
    /// 64-bit kernel. The smoke's scoped-grant scenario is the end-to-end proof of this
    /// equality. Errors when the carrier cannot be stat'ed.
    fn cgroup_id(&self) -> Result<CgroupId> {
        let meta = std::fs::metadata(&self.0).context("bless: stat fresh carrier")?;
        Ok(CgroupId(std::os::unix::fs::MetadataExt::ino(&meta)))
    }

    /// Opens the carrier's `cgroup.procs` for write. A process joins the carrier when its
    /// pid is written through it. Errors when the file cannot be opened.
    fn open_procs(&self) -> Result<CarrierProcs> {
        let path = self.0.join("cgroup.procs");
        let file = std::fs::File::options()
            .write(true)
            .open(&path)
            .with_context(|| format!("bless: open {}", path.display()))?;
        Ok(CarrierProcs(file.into()))
    }

    /// Checks whether the carrier has members now, as its `cgroup.events` says. Returns
    /// `None` when that file, or the carrier itself, is gone.
    fn populated(&self) -> Option<bool> {
        let text = std::fs::read_to_string(self.0.join("cgroup.events")).ok()?;
        events_populated(&text)
    }

    /// Returns the member pids, from `cgroup.procs`. An unreadable or vanished carrier has
    /// none.
    fn pids(&self) -> Vec<Pid> {
        std::fs::read_to_string(self.0.join("cgroup.procs"))
            .map(|text| {
                text.lines()
                    .filter_map(|l| l.trim().parse().ok())
                    .map(Pid)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Kills every member through `cgroup.kill`.
    fn kill(&self) -> std::io::Result<()> {
        std::fs::write(self.0.join("cgroup.kill"), "1")
    }

    /// Removes the carrier, which the kernel allows only once it is empty.
    fn remove(&self) -> std::io::Result<()> {
        std::fs::remove_dir(&self.0)
    }
}

impl std::fmt::Display for CarrierDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
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
        // Not ours, malformed, a bad charset, or no id.
        assert!(parse_dir_name("system.slice").is_none());
        assert!(parse_dir_name("cordon-bless-").is_none());
        assert!(parse_dir_name("cordon-bless-7").is_none()); // no `.class`
        assert!(parse_dir_name("cordon-bless-x.ro").is_none()); // non-numeric id
        assert!(parse_dir_name("cordon-bless-7.").is_none()); // empty class
        assert!(parse_dir_name("cordon-bless-7.a/b").is_none()); // bad charset
        // The first `.` splits, so a dotted suffix lands in the class and fails the
        // charset.
        assert!(parse_dir_name("cordon-bless-7.ro.bak").is_none());
    }

    #[test]
    fn resolve_class_defaults_and_errors() {
        let ro = ClassName::new("ro");
        let rw = ClassName::new("rw");
        let one = ClassRegistry::new([ro.clone()]);
        let two = ClassRegistry::new([ro.clone(), rw.clone()]);
        let none = ClassRegistry::default();

        // An explicit, declared class resolves to itself.
        assert_eq!(resolve_class(Some(ro.clone()), &two).unwrap().1, ClassId(1));
        // With the class omitted and exactly one declared, the sole class is picked.
        assert_eq!(resolve_class(None, &one).unwrap().0, ro);
        // With the class omitted and several declared, the error lists the choices.
        let e = resolve_class(None, &two).unwrap_err().to_string();
        assert!(e.contains("ro, rw"), "{e}");
        // An unknown explicit class errors and lists the choices.
        let e = resolve_class(Some(ClassName::new("nope")), &two)
            .unwrap_err()
            .to_string();
        assert!(e.contains("ro, rw"), "{e}");
        // With nothing declared, both forms error.
        assert!(resolve_class(None, &none).is_err());
        assert!(resolve_class(Some(ro), &none).is_err());
    }

    /// Returns a blessing as `mint` leaves it, `age` ago.
    fn blessing(age: Duration) -> Blessing {
        Blessing {
            id: BlessId(1),
            class: ClassName::new("ro"),
            dir: CarrierDir(PathBuf::from("/nonexistent")),
            owner: None,
            cgroup: CgroupId(1),
            registered: true,
            saw_populated: false,
            revoked: false,
            minted: Instant::now() - age,
        }
    }

    #[test]
    fn gc_reaps_only_meaningful_emptiness() {
        let fresh = Duration::from_secs(1);
        // A fresh carrier that was never populated or revoked stays, because the CLI may
        // still be about to join.
        assert!(!blessing(fresh).should_reap());
        // A carrier whose members all exited is reaped.
        let exited = Blessing {
            saw_populated: true,
            ..blessing(fresh)
        };
        assert!(exited.should_reap());
        // A revoked carrier is reaped as soon as it reads empty.
        let revoked = Blessing {
            revoked: true,
            ..blessing(fresh)
        };
        assert!(revoked.should_reap());
        // A carrier nobody joined before the grace expired is reaped, because the CLI
        // died first.
        assert!(blessing(MINT_GRACE + Duration::from_secs(1)).should_reap());
        // A carrier whose directory is gone is dead.
        assert!(blessing(fresh).check_dead());
    }

    #[test]
    fn remap_plan_covers_rename_renumber_vanish() {
        let live = blessing(Duration::ZERO);
        let inert = Blessing {
            registered: false,
            ..blessing(Duration::ZERO)
        };
        // A class that is still declared, under the same or a new id, is always
        // registered again.
        assert!(matches!(
            live.remap_plan(Some(ClassId(3))),
            Remap::Register(ClassId(3))
        ));
        assert!(matches!(
            inert.remap_plan(Some(ClassId(1))),
            Remap::Register(ClassId(1))
        ));
        // A vanished class with a live entry is unregistered. The blessing goes inert and
        // its tree survives.
        assert!(matches!(live.remap_plan(None), Remap::Unregister));
        // A vanished class that is already inert needs nothing.
        assert!(matches!(inert.remap_plan(None), Remap::Keep));
    }

    #[test]
    fn cgroup_path_parses_the_unified_line() {
        // A hybrid listing has v1 controllers and the unified line.
        let text =
            "12:pids:/user.slice\n1:name=systemd:/init.scope\n0::/system.slice/cordond.service\n";
        assert_eq!(
            CgroupPath::parse(text),
            Some(CgroupPath::new("/system.slice/cordond.service"))
        );
        // Pure v2 at the root. The path is relative to the mount, so it resolves to the
        // mount itself.
        assert_eq!(CgroupPath::parse("0::/\n"), Some(CgroupPath::new("/")));
        assert_eq!(CgroupPath::new("/").under(cgroup_root()), cgroup_root());
        assert_eq!(
            CgroupPath::new("/user.slice/session-3.scope").under(cgroup_root()),
            cgroup_root().join("user.slice/session-3.scope"),
            "the leading slash must not make `join` discard the mount"
        );
        // No unified hierarchy at all.
        assert_eq!(CgroupPath::parse("12:pids:/user.slice\n"), None);
    }

    /// Checks where a carrier goes for the cgroup shapes that actually occur.
    ///
    /// It guards the desktop row in particular. A terminal under the delegated
    /// `user@UID.service`, with no session scope above it, must still be placed in its
    /// user slice rather than fall back to the daemon's cgroup (see
    /// [`CgroupPath::placement`]).
    #[test]
    fn placement_covers_the_cgroup_shapes_that_actually_occur() {
        let rel = |p: &str| CgroupPath::new(p).placement();
        let scope = |p: &str| Some(CgroupPath::new(p));

        // A tty or login session places in the session scope, which is the deepest and
        // most precise.
        let session = "/user.slice/user-1000.slice/session-3.scope";
        assert_eq!(rel(session), scope(session));
        assert_eq!(
            rel("/user.slice/user-1000.slice/session-3.scope/cordon-bless-1.ro"),
            scope(session)
        );

        // A desktop has no session scope in the ancestry at all. The user slice is what
        // keeps the process attributable, and it is the only root-owned option here.
        let slice = "/user.slice/user-1000.slice";
        assert_eq!(
            rel("/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-term.scope"),
            scope(slice)
        );
        assert_eq!(rel(slice), scope(slice));

        // A session scope wins over the user slice when both are present, because it is
        // more precise.
        assert_eq!(
            rel("/user.slice/user-1000.slice/session-12.scope/app.slice/x.service"),
            scope("/user.slice/user-1000.slice/session-12.scope")
        );

        // With nothing user-attributable there is no placement, so the carrier falls back.
        assert_eq!(rel("/system.slice/cordond.service"), None);
        assert_eq!(rel("/system.slice/cordond.service/cordon-bless-3.ro"), None);
        assert_eq!(rel("/"), None);

        // Near misses. `user.slice` has no hyphen and must not match. It is the shared
        // parent of every user, so a carrier there would be attributable to nobody.
        assert_eq!(rel("/user.slice"), None);
        assert_eq!(rel("/user.slice/session-3.slice"), None);
        assert_eq!(rel("/user.slice/mysession-3.scope"), None);
    }

    /// Checks the placement decision end to end, with the filesystem injected. The
    /// ownership refusal, which is the security-relevant half, is asserted without a cgroup
    /// hierarchy or root, and independently of where the test runner sits.
    #[test]
    fn placement_requires_a_root_owned_parent() {
        let mount = Path::new("/fake/cgroup");
        let desktop =
            CgroupPath::new("/user.slice/user-1000.slice/user@1000.service/app.slice/app-t.scope");
        let root_owned = |_: &Path| Some(Uid::ROOT);

        assert_eq!(
            resolve_placement(&desktop, mount, root_owned),
            Ok(mount.join("user.slice/user-1000.slice"))
        );
        // A parent the requester's own user owns is refused (see `carrier_parent`).
        assert_eq!(
            resolve_placement(&desktop, mount, |_| Some(Uid(1000))),
            Err("chosen parent is not root-owned")
        );
        // Gone between the cgroup read and the stat.
        assert_eq!(
            resolve_placement(&desktop, mount, |_| None),
            Err("chosen parent vanished")
        );
        // With nothing user-attributable at all, the caller falls back to the daemon's
        // cgroup.
        assert_eq!(
            resolve_placement(
                &CgroupPath::new("/system.slice/cordond.service"),
                mount,
                root_owned
            ),
            Err("requester's cgroup has no session scope or user slice")
        );
    }

    /// Checks the one ambient path left, which is deterministic everywhere. Pid 0 is never
    /// a process, so `/proc/0/cgroup` cannot be read, and placement falls back rather than
    /// failing the mint.
    #[test]
    fn an_unreadable_requester_falls_back() {
        let fallback = Path::new("/some/daemon/cgroup");
        assert_eq!(carrier_parent(Pid(0), fallback), fallback);
        assert_eq!(usable_session_scope(Pid(0)), Err("cgroup unreadable"));
    }

    /// Guards the pairing that [`carrier_roots`] documents. Reconcile's search space must
    /// cover every parent that [`CgroupPath::placement`] can choose.
    ///
    /// It asserts the pairing rather than a list of paths, so the two cannot drift apart.
    /// For each shape a requester can be in, whatever placement picks must be somewhere
    /// reconcile looks.
    #[test]
    fn reconcile_scans_every_parent_placement_can_choose() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let user_slice = root.join("user.slice/user-1000.slice");
        std::fs::create_dir_all(user_slice.join("session-3.scope")).unwrap();
        std::fs::create_dir_all(user_slice.join("user@1000.service/app.slice")).unwrap();
        let daemon = root.join("system.slice/cordond.service");
        std::fs::create_dir_all(&daemon).unwrap();

        let roots = carrier_roots(&daemon, &root);

        // The placement for every requester shape must be covered.
        for requester in [
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-term.scope", // desktop
            "/user.slice/user-1000.slice/session-3.scope",                            // tty
            "/user.slice/user-1000.slice",
        ] {
            let parent = CgroupPath::new(requester)
                .placement()
                .expect("a placement")
                .under(&root);
            assert!(
                roots.contains(&parent),
                "placement picks {parent:?} for a requester in {requester}, \
                 but reconcile never scans it — that carrier would leak and \
                 block the next mint. roots={roots:?}"
            );
        }
        // The fallback parent is covered too.
        assert!(roots.contains(&daemon));
        // …and nothing is scanned twice, because the daemon's cgroup can also be a
        // session scope.
        let mut unique = roots.clone();
        unique.dedup();
        assert_eq!(unique, roots, "reconcile would scan a directory twice");
    }

    /// Checks that a carrier this daemon did not create as root is not re-registered (see
    /// [`adoptable`]).
    #[test]
    fn only_root_owned_carriers_are_adoptable() {
        assert!(adoptable(Uid::ROOT));
        assert!(!adoptable(Uid(1000)));
        assert!(!adoptable(Uid(u32::MAX)));
    }

    #[test]
    fn events_populated_parses_both_states() {
        assert_eq!(events_populated("populated 1\nfrozen 0\n"), Some(true));
        assert_eq!(events_populated("populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(events_populated("frozen 0\n"), None);
    }

    /// Checks reconcile's filesystem half against a fake carrier root. `scan` finds
    /// exactly the well-formed carrier directories and reads their populated state.
    #[test]
    fn scan_finds_carriers_in_a_fake_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let mk = |name: &str, events: Option<&str>| {
            let dir = root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(text) = events {
                std::fs::write(dir.join("cgroup.events"), text).unwrap();
            }
        };
        mk("cordon-bless-3.ro", Some("populated 1\n"));
        mk("cordon-bless-9.rw", Some("populated 0\n"));
        mk("cordon-bless-4.ro", None); // no events file, so unpopulated
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
    }
}
