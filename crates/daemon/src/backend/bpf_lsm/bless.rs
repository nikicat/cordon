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
use cordon_core::proto::{BlessId, BlessingView, Pid};
use cordon_core::{Error, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// How long a fresh, never-populated carrier is left alone before GC may reap it.
/// Load-bearing: a carrier is empty from mint until the CLI's `pre_exec` writes the
/// target pid into it — without the grace, the 500ms GC tick would reap it first.
/// Generous because the cost of a leak is one empty cgroup dir for 30s; a CLI that
/// died before joining is cleaned up right after.
const MINT_GRACE: Duration = Duration::from_secs(30);

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

    /// Mint a blessing: create the carrier cgroup and register it in `MAP_BLESSED`.
    /// The caller (CLI, root) execs the target into the returned carrier.
    pub(super) fn mint(
        &mut self,
        ebpf: &mut Ebpf,
        class: Option<ClassName>,
        registry: &BTreeMap<ClassName, ClassId>,
    ) -> Result<BlessingView> {
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
        let dir = root.join(dir_name(id, &class));
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
        if let Err(e) = seed::blessed_insert(ebpf, cgroup, class_id) {
            let _ = std::fs::remove_dir(&dir);
            return Err(e);
        }

        self.next = id.successor();
        self.live.push(Blessing {
            id,
            class: class.clone(),
            dir: dir.clone(),
            cgroup,
            registered: true,
            saw_populated: false,
            revoked: false,
            minted: Instant::now(),
        });
        info!(%id, %class, cgroup = %dir.display(), "blessing minted");
        Ok(BlessingView {
            id,
            class,
            cgroup: dir,
            pids: Vec::new(),
            age: Duration::ZERO,
        })
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
    pub(super) fn revoke(&mut self, id: BlessId) -> Result<()> {
        let b = self
            .live
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or_else(|| Error::msg(format!("no blessing with id {id}")))?;
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
    pub(super) fn reconcile(&mut self, ebpf: &mut Ebpf, registry: &BTreeMap<ClassName, ClassId>) {
        let Some(root) = self.root.clone() else {
            return;
        };
        for found in scan(&root) {
            if !found.populated {
                let _ = std::fs::remove_dir(&found.dir);
                info!(dir = %found.dir.display(), "bless: removed empty leftover carrier");
                continue;
            }
            let cgroup = match std::fs::metadata(&found.dir) {
                Ok(meta) => CgroupId(std::os::unix::fs::MetadataExt::ino(&meta)),
                Err(e) => {
                    warn!(dir = %found.dir.display(), error = %e, "bless: reconcile stat failed; skipped");
                    continue;
                }
            };
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
    Ok(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// The unified-hierarchy path from a `/proc/<pid>/cgroup` listing: the `0::<path>`
/// line's path part (without a leading `/`, it *is* the cgroup2 root).
fn cgroup_v2_path(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("0::"))
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
        assert_eq!(cgroup_v2_path(text), Some("/system.slice/cordond.service"));
        // Pure v2 at the root.
        assert_eq!(cgroup_v2_path("0::/\n"), Some("/"));
        // No unified hierarchy at all.
        assert_eq!(cgroup_v2_path("12:pids:/user.slice\n"), None);
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
