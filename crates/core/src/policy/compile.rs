//! Stage 3 — compile a [`ResolvedPolicy`] into the flat, per-object decision table
//! the kernel evaluates (DESIGN §15.3).
//!
//! ## Copy-down object precedence (M1 decision #1)
//! Objects (the distinct `where` paths) form a forest under the path-prefix relation.
//! Rather than make the kernel walk every protected ancestor at decision time, the
//! compiler folds each ancestor's rules **down** into every protected descendant's
//! bucket, then sorts each bucket **most-specific-object-first, then deny-before-allow**
//! and dedups. The kernel then does the dumb thing: find the deepest protected object
//! in the dentry walk, scan its one bucket, apply the **first matching** rule.
//!
//! This supports per-subject sub-object exceptions that a "deepest bucket only" model
//! breaks — e.g. `allow {a,b} read ~/.aws` + `deny evil read ~/.aws/secret`: under
//! copy-down `a`/`b` still read `secret` (they match the inherited allow after the
//! more-specific deny is skipped), where a shadowing model would default-deny them.
//!
//! Paths are resolved to `(dev,ino)` by an injected resolver — the daemon's
//! `proc::file_id` in production, a fake in tests — so this stage stays pure and
//! unit-testable. A path that doesn't resolve yet is **pending** (re-tried on a later
//! apply / `inode_create` in M3); an exe that doesn't resolve drops that one rule with
//! a warning.

use super::{ClassName, Diagnostic, ResolvedPolicy, Severity, SubjectSpec};
use crate::paths;
use cordon_bpf_common::{
    ClassId, CompiledRule, FileId, MAX_RULES_PER_OBJ, ObjId, SubjectFlags, SubjectMatch,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The compiled policy: protected objects with their pre-merged, pre-sorted rule
/// buckets, plus the paths that didn't resolve and any diagnostics. The daemon loads
/// `objects` into the BPF maps (keyed by [`FileId`], addressed by [`ObjId`]) only if
/// [`CompiledPolicy::has_errors`] is false.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    pub objects: Vec<CompiledObject>,
    /// Object paths that don't currently resolve to an inode — re-tried on a later
    /// `cordon policy apply` (or when the path is created, M3).
    pub pending: Vec<PathBuf>,
    pub diagnostics: Vec<Diagnostic>,
    /// The blessing class registry (DESIGN §16.3): each declared class name → its dense
    /// [`ClassId`], sorted by name. The daemon validates `cordon bless --class` against this
    /// and writes the `BLESSED` map at mint; [`ClassId::UNBLESSED`] (0) is never assigned.
    pub blessing_classes: Vec<(ClassName, ClassId)>,
}

/// One protected object and its flat rule bucket (sorted, copy-down-merged, deduped,
/// `≤ MAX_RULES_PER_OBJ` unless an error diagnostic says otherwise).
#[derive(Clone, Debug)]
pub struct CompiledObject {
    pub id: ObjId,
    pub file: FileId,
    /// The source path, for `cordon policy show` and diagnostics.
    pub path: PathBuf,
    pub rules: Vec<CompiledRule>,
}

impl CompiledPolicy {
    /// Whether any diagnostic is an error — `cordon policy apply` must refuse if so.
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }
}

/// A `stat(2)`-based resolver for **linting** (`cordon policy check`): a path's
/// `(dev,ino)` if it exists, else `None`. Uses `stat`'s `st_dev`, *not* the kernel's
/// mount-table device — fine here, where resolution only drives existence + uniqueness
/// diagnostics; the daemon's `apply` uses the mount-aware resolver (`proc::file_id`)
/// for the identities it actually enforces on.
pub fn stat_resolver(path: &Path) -> Option<FileId> {
    use cordon_bpf_common::{Dev, Ino};
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(FileId::new(Dev(m.dev()), Ino(m.ino())))
}

/// A resolved protected object, before its bucket is built.
struct Object {
    id: ObjId,
    file: FileId,
    path: PathBuf,
    /// Path-component count — the specificity used to sort copied-down rules.
    depth: usize,
}

/// A rule plus the depth of the object it was authored on (its specificity), so a
/// rule copied down into a deeper object keeps its original, lower precedence.
#[derive(Clone)]
struct ProvRule {
    rule: CompiledRule,
    depth: usize,
}

/// Compile `resolved` to the flat table. `resolve_fileid` maps an absolute path to its
/// inode identity (`None` ⇒ doesn't exist / unreadable).
pub fn compile<R>(resolved: &ResolvedPolicy, mut resolve_fileid: R) -> CompiledPolicy
where
    R: FnMut(&Path) -> Option<FileId>,
{
    let mut diagnostics = Vec::new();

    // 0. Blessing class registry (DESIGN §16.3): assign each declared class a dense ClassId
    //    starting at 1 (ClassId(0) = the UNBLESSED sentinel). `resolved.blessing_classes` is
    //    already sorted, so the ids are stable across compiles.
    let blessing_classes: Vec<(ClassName, ClassId)> = resolved
        .blessing_classes
        .iter()
        .enumerate()
        .map(|(i, name)| (name.clone(), ClassId(i as u32 + 1)))
        .collect();
    let class_ids: BTreeMap<ClassName, ClassId> = blessing_classes.iter().cloned().collect();

    // 1. Resolve the distinct object paths → objects (sorted for stable ObjIds) +
    //    pending. A `BTreeSet` gives a deterministic order so ObjIds don't churn
    //    across compiles of the same policy.
    let distinct_objs: BTreeSet<&Path> = resolved
        .rules
        .iter()
        .flat_map(|r| r.objects.iter().map(PathBuf::as_path))
        .collect();

    let mut objects: Vec<Object> = Vec::new();
    let mut pending: Vec<PathBuf> = Vec::new();
    for path in distinct_objs {
        match resolve_fileid(path) {
            Some(file) => {
                objects.push(Object {
                    id: ObjId(objects.len() as u32),
                    file,
                    path: path.to_path_buf(),
                    depth: paths::depth(path),
                });
            }
            None => pending.push(path.to_path_buf()),
        }
    }
    let index_of = |p: &Path| objects.iter().position(|o| o.path == p);

    // 2. Per-object "own" rules: cross-product subjects × this object, lowering each
    //    subject to a `SubjectMatch` (resolving exe paths). Unknown exe ⇒ drop that one
    //    rule with a warning; a pending object ⇒ warn + skip (recorded above).
    let mut own: Vec<Vec<ProvRule>> = (0..objects.len()).map(|_| Vec::new()).collect();
    for rule in &resolved.rules {
        let subjects = lower_subjects(
            &rule.subjects,
            &mut resolve_fileid,
            &class_ids,
            rule.pos,
            &mut diagnostics,
        );
        for obj_path in &rule.objects {
            match index_of(obj_path) {
                Some(idx) => {
                    let depth = objects[idx].depth;
                    for &subject in &subjects {
                        own[idx].push(ProvRule {
                            rule: CompiledRule::new(subject, rule.actions, rule.policy),
                            depth,
                        });
                    }
                }
                None => diagnostics.push(Diagnostic::warn(
                    rule.pos,
                    format!(
                        "path {} does not exist yet; this rule is not enforced until it is created and you re-apply",
                        obj_path.display()
                    ),
                )),
            }
        }
    }

    // 3. Copy-down: each object's bucket = its own rules + every protected ancestor's
    //    own rules; sort (specificity desc, deny before allow); dedup; cap-check.
    let mut compiled = Vec::with_capacity(objects.len());
    for i in 0..objects.len() {
        let mut bucket: Vec<ProvRule> = own[i].clone();
        for j in 0..objects.len() {
            if j != i && paths::is_within(&objects[i].path, &objects[j].path) {
                bucket.extend(own[j].iter().cloned());
            }
        }
        sort_bucket(&mut bucket);
        dedup_bucket(&mut bucket);

        if bucket.len() > MAX_RULES_PER_OBJ {
            diagnostics.push(Diagnostic::error(
                None,
                format!(
                    "object {} compiles to {} rules, over the per-object limit of {} \
                     (split the policy or raise MAX_RULES_PER_OBJ)",
                    objects[i].path.display(),
                    bucket.len(),
                    MAX_RULES_PER_OBJ
                ),
            ));
        }

        compiled.push(CompiledObject {
            id: objects[i].id,
            file: objects[i].file,
            path: objects[i].path.clone(),
            rules: bucket.into_iter().map(|pr| pr.rule).collect(),
        });
    }

    CompiledPolicy {
        objects: compiled,
        pending,
        diagnostics,
        blessing_classes,
    }
}

/// Lower a rule's subjects to `SubjectMatch`es: resolve exe paths to inodes, and map a
/// blessing class name to its dense [`ClassId`] via `class_ids` (DESIGN §16.3).
fn lower_subjects<R>(
    subjects: &[SubjectSpec],
    resolve_fileid: &mut R,
    class_ids: &BTreeMap<ClassName, ClassId>,
    pos: Option<super::Pos>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<SubjectMatch>
where
    R: FnMut(&Path) -> Option<FileId>,
{
    let mut out = Vec::new();
    for s in subjects {
        match s {
            SubjectSpec::Any => out.push(SubjectMatch::ANY),
            SubjectSpec::Exe(path) => match resolve_fileid(path) {
                Some(file) => out.push(SubjectMatch::exe(file)),
                None => diagnostics.push(Diagnostic::warn(
                    pos,
                    format!(
                        "exe {} does not exist; this rule is not enforced for it",
                        path.display()
                    ),
                )),
            },
            // `resolve` only emits a `Blessed` for a *declared* class, so the lookup always
            // hits; guard it as an internal error rather than panicking in the daemon.
            SubjectSpec::Blessed(name) => match class_ids.get(name) {
                Some(&id) => out.push(SubjectMatch::blessed(id)),
                None => diagnostics.push(Diagnostic::error(
                    pos,
                    format!("internal: blessing class {name:?} is not in the registry"),
                )),
            },
        }
    }
    out
}

/// Sort a bucket into kernel first-match order: most-specific object first, then
/// `deny`/`silence` before `allow`/`audit` (fail-safe tie-break). A stable sort keeps
/// authoring order within a precedence class, so compiles are deterministic.
fn sort_bucket(bucket: &mut [ProvRule]) {
    bucket.sort_by(|a, b| {
        // DESIGN §15.6 precedence, most-specific first: (1) object depth, (2) subject
        // specificity, (3) deny>allow as the tie-break among rules of *equal* object+
        // subject specificity. The kernel then takes the first match. (1) and (2) are
        // `b.cmp(a)` — descending, since a higher depth/specificity is more specific;
        // (3) is `a.cmp(b)` — `Polarity::Deny` is declared first, so ascending puts it
        // ahead of `Allow`.
        b.depth
            .cmp(&a.depth)
            .then_with(|| subject_specificity(b.rule).cmp(&subject_specificity(a.rule)))
            .then_with(|| polarity(a.rule).cmp(&polarity(b.rule)))
    });
}

/// The count of non-wildcard subject predicates (DESIGN §15.6 step 2); a higher count is
/// more specific. A concrete subject (`exe=X`) outranks a `who="*"` catch-all on the same
/// object, so a specific `allow`/`deny` wins over a broad `audit`/`deny` — the basis of
/// the audit→admit→enforce flow (§15.10 flow A): an admitted `allow exe=X` goes silent while
/// the `*` catch-all keeps observing the not-yet-admitted. A concrete `blessing` predicate
/// (PLAN-bless B1) counts the same way, so a blessing `allow` likewise outranks the catch-all.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Specificity(u32);

/// M1 fills only `exe`, so the count is 1 (concrete exe) or 0 (`*`); the popcount over the
/// wildcard flags generalizes for free as the `uid`/`cgroup` (M2) and `blessing` (B1)
/// predicates land — each concrete one clears its bit and adds a unit of specificity.
fn subject_specificity(r: CompiledRule) -> Specificity {
    // All subject predicates; a rule's specificity is how many are *not* wildcard.
    let predicates = SubjectFlags::all();
    Specificity(
        predicates.bits().count_ones()
            - r.subject.flags.intersection(predicates).bits().count_ones(),
    )
}

/// Allow-vs-deny polarity — the fail-safe tie-break (§15.6 step 3). `Deny` is declared
/// first so the derived `Ord` sorts it ahead of `Allow`: among rules of equal object +
/// subject specificity, a denying policy wins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Polarity {
    Deny,
    Allow,
}

fn polarity(r: CompiledRule) -> Polarity {
    if r.policy.denies() {
        Polarity::Deny
    } else {
        Polarity::Allow
    }
}

/// Drop later duplicates of an identical [`CompiledRule`], keeping the first (highest
/// precedence after [`sort_bucket`]). Buckets are small, so a linear scan is fine and
/// avoids requiring `Hash` on the POD types.
fn dedup_bucket(bucket: &mut Vec<ProvRule>) {
    let mut seen: Vec<CompiledRule> = Vec::new();
    bucket.retain(|pr| {
        if seen.contains(&pr.rule) {
            false
        } else {
            seen.push(pr.rule);
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{parse, resolve};
    use cordon_bpf_common::{Action, Dev, Ino, Policy};
    use std::collections::HashMap;

    /// A fake path→FileId resolver from `(path, inode)` pairs (device 0). Any path not
    /// listed resolves to `None` (doesn't exist).
    fn resolver(pairs: &[(&str, u64)]) -> impl FnMut(&Path) -> Option<FileId> {
        let map: HashMap<PathBuf, FileId> = pairs
            .iter()
            .map(|(p, ino)| (PathBuf::from(p), FileId::new(Dev(0), Ino(*ino))))
            .collect();
        move |p: &Path| map.get(p).copied()
    }

    fn compile_text(text: &str, pairs: &[(&str, u64)]) -> CompiledPolicy {
        let resolved = resolve(&parse(text).unwrap(), Path::new("/home/u")).unwrap();
        compile(&resolved, resolver(pairs))
    }

    /// A single `[[rule]]` block from already-quoted/-bracketed TOML fields.
    fn rule(who: &str, where_: &str, action: &str, policy: &str) -> String {
        format!("[[rule]]\nwho = {who}\nwhere = {where_}\naction = {action}\npolicy = {policy}\n")
    }

    fn object<'a>(p: &'a CompiledPolicy, path: &str) -> &'a CompiledObject {
        p.objects
            .iter()
            .find(|o| o.path == Path::new(path))
            .unwrap_or_else(|| panic!("no compiled object for {path}"))
    }

    #[test]
    fn cross_product_expands_per_object() {
        let p = compile_text(
            &rule(r#"["/a","/b"]"#, r#"["/x","/y"]"#, "\"read\"", "\"allow\""),
            &[("/a", 1), ("/b", 2), ("/x", 10), ("/y", 11)],
        );
        assert!(!p.has_errors());
        assert_eq!(p.objects.len(), 2);
        // Each object gets one rule per subject (2), no nesting.
        assert_eq!(object(&p, "/x").rules.len(), 2);
        assert_eq!(object(&p, "/y").rules.len(), 2);
    }

    #[test]
    fn copydown_broad_allow_narrow_deny() {
        // allow {a,b,s} read /d ; deny s read /d/f. After copy-down, /d/f's bucket must
        // deny s first but still allow a/b (the inherited rule).
        let text = format!(
            "{}{}",
            rule(r#"["/a","/b","/s"]"#, "\"/d\"", "\"read\"", "\"allow\""),
            rule("\"/s\"", "\"/d/f\"", "\"read\"", "\"deny\""),
        );
        let p = compile_text(
            &text,
            &[("/a", 1), ("/b", 2), ("/s", 3), ("/d", 10), ("/d/f", 11)],
        );
        assert!(!p.has_errors(), "{:?}", p.diagnostics);
        let f = object(&p, "/d/f");
        // Most-specific first: the deny on s.
        assert_eq!(f.rules[0].policy, Policy::DENY);
        assert_eq!(
            f.rules[0].subject,
            SubjectMatch::exe(FileId::new(Dev(0), Ino(3)))
        );
        // The inherited allow for a and b survives (so a/b still read /d/f).
        let allow_a = f.rules.iter().any(|r| {
            r.policy == Policy::ALLOW && r.subject == SubjectMatch::exe(FileId::new(Dev(0), Ino(1)))
        });
        let allow_b = f.rules.iter().any(|r| {
            r.policy == Policy::ALLOW && r.subject == SubjectMatch::exe(FileId::new(Dev(0), Ino(2)))
        });
        assert!(allow_a && allow_b, "inherited allows lost: {:?}", f.rules);
    }

    #[test]
    fn copydown_broad_deny_narrow_allow() {
        // deny {a,b,s} read /d ; allow s read /d/f. /d/f must allow s first, deny the rest.
        let text = format!(
            "{}{}",
            rule(r#"["/a","/b","/s"]"#, "\"/d\"", "\"read\"", "\"deny\""),
            rule("\"/s\"", "\"/d/f\"", "\"read\"", "\"allow\""),
        );
        let p = compile_text(
            &text,
            &[("/a", 1), ("/b", 2), ("/s", 3), ("/d", 10), ("/d/f", 11)],
        );
        assert!(!p.has_errors());
        let f = object(&p, "/d/f");
        assert_eq!(f.rules[0].policy, Policy::ALLOW);
        assert_eq!(
            f.rules[0].subject,
            SubjectMatch::exe(FileId::new(Dev(0), Ino(3)))
        );
        // The inherited denies for a and b follow.
        assert!(f.rules.iter().any(|r| r.policy == Policy::DENY));
    }

    #[test]
    fn deny_sorts_before_allow_at_same_specificity() {
        let text = format!(
            "{}{}",
            rule("\"/a\"", "\"/d\"", "\"read\"", "\"allow\""),
            rule("\"/a\"", "\"/d\"", "\"read\"", "\"deny\""),
        );
        let p = compile_text(&text, &[("/a", 1), ("/d", 10)]);
        let d = object(&p, "/d");
        assert_eq!(d.rules[0].policy, Policy::DENY); // fail-safe tie-break
    }

    #[test]
    fn concrete_subject_beats_wildcard_catchall() {
        // §15.10 flow A step 2: a blessed `allow exe=X` must win over a `who="*"` audit
        // catch-all on the same object, so the blessed exe goes silent while the catch-all
        // keeps observing everyone else. Author the catch-all *first* to prove the order
        // comes from specificity, not insertion order.
        let text = format!(
            "{}{}",
            rule("\"*\"", "\"/d\"", "\"read\"", "\"audit\""),
            rule("\"/a\"", "\"/d\"", "\"read\"", "\"allow\""),
        );
        let p = compile_text(&text, &[("/a", 1), ("/d", 10)]);
        let d = object(&p, "/d");
        assert_eq!(d.rules[0].policy, Policy::ALLOW);
        assert_eq!(
            d.rules[0].subject,
            SubjectMatch::exe(FileId::new(Dev(0), Ino(1)))
        );
        // The wildcard audit catch-all still follows (so non-X openers are observed).
        assert_eq!(d.rules[1].policy, Policy::AUDIT);
        assert_eq!(d.rules[1].subject, SubjectMatch::ANY);
    }

    #[test]
    fn concrete_allow_beats_wildcard_deny() {
        // The motivating case for subject-specificity: without it, deny>allow would sort
        // the `who="*"` deny first and block X. Specificity puts `allow exe=X` ahead, so X
        // is allowed while everyone else is denied by the catch-all.
        let text = format!(
            "{}{}",
            rule("\"*\"", "\"/d\"", "\"read\"", "\"deny\""),
            rule("\"/a\"", "\"/d\"", "\"read\"", "\"allow\""),
        );
        let p = compile_text(&text, &[("/a", 1), ("/d", 10)]);
        let d = object(&p, "/d");
        assert_eq!(d.rules[0].policy, Policy::ALLOW);
        assert_eq!(
            d.rules[0].subject,
            SubjectMatch::exe(FileId::new(Dev(0), Ino(1)))
        );
        assert_eq!(d.rules[1].policy, Policy::DENY);
        assert_eq!(d.rules[1].subject, SubjectMatch::ANY);
    }

    #[test]
    fn pending_path_is_recorded_not_compiled() {
        let p = compile_text(
            &rule("\"/a\"", "\"/missing\"", "\"read\"", "\"allow\""),
            &[("/a", 1)], // /missing not resolvable
        );
        assert_eq!(p.objects.len(), 0);
        assert_eq!(p.pending, vec![PathBuf::from("/missing")]);
        assert!(
            p.diagnostics
                .iter()
                .any(|d| d.message.contains("does not exist yet"))
        );
        assert!(!p.has_errors()); // pending is a warning, not an error
    }

    #[test]
    fn unknown_exe_drops_rule_with_warning() {
        let p = compile_text(
            &rule("\"/gone\"", "\"/d\"", "\"read\"", "\"allow\""),
            &[("/d", 10)], // /gone not resolvable
        );
        // /d is still a protected object (default-deny), but its bucket is empty.
        assert_eq!(object(&p, "/d").rules.len(), 0);
        assert!(
            p.diagnostics
                .iter()
                .any(|d| d.message.contains("not enforced for it"))
        );
    }

    #[test]
    fn identical_rules_dedup() {
        // The same (subject, action, policy) authored twice on one object → one entry.
        let one = rule("\"/a\"", "\"/d\"", "\"read\"", "\"allow\"");
        let p = compile_text(&format!("{one}{one}"), &[("/a", 1), ("/d", 10)]);
        assert_eq!(object(&p, "/d").rules.len(), 1);
    }

    #[test]
    fn over_cap_is_an_error() {
        // MAX+1 distinct subjects on one object > MAX_RULES_PER_OBJ.
        let mut pairs = vec![("/d", 10u64)];
        let mut whos = Vec::new();
        let exes: Vec<String> = (0..(MAX_RULES_PER_OBJ + 1))
            .map(|i| format!("/e{i}"))
            .collect();
        for (i, e) in exes.iter().enumerate() {
            whos.push(format!("\"{e}\""));
            pairs.push((e.as_str(), 100 + i as u64));
        }
        let text = rule(
            &format!("[{}]", whos.join(",")),
            "\"/d\"",
            "\"read\"",
            "\"allow\"",
        );
        let p = compile_text(&text, &pairs);
        assert!(p.has_errors());
        assert!(
            p.diagnostics
                .iter()
                .any(|d| d.message.contains("per-object limit"))
        );
    }

    #[test]
    fn action_mask_is_carried() {
        let p = compile_text(
            &rule("\"*\"", "\"/d\"", r#"["read","write"]"#, "\"audit\""),
            &[("/d", 10)],
        );
        let d = object(&p, "/d");
        assert_eq!(d.rules.len(), 1);
        assert_eq!(d.rules[0].action_mask, Action::READ | Action::WRITE);
        assert_eq!(d.rules[0].policy, Policy::AUDIT);
        assert_eq!(d.rules[0].subject, SubjectMatch::ANY);
    }

    // ---- blessing (DESIGN §16.3 / PLAN-bless B1c) ----

    /// A blessing rule lowers to `SubjectMatch::blessed(id)`: BLESSING_ANY cleared, the class
    /// stamped in, and the registry maps the name → a dense id ≥ 1.
    #[test]
    fn blessing_rule_lowers_and_registry_is_assigned() {
        let text = r#"
            [group.subject.blessed-ro]
            blessing = "ro"
            [group.subject.blessed-rw]
            blessing = "rw"
            [[rule]]
            who = "@blessed-ro"
            where = "/d"
            action = "read"
            policy = "allow"
        "#;
        let p = compile_text(text, &[("/d", 10)]);
        assert!(!p.has_errors(), "{:?}", p.diagnostics);

        // Registry: both declared classes present, sorted by name, dense ids from 1
        // (ClassId(0) reserved for UNBLESSED).
        let reg: std::collections::BTreeMap<_, _> = p
            .blessing_classes
            .iter()
            .map(|(n, id)| (n.as_str().to_string(), id.0))
            .collect();
        assert_eq!(reg["ro"], 1);
        assert_eq!(reg["rw"], 2);

        // The referencing rule's subject carries the stamped class id and clears BLESSING_ANY.
        let d = object(&p, "/d");
        assert_eq!(d.rules.len(), 1);
        assert_eq!(d.rules[0].subject, SubjectMatch::blessed(ClassId(1)));
        assert!(
            !d.rules[0]
                .subject
                .flags
                .contains(cordon_bpf_common::SubjectFlags::BLESSING_ANY)
        );
    }

    /// A blessing predicate is one unit of subject specificity, so it outranks a `who="*"`
    /// catch-all on the same object — the basis of a blessing `allow` beating a catch-all
    /// `deny` (PLAN-bless B1 decision #5).
    #[test]
    fn blessed_allow_outranks_wildcard_deny() {
        let text = r#"
            [group.subject.blessed-ro]
            blessing = "ro"
            [[rule]]
            who = "*"
            where = "/d"
            action = "read"
            policy = "deny"
            [[rule]]
            who = "@blessed-ro"
            where = "/d"
            action = "read"
            policy = "allow"
        "#;
        let p = compile_text(text, &[("/d", 10)]);
        assert!(!p.has_errors());
        // First-match = most-specific: the blessed allow beats the wildcard deny.
        let d = object(&p, "/d");
        assert_eq!(d.rules[0].policy, Policy::ALLOW, "{:?}", d.rules);
        assert_eq!(d.rules[0].subject, SubjectMatch::blessed(ClassId(1)));
    }
}
