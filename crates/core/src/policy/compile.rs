//! Stage 3, which compiles a [`ResolvedPolicy`] into the flat per-object decision table
//! that the kernel evaluates (DESIGN §15.3).
//!
//! ## Copy-down object precedence
//! Objects, the distinct `where` paths, form a forest under the path-prefix relation.
//! Rather than make the kernel walk every protected ancestor at decision time, the
//! compiler folds each ancestor's rules down into the bucket of every protected
//! descendant (`Compiler::buckets`), in first-match order (`sort_bucket`). At decision
//! time the kernel only finds the deepest protected object in the dentry walk, scans
//! that one bucket, and applies the first rule that matches.
//!
//! This supports per-subject exceptions on a sub-object, which a model that consults
//! only the deepest bucket breaks. Take `allow {a,b} read ~/.aws` together with
//! `deny evil read ~/.aws/secret`. Under copy-down, `a` and `b` can still read `secret`,
//! because they skip the more specific deny and match the inherited allow. A shadowing
//! model would deny them by default.
//!
//! An injected resolver turns paths into `(dev,ino)`. It is the daemon's `fsid::file_id`
//! in production and a fake in tests, so this stage stays pure and testable on its own.

use super::{ClassName, Diagnostic, Loc, ResolvedPolicy, Severity, SubjectSpec};
use crate::paths;
use cordon_bpf_common::{
    ClassId, CompiledRule, FileId, MAX_OBJECTS, MAX_RULES_PER_OBJ, ObjId, SubjectFlags,
    SubjectMatch,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The output of a compile, which the daemon loads into the BPF maps, keyed by
/// [`FileId`] and addressed by [`ObjId`]. The daemon loads it only when
/// [`CompiledPolicy::has_errors`] is false.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    pub objects: Vec<CompiledObject>,
    /// The object paths that do not resolve to an inode yet (see `Compiler::objects`).
    pub pending: Vec<PathBuf>,
    pub diagnostics: Vec<Diagnostic>,
    /// The declared blessing classes and the ids this compile gives them.
    pub classes: ClassRegistry,
}

/// The declared blessing classes (DESIGN §16.3) and their dense [`ClassId`]s. The kernel
/// knows a class only by its id, so the daemon goes through this registry to turn a
/// requested class name into an id at mint, and an id back into a name in the journal.
/// Ids follow name order from `UNBLESSED + 1`, so every compile renumbers them. Nothing
/// may keep an id across an apply without resolving it again by name, which is why the
/// daemon remaps the live blessings by class name after each apply (`Blessings::remap`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassRegistry(Vec<ClassName>);

impl ClassRegistry {
    /// Returns the registry of `classes`, ignoring duplicates.
    pub fn new(classes: impl IntoIterator<Item = ClassName>) -> ClassRegistry {
        ClassRegistry(
            classes
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        )
    }

    /// Returns the id of the class `name`, or `None` when the policy doesn't declare it.
    pub fn id(&self, name: &ClassName) -> Option<ClassId> {
        let i = self.0.binary_search(name).ok()?;
        Some(ClassId(ClassId::UNBLESSED.0 + 1 + i as u32))
    }

    /// Returns the name of the class `id`, or `None` for [`ClassId::UNBLESSED`] and for an
    /// id this compile didn't assign.
    pub fn name(&self, id: ClassId) -> Option<&ClassName> {
        let i = id.0.checked_sub(ClassId::UNBLESSED.0 + 1)?;
        self.0.get(i as usize)
    }

    /// Returns every declared class with its id, in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&ClassName, ClassId)> {
        self.0
            .iter()
            .filter_map(|name| Some((name, self.id(name)?)))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One protected object and its flat rule bucket. The bucket is sorted, merged by
/// copy-down and deduplicated, and holds at most `MAX_RULES_PER_OBJ` rules unless an
/// error diagnostic says otherwise.
#[derive(Clone, Debug)]
pub struct CompiledObject {
    pub id: ObjId,
    pub file: FileId,
    /// The source path, for `cordon policy show` and diagnostics.
    pub path: PathBuf,
    pub rules: Vec<CompiledRule>,
}

impl CompiledPolicy {
    /// Checks whether any diagnostic is an error, in which case the policy must not be
    /// applied.
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }
}

/// Returns the `(dev,ino)` of `path` from `stat(2)`, or `None` when the path does not
/// exist. Its `st_dev` can differ from the device that the kernel enforces on, which the
/// daemon's `fsid::file_id` resolves. That makes it fit only for linting
/// (`cordon policy check`), where resolution drives just the existence and uniqueness
/// diagnostics.
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
    /// The number of path components, which is the specificity that sorts copied-down
    /// rules.
    depth: usize,
}

/// A rule together with the depth of the object it was authored on, so that a rule
/// copied down into a deeper object keeps its original, lower precedence.
#[derive(Clone)]
struct ProvRule {
    rule: CompiledRule,
    depth: usize,
}

/// Compiles `resolved` into the flat decision table. `resolve_fileid` maps an absolute
/// path to its inode identity, or to `None` when the path does not exist or cannot be
/// read. Problems end up in the result's diagnostics rather than in an error.
pub fn compile<R>(resolved: &ResolvedPolicy, resolve_fileid: R) -> CompiledPolicy
where
    R: FnMut(&Path) -> Option<FileId>,
{
    let mut compiler = Compiler {
        resolve_fileid,
        classes: ClassRegistry::new(resolved.blessing_classes.iter().cloned()),
        diagnostics: Vec::new(),
    };
    let (objects, pending) = compiler.objects(resolved);
    let own = compiler.own_rules(resolved, &objects);
    let objects = compiler.buckets(&objects, &own);
    CompiledPolicy {
        objects,
        pending,
        diagnostics: compiler.diagnostics,
        classes: compiler.classes,
    }
}

/// The state of one compile, shared by its steps so that each step can add diagnostics.
struct Compiler<R> {
    resolve_fileid: R,
    classes: ClassRegistry,
    diagnostics: Vec<Diagnostic>,
}

impl<R> Compiler<R>
where
    R: FnMut(&Path) -> Option<FileId>,
{
    /// Resolves the distinct object paths. Returns the objects, numbered in path order so
    /// that ObjIds do not churn across compiles of the same policy, and the paths that do
    /// not resolve yet. Such a path is pending. None of its rules are enforced, and the
    /// next `cordon policy apply` resolves it again. Adds an error diagnostic when there
    /// are more than `MAX_OBJECTS` objects.
    fn objects(&mut self, resolved: &ResolvedPolicy) -> (Vec<Object>, Vec<PathBuf>) {
        let distinct: BTreeSet<&Path> = resolved
            .rules
            .iter()
            .flat_map(|r| r.objects.iter().map(PathBuf::as_path))
            .collect();

        let mut objects: Vec<Object> = Vec::new();
        let mut pending: Vec<PathBuf> = Vec::new();
        for path in distinct {
            match (self.resolve_fileid)(path) {
                Some(file) => objects.push(Object {
                    id: ObjId(objects.len() as u32),
                    file,
                    path: path.to_path_buf(),
                    depth: paths::depth(path),
                }),
                None => pending.push(path.to_path_buf()),
            }
        }
        if objects.len() > MAX_OBJECTS {
            self.diagnostics.push(Diagnostic::error(
                Loc::default(),
                format!(
                    "the policy protects {} objects, over the limit of {MAX_OBJECTS} \
                     (merge objects under a common parent or raise MAX_OBJECTS)",
                    objects.len()
                ),
            ));
        }
        (objects, pending)
    }

    /// Returns each object's own rules, indexed like `objects`. They are the cross product
    /// of every rule's subjects with that object. Adds a warning for each rule on a
    /// pending object.
    fn own_rules(&mut self, resolved: &ResolvedPolicy, objects: &[Object]) -> Vec<Vec<ProvRule>> {
        let mut own: Vec<Vec<ProvRule>> = (0..objects.len()).map(|_| Vec::new()).collect();
        for rule in &resolved.rules {
            let subjects = self.lower_subjects(&rule.subjects, &rule.loc());
            for obj_path in &rule.objects {
                match objects.iter().position(|o| &o.path == obj_path) {
                    Some(idx) => {
                        let depth = objects[idx].depth;
                        own[idx].extend(subjects.iter().map(|&subject| ProvRule {
                            rule: CompiledRule::new(subject, rule.actions, rule.policy),
                            depth,
                        }));
                    }
                    None => self.diagnostics.push(Diagnostic::warn(
                        rule.loc(),
                        format!(
                            "path {} does not exist yet; this rule is not enforced until it is created and you re-apply",
                            obj_path.display()
                        ),
                    )),
                }
            }
        }
        own
    }

    /// Returns a rule's subjects as `SubjectMatch`es, with exe paths resolved to inodes
    /// and blessing class names mapped to their [`ClassId`]s. An exe that does not resolve
    /// is dropped with a warning, and the rule still applies to its other subjects.
    fn lower_subjects(&mut self, subjects: &[SubjectSpec], loc: &Loc) -> Vec<SubjectMatch> {
        let mut out = Vec::new();
        for s in subjects {
            match s {
                SubjectSpec::Any => out.push(SubjectMatch::ANY),
                SubjectSpec::Exe(path) => match (self.resolve_fileid)(path) {
                    Some(file) => out.push(SubjectMatch::exe(file)),
                    None => self.diagnostics.push(Diagnostic::warn(
                        loc.clone(),
                        format!(
                            "exe {} does not exist; this rule is not enforced for it",
                            path.display()
                        ),
                    )),
                },
                // `resolve` only emits a `Blessed` for a declared class, so the lookup
                // always hits. A miss is reported as an internal error rather than a panic
                // in the daemon.
                SubjectSpec::Blessed(name) => match self.classes.id(name) {
                    Some(id) => out.push(SubjectMatch::blessed(id)),
                    None => self.diagnostics.push(Diagnostic::error(
                        loc.clone(),
                        format!("internal: blessing class {name:?} is not in the registry"),
                    )),
                },
            }
        }
        out
    }

    /// Returns each object with its bucket, built by copy-down from its own rules and the
    /// rules of every protected ancestor, in first-match order and without duplicates.
    /// Adds an error diagnostic for a bucket over `MAX_RULES_PER_OBJ`.
    fn buckets(&mut self, objects: &[Object], own: &[Vec<ProvRule>]) -> Vec<CompiledObject> {
        let mut compiled = Vec::with_capacity(objects.len());
        for (obj, own_rules) in objects.iter().zip(own) {
            let mut bucket: Vec<ProvRule> = own_rules.clone();
            for (anc, anc_rules) in objects.iter().zip(own) {
                if anc.id != obj.id && paths::is_within(&obj.path, &anc.path) {
                    bucket.extend(anc_rules.iter().cloned());
                }
            }
            sort_bucket(&mut bucket);
            dedup_bucket(&mut bucket);

            if bucket.len() > MAX_RULES_PER_OBJ {
                self.diagnostics.push(Diagnostic::error(
                    Loc::default(),
                    format!(
                        "object {} compiles to {} rules, over the per-object limit of {} \
                         (split the policy or raise MAX_RULES_PER_OBJ)",
                        obj.path.display(),
                        bucket.len(),
                        MAX_RULES_PER_OBJ
                    ),
                ));
            }

            compiled.push(CompiledObject {
                id: obj.id,
                file: obj.file,
                path: obj.path.clone(),
                rules: bucket.into_iter().map(|pr| pr.rule).collect(),
            });
        }
        compiled
    }
}

/// Sorts a bucket into the kernel's first-match order (DESIGN §15.6), most specific
/// first: (1) the depth of the object the rule was authored on, (2) subject specificity
/// ([`subject_specificity`]), (3) a denying policy (`Policy::denies`) before a
/// non-denying one, the fail-safe tie-break among rules equal on (1) and (2). A stable
/// sort keeps authoring order within a precedence class, so compiles are deterministic.
fn sort_bucket(bucket: &mut [ProvRule]) {
    bucket.sort_by(|a, b| {
        // Keys (1) and (2) compare `b` with `a`, which sorts them descending, since
        // higher is more specific. Key (3) compares `a` with `b`, and `Polarity::Deny` is
        // declared first, so the ascending order puts it ahead.
        b.depth
            .cmp(&a.depth)
            .then_with(|| subject_specificity(b.rule).cmp(&subject_specificity(a.rule)))
            .then_with(|| polarity(a.rule).cmp(&polarity(b.rule)))
    });
}

/// A rule's subject specificity, as [`subject_specificity`] counts it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Specificity(u32);

/// Returns the number of subject predicates in `r` that are not wildcards (DESIGN §15.6
/// step 2). A higher count is more specific. Each concrete predicate, such as `exe` or
/// `blessing`, clears its wildcard bit and adds one, so a concrete subject outranks a
/// `who="*"` catch-all on the same object. A specific `allow` or `deny` therefore wins
/// over a broad `audit` or `deny`. The audit, admit and enforce flow (§15.10 flow A)
/// rests on this. An admitted `allow exe=X` goes silent while the `*` catch-all keeps
/// observing every program not yet admitted, and a blessing `allow` outranks the
/// catch-all the same way.
fn subject_specificity(r: CompiledRule) -> Specificity {
    // A rule's specificity is how many of all the subject predicates are not wildcards.
    let predicates = SubjectFlags::all();
    Specificity(
        predicates.bits().count_ones()
            - r.subject.flags.intersection(predicates).bits().count_ones(),
    )
}

/// Whether a rule allows or denies, which is the last key of [`sort_bucket`]. `Deny` is
/// declared first, so that the derived `Ord` sorts it ahead of `Allow`.
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

/// Removes later duplicates of an identical [`CompiledRule`] from `bucket`. The first
/// copy stays, because it has the highest precedence after [`sort_bucket`].
fn dedup_bucket(bucket: &mut Vec<ProvRule>) {
    // Buckets are small, so a linear scan is fine, and it avoids requiring `Hash` on the
    // POD types.
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

    /// Returns a fake resolver built from `(path, inode)` pairs on device 0. A path that
    /// is not listed resolves to `None`, as if it did not exist.
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

    /// Returns a single `[[rule]]` block built from TOML fields that are already quoted
    /// or bracketed.
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
        // allow {a,b,s} read /d, and deny s read /d/f. After copy-down, the bucket of
        // /d/f must deny s first but still allow a and b through the inherited rule.
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
        // The most specific rule, the deny on s, comes first.
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
        // deny {a,b,s} read /d, and allow s read /d/f. /d/f must allow s first and deny
        // the rest.
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
        // §15.10 flow A step 2: an admitted `allow exe=X` sorts ahead of a `who="*"`
        // audit catch-all. The catch-all is authored *first* to prove the order comes
        // from specificity, not insertion order.
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
        // Specificity ranks above the tie-break of deny over allow. `allow exe=X` sorts
        // ahead of the `who="*"` deny, so X is allowed while everyone else is denied.
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
    fn too_many_objects_is_an_error() {
        let paths: Vec<String> = (0..=MAX_OBJECTS).map(|i| format!("\"/o{i}\"")).collect();
        let text = rule(
            "\"*\"",
            &format!("[{}]", paths.join(",")),
            "\"read\"",
            "\"deny\"",
        );
        let resolved = resolve(&parse(&text).unwrap(), Path::new("/home/u")).unwrap();
        let mut ino = 0;
        let p = compile(&resolved, |_: &Path| {
            ino += 1;
            Some(FileId::new(Dev(0), Ino(ino)))
        });
        assert!(p.has_errors());
        assert!(
            p.diagnostics
                .iter()
                .any(|d| d.message.contains("over the limit of"))
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

    // ---- blessing (DESIGN §16.3) ----

    /// Duplicates collapse, ids follow name order from `UNBLESSED + 1`, and every id maps
    /// back to its name.
    #[test]
    fn class_registry_round_trips_ids() {
        let reg = ClassRegistry::new(["rw", "ro", "rw"].map(ClassName::new));
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.id(&ClassName::new("ro")), Some(ClassId(1)));
        assert_eq!(reg.id(&ClassName::new("rw")), Some(ClassId(2)));
        assert_eq!(reg.id(&ClassName::new("nope")), None);
        for (name, id) in reg.iter() {
            assert_eq!(reg.name(id), Some(name));
        }
        assert_eq!(reg.name(ClassId::UNBLESSED), None);
        assert_eq!(reg.name(ClassId(3)), None);
    }

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

        // The registry holds both declared classes, with ids in name order.
        let reg: std::collections::BTreeMap<_, _> = p
            .classes
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

    /// A blessing `allow` sorts ahead of a `who="*"` catch-all `deny` on the same object.
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
        // The first match is the most specific, so the blessed allow beats the wildcard
        // deny.
        let d = object(&p, "/d");
        assert_eq!(d.rules[0].policy, Policy::ALLOW, "{:?}", d.rules);
        assert_eq!(d.rules[0].subject, SubjectMatch::blessed(ClassId(1)));
    }
}
