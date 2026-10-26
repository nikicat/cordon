//! Stage 2 — resolve a [`ParsedPolicy`] into a group-free, name-validated, but still
//! **path-based** [`ResolvedPolicy`].
//!
//! Per axis (subject/object/action) we recursively expand `@group` refs (cycle-checked
//! against a path stack), then interpret each leaf in that axis's terms: a subject leaf
//! is an exe path (or `*` → any), an object leaf is a path (`*` is rejected — you can't
//! protect the whole filesystem), an action leaf is an [`ActionName`] (`*` → all). Paths
//! get `~`-expanded and lexically normalized here; inode resolution is deferred to
//! [`super::compile`].

use super::parse::{GroupDef, Groups, ParsedPolicy, ParsedRule, Token};
use super::{ActionName, ClassName, GroupName, Loc, Pos, expand_path};
use crate::{Error, Result};
use cordon_bpf_common as bpf;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use toml::Spanned;

/// A subject after group expansion, before inode resolution (M1: exe, wildcard, or a
/// blessing class; M2 extends to conjunctive predicates — DESIGN §15.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectSpec {
    /// `who = "*"` — any caller.
    Any,
    /// A concrete executable path, resolved to a `(dev,ino)` by [`super::compile`].
    Exe(PathBuf),
    /// `@<group>` where the group declares `blessing = "<class>"` (DESIGN §16.3) — matches a
    /// caller in a blessed cgroup of that class. [`super::compile`] maps the class name to a
    /// dense [`bpf::ClassId`].
    Blessed(ClassName),
}

/// One rule with all groups expanded: a cross-product of `subjects × objects`, each
/// covering `actions`, with effect `policy`. Object/exe paths are still paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRule {
    pub subjects: Vec<SubjectSpec>,
    pub objects: Vec<PathBuf>,
    pub actions: bpf::Action,
    pub policy: bpf::Policy,
    /// The fragment the rule came from. Resolve leaves it unset; the merge in
    /// [`super::compile_fragments`] names it.
    pub source: Option<String>,
    /// The originating `[[rule]]`'s position in its fragment.
    pub pos: Pos,
}

impl ResolvedRule {
    /// Returns where the rule was written, for a diagnostic about it.
    pub fn loc(&self) -> Loc {
        Loc {
            source: self.source.clone(),
            pos: Some(self.pos),
        }
    }
}

/// A fully group-expanded, name-validated policy. Still path-based; [`super::compile`]
/// resolves paths to inode identity and applies object precedence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub rules: Vec<ResolvedRule>,
    /// The blessing classes this policy **declares** (a `[group.subject.*] blessing = "…"`
    /// predicate, DESIGN §16.3). [`super::compile`] turns them into the
    /// [`ClassRegistry`](super::ClassRegistry). A class may be declared without a rule
    /// referencing it; it then grants nothing.
    pub blessing_classes: BTreeSet<ClassName>,
}

/// Resolve every rule. Hard-errors (with a `line:col` prefix) on a cycle, an unknown
/// `@ref`, a bad action name, a non-absolute path, an empty axis, or a misplaced/ambiguous
/// `blessing` group — the policy is structurally unusable until fixed.
pub fn resolve(parsed: &ParsedPolicy, home: &Path) -> Result<ResolvedPolicy> {
    let blessing_classes = declared_classes(&parsed.groups)?;
    let resolver = Resolver { parsed, home };
    let rules = parsed
        .rules
        .iter()
        .map(|rule| resolver.rule(rule))
        .collect::<Result<_>>()?;
    Ok(ResolvedPolicy {
        rules,
        blessing_classes,
    })
}

/// Collect the declared blessing classes (DESIGN §16.3) and validate the `blessing` predicate
/// is well-placed: it lives only on a **subject** group, and is mutually exclusive with
/// `members`. Returns the distinct class names.
fn declared_classes(groups: &Groups) -> Result<BTreeSet<ClassName>> {
    // `blessing` is a subject predicate — reject it in the object/action namespaces.
    for axis in [Axis::Object, Axis::Action] {
        if let Some(name) = axis
            .groups(groups)
            .iter()
            .find(|(_, g)| g.get_ref().blessing.is_some())
            .map(|(name, _)| name)
        {
            return Err(Error::msg(format!(
                "group @{name} in the {axis} namespace has a `blessing` predicate, which is \
                 only valid on a subject group"
            )));
        }
    }
    let mut classes = BTreeSet::new();
    for (name, g) in &groups.subject {
        if let Some(class) = &g.get_ref().blessing {
            if !g.get_ref().members.is_empty() {
                return Err(Error::msg(format!(
                    "subject group @{name} mixes a `blessing` predicate with `members` — a \
                     blessing class group declares only `blessing`"
                )));
            }
            classes.insert(class.clone());
        }
    }
    Ok(classes)
}

/// One of a rule's three axes, each with its own group namespace.
#[derive(Clone, Copy, Debug)]
enum Axis {
    Subject,
    Object,
    Action,
}

impl Axis {
    /// Returns this axis's group namespace.
    fn groups(self, groups: &Groups) -> &BTreeMap<GroupName, Spanned<GroupDef>> {
        match self {
            Axis::Subject => &groups.subject,
            Axis::Object => &groups.object,
            Axis::Action => &groups.action,
        }
    }
}

impl std::fmt::Display for Axis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Axis::Subject => "subject",
            Axis::Object => "object",
            Axis::Action => "action",
        })
    }
}

/// Resolves the rules of one parsed policy, expanding `~` against `home`.
struct Resolver<'a> {
    parsed: &'a ParsedPolicy,
    home: &'a Path,
}

impl Resolver<'_> {
    fn rule(&self, rule: &ParsedRule) -> Result<ResolvedRule> {
        let pos = rule.pos;
        let subjects = self.subjects(&rule.who, pos)?;
        let objects = self.objects(&rule.where_, pos)?;
        let actions = self.actions(&rule.action, pos)?;

        if subjects.is_empty() {
            return Err(Error::at(pos, "rule `who` resolves to nothing"));
        }
        if objects.is_empty() {
            return Err(Error::at(pos, "rule `where` resolves to nothing"));
        }
        if actions.is_empty() {
            return Err(Error::at(pos, "rule `action` resolves to no actions"));
        }
        Ok(ResolvedRule {
            subjects,
            objects,
            actions,
            policy: rule.policy.lower(),
            source: None,
            pos,
        })
    }

    fn subjects(&self, tokens: &[Token], pos: Pos) -> Result<Vec<SubjectSpec>> {
        let mut out = Vec::new();
        self.expand(Axis::Subject, tokens, pos, &mut |tok, _p| {
            match tok {
                Token::Wildcard => push_unique(&mut out, SubjectSpec::Any),
                Token::Leaf(s) => {
                    push_unique(&mut out, SubjectSpec::Exe(expand_path(s, self.home)?))
                }
                Token::Blessing(class) => {
                    push_unique(&mut out, SubjectSpec::Blessed(class.clone()))
                }
                Token::Group(_) => unreachable!("group tokens are consumed by expand"),
            }
            Ok(())
        })?;
        Ok(out)
    }

    fn objects(&self, tokens: &[Token], pos: Pos) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        self.expand(Axis::Object, tokens, pos, &mut |tok, p| match tok {
            Token::Wildcard => Err(Error::at(
                p,
                "`where` cannot be `*` — the filesystem can't be default-denied wholesale",
            )),
            Token::Leaf(s) => {
                push_unique(&mut out, expand_path(s, self.home)?);
                Ok(())
            }
            Token::Blessing(_) => Err(Error::at(
                p,
                "a blessing group is a subject predicate; it can't appear in `where`",
            )),
            Token::Group(_) => unreachable!("group tokens are consumed by expand"),
        })?;
        Ok(out)
    }

    fn actions(&self, tokens: &[Token], pos: Pos) -> Result<bpf::Action> {
        let mut mask = bpf::Action::empty();
        self.expand(Axis::Action, tokens, pos, &mut |tok, p| {
            match tok {
                Token::Wildcard => mask |= bpf::Action::all(),
                Token::Leaf(s) => {
                    let name = ActionName::parse(s)
                        .ok_or_else(|| Error::at(p, format!("unknown action: {s:?}")))?;
                    mask |= name.bit();
                }
                Token::Blessing(_) => {
                    return Err(Error::at(
                        p,
                        "a blessing group is a subject predicate; it can't appear in `action`",
                    ));
                }
                Token::Group(_) => unreachable!("group tokens are consumed by expand"),
            }
            Ok(())
        })?;
        Ok(mask)
    }

    /// Expands `@group` refs in `tokens` and hands every other token to `leaf`, with the
    /// position of its enclosing rule or group. A `@ref` to a `blessing = "…"` group
    /// (DESIGN §16.3) is a leaf, not a member list: `leaf` gets a [`Token::Blessing`],
    /// which the subject axis accepts and the others reject. Errors on a cycle or an
    /// unknown group.
    fn expand(
        &self,
        axis: Axis,
        tokens: &[Token],
        enclosing: Pos,
        leaf: &mut dyn FnMut(&Token, Pos) -> Result<()>,
    ) -> Result<()> {
        self.expand_within(axis, tokens, enclosing, &mut Vec::new(), leaf)
    }

    /// [`expand`](Self::expand) inside the groups on `stack`, which a ref back into is a
    /// cycle.
    fn expand_within(
        &self,
        axis: Axis,
        tokens: &[Token],
        enclosing: Pos,
        stack: &mut Vec<GroupName>,
        leaf: &mut dyn FnMut(&Token, Pos) -> Result<()>,
    ) -> Result<()> {
        let groups = axis.groups(&self.parsed.groups);
        for tok in tokens {
            let Token::Group(name) = tok else {
                leaf(tok, enclosing)?;
                continue;
            };
            let group_pos = |g: &Spanned<GroupDef>| self.parsed.lines.pos(g.span().start);
            if stack.contains(name) {
                let chain = stack
                    .iter()
                    .map(GroupName::as_str)
                    .collect::<Vec<_>>()
                    .join(" -> @");
                let gpos = groups.get(name).map(group_pos).unwrap_or(enclosing);
                return Err(Error::at(
                    gpos,
                    format!("{axis} group cycle: @{chain} -> @{name}"),
                ));
            }
            let g = groups
                .get(name)
                .ok_or_else(|| Error::at(enclosing, format!("unknown {axis} group: @{name}")))?;
            let gpos = group_pos(g);
            // A blessing-class group is a subject predicate, not a member list: emit a
            // synthesized `Blessing` leaf and don't recurse (it has no members).
            if let Some(class) = &g.get_ref().blessing {
                leaf(&Token::Blessing(class.clone()), gpos)?;
                continue;
            }
            stack.push(name.clone());
            self.expand_within(axis, &g.get_ref().members, gpos, stack, leaf)?;
            stack.pop();
        }
        Ok(())
    }
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse;

    fn resolve_text(text: &str) -> Result<ResolvedPolicy> {
        resolve(&parse(text).unwrap(), Path::new("/home/u"))
    }

    /// A single `[[rule]]` block from its four already-quoted/-bracketed fields.
    fn rule(who: &str, where_: &str, action: &str, policy: &str) -> String {
        format!("[[rule]]\nwho = {who}\nwhere = {where_}\naction = {action}\npolicy = {policy}\n")
    }

    #[test]
    fn expands_nested_groups_on_all_axes() {
        let text = r#"
            [group.subject.base]
            members = ["/usr/bin/ssh"]
            [group.subject.tools]
            members = ["@base", "/usr/bin/scp"]
            [group.object.creds]
            members = ["~/.aws", "~/.ssh"]
            [group.action.ro]
            members = ["read", "listdir"]

            [[rule]]
            who = "@tools"
            where = "@creds"
            action = "@ro"
            policy = "allow"
        "#;
        let r = resolve_text(text).unwrap();
        assert_eq!(r.rules.len(), 1);
        let rule = &r.rules[0];
        assert_eq!(
            rule.subjects,
            vec![
                SubjectSpec::Exe(PathBuf::from("/usr/bin/ssh")),
                SubjectSpec::Exe(PathBuf::from("/usr/bin/scp")),
            ]
        );
        assert_eq!(
            rule.objects,
            vec![PathBuf::from("/home/u/.aws"), PathBuf::from("/home/u/.ssh")]
        );
        assert_eq!(rule.actions, bpf::Action::READ | bpf::Action::LISTDIR);
        assert_eq!(rule.policy, bpf::Policy::ALLOW);
    }

    #[test]
    fn wildcards() {
        let r = resolve_text(&rule("\"*\"", "\"/x\"", "\"*\"", "\"deny\"")).unwrap();
        assert_eq!(r.rules[0].subjects, vec![SubjectSpec::Any]);
        assert_eq!(r.rules[0].actions, bpf::Action::all());
    }

    #[test]
    fn multi_value_fields() {
        let r = resolve_text(&rule(
            r#"["/a","/b"]"#,
            r#"["/x","/y"]"#,
            r#"["read","write"]"#,
            "\"allow\"",
        ))
        .unwrap();
        assert_eq!(r.rules[0].subjects.len(), 2);
        assert_eq!(r.rules[0].objects.len(), 2);
        assert_eq!(r.rules[0].actions, bpf::Action::READ | bpf::Action::WRITE);
    }

    #[test]
    fn rejects_cycle() {
        let text = r#"
            [group.subject.a]
            members = ["@b"]
            [group.subject.b]
            members = ["@a"]
            [[rule]]
            who = "@a"
            where = "/x"
            action = "read"
            policy = "allow"
        "#;
        let err = format!("{}", resolve_text(text).unwrap_err());
        assert!(err.contains("cycle"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_ref() {
        let err = format!(
            "{}",
            resolve_text(&rule("\"@ghost\"", "\"/x\"", "\"read\"", "\"allow\"")).unwrap_err()
        );
        assert!(err.contains("unknown subject group: @ghost"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_action() {
        let err = format!(
            "{}",
            resolve_text(&rule("\"*\"", "\"/x\"", "\"frobnicate\"", "\"allow\"")).unwrap_err()
        );
        assert!(err.contains("unknown action"), "got: {err}");
    }

    #[test]
    fn rejects_wildcard_object() {
        let err = format!(
            "{}",
            resolve_text(&rule("\"*\"", "\"*\"", "\"read\"", "\"allow\"")).unwrap_err()
        );
        assert!(err.contains("cannot be `*`"), "got: {err}");
    }

    #[test]
    fn rejects_relative_path() {
        let err = format!(
            "{}",
            resolve_text(&rule("\"*\"", "\"relative/dir\"", "\"read\"", "\"allow\"")).unwrap_err()
        );
        assert!(err.contains("absolute or ~-relative"), "got: {err}");
    }

    #[test]
    fn dedups_repeated_subjects() {
        let text = r#"
            [group.subject.a]
            members = ["/usr/bin/ssh"]
            [group.subject.b]
            members = ["/usr/bin/ssh", "@a"]
            [[rule]]
            who = "@b"
            where = "/x"
            action = "read"
            policy = "allow"
        "#;
        let r = resolve_text(text).unwrap();
        assert_eq!(
            r.rules[0].subjects,
            vec![SubjectSpec::Exe(PathBuf::from("/usr/bin/ssh"))]
        );
    }

    // ---- blessing (DESIGN §16.3 / PLAN-bless B1c) ----

    /// A subject group with `blessing = "…"` is a class declaration: `@<group>` in `who`
    /// resolves to a blessing predicate (not an exe), and the class is collected.
    #[test]
    fn blessing_group_resolves_to_predicate() {
        let text = r#"
            [group.subject.blessed-ro]
            blessing = "ro"
            [[rule]]
            who = "@blessed-ro"
            where = "/x"
            action = "read"
            policy = "allow"
        "#;
        let r = resolve_text(text).unwrap();
        assert_eq!(
            r.rules[0].subjects,
            vec![SubjectSpec::Blessed(ClassName::new("ro"))]
        );
        assert_eq!(r.blessing_classes, BTreeSet::from([ClassName::new("ro")]));
    }

    /// A blessing class may be declared without any rule referencing it — it still appears
    /// in the registry (it grants nothing until a rule names it).
    #[test]
    fn declared_class_without_a_rule_is_collected() {
        let text = r#"
            [group.subject.blessed-rw]
            blessing = "rw"
            [[rule]]
            who = "*"
            where = "/x"
            action = "read"
            policy = "deny"
        "#;
        let r = resolve_text(text).unwrap();
        assert_eq!(r.rules[0].subjects, vec![SubjectSpec::Any]);
        assert_eq!(r.blessing_classes, BTreeSet::from([ClassName::new("rw")]));
    }

    /// Two declarations of the same class collapse to one; distinct classes are sorted.
    #[test]
    fn declared_classes_dedup_and_sort() {
        let text = r#"
            [group.subject.a]
            blessing = "rw"
            [group.subject.b]
            blessing = "ro"
            [group.subject.c]
            blessing = "rw"
            [[rule]]
            who = "@a"
            where = "/x"
            action = "read"
            policy = "allow"
        "#;
        let r = resolve_text(text).unwrap();
        assert_eq!(
            r.blessing_classes,
            BTreeSet::from([ClassName::new("ro"), ClassName::new("rw")])
        );
    }

    /// `blessing` is a subject predicate — placing it on an object group is rejected.
    #[test]
    fn rejects_blessing_on_object_group() {
        let text = r#"
            [group.object.bad]
            blessing = "ro"
            [[rule]]
            who = "*"
            where = "@bad"
            action = "read"
            policy = "allow"
        "#;
        let err = format!("{}", resolve_text(text).unwrap_err());
        assert!(err.contains("only valid on a subject group"), "got: {err}");
    }

    /// …and on an action group.
    #[test]
    fn rejects_blessing_on_action_group() {
        let text = r#"
            [group.action.bad]
            blessing = "ro"
            [[rule]]
            who = "*"
            where = "/x"
            action = "@bad"
            policy = "allow"
        "#;
        let err = format!("{}", resolve_text(text).unwrap_err());
        assert!(err.contains("only valid on a subject group"), "got: {err}");
    }

    /// A blessing group can't also carry `members` — it declares only the class.
    #[test]
    fn rejects_blessing_mixed_with_members() {
        let text = r#"
            [group.subject.bad]
            blessing = "ro"
            members = ["/usr/bin/cat"]
            [[rule]]
            who = "@bad"
            where = "/x"
            action = "read"
            policy = "allow"
        "#;
        let err = format!("{}", resolve_text(text).unwrap_err());
        assert!(
            err.contains("mixes a `blessing` predicate with `members`"),
            "got: {err}"
        );
    }

    /// A blessing group lives in the **subject** namespace, so referencing it from `where`
    /// (the object axis) can't reach it — namespace separation rejects the misuse as an
    /// unknown object group, the same way any cross-namespace `@ref` is caught.
    #[test]
    fn blessing_group_cannot_appear_in_where() {
        let text = r#"
            [group.subject.b]
            blessing = "ro"
            [[rule]]
            who = "*"
            where = "@b"
            action = "read"
            policy = "allow"
        "#;
        let err = format!("{}", resolve_text(text).unwrap_err());
        assert!(err.contains("unknown object group: @b"), "got: {err}");
    }
}
