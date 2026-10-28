//! Stage 2, which turns a [`ParsedPolicy`] into a [`ResolvedPolicy`] that has no groups
//! left and only valid names, but still names objects by path.
//!
//! A leaf means something different on each axis. A subject leaf is an exe path, and `*`
//! means any caller. An object leaf is a path, and `*` is rejected, because the whole
//! filesystem cannot be protected. An action leaf is a name from [`bpf::Action::NAMED`],
//! and `*` means all actions. Paths are `~`-expanded and normalized lexically here, and
//! [`super::compile`] resolves them to inodes.

use super::parse::{MemberGroup, ParsedPolicy, ParsedRule, RawLeaf, SubjectGroup, Token};
use super::{ClassName, GroupName, Loc, Pos, expand_path};
use crate::{Error, Result};
use cordon_bpf_common as bpf;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use toml::Spanned;

/// A subject after group expansion and before inode resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectSpec {
    /// A wildcard that matches every caller, as `who = "*"` writes it.
    Any,
    /// A concrete executable path, which [`super::compile`] resolves to a `(dev,ino)`.
    Exe(PathBuf),
    /// A caller in a blessed cgroup of this class, written as a `@<group>` reference to a
    /// `blessing = "<class>"` group (ADR 0012). [`super::compile`] maps the class
    /// name to a dense [`bpf::ClassId`].
    Blessed(ClassName),
}

/// One rule with all of its groups expanded. It applies `policy` to `actions` for every
/// pairing of its subjects and objects, which are still named by path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRule {
    pub subjects: Vec<SubjectSpec>,
    pub objects: Vec<PathBuf>,
    pub actions: bpf::Action,
    pub policy: bpf::Policy,
    /// The fragment that the rule came from. Resolve leaves it unset, and the merge in
    /// [`super::compile_fragments`] fills it in.
    pub source: Option<String>,
    /// The position of the rule in its fragment.
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

/// A policy with every group expanded and every name validated, which [`super::compile`]
/// consumes. It still names objects by path, and compile resolves them to inodes and
/// applies object precedence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub rules: Vec<ResolvedRule>,
    /// The blessing classes that this policy declares with a
    /// `[group.subject.*] blessing = "…"` predicate (ADR 0012). [`super::compile`]
    /// turns them into the [`ClassRegistry`](super::ClassRegistry). A class may be
    /// declared without any rule that references it, and it then grants nothing.
    pub blessing_classes: BTreeSet<ClassName>,
}

/// Resolves every rule of `parsed`, expanding `~` against `home`.
///
/// Errors on any of these, with a `line:col` prefix where the rule or group is known:
/// - a group cycle, or a `@ref` to an unknown group
/// - an unknown action name, or a path that is not absolute
/// - an axis that resolves to nothing
pub fn resolve(parsed: &ParsedPolicy, home: &Path) -> Result<ResolvedPolicy> {
    let blessing_classes = parsed
        .groups
        .subject
        .values()
        .filter_map(|g| match g.get_ref() {
            SubjectGroup::Blessing(class) => Some(class.clone()),
            SubjectGroup::Members(_) => None,
        })
        .collect();
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

/// One of a rule's three axes, each with its own group namespace.
#[derive(Clone, Copy, Debug)]
enum Axis {
    Subject,
    Object,
    Action,
}

/// A token after group expansion, with no `@ref` left. `B` is what a group can stand
/// for besides its members: a blessing class on the subject axis, and nothing on the
/// others.
enum Leaf<B> {
    Wildcard,
    Name(RawLeaf),
    Blessing(B),
}

/// What a `@ref` to a group expands to.
enum GroupBody<'g, B> {
    Members(&'g [Token]),
    /// A group that is one leaf rather than a member list.
    Blessing(&'g B),
}

/// A group definition as expansion sees it.
trait Group {
    type Blessing: Clone;
    fn body(&self) -> GroupBody<'_, Self::Blessing>;
}

impl Group for MemberGroup {
    type Blessing = Infallible;
    fn body(&self) -> GroupBody<'_, Infallible> {
        GroupBody::Members(&self.members)
    }
}

impl Group for SubjectGroup {
    type Blessing = ClassName;
    fn body(&self) -> GroupBody<'_, ClassName> {
        match self {
            SubjectGroup::Members(members) => GroupBody::Members(members),
            SubjectGroup::Blessing(class) => GroupBody::Blessing(class),
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
            policy: rule.policy,
            source: None,
            pos,
        })
    }

    fn subjects(&self, tokens: &[Token], pos: Pos) -> Result<Vec<SubjectSpec>> {
        let groups = &self.parsed.groups.subject;
        let mut out = Vec::new();
        for (leaf, _) in self.expand(Axis::Subject, groups, tokens, pos)? {
            let spec = match leaf {
                Leaf::Wildcard => SubjectSpec::Any,
                Leaf::Name(s) => SubjectSpec::Exe(expand_path(&s, self.home)?),
                Leaf::Blessing(class) => SubjectSpec::Blessed(class),
            };
            push_unique(&mut out, spec);
        }
        Ok(out)
    }

    fn objects(&self, tokens: &[Token], pos: Pos) -> Result<Vec<PathBuf>> {
        let groups = &self.parsed.groups.object;
        let mut out = Vec::new();
        for (leaf, p) in self.expand(Axis::Object, groups, tokens, pos)? {
            match leaf {
                Leaf::Wildcard => {
                    return Err(Error::at(
                        p,
                        "`where` cannot be `*` — the filesystem can't be default-denied wholesale",
                    ));
                }
                Leaf::Name(s) => push_unique(&mut out, expand_path(&s, self.home)?),
                Leaf::Blessing(never) => match never {},
            }
        }
        Ok(out)
    }

    fn actions(&self, tokens: &[Token], pos: Pos) -> Result<bpf::Action> {
        let groups = &self.parsed.groups.action;
        let mut mask = bpf::Action::empty();
        for (leaf, p) in self.expand(Axis::Action, groups, tokens, pos)? {
            match leaf {
                Leaf::Wildcard => mask |= bpf::Action::all(),
                Leaf::Name(s) => {
                    mask |= bpf::Action::from_authored(&s)
                        .ok_or_else(|| Error::at(p, format!("unknown action: {s:?}")))?;
                }
                Leaf::Blessing(never) => match never {},
            }
        }
        Ok(mask)
    }

    /// Returns `tokens` with every `@group` ref expanded against `groups`, the namespace
    /// of `axis`, each leaf paired with the position of its enclosing rule or group. A
    /// group that is a blessing class (ADR 0012) comes back as one
    /// [`Leaf::Blessing`]. Errors when the groups form a cycle or when a `@ref` names an
    /// unknown group.
    fn expand<G: Group>(
        &self,
        axis: Axis,
        groups: &BTreeMap<GroupName, Spanned<G>>,
        tokens: &[Token],
        enclosing: Pos,
    ) -> Result<Vec<(Leaf<G::Blessing>, Pos)>> {
        let mut out = Vec::new();
        self.expand_within(axis, groups, tokens, enclosing, &mut Vec::new(), &mut out)?;
        Ok(out)
    }

    /// Behaves like [`expand`](Self::expand), but inside the groups on `stack`, and
    /// appends to `out`. A reference back to any group on `stack` is a cycle.
    fn expand_within<G: Group>(
        &self,
        axis: Axis,
        groups: &BTreeMap<GroupName, Spanned<G>>,
        tokens: &[Token],
        enclosing: Pos,
        stack: &mut Vec<GroupName>,
        out: &mut Vec<(Leaf<G::Blessing>, Pos)>,
    ) -> Result<()> {
        for tok in tokens {
            let name = match tok {
                Token::Wildcard => {
                    out.push((Leaf::Wildcard, enclosing));
                    continue;
                }
                Token::Leaf(s) => {
                    out.push((Leaf::Name(s.clone()), enclosing));
                    continue;
                }
                Token::Group(name) => name,
            };
            let group_pos = |g: &Spanned<G>| self.parsed.lines.pos(g.span().start);
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
            match g.get_ref().body() {
                GroupBody::Blessing(b) => out.push((Leaf::Blessing(b.clone()), gpos)),
                GroupBody::Members(members) => {
                    stack.push(name.clone());
                    self.expand_within(axis, groups, members, gpos, stack, out)?;
                    stack.pop();
                }
            }
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

    /// Returns a single `[[rule]]` block built from four fields that are already quoted
    /// or bracketed.
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

    // ---- blessing (ADR 0012) ----

    /// A subject group with `blessing = "…"` declares a class. `@<group>` in `who`
    /// resolves to a blessing predicate rather than an exe, and the class is collected.
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

    /// A blessing class may be declared without any rule that references it. It still
    /// appears in the registry, and grants nothing until a rule names it.
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

    /// Two declarations of the same class collapse to one, and distinct classes come out
    /// sorted.
    #[test]
    fn blessing_classes_dedup_and_sort() {
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

    /// `blessing` is a subject predicate, so an object group that carries it is rejected.
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
        let err = format!("{:#}", parse(text).unwrap_err());
        assert!(err.contains("unknown field `blessing`"), "got: {err}");
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
        let err = format!("{:#}", parse(text).unwrap_err());
        assert!(err.contains("unknown field `blessing`"), "got: {err}");
    }

    /// A blessing group cannot also carry `members`, because it declares only the class.
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
        let err = format!("{:#}", parse(text).unwrap_err());
        assert!(err.contains("not both"), "got: {err}");
    }

    /// A blessing group lives in the subject namespace, so a reference from `where`, the
    /// object axis, cannot reach it. Namespace separation rejects the misuse as an unknown
    /// object group, the same way it catches any cross-namespace `@ref`.
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
