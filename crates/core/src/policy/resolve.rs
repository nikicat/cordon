//! Stage 2 — resolve a [`ParsedPolicy`] into a group-free, name-validated, but still
//! **path-based** [`ResolvedPolicy`].
//!
//! Per axis (subject/object/action) we recursively expand `@group` refs (cycle-checked
//! against a path stack), then interpret each leaf in that axis's terms: a subject leaf
//! is an exe path (or `*` → any), an object leaf is a path (`*` is rejected — you can't
//! protect the whole filesystem, DESIGN §15.6.4), an action leaf is one of the nine
//! names (`*` → all). Paths get `~`-expanded and lexically normalized here; inode
//! resolution is deferred to [`super::compile`].

use super::parse::{GroupDef, ParsedPolicy, Token};
use super::{ActionName, Mode, Pos, expand_path};
use crate::{Error, Result};
use cordon_bpf_common as bpf;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use toml::Spanned;

/// A subject after group expansion, before inode resolution (M1: exe or wildcard;
/// M2 extends to conjunctive predicates — DESIGN §15.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectSpec {
    /// `who = "*"` — any caller.
    Any,
    /// A concrete executable path, resolved to a `(dev,ino)` by [`super::compile`].
    Exe(PathBuf),
}

/// One rule with all groups expanded: a cross-product of `subjects × objects`, each
/// covering `actions`, with effect `policy`. Object/exe paths are still paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRule {
    pub subjects: Vec<SubjectSpec>,
    pub objects: Vec<PathBuf>,
    pub actions: bpf::Action,
    pub policy: bpf::Policy,
    /// Source position of the originating `[[rule]]`, for diagnostics.
    pub pos: Option<Pos>,
}

/// A fully group-expanded, name-validated policy. Still path-based; [`super::compile`]
/// resolves paths to inode identity and applies object precedence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub mode: Mode,
    pub rules: Vec<ResolvedRule>,
}

/// Resolve every rule. Hard-errors (with a `line:col` prefix) on a cycle, an unknown
/// `@ref`, a bad action name, a non-absolute path, or an empty axis — the policy is
/// structurally unusable until fixed.
pub fn resolve(parsed: &ParsedPolicy, home: &Path) -> Result<ResolvedPolicy> {
    let mut rules = Vec::with_capacity(parsed.rules.len());
    for spanned in &parsed.rules {
        let pos = parsed.lines.pos(spanned.span().start);
        let rule = spanned.get_ref();

        let subjects = resolve_subjects(&rule.who.classified(), parsed, home, pos)?;
        let objects = resolve_objects(&rule.where_.classified(), parsed, home, pos)?;
        let actions = resolve_actions(&rule.action.classified(), parsed, pos)?;

        if subjects.is_empty() {
            return Err(at(pos, "rule `who` resolves to nothing"));
        }
        if objects.is_empty() {
            return Err(at(pos, "rule `where` resolves to nothing"));
        }
        if actions.is_empty() {
            return Err(at(pos, "rule `action` resolves to no actions"));
        }

        rules.push(ResolvedRule {
            subjects,
            objects,
            actions,
            policy: rule.policy.lower(),
            pos: Some(pos),
        });
    }
    Ok(ResolvedPolicy {
        mode: parsed.mode,
        rules,
    })
}

fn resolve_subjects(
    tokens: &[Token],
    parsed: &ParsedPolicy,
    home: &Path,
    pos: Pos,
) -> Result<Vec<SubjectSpec>> {
    let mut out = Vec::new();
    let mut stack = Vec::new();
    expand_axis(
        tokens,
        &parsed.groups.subject,
        "subject",
        parsed,
        pos,
        &mut stack,
        &mut |tok, _p| -> Result<()> {
            match tok {
                Token::Wildcard => push_unique(&mut out, SubjectSpec::Any),
                Token::Leaf(s) => push_unique(&mut out, SubjectSpec::Exe(expand_path(s, home)?)),
                Token::Group(_) => unreachable!("group tokens are consumed by expand_axis"),
            }
            Ok(())
        },
    )?;
    Ok(out)
}

fn resolve_objects(
    tokens: &[Token],
    parsed: &ParsedPolicy,
    home: &Path,
    pos: Pos,
) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = Vec::new();
    expand_axis(
        tokens,
        &parsed.groups.object,
        "object",
        parsed,
        pos,
        &mut stack,
        &mut |tok, p| -> Result<()> {
            match tok {
                Token::Wildcard => Err(at(
                    p,
                    "`where` cannot be `*` — the filesystem can't be default-denied wholesale",
                )),
                Token::Leaf(s) => {
                    push_unique(&mut out, expand_path(s, home)?);
                    Ok(())
                }
                Token::Group(_) => unreachable!("group tokens are consumed by expand_axis"),
            }
        },
    )?;
    Ok(out)
}

fn resolve_actions(tokens: &[Token], parsed: &ParsedPolicy, pos: Pos) -> Result<bpf::Action> {
    let mut mask = bpf::Action::empty();
    let mut stack = Vec::new();
    expand_axis(
        tokens,
        &parsed.groups.action,
        "action",
        parsed,
        pos,
        &mut stack,
        &mut |tok, p| -> Result<()> {
            match tok {
                Token::Wildcard => mask |= bpf::Action::all(),
                Token::Leaf(s) => {
                    let name = ActionName::parse(s)
                        .ok_or_else(|| at(p, format!("unknown action: {s:?}")))?;
                    mask |= name.bit();
                }
                Token::Group(_) => unreachable!("group tokens are consumed by expand_axis"),
            }
            Ok(())
        },
    )?;
    Ok(mask)
}

/// Recursively expand a token list for one axis. `@group` refs recurse (cycle-checked
/// against `stack` of group names); every non-group token is handed to `leaf` with the
/// position of its enclosing rule/group, for axis-specific interpretation.
fn expand_axis<F>(
    tokens: &[Token],
    groups: &BTreeMap<String, Spanned<GroupDef>>,
    axis: &str,
    parsed: &ParsedPolicy,
    enclosing: Pos,
    stack: &mut Vec<String>,
    leaf: &mut F,
) -> Result<()>
where
    F: FnMut(&Token, Pos) -> Result<()>,
{
    for tok in tokens {
        match tok {
            Token::Group(name) => {
                if stack.iter().any(|s| s == name) {
                    let chain = stack.join(" -> @");
                    let gpos = groups
                        .get(name)
                        .map(|g| parsed.lines.pos(g.span().start))
                        .unwrap_or(enclosing);
                    return Err(at(gpos, format!("{axis} group cycle: @{chain} -> @{name}")));
                }
                let g = groups
                    .get(name)
                    .ok_or_else(|| at(enclosing, format!("unknown {axis} group: @{name}")))?;
                let gpos = parsed.lines.pos(g.span().start);
                stack.push(name.clone());
                expand_axis(
                    &g.get_ref().classified(),
                    groups,
                    axis,
                    parsed,
                    gpos,
                    stack,
                    leaf,
                )?;
                stack.pop();
            }
            other => leaf(other, enclosing)?,
        }
    }
    Ok(())
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

/// An error with a `line:col` prefix.
fn at(pos: Pos, msg: impl AsRef<str>) -> Error {
    Error::msg(format!("{pos}: {}", msg.as_ref()))
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
}
