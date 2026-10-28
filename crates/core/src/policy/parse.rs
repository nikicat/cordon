//! Stage 1, which turns TOML text into a structurally valid policy that keeps its source
//! spans.
//!
//! Serde with `#[serde(deny_unknown_fields)]` does the structural validation, so a
//! misspelled key or a bad enum value fails here with `toml`'s own line and column. Each
//! rule and group is wrapped in [`toml::Spanned`], so that later stages can point a
//! diagnostic at its source line. Semantic validation, such as `@ref` resolution, cycles
//! and paths, belongs to [`super::resolve`].

use super::{ClassName, GroupName, LineIndex, Pos, UserName, parse_policy};
use crate::{Context, Error, Result};
use cordon_bpf_common as bpf;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use toml::Spanned;

/// A policy that is parsed but not yet resolved, which [`super::resolve`] consumes. It
/// keeps a line index because the resolver still needs it for group positions.
///
/// Both authoring forms end up here. The verbose `[[rule]]` tables and the compact
/// `rules = '''…'''` DSL block ([`super::ruleline`]) normalize to the same `ParsedRule`,
/// so nothing after parse depends on the syntax.
#[derive(Debug)]
pub struct ParsedPolicy {
    pub(crate) groups: Groups,
    pub(crate) rules: Vec<ParsedRule>,
    pub(crate) lines: LineIndex,
    /// The optional `user = "name"` header. It lets a root-owned, per-user policy file
    /// write `~` instead of `/home/<name>` (DESIGN §15.8), and [`super::home_for`] turns
    /// it into the home that `~` expands to.
    pub(crate) user: Option<UserName>,
    /// The user-tier files that this system fragment pulls in with `[[include]]`
    /// (DESIGN §15.8). [`super::PolicyRoot::load`] reads them, not the parser.
    pub(crate) includes: Vec<Include>,
}

impl ParsedPolicy {
    /// Returns the `user =` header, if the policy declared one.
    pub fn user(&self) -> Option<&UserName> {
        self.user.as_ref()
    }

    /// Returns the `[[include]]` directives of this fragment. Most fragments have none.
    pub fn includes(&self) -> &[Include] {
        &self.includes
    }
}

/// One `[[include]]` directive, by which a system fragment pulls in a user-tier policy
/// file (DESIGN §15.8). [`super::PolicyRoot::load`] reads the file as a
/// [`super::SourceOrigin::User`] fragment.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Include {
    user: UserName,
    path: PathBuf,
}

impl Include {
    /// Returns the include of `path` for `user`. Errors when `path` is not absolute, because
    /// the CLI and the daemon would otherwise resolve it against different directories.
    pub fn new(user: UserName, path: PathBuf) -> Result<Include> {
        if !path.is_absolute() {
            return Err(Error::msg(format!(
                "an `[[include]]` path must be absolute: {}",
                path.display()
            )));
        }
        Ok(Include { user, path })
    }

    pub fn user(&self) -> &UserName {
        &self.user
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns this include as a TOML `[[include]]` table, which [`parse`] reads back.
    /// Errors when the path is not valid UTF-8, which TOML cannot hold.
    pub fn to_toml(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Table<'a> {
            include: [&'a Include; 1],
        }
        toml::to_string(&Table { include: [self] })
            .with_context(|| format!("render the include of {}", self.path.display()))
    }
}

/// One rule, normalized from either authoring form so that resolve handles both alike.
#[derive(Debug)]
pub(crate) struct ParsedRule {
    pub(crate) who: Vec<Token>,
    pub(crate) where_: Vec<Token>,
    pub(crate) action: Vec<Token>,
    pub(crate) policy: bpf::Policy,
    /// The rule's source position for diagnostics, which is its `[[rule]]` header or the
    /// first field of its DSL line.
    pub(crate) pos: Pos,
}

/// The top-level TOML shape of a policy, as serde reads it before normalization.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    /// The `user` header ([`ParsedPolicy::user`]). Like `rules`, it is a top-level key,
    /// so it must come before any `[group.*]` header.
    #[serde(default)]
    user: Option<UserName>,
    #[serde(default)]
    group: Groups,
    #[serde(default, rename = "rule")]
    blocks: Vec<Spanned<RuleDef>>,
    /// The compact rule DSL, with one `POLICY SUBJECT ACTION OBJECT` rule per line. It is
    /// a TOML literal (`'''…'''`) string, so paths keep their backslashes and the DSL's
    /// own `"…"` quoting is not subject to TOML's escape processing. Its content is also a
    /// verbatim slice of the source, so byte offsets in it map straight to file
    /// positions. It must come before any `[group.*]` header, because a bare top-level
    /// key otherwise binds to the last table.
    #[serde(default)]
    rules: Option<Spanned<String>>,
    /// The `[[include]]` tables, which name the user-tier files that this system
    /// fragment pulls in (DESIGN §15.8).
    #[serde(default, rename = "include")]
    includes: Vec<Spanned<Include>>,
}

/// The three group namespaces (DESIGN §15.7), each mapping a group name to its
/// definition.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Groups {
    #[serde(default)]
    pub(crate) subject: BTreeMap<GroupName, Spanned<SubjectGroup>>,
    #[serde(default)]
    pub(crate) object: BTreeMap<GroupName, Spanned<MemberGroup>>,
    #[serde(default)]
    pub(crate) action: BTreeMap<GroupName, Spanned<MemberGroup>>,
}

/// A named object or action group. Its member tokens (`@ref`, `*` or a leaf) follow the
/// same grammar as a rule field, so groups nest.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberGroup {
    #[serde(default)]
    pub(crate) members: Vec<Token>,
}

/// A named subject group: a list of members, as a [`MemberGroup`] has, or a single
/// `blessing = "<class>"` predicate (DESIGN §16.3), which declares a blessing class that
/// rules reference as `@<group>`. The other conjunctive subject predicates
/// (`exe = … argv0 = …`, DESIGN §15.4) are not implemented, so they are rejected as
/// unknown fields.
#[derive(Deserialize, Debug)]
#[serde(try_from = "RawSubjectGroup")]
pub(crate) enum SubjectGroup {
    Members(Vec<Token>),
    Blessing(ClassName),
}

/// A subject group as written, before [`SubjectGroup`] picks its form.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubjectGroup {
    #[serde(default)]
    members: Option<Vec<Token>>,
    #[serde(default)]
    blessing: Option<ClassName>,
}

impl TryFrom<RawSubjectGroup> for SubjectGroup {
    type Error = &'static str;

    fn try_from(raw: RawSubjectGroup) -> std::result::Result<SubjectGroup, Self::Error> {
        match (raw.members, raw.blessing) {
            (members, None) => Ok(SubjectGroup::Members(members.unwrap_or_default())),
            (None, Some(class)) => Ok(SubjectGroup::Blessing(class)),
            (Some(_), Some(_)) => Err(
                "a subject group has `members` or a `blessing` predicate, not both — a \
                 blessing class group declares only `blessing`",
            ),
        }
    }
}

/// One `[[rule]]` table. Each of `who`, `where` and `action` is a single token or a list
/// of them, and serde rejects any `policy` but the four effects.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleDef {
    pub(crate) who: OneOrMany,
    #[serde(rename = "where")]
    pub(crate) where_: OneOrMany,
    pub(crate) action: OneOrMany,
    #[serde(deserialize_with = "authored_policy")]
    pub(crate) policy: bpf::Policy,
}

fn authored_policy<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<bpf::Policy, D::Error> {
    let name = String::deserialize(d)?;
    parse_policy(&name).map_err(serde::de::Error::custom)
}

/// A rule field, written as a bare value or as a list. It is not `Spanned`, because
/// `toml::Spanned` does not survive `#[serde(untagged)]`, which buffers the input. So a
/// position exists for each rule and group, but not for each token.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum OneOrMany {
    One(Token),
    Many(Vec<Token>),
}

impl From<OneOrMany> for Vec<Token> {
    fn from(field: OneOrMany) -> Vec<Token> {
        match field {
            OneOrMany::One(t) => vec![t],
            OneOrMany::Many(v) => v,
        }
    }
}

/// The text of a leaf token, which is an exe path, an object path or an action name.
/// [`super::resolve`] decides which one on each axis, and turns it into a `PathBuf` or a
/// [`bpf::Action`]. It is an alias rather than a newtype because every string is a valid
/// leaf at this lexical layer.
pub(crate) type RawLeaf = String;

/// A single token, classified by its lexical form alone, the same way on every axis. The
/// meaning of a [`Token::Leaf`] depends on the axis, where it is an exe path, an object
/// path or an action name. [`super::resolve`] interprets it, because resolve holds the
/// home directory for `~` and the action vocabulary. The split keeps the one classifier
/// of `@ref`, `*` and leaf in a single place, and leaves the meaning where its context
/// lives.
///
/// A token whose first character is `@` is always a group reference. So an exe or object
/// whose leading component is literally `@name` cannot be named. That limit is
/// acceptable, just as treating `*` as the wildcard is.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    /// The `*` wildcard. It means any subject or all actions, and the `where` axis
    /// rejects it.
    Wildcard,
    /// A `@name` reference to a group on the same axis.
    Group(GroupName),
    /// A literal leaf, which is an exe path, an object path or an action name (see
    /// [`RawLeaf`]).
    Leaf(RawLeaf),
}

impl<'de> serde::Deserialize<'de> for Token {
    /// Lexes a TOML string into a [`Token`]. The split into `@ref`, `*` and leaf is
    /// purely lexical and the same on every axis, so it can run during deserialization.
    /// The raw policy forms (`members`, a rule field) then hold tokens, not bare strings.
    fn deserialize<D>(de: D) -> std::result::Result<Token, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Token::classify(&String::deserialize(de)?))
    }
}

impl Token {
    pub(crate) fn classify(raw: &str) -> Token {
        if raw == "*" {
            Token::Wildcard
        } else if let Some(name) = raw.strip_prefix('@') {
            Token::Group(GroupName::new(name))
        } else {
            Token::Leaf(raw.to_string())
        }
    }
}

/// Parses policy text into a [`ParsedPolicy`]. Errors when the TOML is structurally
/// wrong (bad syntax, an unknown key, a bad enum value), with `toml`'s own location. Also
/// errors when a DSL rule line is malformed (a wrong field count, an unknown policy
/// keyword, an unterminated quote), with a `line:col` prefix inside the `rules` block.
pub fn parse(text: &str) -> Result<ParsedPolicy> {
    let raw: RawPolicy = toml::from_str(text).context("policy parse error")?;
    let lines = LineIndex::new(text);

    let mut rules = Vec::with_capacity(raw.blocks.len());
    // A `[[rule]]` table's position is its header.
    for spanned in raw.blocks {
        let pos = lines.pos(spanned.span().start);
        let rd = spanned.into_inner();
        rules.push(ParsedRule {
            who: rd.who.into(),
            where_: rd.where_.into(),
            action: rd.action.into(),
            policy: rd.policy,
            pos,
        });
    }
    // The DSL block's content starts at `content_start`, so byte offsets inside it map
    // back to file positions through `lines`.
    if let Some(block) = &raw.rules {
        let content = block.get_ref();
        let content_start = block_content_start(text, block.span().start);
        rules.extend(super::ruleline::parse_block(
            content,
            content_start,
            &lines,
        )?);
    }

    let includes = raw
        .includes
        .into_iter()
        .map(|spanned| {
            let pos = lines.pos(spanned.span().start);
            let inc = spanned.into_inner();
            Include::new(inc.user, inc.path).map_err(|e| Error::at(pos, e.to_string()))
        })
        .collect::<Result<_>>()?;

    Ok(ParsedPolicy {
        groups: raw.group,
        rules,
        lines,
        user: raw.user,
        includes,
    })
}

/// Returns the absolute byte offset at which a multiline string's content begins. That is
/// past the opening `'''` or `"""` delimiter and the one newline that TOML trims right
/// after it, where CRLF counts as one newline. In the literal (`'''`) form, the content
/// from there is a verbatim slice of the source, so DSL offsets map to exact positions.
fn block_content_start(text: &str, span_start: usize) -> usize {
    let after = &text[span_start..];
    let Some(rest) = after
        .strip_prefix("'''")
        .or_else(|| after.strip_prefix("\"\"\""))
    else {
        // A single-line string's content begins just past its one quote character.
        return span_start + after.chars().next().map_or(0, |c| c.len_utf8());
    };
    let trimmed = if rest.starts_with("\r\n") {
        2
    } else if rest.starts_with('\n') || rest.starts_with('\r') {
        1
    } else {
        0
    };
    span_start + 3 + trimmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_groups_and_rules() {
        let text = r#"
            [group.subject.ssh-tools]
            members = ["/usr/bin/ssh", "/usr/bin/scp"]

            [group.action.ro]
            members = ["read", "listdir"]

            [[rule]]
            who = "@ssh-tools"
            where = "~/.ssh"
            action = "@ro"
            policy = "allow"

            [[rule]]
            who = "*"
            where = ["~/.aws", "~/.config/gcloud"]
            action = ["read", "write"]
            policy = "audit"
        "#;
        let p = parse(text).unwrap();
        assert_eq!(p.groups.subject.len(), 1);
        assert_eq!(p.groups.action.len(), 1);
        assert_eq!(p.rules.len(), 2);
        assert_eq!(p.rules[0].who, vec![Token::Group("ssh-tools".into())]);
        assert_eq!(
            p.rules[1].where_,
            vec![
                Token::Leaf("~/.aws".into()),
                Token::Leaf("~/.config/gcloud".into()),
            ]
        );
    }

    #[test]
    fn parses_user_header() {
        let p = parse(
            "user = \"alice\"\n[[rule]]\nwho = \"*\"\nwhere = \"/x\"\naction = \"read\"\npolicy = \"deny\"\n",
        )
        .unwrap();
        assert_eq!(p.user().map(|u| u.as_str()), Some("alice"));
        // absent ⇒ None (the caller falls back to its own `$HOME`).
        let p2 =
            parse("[[rule]]\nwho = \"*\"\nwhere = \"/x\"\naction = \"read\"\npolicy = \"deny\"\n")
                .unwrap();
        assert!(p2.user().is_none());
    }

    #[test]
    fn parses_includes() {
        let p = parse(
            "[[include]]\nuser = \"alice\"\npath = \"/etc/cordon/users/alice.toml\"\n\
             [[include]]\nuser = \"bob\"\npath = \"/etc/cordon/users/bob.toml\"\n",
        )
        .unwrap();
        assert_eq!(p.includes().len(), 2);
        assert_eq!(p.includes()[0].user().as_str(), "alice");
        assert_eq!(
            p.includes()[0].path(),
            Path::new("/etc/cordon/users/alice.toml")
        );
        assert_eq!(p.includes()[1].user().as_str(), "bob");
        // a policy with no include directive has an empty list.
        assert!(
            parse("rules = '''\nallow /b read /x\n'''\n")
                .unwrap()
                .includes()
                .is_empty()
        );
    }

    /// Checks that a rendered include reads back unchanged, also for a path that Rust's
    /// `Debug` would escape in a form TOML rejects, and that a relative path is refused.
    #[test]
    fn include_round_trips_and_must_be_absolute() {
        let inc = Include::new(
            UserName::new("alice"),
            PathBuf::from("/etc/cordon/users/äl \"q\".toml"),
        )
        .unwrap();
        let parsed = parse(&inc.to_toml().unwrap()).unwrap();
        assert_eq!(parsed.includes(), [inc]);

        assert!(Include::new(UserName::new("alice"), PathBuf::from("users/a.toml")).is_err());
        let err = parse("[[include]]\nuser = \"alice\"\npath = \"users/a.toml\"\n").unwrap_err();
        assert!(err.to_string().contains("must be absolute"), "{err}");
    }

    #[test]
    fn token_classification() {
        assert_eq!(Token::classify("*"), Token::Wildcard);
        assert_eq!(
            Token::classify("@ssh-tools"),
            Token::Group("ssh-tools".into())
        );
        assert_eq!(
            Token::classify("/usr/bin/ssh"),
            Token::Leaf("/usr/bin/ssh".into())
        );
        assert_eq!(Token::classify("read"), Token::Leaf("read".into()));
    }

    /// A single `[[rule]]` block, for the one-rule tests.
    fn one_rule(body: &str) -> String {
        format!("[[rule]]\n{body}\n")
    }

    /// Guards against a leftover top-level `mode = "…"` key silently parsing: it must
    /// fail loud (unknown field), so a stale policy surfaces at `cordon policy check`
    /// instead of being half-honored.
    #[test]
    fn rejects_mode_key() {
        let err = parse(
            "mode = \"enforce\"\n[[rule]]\nwho = \"*\"\nwhere = \"/x\"\naction = \"read\"\npolicy = \"deny\"\n",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("mode") || format!("{err}").contains("unknown"));
    }

    #[test]
    fn rejects_unknown_field() {
        let err = parse(&one_rule(
            r#"who = "*"
               where = "/x"
               action = "read"
               policy = "deny"
               oops = 1"#,
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("oops") || format!("{err}").contains("unknown"));
    }

    #[test]
    fn rejects_bad_policy_value() {
        let err = parse(&one_rule(
            r#"who = "*"
               where = "/x"
               action = "read"
               policy = "maybe""#,
        ))
        .unwrap_err();
        assert!(
            format!("{err}").contains("maybe")
                || format!("{err}").to_lowercase().contains("expected")
        );
    }

    #[test]
    fn rejects_conjunctive_subject_group_until_m2() {
        // The conjunctive `exe = … argv0 = …` form is not a known field.
        let err = parse("[group.subject.aws]\nexe = \"/usr/bin/python3\"\nargv0 = \"aws\"\n")
            .unwrap_err();
        assert!(format!("{err}").contains("exe") || format!("{err}").contains("unknown"));
    }
}
