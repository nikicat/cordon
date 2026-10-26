//! Stage 1 — parse TOML text into a structurally-valid, span-carrying policy.
//!
//! serde + `#[serde(deny_unknown_fields)]` does the structural validation for free
//! (typo'd keys and bad enum values fail here, with `toml`'s own line/column in the
//! error). Each rule and group is wrapped in [`toml::Spanned`] so later stages can
//! point a diagnostic at the offending source line. Semantic validation — `@ref`
//! resolution, cycles, paths — is [`super::resolve`]'s job.

use super::{ClassName, GroupName, LineIndex, PolicyName, Pos, UserName};
use crate::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use toml::Spanned;

/// A parsed-but-unresolved policy: every rule normalized to a [`ParsedRule`] (its
/// fields lexed to [`Token`]s, its source [`Pos`] already resolved), plus a line index
/// the resolver still needs for *group* positions. Consumed by [`super::resolve`].
///
/// Both authoring surfaces land here: the verbose `[[rule]]` tables and the compact
/// `rules = '''…'''` DSL block ([`super::ruleline`]) are normalized to the same
/// `ParsedRule`, so everything downstream of parse is syntax-agnostic.
#[derive(Debug)]
pub struct ParsedPolicy {
    pub(crate) groups: Groups,
    pub(crate) rules: Vec<ParsedRule>,
    pub(crate) lines: LineIndex,
    /// The optional `user = "name"` header. Lets a root-owned, per-user policy file use
    /// `~` instead of spelling out `/home/<name>` (DESIGN §15.8); [`super::home_for`]
    /// resolves it to the home `~` expands against.
    pub(crate) user: Option<UserName>,
    /// `[[include]]` directives: user-tier files this (system) fragment pulls in
    /// (DESIGN §15.8). Resolved by [`super::load_policy`] at read time, not here.
    pub(crate) includes: Vec<Include>,
}

impl ParsedPolicy {
    /// The `user =` header, if the policy declared one.
    pub fn user(&self) -> Option<&UserName> {
        self.user.as_ref()
    }

    /// The `[[include]]` directives this fragment declares (empty for most fragments).
    pub fn includes(&self) -> &[Include] {
        &self.includes
    }
}

/// One `[[include]]` directive — a system fragment pulling in a user-tier policy file
/// (DESIGN §15.8): the owning `user` and the `path` to read, loaded as
/// [`super::SourceOrigin::User`].
#[derive(Debug)]
pub struct Include {
    user: UserName,
    path: String,
}

impl Include {
    pub fn user(&self) -> &UserName {
        &self.user
    }
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// One rule, normalized from either authoring surface: each axis lexed to its
/// [`Token`] list, the effect as a [`PolicyName`], and the source [`Pos`] of the rule
/// (the `[[rule]]` header, or the first field of a DSL line) for diagnostics.
#[derive(Debug)]
pub(crate) struct ParsedRule {
    pub(crate) who: Vec<Token>,
    pub(crate) where_: Vec<Token>,
    pub(crate) action: Vec<Token>,
    pub(crate) policy: PolicyName,
    pub(crate) pos: Pos,
}

/// The top-level TOML shape. `[[rule]]` tables collect into `blocks`; the optional
/// `rules = '''…'''` literal block into `rules` (the DSL, [`super::ruleline`]);
/// `[group.{subject,object,action}.NAME]` into `group`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    /// `user = "name"` ([`ParsedPolicy::user`]). Like `rules`, a top-level key, so it
    /// must precede any `[group.*]` header.
    #[serde(default)]
    user: Option<UserName>,
    #[serde(default)]
    group: Groups,
    #[serde(default, rename = "rule")]
    blocks: Vec<Spanned<RuleDef>>,
    /// The compact rule DSL. A TOML *literal* (`'''…'''`) string so paths keep their
    /// backslashes and our own `"…"` quoting is free of TOML escape processing, and so
    /// its content is a verbatim slice of the source: byte offsets in it map straight to
    /// file positions. One rule per line, `POLICY SUBJECT ACTION OBJECT`. Must precede
    /// any `[group.*]` header (a bare top-level key binds to the last table otherwise).
    #[serde(default)]
    rules: Option<Spanned<String>>,
    /// `[[include]]` tables — user-tier files this system fragment pulls in (DESIGN §15.8).
    #[serde(default, rename = "include")]
    includes: Vec<Spanned<IncludeDef>>,
}

/// One `[[include]] user = "name" path = "…"` table.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct IncludeDef {
    user: UserName,
    path: String,
}

/// The three group namespaces (DESIGN §15.7), each `name → members`.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Groups {
    #[serde(default)]
    pub(crate) subject: BTreeMap<GroupName, Spanned<GroupDef>>,
    #[serde(default)]
    pub(crate) object: BTreeMap<GroupName, Spanned<GroupDef>>,
    #[serde(default)]
    pub(crate) action: BTreeMap<GroupName, Spanned<GroupDef>>,
}

/// A named group. The usual form is `members` (a list of leaf tokens / nested `@ref`s). A
/// **subject** group may instead carry a single `blessing = "<class>"` predicate (DESIGN
/// §16.3) — declaring a blessing class referenced as `@<group>`; [`super::resolve`] rejects
/// `blessing` on an object/action group and rejects mixing it with `members`. The other
/// conjunctive subject predicates (`exe = … argv0 = …`, DESIGN §15.4) are not implemented,
/// so `deny_unknown_fields` rejects them.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupDef {
    /// Member tokens (`@ref`/`*`/leaf), each lexed to a [`Token`] at deserialize time —
    /// they follow the same grammar as a rule field, so groups nest recursively.
    #[serde(default)]
    pub(crate) members: Vec<Token>,
    /// A blessing class this (subject) group matches (DESIGN §16.3); mutually exclusive with
    /// `members`. `None` for an ordinary member-list group. Deserializes transparently from
    /// the TOML string into the [`ClassName`] newtype.
    #[serde(default)]
    pub(crate) blessing: Option<ClassName>,
}

/// One `[[rule]]`: who/where/action are each a single token or a list (groups,
/// wildcards, or leaves); `policy` is one of the four effects (serde-validated).
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleDef {
    pub(crate) who: OneOrMany,
    #[serde(rename = "where")]
    pub(crate) where_: OneOrMany,
    pub(crate) action: OneOrMany,
    pub(crate) policy: PolicyName,
}

/// A rule field that may be written as a bare value or a list — each lexed to a [`Token`]
/// at deserialize time (via [`Token`]'s `Deserialize`). (Not `Spanned`: `toml::Spanned`
/// does not survive `#[serde(untagged)]`, which buffers the input — so token-level
/// positions aren't available; rule/group spans are.)
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum OneOrMany {
    One(Token),
    Many(Vec<Token>),
}

impl OneOrMany {
    /// The tokens, as a slice (a single value is a one-element slice).
    pub(crate) fn tokens(&self) -> &[Token] {
        match self {
            OneOrMany::One(t) => std::slice::from_ref(t),
            OneOrMany::Many(v) => v,
        }
    }

    /// The tokens as an owned list, for [`ParsedRule`].
    pub(crate) fn classified(&self) -> Vec<Token> {
        self.tokens().to_vec()
    }
}

/// The text of a leaf token: an exe path, an object path or an action name. Which one it
/// is gets decided per axis in [`super::resolve`], which turns it into a `PathBuf` or an
/// [`ActionName`]. It is an alias rather than a newtype because every string is a valid
/// leaf at this lexical layer.
pub(crate) type RawLeaf = String;

/// A single token, classified by its **lexical** form only (axis-independent). The
/// *meaning* of a [`Token::Leaf`] is axis-specific — an exe path, an object path, or an
/// action name — and is interpreted by [`super::resolve`], which holds the `home` dir
/// (for `~`) and the action vocabulary. Splitting it this way keeps the one
/// `@ref`/`*`/leaf classifier in a single place while leaving semantics where the
/// context lives.
///
/// A token whose first character is `@` is always a group ref (so an exe/object whose
/// leading component is literally `@name` can't be named — an acceptable limit, same
/// as treating `*` as the wildcard).

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    /// `*` — wildcard (axis-specific: any subject / all actions; rejected for `where`).
    Wildcard,
    /// `@name` — a reference to a same-axis group.
    Group(GroupName),
    /// A literal leaf: an exe/object path or an action name (see [`RawLeaf`]).
    Leaf(RawLeaf),
    /// A blessing class (DESIGN §16.3), **synthesized** by [`super::resolve`] when a `@ref`
    /// resolves to a `blessing = "<class>"` group — never produced by lexing (a blessing is
    /// not a surface token, so [`classify`](Token::classify) never returns it). The subject
    /// axis turns it into a blessing predicate; the object/action axes reject it.
    Blessing(ClassName),
}

impl<'de> serde::Deserialize<'de> for Token {
    /// Lex a TOML string into a [`Token`] at deserialize time (the `@ref`/`*`/leaf split is
    /// purely lexical, so it is axis-independent and can run here) — so the raw policy
    /// surfaces (`members`, a rule field) hold `Token`s, not bare strings.
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

/// Parse policy text. Fails on a structural TOML problem (syntax, unknown key, bad
/// enum value — `toml`'s own error, with location), or on a malformed DSL rule line
/// (arity, unknown policy keyword, unterminated quote — a `line:col`-prefixed error
/// pointing into the `rules` block). Both rule surfaces normalize to [`ParsedRule`].
pub fn parse(text: &str) -> Result<ParsedPolicy> {
    let raw: RawPolicy = toml::from_str(text).context("policy parse error")?;
    let lines = LineIndex::new(text);

    let mut rules = Vec::with_capacity(raw.blocks.len());
    // `[[rule]]` tables → normalized rules (pos = the table header).
    for spanned in &raw.blocks {
        let rd = spanned.get_ref();
        rules.push(ParsedRule {
            who: rd.who.classified(),
            where_: rd.where_.classified(),
            action: rd.action.classified(),
            policy: rd.policy,
            pos: lines.pos(spanned.span().start),
        });
    }
    // `rules = '''…'''` DSL block → normalized rules. Its content starts at
    // `content_start`, so byte offsets inside it map back to file positions via `lines`.
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
        .iter()
        .map(|spanned| {
            let def = spanned.get_ref();
            Include {
                user: def.user.clone(),
                path: def.path.clone(),
            }
        })
        .collect();

    Ok(ParsedPolicy {
        groups: raw.group,
        rules,
        lines,
        user: raw.user,
        includes,
    })
}

/// The absolute byte offset where a multiline literal/basic string's *content* begins:
/// past the opening `'''`/`"""` delimiter and the single newline TOML trims right after
/// it (CRLF counts as one). For the literal (`'''`) form the content is then a verbatim
/// slice of the source from here, so DSL offsets translate to exact source positions.
fn block_content_start(text: &str, span_start: usize) -> usize {
    let after = &text[span_start..];
    let Some(rest) = after
        .strip_prefix("'''")
        .or_else(|| after.strip_prefix("\"\"\""))
    else {
        // A single-line string value: content begins just past one quote char.
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
        assert_eq!(p.includes()[0].path(), "/etc/cordon/users/alice.toml");
        assert_eq!(p.includes()[1].user().as_str(), "bob");
        // a policy with no include directive has an empty list.
        assert!(
            parse("rules = '''\nallow /b read /x\n'''\n")
                .unwrap()
                .includes()
                .is_empty()
        );
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
