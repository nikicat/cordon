//! Stage 1 — parse TOML text into a structurally-valid, span-carrying policy.
//!
//! serde + `#[serde(deny_unknown_fields)]` does the structural validation for free
//! (typo'd keys and bad enum values fail here, with `toml`'s own line/column in the
//! error). Each rule and group is wrapped in [`toml::Spanned`] so later stages can
//! point a diagnostic at the offending source line. Semantic validation — `@ref`
//! resolution, cycles, paths — is [`super::resolve`]'s job.

use super::{LineIndex, PolicyName};
use crate::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use toml::Spanned;

/// A parsed-but-unresolved policy: serde-validated structure with retained spans, plus
/// a line index for turning those spans into [`super::Pos`]. Consumed by
/// [`super::resolve`].
#[derive(Debug)]
pub struct ParsedPolicy {
    pub(crate) groups: Groups,
    pub(crate) rules: Vec<Spanned<RuleDef>>,
    pub(crate) lines: LineIndex,
}

/// The top-level TOML shape. `[[rule]]` tables collect into `rules`;
/// `[group.{subject,object,action}.NAME]` into `group`. There is no top-level `mode`
/// key — the per-rule `policy` is the only enforcement level (DESIGN §15.6).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    group: Groups,
    #[serde(default, rename = "rule")]
    rules: Vec<Spanned<RuleDef>>,
}

/// The three group namespaces (DESIGN §15.7), each `name → members`.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Groups {
    #[serde(default)]
    pub(crate) subject: BTreeMap<String, Spanned<GroupDef>>,
    #[serde(default)]
    pub(crate) object: BTreeMap<String, Spanned<GroupDef>>,
    #[serde(default)]
    pub(crate) action: BTreeMap<String, Spanned<GroupDef>>,
}

/// A named group. M1 supports only `members` (a list of leaf tokens / nested `@ref`s);
/// the conjunctive subject form (`exe = … argv0 = …`, DESIGN §15.4) lands in M2 and is
/// rejected here by `deny_unknown_fields` until then.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupDef {
    pub(crate) members: Vec<String>,
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

/// A field that may be written as a bare string or a list of strings. (Not
/// `Spanned`: `toml::Spanned` does not survive `#[serde(untagged)]`, which buffers the
/// input — so token-level positions aren't available; rule/group spans are.)
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    /// The raw tokens, as a slice (a single value is a one-element slice).
    pub(crate) fn tokens(&self) -> &[String] {
        match self {
            OneOrMany::One(s) => std::slice::from_ref(s),
            OneOrMany::Many(v) => v,
        }
    }

    /// The tokens, lexically classified for [`super::resolve`].
    pub(crate) fn classified(&self) -> Vec<Token> {
        self.tokens().iter().map(|s| Token::classify(s)).collect()
    }
}

impl GroupDef {
    /// Group members, lexically classified (members follow the same token grammar as a
    /// rule field, so `@ref`/`*`/leaf nest recursively).
    pub(crate) fn classified(&self) -> Vec<Token> {
        self.members.iter().map(|s| Token::classify(s)).collect()
    }
}

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
    Group(String),
    /// A literal leaf: an exe/object path or an action name.
    Leaf(String),
}

impl Token {
    pub(crate) fn classify(raw: &str) -> Token {
        if raw == "*" {
            Token::Wildcard
        } else if let Some(name) = raw.strip_prefix('@') {
            Token::Group(name.to_string())
        } else {
            Token::Leaf(raw.to_string())
        }
    }
}

/// Parse policy text. Fails only on a structural problem (TOML syntax, unknown key,
/// bad enum value); `toml`'s error renders the location and a source snippet.
pub fn parse(text: &str) -> Result<ParsedPolicy> {
    let raw: RawPolicy =
        toml::from_str(text).map_err(|e| Error::msg(format!("policy parse error: {e}")))?;
    Ok(ParsedPolicy {
        groups: raw.group,
        rules: raw.rules,
        lines: LineIndex::new(text),
    })
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
        assert_eq!(
            p.rules[0].get_ref().who.tokens(),
            &["@ssh-tools".to_string()]
        );
        assert_eq!(
            p.rules[1].get_ref().where_.tokens(),
            &["~/.aws".to_string(), "~/.config/gcloud".to_string()]
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

    /// The global mode is gone (DESIGN §15.6): a leftover top-level `mode = "…"` key
    /// must fail loud (unknown field) rather than silently parse, so stale policies
    /// surface at `cordon policy check` instead of being half-honored.
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
        // The M2 `exe = … argv0 = …` form is not a known field in M1.
        let err = parse("[group.subject.aws]\nexe = \"/usr/bin/python3\"\nargv0 = \"aws\"\n")
            .unwrap_err();
        assert!(format!("{err}").contains("exe") || format!("{err}").contains("unknown"));
    }
}
