//! The flat **rule model** (DESIGN §15): a root-owned text policy compiled in
//! userspace into the flat per-object decision table the kernel evaluates.
//!
//! Three pure, unit-testable stages:
//!   1. [`parse`] — TOML text → [`ParsedPolicy`] (serde; structural validation, with
//!      source spans retained via [`toml::Spanned`]).
//!   2. [`resolve`] — expand `@group` refs on all three axes (subject/object/action),
//!      cycle-check, validate action/policy names, expand `~`, lexically normalize →
//!      a [`ResolvedPolicy`] that is group-free but still **path-based**.
//!   3. [`compile`] — cross-product `who × where × action`, resolve object/exe paths
//!      to inode identity, apply **copy-down** object precedence, sort + dedup → a
//!      [`CompiledPolicy`] of per-object [`cordon_bpf_common::CompiledRule`] buckets.
//!
//! All group expansion, nesting, and object precedence resolve *here*, so the kernel
//! stays flat (DESIGN §15.3): each protected object's bucket is pre-merged and
//! pre-sorted, and the kernel applies the first matching rule in the deepest object's
//! bucket.
//!
//! Diagnostics carry a source [`Pos`] (rule-/group-level) so `cordon policy check`
//! can report `config.toml:LINE: …`. We reuse the `toml` crate's spans rather than
//! tracking positions by hand, and lean on serde + `deny_unknown_fields` + typed
//! enums for structural validation — only the domain-specific checks (cycles, refs,
//! paths, precedence) are hand-written.

mod compile;
mod parse;
mod resolve;

pub use compile::{CompiledObject, CompiledPolicy, compile, stat_resolver};
pub use parse::{ParsedPolicy, parse};
pub use resolve::{ResolvedPolicy, ResolvedRule, SubjectSpec, resolve};

use crate::Result;
use cordon_bpf_common as bpf;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The global enforcement mode (DESIGN §15.6), orthogonal to per-rule policy. The
/// policy file's top-level `mode = "…"`; omitted ⇒ [`Mode::Enforce`] (fail-safe).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Per-rule policy applies as authored — a `deny`/`silence` blocks.
    #[default]
    Enforce,
    /// Every denying policy is downgraded to a logged allow, system-wide — the
    /// safe-rollout lever (SELinux permissive).
    Permissive,
    /// No mediation at all.
    Off,
}

/// A 1-based line/column into the policy source. Column is a byte offset within the
/// line (fine for the ASCII paths/names a policy holds; not grapheme-aware).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pos {
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for Pos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

/// Maps a byte offset in the source to a [`Pos`]. Built once from the text so resolve
/// can turn a [`toml::Spanned`] span into a position when emitting a diagnostic.
#[derive(Clone, Debug)]
pub(crate) struct LineIndex {
    /// Byte offset at which each line starts (`line_starts[0] == 0`).
    line_starts: Vec<usize>,
}

impl LineIndex {
    pub(crate) fn new(source: &str) -> LineIndex {
        let mut line_starts = vec![0];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        LineIndex { line_starts }
    }

    /// The [`Pos`] of a byte offset. `partition_point` finds the last line start at or
    /// before `byte`; the column is the 1-based byte offset within that line.
    pub(crate) fn pos(&self, byte: usize) -> Pos {
        let line = self.line_starts.partition_point(|&s| s <= byte).max(1);
        let col = byte - self.line_starts[line - 1] + 1;
        Pos {
            line: line as u32,
            col: col as u32,
        }
    }
}

/// A finding from parse/resolve/compile, surfaced by `cordon policy check`. An
/// `Error` means the policy must not be applied; `Warning` means it applies but
/// something is off (a rule won't be enforced, a path is missing, …). `pos` points at
/// the offending rule/group when the source location is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub pos: Option<Pos>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Error,
}

impl Diagnostic {
    pub(crate) fn warn(pos: Option<Pos>, msg: impl Into<String>) -> Diagnostic {
        Diagnostic {
            severity: Severity::Warning,
            message: msg.into(),
            pos,
        }
    }
    pub(crate) fn error(pos: Option<Pos>, msg: impl Into<String>) -> Diagnostic {
        Diagnostic {
            severity: Severity::Error,
            message: msg.into(),
            pos,
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        match self.pos {
            Some(p) => write!(f, "{p}: {kind}: {}", self.message),
            None => write!(f, "{kind}: {}", self.message),
        }
    }
}

/// An authoring-layer action name (DESIGN §15.5). A real enum (vs the kernel's
/// [`bpf::Action`] bitset) so the token set is closed and the lowering match is
/// exhaustive — adding an action forces updating [`ActionName::bit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionName {
    Read,
    Write,
    Create,
    Execute,
    Listdir,
    Unlink,
    Mkdir,
    Rmdir,
    Rename,
}

impl ActionName {
    /// Parse one action token (lower-case, as authored). `None` if unknown — the
    /// caller turns that into a resolve error naming the offending token.
    pub fn parse(token: &str) -> Option<ActionName> {
        Some(match token {
            "read" => ActionName::Read,
            "write" => ActionName::Write,
            "create" => ActionName::Create,
            "execute" => ActionName::Execute,
            "listdir" => ActionName::Listdir,
            "unlink" => ActionName::Unlink,
            "mkdir" => ActionName::Mkdir,
            "rmdir" => ActionName::Rmdir,
            "rename" => ActionName::Rename,
            _ => return None,
        })
    }

    /// The single-bit [`bpf::Action`] this name maps to.
    pub fn bit(self) -> bpf::Action {
        use bpf::Action;
        match self {
            ActionName::Read => Action::READ,
            ActionName::Write => Action::WRITE,
            ActionName::Create => Action::CREATE,
            ActionName::Execute => Action::EXECUTE,
            ActionName::Listdir => Action::LISTDIR,
            ActionName::Unlink => Action::UNLINK,
            ActionName::Mkdir => Action::MKDIR,
            ActionName::Rmdir => Action::RMDIR,
            ActionName::Rename => Action::RENAME,
        }
    }
}

/// An authoring-layer policy name. Deserialized directly from a rule's `policy` field
/// (serde validates it's one of the four), then lowered to [`bpf::Policy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyName {
    Allow,
    Deny,
    Audit,
    Silence,
}

impl PolicyName {
    /// Lower to the kernel's POD [`bpf::Policy`].
    pub fn lower(self) -> bpf::Policy {
        use bpf::Policy;
        match self {
            PolicyName::Allow => Policy::ALLOW,
            PolicyName::Deny => Policy::DENY,
            PolicyName::Audit => Policy::AUDIT,
            PolicyName::Silence => Policy::SILENCE,
        }
    }
}

/// Expand a leading `~` to `home`, then lexically normalize. Errors if the result is
/// neither absolute nor `~`-relative — policy paths must be unambiguous (no
/// cwd-relative surprises in a reviewable, root-owned file; DESIGN §15.8).
pub(crate) fn expand_path(raw: &str, home: &std::path::Path) -> Result<std::path::PathBuf> {
    use crate::paths::normalize;
    use std::path::{Path, PathBuf};

    let expanded: PathBuf = if raw == "~" {
        home.to_path_buf()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(raw)
    };
    if !expanded.is_absolute() {
        return Err(crate::Error::msg(format!(
            "policy path must be absolute or ~-relative: {raw:?}"
        )));
    }
    Ok(normalize(Path::new(&expanded)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_index_maps_offsets() {
        let src = "mode = \"off\"\n[[rule]]\nwho = \"*\"\n";
        let idx = LineIndex::new(src);
        assert_eq!(idx.pos(0), Pos { line: 1, col: 1 });
        // first byte of line 2 ('[') is at offset 13
        assert_eq!(idx.pos(13), Pos { line: 2, col: 1 });
        // 'w' of line 3 ("who") is at offset 22
        assert_eq!(idx.pos(22), Pos { line: 3, col: 1 });
    }

    #[test]
    fn expand_path_handles_tilde_and_normalizes() {
        let home = std::path::Path::new("/home/u");
        assert_eq!(
            expand_path("~/.aws", home).unwrap(),
            std::path::PathBuf::from("/home/u/.aws")
        );
        assert_eq!(
            expand_path("~", home).unwrap(),
            std::path::PathBuf::from("/home/u")
        );
        assert_eq!(
            expand_path("/etc/./ssh/../ssh", home).unwrap(),
            std::path::PathBuf::from("/etc/ssh")
        );
        assert!(expand_path("relative/path", home).is_err());
    }

    #[test]
    fn action_and_policy_lowering() {
        assert_eq!(ActionName::parse("read"), Some(ActionName::Read));
        assert_eq!(ActionName::parse("nope"), None);
        assert_eq!(ActionName::Write.bit(), bpf::Action::WRITE);
        assert_eq!(PolicyName::Silence.lower(), bpf::Policy::SILENCE);
    }

    /// The shipped example policy must always parse + resolve (group refs, action
    /// names, paths) — guards `packaging/cordon.example.policy.toml` against drift.
    /// Inode resolution (compile) is left out: the example's exes/dirs need not exist
    /// on the test box.
    #[test]
    fn shipped_example_policy_resolves() {
        let text = include_str!("../../../../packaging/cordon.example.policy.toml");
        let parsed = parse(text).expect("example policy parses");
        let resolved =
            resolve(&parsed, std::path::Path::new("/home/u")).expect("example policy resolves");
        assert_eq!(resolved.mode, Mode::Enforce);
        assert!(!resolved.rules.is_empty());
    }
}
