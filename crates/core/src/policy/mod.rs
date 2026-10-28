//! The flat rule model (ADR 0005). It compiles a root-owned text policy, in userspace,
//! into the flat per-object decision table that the kernel evaluates.
//!
//! Compilation runs in three pure stages, each testable on its own:
//!   1. [`parse`] turns TOML text into a [`ParsedPolicy`]. Serde does the structural
//!      validation, and [`toml::Spanned`] keeps the source spans.
//!   2. [`resolve`] expands `@group` references on all three axes (subject, object and
//!      action), rejects cycles and unknown action or policy names, expands `~`, and
//!      normalizes paths lexically. The result is a [`ResolvedPolicy`] with no groups
//!      left, which still names objects by path.
//!   3. [`compile`] takes the cross product of subject, object and action, resolves
//!      object and exe paths to inodes, and builds each object's copy-down bucket. The
//!      result is a [`CompiledPolicy`] of per-object
//!      [`cordon_bpf_common::CompiledRule`] buckets.
//!
//! All group expansion, nesting and object precedence are settled here, so the kernel
//! stays flat (ADR 0005).
//!
//! Diagnostics carry the source [`Pos`] of their rule or group, so that
//! `cordon policy check` can report `config.toml:LINE: …`. Positions come from the `toml`
//! crate's spans instead of being tracked by hand. Serde, `deny_unknown_fields` and typed
//! enums do the structural validation, so only the domain checks (cycles, references,
//! paths, precedence) are written by hand.

mod compile;
mod parse;
mod resolve;
mod ruleline;

pub use compile::{ClassRegistry, CompiledObject, CompiledPolicy, compile, stat_resolver};
pub use parse::{Include, ParsedPolicy, parse};
pub use resolve::{ResolvedPolicy, ResolvedRule, SubjectSpec, resolve};

use crate::{Context, Result};
use cordon_bpf_common as bpf;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// A 1-based line and column in the policy source. The column counts bytes within the
/// line, which suits the ASCII paths and names a policy holds but is not grapheme-aware.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pos {
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for Pos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

/// The place in the policy that a diagnostic points to. A merged policy has several
/// fragments, so a position needs the fragment's name to mean anything. Either part may
/// be unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loc {
    /// The fragment's name, as [`PolicySource::name`] gives it.
    pub source: Option<String>,
    pub pos: Option<Pos>,
}

impl Loc {
    fn is_empty(&self) -> bool {
        self.source.is_none() && self.pos.is_none()
    }
}

/// Renders `source:line:col`, dropping whichever part is unknown.
impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.source, self.pos) {
            (Some(s), Some(p)) => write!(f, "{s}:{p}"),
            (Some(s), None) => f.write_str(s),
            (None, Some(p)) => write!(f, "{p}"),
            (None, None) => Ok(()),
        }
    }
}

/// Maps a byte offset in the source to a [`Pos`]. It is built once from the text, so
/// that resolve can turn any [`toml::Spanned`] span into a position for a diagnostic.
#[derive(Clone, Debug)]
pub(crate) struct LineIndex {
    /// The byte offset at which each line starts. The first entry is always 0.
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

    /// Returns the position of `byte`, with the column counted in bytes from 1.
    pub(crate) fn pos(&self, byte: usize) -> Pos {
        // The line is the one whose start is the last at or before `byte`.
        let line = self.line_starts.partition_point(|&s| s <= byte).max(1);
        let col = byte - self.line_starts[line - 1] + 1;
        Pos {
            line: line as u32,
            col: col as u32,
        }
    }
}

/// A finding from parse, resolve or compile, which `cordon policy check` reports. An
/// error means that the policy must not be applied. A warning means that it applies but
/// something is off, such as a rule that will not be enforced or a missing path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    /// The offending rule or group, as far as it is known.
    pub loc: Loc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Error,
}

impl Diagnostic {
    pub(crate) fn warn(loc: Loc, msg: impl Into<String>) -> Diagnostic {
        Diagnostic {
            severity: Severity::Warning,
            message: msg.into(),
            loc,
        }
    }
    pub fn error(loc: Loc, msg: impl Into<String>) -> Diagnostic {
        Diagnostic {
            severity: Severity::Error,
            message: msg.into(),
            loc,
        }
    }

    /// Returns the error diagnostic for fragment `source` failing with `err`.
    fn of_fragment(source: &str, err: crate::Error) -> Diagnostic {
        let (pos, message) = match err {
            crate::Error::Located(pos, msg) => (Some(pos), msg),
            other => (None, other.to_string()),
        };
        let loc = Loc {
            source: Some(source.to_string()),
            pos,
        };
        Diagnostic::error(loc, message)
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        if self.loc.is_empty() {
            write!(f, "{kind}: {}", self.message)
        } else {
            write!(f, "{}: {kind}: {}", self.loc, self.message)
        }
    }
}

/// Parses a rule's authored policy name, the `policy` field of a `[[rule]]` and the leading
/// field of a DSL rule line. Errors with a message that lists the accepted names.
pub(crate) fn parse_policy(name: &str) -> std::result::Result<bpf::Policy, String> {
    bpf::Policy::from_authored(name).ok_or_else(|| {
        let authored: Vec<&str> = bpf::Policy::NAMED[..bpf::Policy::AUTHORED]
            .iter()
            .map(|(_, n)| *n)
            .collect();
        format!(
            "unknown policy {name:?} (expected one of {})",
            authored.join(", ")
        )
    })
}

/// The login name of the account that a policy's `user =` header names (see
/// [`home_for`]). It is a newtype so that it cannot be mixed up with the other strings of
/// the policy layer, such as paths, group names and tokens. It serializes as a plain
/// string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UserName(String);

impl UserName {
    /// Wraps a raw login name without checking that the account exists.
    pub fn new(name: impl Into<String>) -> UserName {
        UserName(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for UserName {
    type Error = crate::Error;
    fn try_from(s: String) -> Result<UserName> {
        s.parse()
    }
}

impl From<UserName> for String {
    fn from(name: UserName) -> String {
        name.0
    }
}

impl std::str::FromStr for UserName {
    type Err = crate::Error;
    /// Parses a candidate login name. Errors when it is empty or holds `/`, `:`, a newline
    /// or NUL. The name becomes a file name (`users/<name>.toml`), so a `/` could escape
    /// `users/`, and `:` or a newline cannot appear in an account name. Whether the
    /// account exists is checked later, through [`home_for`].
    fn from_str(s: &str) -> Result<UserName> {
        if s.is_empty() || s.contains(['/', ':', '\n', '\0']) {
            return Err(crate::Error::msg(format!("invalid user name {s:?}")));
        }
        Ok(UserName::new(s))
    }
}

impl fmt::Display for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a `[group.{subject,object,action}.NAME]` group, which a rule references
/// as `@NAME` (ADR 0009). It is a newtype so that a group name cannot be confused with
/// the other strings of the policy layer, such as paths, leaves and class names. It
/// serializes as a plain string or TOML table key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupName(String);

impl GroupName {
    pub fn new(name: impl Into<String>) -> GroupName {
        GroupName(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for GroupName {
    fn from(s: &str) -> GroupName {
        GroupName(s.to_string())
    }
}

impl From<String> for GroupName {
    fn from(s: String) -> GroupName {
        GroupName(s)
    }
}

impl fmt::Display for GroupName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a blessing class (ADR 0012), as a subject group's
/// `blessing = "<name>"` predicate spells it. It is a newtype so that it cannot be mixed
/// up with the other strings of the policy layer, such as group names, paths and tokens.
/// The compiler assigns each distinct name a dense [`cordon_bpf_common::ClassId`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClassName(String);

impl ClassName {
    /// Wraps `name` without the charset check. Input from a policy, a request or a
    /// directory name goes through [`str::parse`] instead.
    pub fn new(name: impl Into<String>) -> ClassName {
        ClassName(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClassName {
    type Error = crate::Error;
    fn try_from(s: String) -> Result<ClassName> {
        s.parse()
    }
}

impl From<ClassName> for String {
    fn from(name: ClassName) -> String {
        name.0
    }
}

impl std::str::FromStr for ClassName {
    type Err = crate::Error;
    /// Parses a class name. Errors when it is empty or has a character outside
    /// `[A-Za-z0-9_-]`. The daemon embeds the name in a carrier cgroup's directory name,
    /// and that charset keeps the encoding unambiguous. Whether the policy declares the
    /// class is checked later, against the compiled registry.
    fn from_str(s: &str) -> Result<ClassName> {
        let valid = !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !valid {
            return Err(crate::Error::msg(format!(
                "invalid blessing class {s:?}: use only letters, digits, `_` and `-`"
            )));
        }
        Ok(ClassName::new(s))
    }
}

impl fmt::Display for ClassName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Returns the home that `~` expands to in a fragment with no `user =` header. It is
/// `$HOME`, or `/root` when that is unset. The daemon and the CLI's local compile both use
/// it, so they expand a fragment alike.
pub fn fallback_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}

/// Returns the home directory that `~` expands to in a policy. That is the home of the
/// account that `user` names, looked up through NSS, or `fallback` when the policy names
/// no user. Errors when the named account does not exist, so that a missing user does not
/// silently fall through to the wrong home.
pub fn home_for(user: Option<&UserName>, fallback: &Path) -> Result<PathBuf> {
    let Some(user) = user else {
        return Ok(fallback.to_path_buf());
    };
    crate::passwd::home_of(user)?
        .ok_or_else(|| crate::Error::msg(format!("policy user {:?} has no account", user.as_str())))
}

/// The tier that a [`PolicySource`] belongs to (ADR 0010). The tier decides how `~`
/// expands and whether the rules are confined to a home. The tiers merge flat, with no
/// precedence between them.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceOrigin {
    /// The system policy and its conf.d fragments, which root authors and which have
    /// full authority.
    #[default]
    System,
    /// A user-tier policy that a system fragment pulls in with `[[include]]`. Its rules
    /// are confined to the home of `user` (see `check_scope`).
    User { user: UserName },
}

/// One named policy fragment, the unit of both the conf.d split and the system and user
/// tiers (ADR 0010). A set of them travels over IPC on `apply`, and
/// [`compile_fragments`] compiles them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicySource {
    /// The fragment's file path, which its diagnostics name.
    pub name: String,
    pub text: String,
    #[serde(default)]
    pub origin: SourceOrigin,
}

impl PolicySource {
    /// Creates a system-tier fragment.
    pub fn system(name: impl Into<String>, text: impl Into<String>) -> PolicySource {
        PolicySource {
            name: name.into(),
            text: text.into(),
            origin: SourceOrigin::System,
        }
    }
}

/// The configured policy path, classified as one file or as a conf.d directory of
/// `*.toml` fragments (ADR 0010). It owns how the system fragments and the
/// `[[include]]`d user files are found and read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyRoot {
    /// A single policy file, which may not exist yet.
    File(PathBuf),
    ConfD(PathBuf),
}

impl PolicyRoot {
    /// The extension a file needs to load as a conf.d fragment.
    pub const FRAGMENT_EXT: &str = "toml";

    /// Classifies `path`, treating a path that does not exist as a [`File`](Self::File).
    /// Errors when `path` cannot be inspected.
    pub fn at(path: &Path) -> Result<PolicyRoot> {
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_dir() => Ok(PolicyRoot::ConfD(path.to_path_buf())),
            Ok(_) => Ok(PolicyRoot::File(path.to_path_buf())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(PolicyRoot::File(path.to_path_buf()))
            }
            Err(e) => Err(crate::Error::msg(format!("policy {}: {e}", path.display()))),
        }
    }

    pub fn path(&self) -> &Path {
        match self {
            PolicyRoot::File(p) | PolicyRoot::ConfD(p) => p,
        }
    }

    /// Checks whether `path` has the extension that a conf.d fragment needs to load.
    pub fn is_fragment(path: &Path) -> bool {
        path.extension().is_some_and(|x| x == Self::FRAGMENT_EXT)
    }

    /// Returns the system fragment files that exist, which are the file itself or the
    /// directory's `*.toml` fragments sorted by name, so that the load order is
    /// deterministic. Errors when the path cannot be inspected or the directory cannot be
    /// read.
    pub fn fragments(&self) -> Result<Vec<PathBuf>> {
        match self {
            PolicyRoot::File(p) if p.try_exists()? => Ok(vec![p.clone()]),
            PolicyRoot::File(_) => Ok(Vec::new()),
            PolicyRoot::ConfD(dir) => {
                let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
                    .with_context(|| format!("read policy dir {}", dir.display()))?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| Self::is_fragment(p))
                    .collect();
                files.sort();
                Ok(files)
            }
        }
    }

    /// Returns the system fragments, read. Errors when one cannot be read, or when there
    /// are none, because a policy without fragments is a misconfiguration rather than an
    /// empty allow-all.
    fn system_sources(&self) -> Result<Vec<PolicySource>> {
        let files = self.fragments()?;
        if files.is_empty() {
            return Err(crate::Error::msg(match self {
                PolicyRoot::File(p) => format!("policy {} does not exist", p.display()),
                PolicyRoot::ConfD(d) => {
                    format!("policy dir {} has no *.toml fragments", d.display())
                }
            }));
        }
        files
            .into_iter()
            .map(|p| {
                let text = std::fs::read_to_string(&p)
                    .with_context(|| format!("read policy {}", p.display()))?;
                Ok(PolicySource::system(p.display().to_string(), text))
            })
            .collect()
    }

    /// Returns the full policy, which is the system fragments plus every user-tier file
    /// that a system fragment pulls in with `[[include]]` (ADR 0010). Each include
    /// names the owning `user` and a `path`, and its file comes back tagged
    /// [`SourceOrigin::User`]. A missing included file reads as empty and still takes its
    /// slot, so that `cordon policy edit` can create it later. Errors as
    /// [`fragments`](Self::fragments) does, when there are no system fragments, and when a
    /// fragment or an existing included file cannot be read.
    pub fn load(&self) -> Result<Vec<PolicySource>> {
        let mut sources = self.system_sources()?;
        let mut included = Vec::new();
        for src in &sources {
            // A system fragment that does not parse still reports its error in
            // `compile_fragments`. Its includes cannot be read, so it is skipped here.
            let Ok(parsed) = parse(&src.text) else {
                continue;
            };
            for inc in parsed.includes() {
                let text = match std::fs::read_to_string(inc.path()) {
                    Ok(t) => t,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(e) => {
                        return Err(crate::Error::msg(format!(
                            "read user policy {}: {e}",
                            inc.path().display()
                        )));
                    }
                };
                included.push(PolicySource {
                    name: inc.path().display().to_string(),
                    text,
                    origin: SourceOrigin::User {
                        user: inc.user().clone(),
                    },
                });
            }
        }
        sources.append(&mut included);
        Ok(sources)
    }

    /// Returns the file that the first system `[[include]]` for `user` names, or `None`
    /// when no system fragment includes `user`. Errors when the system fragments cannot be
    /// read.
    pub fn include_for(&self, user: &UserName) -> Result<Option<PathBuf>> {
        for src in &self.system_sources()? {
            let Ok(parsed) = parse(&src.text) else {
                continue;
            };
            if let Some(inc) = parsed.includes().iter().find(|inc| inc.user() == user) {
                return Ok(Some(inc.path().to_path_buf()));
            }
        }
        Ok(None)
    }
}

/// Compiles a set of fragments into one decision table. Each fragment resolves on its
/// own, so its `@`-groups are local to it, and its `~` expands against its own `user =`
/// header, or against `fallback_home` without one. The resolved rules compile together in
/// the order given, so precedence ([`compile()`]) applies across the whole set.
///
/// A fragment that fails to parse or resolve becomes an error diagnostic that names it,
/// so one bad fragment fails the apply through [`CompiledPolicy::has_errors`] instead of
/// silently losing its rules. A user-tier fragment also fails when it contains
/// `[[include]]` or names an object outside its owner's home.
pub fn compile_fragments<R>(
    sources: &[PolicySource],
    fallback_home: &Path,
    resolve_fileid: R,
) -> CompiledPolicy
where
    R: FnMut(&Path) -> Option<bpf::FileId>,
{
    let mut rules = Vec::new();
    // Declared blessing classes, merged across fragments (a class declared in two fragments
    // collapses to one).
    let mut blessing_classes = std::collections::BTreeSet::new();
    let mut errors = Vec::new();
    for src in sources {
        let resolved = parse(&src.text).and_then(|parsed| match &src.origin {
            // The system tier has full authority and no scope restriction. Its `~` uses
            // the fragment's own `user =` header, or the fallback without one.
            SourceOrigin::System => {
                let home = home_for(parsed.user(), fallback_home)?;
                resolve(&parsed, &home)
            }
            // In the user tier, the include fixes the owning user (see `check_scope`).
            SourceOrigin::User { user } => {
                if !parsed.includes().is_empty() {
                    return Err(crate::Error::msg(
                        "a user policy may not contain `[[include]]`",
                    ));
                }
                let home = home_for(Some(user), fallback_home)?;
                let resolved = resolve(&parsed, &home)?;
                check_scope(&resolved, &home)?;
                Ok(resolved)
            }
        });
        match resolved {
            Ok(r) => {
                rules.extend(r.rules.into_iter().map(|mut rule| {
                    rule.source = Some(src.name.clone());
                    rule
                }));
                blessing_classes.extend(r.blessing_classes);
            }
            Err(e) => errors.push(Diagnostic::of_fragment(&src.name, e)),
        }
    }
    let resolved = ResolvedPolicy {
        rules,
        blessing_classes,
    };
    let mut compiled = compile(&resolved, resolve_fileid);
    // Per-fragment parse and resolve errors go ahead of the compile diagnostics.
    compiled.diagnostics.splice(0..0, errors);
    compiled
}

/// Checks that every object a user-tier policy names lies under the owning user's
/// `home` (ADR 0010). Errors at the first rule with an object outside it, so that a
/// rule reaching into `/etc` or another user's home fails instead of being dropped.
/// [`compile_fragments`] enforces the rest of the user-tier scope by refusing
/// `[[include]]` in a user tier, so only a system fragment binds a user to a file.
fn check_scope(resolved: &ResolvedPolicy, home: &Path) -> Result<()> {
    for rule in &resolved.rules {
        for obj in &rule.objects {
            if !crate::paths::is_within(obj, home) {
                return Err(crate::Error::at(
                    rule.pos,
                    format!(
                        "object {} is outside the owner's home {} — a user policy may only \
                         govern paths under it",
                        obj.display(),
                        home.display(),
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Returns `raw` with a leading `~` expanded to `home`, normalized lexically. Errors when
/// `raw` is neither absolute nor `~`-relative, because a path in a reviewable, root-owned
/// policy must not depend on the working directory (ADR 0010).
pub(crate) fn expand_path(raw: &str, home: &Path) -> Result<PathBuf> {
    use crate::paths::normalize;

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

    /// A class name outside `[A-Za-z0-9_-]` is refused, both as an argument and in a
    /// policy's `blessing =` predicate, so a bad name fails at compile rather than at mint.
    #[test]
    fn class_name_charset() {
        for good in ["ro", "Aws_prod-2"] {
            assert_eq!(good.parse::<ClassName>().unwrap().as_str(), good);
        }
        for bad in ["", "a.b", "a b", "a/b", "é"] {
            assert!(bad.parse::<ClassName>().is_err(), "{bad:?} must be refused");
        }
        let policy = "[group.subject.x]\nblessing = \"a.b\"\n";
        assert!(parse(policy).is_err());
    }

    /// A name that could escape `users/` or match a malformed passwd line is refused, both
    /// from the command line and from a policy's `user =` header.
    #[test]
    fn user_name_rejects_unsafe_names() {
        assert_eq!("alice".parse::<UserName>().unwrap().as_str(), "alice");
        for bad in ["", "../etc/x", "a/b", "a:b", "a\nb", "a\0b"] {
            assert!(bad.parse::<UserName>().is_err(), "{bad:?} must be refused");
        }
        assert!(parse("user = \"\"\n").is_err());
        assert!(parse("user = \"../x\"\n").is_err());
    }

    /// A directory is a conf.d, anything else (including nothing yet) is a file, and only
    /// what exists counts as a fragment.
    #[test]
    fn policy_root_classifies_the_path() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        let confd = base.join("conf.d");
        std::fs::create_dir_all(&confd).unwrap();
        std::fs::write(confd.join("10-a.toml"), "").unwrap();
        std::fs::write(confd.join("notes.txt"), "").unwrap();
        let file = base.join("policy.toml");

        let missing = PolicyRoot::at(&file).unwrap();
        assert_eq!(missing, PolicyRoot::File(file.clone()));
        assert!(missing.fragments().unwrap().is_empty());

        std::fs::write(&file, "").unwrap();
        assert_eq!(
            PolicyRoot::at(&file).unwrap().fragments().unwrap(),
            vec![file.clone()]
        );

        let dir = PolicyRoot::at(&confd).unwrap();
        assert_eq!(dir, PolicyRoot::ConfD(confd.clone()));
        assert_eq!(dir.fragments().unwrap(), vec![confd.join("10-a.toml")]);
    }

    #[test]
    fn line_index_maps_offsets() {
        let src = "# first line\n[[rule]]\nwho = \"*\"\n";
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
    fn home_for_without_user_uses_fallback() {
        let fallback = std::path::Path::new("/root");
        assert_eq!(home_for(None, fallback).unwrap(), fallback);
    }

    #[test]
    fn compile_fragments_merges_and_names_bad_fragment() {
        use cordon_bpf_common::{Dev, FileId, Ino};
        // A deterministic stub resolver gives each path a distinct fake inode (so that
        // /a ≠ /b) without touching the filesystem.
        let resolver = |p: &Path| {
            let ino: u64 = p.to_string_lossy().bytes().map(u64::from).sum();
            Some(FileId::new(Dev(1), Ino(ino)))
        };
        let src = |name: &str, text: &str| PolicySource::system(name, text);
        let frags = [
            src("a.toml", "rules = '''\nallow /usr/bin/ssh read /a\n'''\n"),
            src("b.toml", "rules = '''\naudit * read /b\n'''\n"),
            // 5 fields → an arity error, attributed to this fragment.
            src(
                "bad.toml",
                "rules = '''\nallow /usr/bin/x read /c oops\n'''\n",
            ),
        ];
        let c = compile_fragments(&frags, Path::new("/home/u"), resolver);

        // Rules from the two good fragments merged into one table…
        assert!(c.objects.iter().any(|o| o.path == Path::new("/a")));
        assert!(c.objects.iter().any(|o| o.path == Path::new("/b")));
        // …and the bad fragment surfaced as an error diagnostic naming it.
        assert!(c.has_errors());
        assert!(
            c.diagnostics
                .iter()
                .any(|d| d.loc.source.as_deref() == Some("bad.toml")
                    && d.loc.pos.is_some()
                    && d.message.contains("4 fields")),
            "expected a bad.toml arity error, got: {:?}",
            c.diagnostics
        );
    }

    /// A compile diagnostic about a rule names the fragment the rule came from, and renders
    /// as `source:line:col: severity: message`.
    #[test]
    fn compile_diagnostic_names_the_rules_fragment() {
        let frags = [PolicySource::system(
            "b.toml",
            "\nrules = '''\nallow /usr/bin/ssh read /gone\n'''\n",
        )];
        let c = compile_fragments(&frags, Path::new("/home/u"), |_: &Path| None);
        let d = &c.diagnostics[0];
        assert_eq!(d.loc.source.as_deref(), Some("b.toml"));
        assert!(d.to_string().starts_with("b.toml:3:"), "{d}");
        assert!(d.to_string().contains(": warning: "), "{d}");
    }

    #[test]
    fn check_scope_confines_user_tier_to_home() {
        let home = Path::new("/home/u");
        // A rule reaching outside the owner's home is rejected…
        let out = resolve(
            &parse("rules = '''\nallow /usr/bin/x read /etc/passwd\n'''\n").unwrap(),
            home,
        )
        .unwrap();
        assert!(check_scope(&out, home).is_err());
        // …while one confined to ~ (and absolute paths under it) passes.
        let ok = resolve(
            &parse("rules = '''\nallow /usr/bin/x read ~/.aws\ndeny * read /home/u/.ssh\n'''\n")
                .unwrap(),
            home,
        )
        .unwrap();
        assert!(check_scope(&ok, home).is_ok());
    }

    #[test]
    fn load_expands_includes() {
        // A system fragment that includes a user file → two sources, tagged by tier.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let user_file = dir.join("alice.toml");
        std::fs::write(
            &user_file,
            "rules = '''\nallow /usr/bin/x read ~/.aws\n'''\n",
        )
        .unwrap();
        let sys_file = dir.join("system.toml");
        std::fs::write(
            &sys_file,
            format!(
                "rules = '''\naudit * read /etc/cordon\n'''\n\
                 [[include]]\nuser = \"alice\"\npath = \"{}\"\n",
                user_file.display()
            ),
        )
        .unwrap();

        let sources = PolicyRoot::at(&sys_file).unwrap().load().unwrap();
        assert_eq!(sources.len(), 2);
        assert!(matches!(sources[0].origin, SourceOrigin::System));
        match &sources[1].origin {
            SourceOrigin::User { user } => assert_eq!(user.as_str(), "alice"),
            other => panic!("expected user tier, got {other:?}"),
        }
        // A missing included file is tolerated (empty slot, not an error).
        std::fs::remove_file(&user_file).unwrap();
        let sources = PolicyRoot::at(&sys_file).unwrap().load().unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[1].text, "");
    }

    #[test]
    fn action_and_policy_names_round_trip() {
        // The mutation-hook actions round-trip too: authored name → bit → journal name.
        // `link` has no `file_open` fallback, so a missing table row would surface as
        // `action=read` on a `ln` denial (ADR 0007).
        for (bit, name) in bpf::Action::NAMED {
            assert_eq!(bpf::Action::from_authored(name), Some(bit));
            assert_eq!(bit.to_string(), name);
        }
        for (policy, name) in &bpf::Policy::NAMED[..bpf::Policy::AUTHORED] {
            assert_eq!(parse_policy(name), Ok(*policy));
            assert_eq!(policy.to_string(), *name);
        }
        assert!(
            parse_policy("default-deny")
                .unwrap_err()
                .contains("allow, deny")
        );
    }

    /// The shipped example policy must always parse and resolve, with its group
    /// references, action names and paths. This guards
    /// `packaging/cordon.example.policy.toml` against drift. Compile is left out, because
    /// the example's exes and directories need not exist on the test box.
    #[test]
    fn shipped_example_policy_resolves() {
        let text = include_str!("../../../../packaging/cordon.example.policy.toml");
        let parsed = parse(text).expect("example policy parses");
        let resolved =
            resolve(&parsed, std::path::Path::new("/home/u")).expect("example policy resolves");
        assert!(!resolved.rules.is_empty());
    }

    /// The DSL-form example must parse and resolve too. This guards
    /// `packaging/cordon.example.dsl.policy.toml`, the `rules = '''…'''` form, against
    /// drift in the same way as the `[[rule]]` example above.
    #[test]
    fn shipped_dsl_example_policy_resolves() {
        let text = include_str!("../../../../packaging/cordon.example.dsl.policy.toml");
        let parsed = parse(text).expect("dsl example policy parses");
        let resolved =
            resolve(&parsed, std::path::Path::new("/home/u")).expect("dsl example policy resolves");
        assert!(!resolved.rules.is_empty());
    }
}
