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
mod ruleline;

pub use compile::{CompiledObject, CompiledPolicy, compile, stat_resolver};
pub use parse::{ParsedPolicy, parse};
pub use resolve::{ResolvedPolicy, ResolvedRule, SubjectSpec, resolve};

use crate::Result;
use cordon_bpf_common as bpf;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// A 1-based line/column into the policy source. Column is a byte offset within the
/// line (fine for the ASCII paths/names a policy holds; not grapheme-aware).
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub pos: Option<Pos>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// Parse one policy keyword (the leading field of a DSL rule line). `None` if
    /// unknown — the caller turns that into a diagnostic naming the offending token.
    /// The names match the `#[serde(rename_all = "snake_case")]` the `[[rule]]` form
    /// deserializes, so both authoring surfaces accept exactly the same four words.
    pub fn parse(token: &str) -> Option<PolicyName> {
        Some(match token {
            "allow" => PolicyName::Allow,
            "deny" => PolicyName::Deny,
            "audit" => PolicyName::Audit,
            "silence" => PolicyName::Silence,
            _ => return None,
        })
    }

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

/// The account named by a policy's `user =` header — whose home directory `~` expands
/// against. A newtype over the raw login name so it can't be mixed up with the other
/// strings in the policy layer (paths, group/action names, tokens); (de)serialized
/// transparently from/to the TOML/JSON string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserName(String);

impl UserName {
    /// Wrap a raw login name. Besides the `user =` header (via serde), this is built from a
    /// passwd lookup — e.g. the CLI naming the invoking user for `policy edit`.
    pub fn new(name: impl Into<String>) -> UserName {
        UserName(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for UserName {
    type Err = std::convert::Infallible;
    /// Any non-empty string is a candidate login name; existence is checked later against
    /// `/etc/passwd` (via [`home_for`]). Lets `--user` parse straight into this newtype.
    fn from_str(s: &str) -> std::result::Result<UserName, Self::Err> {
        Ok(UserName::new(s))
    }
}

impl fmt::Display for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a `[group.{subject,object,action}.NAME]` group — the key into a group
/// namespace, referenced by `@NAME` (DESIGN §15.7). A newtype so a group identifier can't
/// be confused with the policy layer's other strings (paths, leaves, class names); used as
/// the `Groups` map key, in [`super::resolve`]'s cycle stack, and as a `Token::Group`
/// payload. (De)serialized transparently from/to a TOML table key / string.
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

/// The name of a **blessing class** (DESIGN §16.3) as authored in policy — the string in a
/// `[group.subject.*] blessing = "<name>"` predicate and in `cordon bless --class <name>`. A
/// newtype (like [`UserName`]) so it can't be mixed up with the policy layer's other strings
/// (group names, paths, tokens); the compiler assigns each distinct one a dense
/// [`cordon_bpf_common::ClassId`]. (De)serialized transparently from/to a TOML/JSON string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClassName(String);

impl ClassName {
    pub fn new(name: impl Into<String>) -> ClassName {
        ClassName(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for ClassName {
    type Err = std::convert::Infallible;
    /// Any string is a candidate class name; whether the policy actually declares it is
    /// checked against the compiled registry. Lets `--class` parse straight into this newtype.
    fn from_str(s: &str) -> std::result::Result<ClassName, Self::Err> {
        Ok(ClassName::new(s))
    }
}

impl fmt::Display for ClassName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolve which home directory `~` expands against for a policy: the home of its
/// `user =` header (looked up in `/etc/passwd`), or `fallback` (the daemon/CLI `$HOME`)
/// when the policy names no user. Errors if the named account has no `/etc/passwd`
/// entry — a root-owned policy naming a missing user is a misconfiguration, not a
/// silent fall-through to the wrong home.
pub fn home_for(user: Option<&UserName>, fallback: &Path) -> Result<PathBuf> {
    let Some(user) = user else {
        return Ok(fallback.to_path_buf());
    };
    let passwd = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| crate::Error::msg(format!("read /etc/passwd: {e}")))?;
    home_in_passwd(&passwd, user.as_str()).ok_or_else(|| {
        crate::Error::msg(format!(
            "policy user {:?} not found in /etc/passwd",
            user.as_str()
        ))
    })
}

/// The home field (index 5) of the `/etc/passwd` line whose login name (index 0)
/// matches `user`. Split from [`home_for`] so it unit-tests without the real file.
fn home_in_passwd(passwd: &str, user: &str) -> Option<PathBuf> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next() != Some(user) {
            return None;
        }
        // name(0):passwd(1):uid(2):gid(3):gecos(4):home(5):shell(6) — name consumed,
        // skip passwd..gecos, take home.
        fields.nth(4).map(PathBuf::from)
    })
}

/// Which tier a [`PolicySource`] belongs to (DESIGN §15.8). Determines how `~` expands,
/// whether the rules are home-scoped, and (later, once user files move into the home) the
/// system-is-a-floor precedence — for now the tiers merge flat, so this only drives `~`
/// resolution and the home-scope lint.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceOrigin {
    /// Root-authored, full authority: the system policy and its conf.d fragments.
    #[default]
    System,
    /// Pulled in by a system fragment's `[[include]]`, scoped to `user`'s home — a
    /// user-tier policy. Its `~` expands against `user`'s home and every object path it
    /// names must resolve under that home (enforced at compile).
    User { user: UserName },
}

/// One named policy fragment: a source name (a file path, for diagnostics), its text, and
/// its [`SourceOrigin`] (tier). The unit of the **conf.d split** + the **system/user tier**
/// model (DESIGN §15.8) — fragments are parsed/resolved independently (groups are
/// file-local; `~` uses the fragment's owning user), then merged into one compiled table.
/// Sent over IPC on `apply`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicySource {
    pub name: String,
    pub text: String,
    #[serde(default)]
    pub origin: SourceOrigin,
}

impl PolicySource {
    /// A system-tier fragment (the common case — `read_sources` and a single-file policy).
    pub fn system(name: impl Into<String>, text: impl Into<String>) -> PolicySource {
        PolicySource {
            name: name.into(),
            text: text.into(),
            origin: SourceOrigin::System,
        }
    }
}

/// Read a policy path into [`PolicySource`]s: a single file → one fragment; a directory
/// → every `*.toml` inside it, **sorted by name** for deterministic load order (the
/// conf.d split, DESIGN §15.8). Errors on I/O or an empty directory — a policy that
/// resolves to no fragments is a misconfiguration, not an empty allow-all.
pub fn read_sources(path: &Path) -> Result<Vec<PolicySource>> {
    let meta = std::fs::metadata(path)
        .map_err(|e| crate::Error::msg(format!("policy {}: {e}", path.display())))?;
    if !meta.is_dir() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::msg(format!("read policy {}: {e}", path.display())))?;
        return Ok(vec![PolicySource::system(path.display().to_string(), text)]);
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(path)
        .map_err(|e| crate::Error::msg(format!("read policy dir {}: {e}", path.display())))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(crate::Error::msg(format!(
            "policy dir {} has no *.toml fragments",
            path.display()
        )));
    }
    files
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p)
                .map_err(|e| crate::Error::msg(format!("read policy {}: {e}", p.display())))?;
            Ok(PolicySource::system(p.display().to_string(), text))
        })
        .collect()
}

/// Read the full policy: the system fragments at `path` ([`read_sources`]) **plus** every
/// user-tier file a system fragment pulls in via `[[include]]` (DESIGN §15.8). Each
/// include names the owning `user` (whose home scopes its rules) and a `path`; the file is
/// read and tagged [`SourceOrigin::User`]. A missing included file is treated as empty (the
/// user simply hasn't authored their policy yet) — it still occupies a slot, so
/// `cordon policy edit --user` can create it. This is what the CLI ships on `apply` and the
/// daemon reads at startup; the pure [`compile_fragments`] then merges every tier.
pub fn load_policy(path: &Path) -> Result<Vec<PolicySource>> {
    let mut sources = read_sources(path)?;
    let mut included = Vec::new();
    for src in &sources {
        // Best-effort: a system fragment that doesn't parse still surfaces its error in
        // `compile_fragments`; we just can't read its includes, so skip it here.
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
                        inc.path()
                    )));
                }
            };
            included.push(PolicySource {
                name: inc.path().to_string(),
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

/// The file a system `[[include]]` binds to `user`, if any — what `cordon policy edit
/// --user <user>` opens. Reads the system fragments at `policy_root` and returns the first
/// matching include's `path`. `Ok(None)` if no system fragment includes `user`.
pub fn user_include_path(policy_root: &Path, user: &str) -> Result<Option<PathBuf>> {
    for src in &read_sources(policy_root)? {
        let Ok(parsed) = parse(&src.text) else {
            continue;
        };
        for inc in parsed.includes() {
            if inc.user().as_str() == user {
                return Ok(Some(PathBuf::from(inc.path())));
            }
        }
    }
    Ok(None)
}

/// Parse → resolve → **merge** → compile a set of fragments into one decision table.
/// Each fragment resolves independently — its `@`-groups are file-local and its `~`
/// expands against its own `user =` header (else `fallback_home`) — then the resolved
/// rules are concatenated and compiled together, so precedence (object/subject
/// specificity then deny>allow, all source-order-independent) applies across the whole
/// set. A fragment's parse/resolve failure becomes an error diagnostic naming it, so one
/// bad fragment fails the apply via [`CompiledPolicy::has_errors`] rather than silently
/// dropping its rules.
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
    // collapses to one); `BTreeSet` keeps them sorted so the compiler's `ClassId`s are stable.
    let mut blessing_classes = std::collections::BTreeSet::new();
    let mut errors = Vec::new();
    for src in sources {
        let resolved = parse(&src.text).and_then(|parsed| match &src.origin {
            // System tier: `~` uses the fragment's own `user =` header (else the fallback);
            // full authority, no scope restriction.
            SourceOrigin::System => {
                let home = home_for(parsed.user(), fallback_home)?;
                resolve(&parsed, &home)
            }
            // User tier: the owning user is fixed by the include, `~` expands against *their*
            // home, every object must resolve under it, and it may not pull in further files.
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
                rules.extend(r.rules);
                blessing_classes.extend(r.blessing_classes);
            }
            Err(e) => errors.push(Diagnostic::error(None, format!("{}: {e}", src.name))),
        }
    }
    let resolved = ResolvedPolicy {
        rules,
        blessing_classes: blessing_classes.into_iter().collect(),
    };
    let mut compiled = compile(&resolved, resolve_fileid);
    // Surface per-fragment parse/resolve errors ahead of the compile diagnostics.
    compiled.diagnostics.splice(0..0, errors);
    compiled
}

/// Enforce the user-tier scope: every object a user policy names must resolve under the
/// owning user's `home` (DESIGN §15.8). Rejects the first out-of-scope object with a
/// `line:col`-prefixed error — a user can only govern paths in their own home, so a rule
/// reaching into `/etc` or another user's home is a hard error, not a silent drop.
fn check_scope(resolved: &ResolvedPolicy, home: &Path) -> Result<()> {
    for rule in &resolved.rules {
        for obj in &rule.objects {
            if !crate::paths::is_within(obj, home) {
                let loc = rule.pos.map(|p| format!("{p}: ")).unwrap_or_default();
                return Err(crate::Error::msg(format!(
                    "{loc}object {} is outside the owner's home {} — a user policy may only \
                     govern paths under it",
                    obj.display(),
                    home.display(),
                )));
            }
        }
    }
    Ok(())
}

/// Expand a leading `~` to `home`, then lexically normalize. Errors if the result is
/// neither absolute nor `~`-relative — policy paths must be unambiguous (no
/// cwd-relative surprises in a reviewable, root-owned file; DESIGN §15.8).
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
    fn home_in_passwd_finds_the_home_field() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      alice:x:1000:1000:Alice,,,:/home/alice:/usr/bin/fish\n";
        assert_eq!(home_in_passwd(passwd, "alice"), Some("/home/alice".into()));
        assert_eq!(home_in_passwd(passwd, "root"), Some("/root".into()));
        assert_eq!(home_in_passwd(passwd, "ghost"), None);
    }

    #[test]
    fn home_for_without_user_uses_fallback() {
        let fallback = std::path::Path::new("/root");
        assert_eq!(home_for(None, fallback).unwrap(), fallback);
    }

    #[test]
    fn compile_fragments_merges_and_names_bad_fragment() {
        use cordon_bpf_common::{Dev, FileId, Ino};
        // Deterministic stub resolver: a distinct fake inode per path (so /a ≠ /b),
        // no filesystem dependency.
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
                .any(|d| d.message.contains("bad.toml") && d.message.contains("4 fields")),
            "expected a bad.toml arity error, got: {:?}",
            c.diagnostics
        );
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
    fn load_policy_expands_includes() {
        // A system fragment that includes a user file → two sources, tagged by tier.
        let dir = std::env::temp_dir().join(format!("cordon-inc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let user_file = dir.join("nb.toml");
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
                 [[include]]\nuser = \"nb\"\npath = \"{}\"\n",
                user_file.display()
            ),
        )
        .unwrap();

        let sources = load_policy(&sys_file).unwrap();
        assert_eq!(sources.len(), 2);
        assert!(matches!(sources[0].origin, SourceOrigin::System));
        match &sources[1].origin {
            SourceOrigin::User { user } => assert_eq!(user.as_str(), "nb"),
            other => panic!("expected user tier, got {other:?}"),
        }
        // A missing included file is tolerated (empty slot, not an error).
        std::fs::remove_file(&user_file).unwrap();
        let sources = load_policy(&sys_file).unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[1].text, "");
        std::fs::remove_dir_all(&dir).ok();
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
        assert!(!resolved.rules.is_empty());
    }

    /// The DSL-form example must parse + resolve too — guards
    /// `packaging/cordon.example.dsl.policy.toml` (the `rules = '''…'''` surface) against
    /// drift, the same way the `[[rule]]` example is guarded above.
    #[test]
    fn shipped_dsl_example_policy_resolves() {
        let text = include_str!("../../../../packaging/cordon.example.dsl.policy.toml");
        let parsed = parse(text).expect("dsl example policy parses");
        let resolved =
            resolve(&parsed, std::path::Path::new("/home/u")).expect("dsl example policy resolves");
        assert!(!resolved.rules.is_empty());
    }
}
