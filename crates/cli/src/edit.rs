//! `cordon policy edit` — the **sudoedit analog** for the root-owned text policy
//! (DESIGN §15.8). Editing the policy that guards every secret has two hazards a plain
//! `sudo $EDITOR /etc/cordon/policy.toml` walks straight into:
//!
//!  1. **A same-uid escalation.** cordon's in-scope adversary is a same-uid scraper
//!     (DESIGN §2) — which can write your `~/.vimrc`, editor plugins, `$EDITOR`. Run the
//!     editor as root and any of those execute as root. So the *standard* way to edit the
//!     policy is a clean escalation for exactly the attacker cordon exists to stop.
//!  2. **On-disk vs. live drift.** `apply` is a separate step; edit-and-forget leaves the
//!     file ahead of the kernel, and a syntactically broken file persists even though the
//!     daemon refuses to load it.
//!
//! This command closes both, borrowing from three tools at once: sudoedit (only a dumb
//! byte copy is privileged; see [`editor_identity`]), visudo (validate before install;
//! reject a broken policy and re-prompt), and `cordon policy apply` (push the validated
//! result to the live kernel in the same step; see [`Session::assess`]).
//!
//! Invoked as `sudo cordon policy edit`, the CLI stays root in the parent, which reads,
//! validates, applies and writes the root-owned file; only the forked editor child drops
//! privilege. No new IPC: the read is a direct file read, validation is the in-process
//! compiler (the same one `policy check` runs), and the commit reuses `PolicyApply`.

use cordon_core::policy::{self, Diagnostic, PolicyRoot, PolicySource, SourceOrigin, UserName};
use cordon_core::proto::{Request, Response};
use cordon_core::{Context, Error, Result, config};
use nix::unistd::{Gid, Uid};
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};

use crate::{Client, sys};

/// Final fallback editor when no `$*EDITOR` is set, and the program when an editor string
/// is all whitespace. The one place `vi` is named.
const DEFAULT_EDITOR: &str = "vi";

/// Starter buffer for a brand-new policy file — a comment header so an empty file isn't a
/// blank canvas. The `rules` block is empty (compiles to zero rules); saving it untouched
/// counts as "no change" (see [`Seed`]), so seeding it never silently wipes enforcement.
const NEW_POLICY_TEMPLATE: &str = "\
# cordon policy — the flat rule model (DESIGN §15). One rule per line:
#     POLICY  SUBJECT  ACTION  OBJECT
# e.g. allow  /usr/bin/ssh  read  ~/.ssh
# `audit` observes an object, `deny` enforces it; there is no global mode.
# Full syntax: packaging/cordon.example.dsl.policy.toml.
#
# Per-user policy: add a `user = \"name\"` header so `~` expands to their home.

rules = '''
'''
";

/// Whether to permit running the editor as root when there is no unprivileged invoker.
/// `main` builds this from the `--allow-root-editor` flag, so the bool stops at the CLI
/// boundary and the rest of the module reasons over the intent.
#[derive(Clone, Copy)]
pub(crate) enum RootEditor {
    Refuse,
    Allow,
}

impl RootEditor {
    /// Map the `--allow-root-editor` flag to the intent.
    pub(crate) fn from_flag(allow_root_editor: bool) -> RootEditor {
        if allow_root_editor {
            RootEditor::Allow
        } else {
            RootEditor::Refuse
        }
    }
}

/// The editor to launch: a command string — program plus optional args, e.g. `emacs -nw`
/// — not a bare path, so it owns the env lookup and the program/args split rather than
/// leaving a loose `String` to be re-split at each use.
struct EditorCommand(String);

impl EditorCommand {
    /// `$CORDON_EDITOR` → `$VISUAL` → `$EDITOR` → `vi` (sudoedit's lookup, with a cordon
    /// override on top).
    fn lookup() -> EditorCommand {
        for var in ["CORDON_EDITOR", "VISUAL", "EDITOR"] {
            if let Some(v) = std::env::var_os(var)
                && !v.is_empty()
            {
                return EditorCommand(v.to_string_lossy().into_owned());
            }
        }
        EditorCommand(DEFAULT_EDITOR.to_string())
    }

    /// Split into `(program, args)`. Whitespace-split so `EDITOR="emacs -nw"` works; an
    /// all-whitespace string falls back to the default program.
    fn program_and_args(&self) -> (&str, std::str::SplitWhitespace<'_>) {
        let mut parts = self.0.split_whitespace();
        let prog = parts.next().unwrap_or(DEFAULT_EDITOR);
        (prog, parts)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who the editor process runs as.
#[derive(Clone)]
enum EditorAs {
    /// Drop to this user in the editor child; the parent stays root. Carries the user's own
    /// `$HOME`/name so the editor reads *their* config and writes *their* state, not root's
    /// (under `sudo` the inherited `HOME` is still `/root`).
    User {
        uid: Uid,
        gid: Gid,
        home: PathBuf,
        name: UserName,
    },
    /// Run as the current user — we're already unprivileged, or root explicitly opted in.
    Current,
}

/// The starting editor buffer and where it came from. The variant *is* the "is this a new
/// file?" signal, so there's no separate bool to keep in sync.
enum Seed {
    Existing(String),
    New(String),
}

impl Seed {
    fn text(&self) -> &str {
        match self {
            Seed::Existing(s) | Seed::New(s) => s,
        }
    }
}

/// What to do with an edited buffer after validation + the apply attempt.
enum Verdict {
    /// The daemon accepted and swapped it live → persist the file.
    Apply,
    /// The daemon is unreachable, but the policy is locally valid → persist, warn it's
    /// not enforced yet.
    SaveOnly,
    /// Errors (local or daemon-reported) were printed → offer to edit again.
    Reedit,
}

/// Answer to the visudo-style re-edit prompt.
enum Prompt {
    Edit,
    Quit,
}

/// What `cordon policy edit` opens.
pub(crate) enum EditTarget {
    /// A system-tier policy file: the configured path (`--system`), a conf.d fragment
    /// name, or a path (`FILE`).
    System(Option<PathBuf>),
    /// The user-tier policy a system `[[include]]` binds to this user.
    User(UserName),
}

/// The mutually-exclusive ways to name what to edit (clap-enforced). Naming nothing
/// edits your own tier.
#[derive(clap::Args, Clone, Debug)]
pub struct EditTargetArgs {
    /// Policy file to edit, system tier (for a conf.d directory, name a fragment,
    /// e.g. `local` → `…/conf.d/local.toml`).
    pub file: Option<PathBuf>,
    /// Edit the user-tier policy a system `[[include]]` binds to this user (its rules
    /// are confined to that user's home).
    #[arg(long, conflicts_with = "file")]
    pub user: Option<UserName>,
    /// Edit the *system* policy at the configured path, rather than your own user tier.
    #[arg(long, conflicts_with_all = ["file", "user"])]
    pub system: bool,
}

impl EditTargetArgs {
    /// Which policy these flags name. `invoker` is consulted only for the bare form, so
    /// naming a target explicitly never depends on resolving one.
    fn resolve(self, invoker: impl FnOnce() -> Result<UserName>) -> Result<EditTarget> {
        Ok(match self {
            EditTargetArgs { system: true, .. } => EditTarget::System(None),
            EditTargetArgs {
                user: Some(user), ..
            } => EditTarget::User(user),
            EditTargetArgs {
                file: Some(file), ..
            } => EditTarget::System(Some(file)),
            _ => EditTarget::User(invoker()?),
        })
    }
}

/// Returns the login name of the account whose tier a bare `cordon policy edit` opens
/// (see [`invoker_uid`]). Errors when that uid has no passwd entry.
fn invoking_user() -> Result<UserName> {
    let uid = invoker_uid(
        Uid::from_raw(config::euid()),
        std::env::var("SUDO_UID").ok().as_deref(),
    )?;
    let (name, _home) = sys::user_identity(uid)
        .ok_or_else(|| Error::msg(format!("uid {uid} has no passwd entry")))?;
    Ok(name)
}

/// Returns the uid whose tier a bare `cordon policy edit` opens: the caller when
/// unprivileged, the `SUDO_UID` invoker under `sudo`. Errors when real root has no
/// non-root `SUDO_UID` (a root login, a cron job, sudo to root), since that has no own
/// tier and must name `--system` or `--user` rather than silently edit the system policy;
/// also errors on a malformed `SUDO_UID`.
fn invoker_uid(euid: Uid, sudo_uid: Option<&str>) -> Result<Uid> {
    if !euid.is_root() {
        return Ok(euid);
    }
    let no_invoker = || {
        Error::msg(
            "running as root with no invoking user — name what to edit: \
             `--system` for the system policy, or `--user NAME` for a user tier",
        )
    };
    let uid = Uid::from_raw(
        sudo_uid
            .ok_or_else(no_invoker)?
            .parse::<u32>()
            .map_err(|_| Error::msg(format!("invalid SUDO_UID: {:?}", sudo_uid.unwrap())))?,
    );
    if uid.is_root() {
        return Err(no_invoker());
    }
    Ok(uid)
}

/// `cordon policy edit`. Returns the process exit code.
pub fn run(target: EditTargetArgs, root_editor: RootEditor, client: &Client) -> ExitCode {
    match target
        .resolve(invoking_user)
        .and_then(|t| Session::open(t, root_editor, client))
        .and_then(Session::edit_loop)
    {
        Ok(code) => code,
        Err(e) => {
            eprintln!("cordon: {e}");
            ExitCode::FAILURE
        }
    }
}

/// One edit session: the resolved paths and the runtime knobs the loop reuses each round.
struct Session {
    /// What the daemon reads on its next restart (the configured `policy`) — the set the
    /// candidate is validated against.
    policy_root: PolicyRoot,
    /// The single file opened in the editor (the same thing in the one-file case, or a
    /// fragment under a conf.d directory).
    target: PathBuf,
    /// The tier the edited file contributes as — `System`, or `User` for a `--user` edit,
    /// so the candidate validates `target` with the right scope even before any
    /// `[[include]]` exists on disk (bootstrap).
    target_origin: SourceOrigin,
    /// A pending `[[include]]` to register — `Some` only for a first-time `--user` edit
    /// with no binding yet (see [`Session::save`]).
    scaffold: Option<Scaffold>,
    /// `$HOME` for `~`-expansion in the local validation compile.
    home: PathBuf,
    /// The daemon control socket for the apply.
    socket: PathBuf,
    editor: EditorCommand,
    editor_as: EditorAs,
    seed: Seed,
    tmp: TempEdit,
}

impl Session {
    /// Resolve paths, decide who the editor runs as, seed the temp copy, and print the
    /// banner — everything before the first keystroke.
    fn open(target: EditTarget, root_editor: RootEditor, client: &Client) -> Result<Session> {
        let policy_root = PolicyRoot::at(&client.policy_path(None)?)?;
        let (target, target_origin, scaffold) = match target {
            EditTarget::System(file) => (
                resolve_target(file.as_deref(), &policy_root)?,
                SourceOrigin::System,
                None,
            ),
            // `--user`: the file a system `[[include]]` binds — or, if none exists yet, the
            // convention path, with a pending include to register on first save (bootstrap).
            EditTarget::User(user) => {
                let (path, scaffold) = resolve_user_target(&policy_root, user.clone())?;
                (path, SourceOrigin::User { user }, scaffold)
            }
        };
        if target.is_dir() {
            return Err(Error::msg(format!(
                "{} is a directory, not a policy file",
                target.display()
            )));
        }
        let editor_as = editor_identity(root_editor)?;
        let seed = read_seed(&target)?;
        let tmp = TempEdit::create(&target, seed.text(), &editor_as)?;
        let session = Session {
            policy_root,
            target,
            target_origin,
            scaffold,
            home: crate::home(),
            socket: client.socket()?,
            editor: EditorCommand::lookup(),
            editor_as,
            seed,
            tmp,
        };
        session.announce();
        Ok(session)
    }

    fn announce(&self) {
        let new = matches!(self.seed, Seed::New(_));
        let who = match &self.editor_as {
            EditorAs::User { uid, .. } => format!(" as uid {uid}"),
            EditorAs::Current if config::is_root() => " as root (--allow-root-editor)".to_string(),
            EditorAs::Current => String::new(),
        };
        eprintln!(
            "cordon: editing {}{} with {:?}{who}",
            self.target.display(),
            if new { " (new)" } else { "" },
            self.editor.as_str(),
        );
        if let Some(s) = &self.scaffold {
            eprintln!(
                "cordon: user {:?} has no `[[include]]` yet — one will be registered in {} \
                 once you save a valid policy.",
                s.user.as_str(),
                s.fragment.display(),
            );
        }
    }

    /// The visudo loop: edit → no-op-or-validate → apply → persist, re-editing on rejection.
    fn edit_loop(self) -> Result<ExitCode> {
        loop {
            self.run_editor()?;
            let edited = read_edited(&self.tmp.file)?;
            // An unchanged buffer is a no-op — *unless* we still owe an include registration
            // (a `--user` bootstrap), where even an untouched-but-valid file should be
            // registered and applied.
            if edited == self.seed.text() && self.scaffold.is_none() {
                println!("cordon: no changes — policy left unchanged");
                return Ok(ExitCode::SUCCESS);
            }

            // The candidate is the *whole* policy with `target` substituted at its tier, so a
            // conf.d fragment or a user file is validated against the rest, not in isolation.
            let candidate = candidate_sources(
                &self.policy_root,
                &self.target,
                &edited,
                &self.target_origin,
            )?;
            match self.assess(candidate)? {
                Verdict::Apply => {
                    self.save(&edited)?;
                    println!("cordon: applied and saved {}", self.target.display());
                    return Ok(ExitCode::SUCCESS);
                }
                Verdict::SaveOnly => {
                    self.save(&edited)?;
                    println!(
                        "cordon: saved {} — NOT applied (daemon unreachable on {}). \
                         Run `cordon policy apply` to enforce.",
                        self.target.display(),
                        self.socket.display(),
                    );
                    return Ok(ExitCode::SUCCESS);
                }
                Verdict::Reedit => match reprompt()? {
                    Prompt::Edit => continue,
                    Prompt::Quit => return Ok(ExitCode::FAILURE),
                },
            }
        }
    }

    /// Persists the edited file, then registers any pending `[[include]]` (the `--user`
    /// bootstrap). Registering last, only after the file validated and saved, means a
    /// cancelled or rejected edit never leaves a stale binding.
    fn save(&self, edited: &str) -> Result<()> {
        self.tmp.commit(&self.target, edited)?;
        if let Some(s) = &self.scaffold {
            s.register()?;
            eprintln!(
                "cordon: registered `[[include]]` for user {:?} in {}",
                s.user.as_str(),
                s.fragment.display(),
            );
        }
        Ok(())
    }

    /// Launch the editor on the temp file and wait. A non-zero exit (e.g. `:cq`) discards.
    fn run_editor(&self) -> Result<()> {
        let status = spawn_editor(&self.editor, &self.tmp.file, &self.editor_as).map_err(|e| {
            Error::msg(format!(
                "failed to run editor {:?}: {e}",
                self.editor.as_str()
            ))
        })?;
        if !status.success() {
            return Err(Error::msg(format!(
                "editor {:?} exited with {status} — discarding changes",
                self.editor.as_str()
            )));
        }
        Ok(())
    }

    /// Runs visudo's two checks and returns the [`Verdict`], printing diagnostics: a fast
    /// local compile (also the only check when the daemon is down), then the daemon's
    /// authoritative mount-aware compile + live swap. The caller writes the file only on
    /// [`Verdict::Apply`], after the daemon accepted it, so on disk matches live with no
    /// rollback; or on [`Verdict::SaveOnly`], when no daemon is listening
    /// ([`is_daemon_down`]), and then reports it as not applied. Errors when the daemon
    /// answers with an error or an unexpected reply, or fails mid-request.
    fn assess(&self, candidate: Vec<PolicySource>) -> Result<Verdict> {
        let compiled = policy::compile_fragments(&candidate, &self.home, policy::stat_resolver);
        print_diags(&compiled.diagnostics);
        if compiled.has_errors() {
            eprintln!("cordon: policy has errors.");
            return Ok(Verdict::Reedit);
        }
        let request = Request::PolicyApply { sources: candidate };
        match crate::round_trip(&self.socket, &request).and_then(Response::into_result) {
            Ok(Response::PolicyApplied {
                applied: true,
                diagnostics,
            }) => {
                print_diags(&diagnostics);
                Ok(Verdict::Apply)
            }
            Ok(Response::PolicyApplied {
                applied: false,
                diagnostics,
            }) => {
                print_diags(&diagnostics);
                eprintln!("cordon: the daemon rejected the policy.");
                Ok(Verdict::Reedit)
            }
            Ok(other) => Err(Error::msg(format!("unexpected daemon response: {other:?}"))),
            Err(e) if is_daemon_down(&e) => Ok(Verdict::SaveOnly),
            Err(e) => Err(e),
        }
    }
}

/// Checks whether `err` means no daemon is listening on the socket, as opposed to a daemon
/// that answered badly or died mid-request.
fn is_daemon_down(err: &Error) -> bool {
    matches!(err, Error::Io(e) if matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    ))
}

/// Resolve which file to open from the optional CLI argument and the configured policy root:
///
/// - **No argument** → the policy path itself when it's a single file; a conf.d *directory*
///   has no single file to open, so the user must name a fragment.
/// - **A bare name** (no `/`, e.g. `nb`) when the policy is a conf.d directory → the fragment
///   `<root>/<name>.toml` (`.toml` appended when the name carries no extension). The
///   convenient form: `cordon policy edit local` edits `…/conf.d/local.toml`.
/// - **Anything with a path separator / absolute** → taken literally.
fn resolve_target(file: Option<&Path>, policy_root: &PolicyRoot) -> Result<PathBuf> {
    match (file, policy_root) {
        (None, PolicyRoot::ConfD(dir)) => Err(Error::msg(format!(
            "policy path {} is a conf.d directory — name a fragment to edit, \
             e.g. `cordon policy edit local`",
            dir.display(),
        ))),
        (None, PolicyRoot::File(path)) => Ok(path.clone()),
        (Some(arg), PolicyRoot::ConfD(dir)) if is_bare_name(arg) => {
            let mut p = dir.join(arg);
            if p.extension().is_none() {
                p.set_extension("toml");
            }
            Ok(p)
        }
        (Some(arg), _) => Ok(arg.to_path_buf()),
    }
}

/// A single-component relative path like `local` or `local.toml` (no separators) — a fragment
/// *name* rather than a path to a particular file.
fn is_bare_name(p: &Path) -> bool {
    !p.as_os_str().is_empty()
        && p.parent()
            .map(|parent| parent.as_os_str().is_empty())
            .unwrap_or(true)
}

/// Decides who the editor runs as: never root unless `root_editor` allows it. An
/// unprivileged caller is already the right user. Under `sudo`, the editor drops to
/// `SUDO_UID`/`SUDO_GID` with that user's own home and name ([`EditorAs::User`]). Errors
/// when root has no non-root invoker (no `SUDO_UID`/`SUDO_GID`, or sudo to root) and
/// `root_editor` is [`RootEditor::Refuse`], because a root editor is the same-uid
/// escalation the module doc describes; also errors when `SUDO_UID`/`SUDO_GID` don't
/// parse or the uid has no passwd home.
fn editor_identity(root_editor: RootEditor) -> Result<EditorAs> {
    if !config::is_root() {
        return Ok(EditorAs::Current);
    }
    let refuse = |what: &str| -> Result<EditorAs> {
        match root_editor {
            RootEditor::Allow => Ok(EditorAs::Current),
            RootEditor::Refuse => Err(Error::msg(format!(
                "{what} — refusing to launch the editor as root (a same-uid attacker who \
                 can write your editor config would gain root). Run as your user via \
                 `sudo cordon policy edit`, or pass --allow-root-editor to override."
            ))),
        }
    };
    let (Ok(u), Ok(g)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) else {
        return refuse("running as root without sudo");
    };
    let uid = Uid::from_raw(
        u.parse::<u32>()
            .map_err(|_| Error::msg(format!("invalid SUDO_UID: {u:?}")))?,
    );
    let gid = Gid::from_raw(
        g.parse::<u32>()
            .map_err(|_| Error::msg(format!("invalid SUDO_GID: {g:?}")))?,
    );
    if uid.is_root() {
        return refuse("the invoking user is root");
    }
    let (name, home) = sys::user_identity(uid)
        .ok_or_else(|| Error::msg(format!("cannot resolve home directory for uid {uid}")))?;
    Ok(EditorAs::User {
        uid,
        gid,
        home,
        name,
    })
}

/// Spawns the editor on `file` and waits for it, running it as `editor_as` says.
fn spawn_editor(
    editor: &EditorCommand,
    file: &Path,
    editor_as: &EditorAs,
) -> io::Result<ExitStatus> {
    let (prog, args) = editor.program_and_args();
    let mut cmd = Command::new(prog);
    cmd.args(args).arg(file);
    if let EditorAs::User {
        uid,
        gid,
        home,
        name,
    } = editor_as
    {
        cmd.env("HOME", home)
            .env("USER", name.as_str())
            .env("LOGNAME", name.as_str());
        sys::drop_to_on_exec(&mut cmd, *uid, *gid);
    }
    cmd.status()
}

/// Build the policy set to validate + apply: the whole effective policy of `policy_root`
/// (system fragments **and** `[[include]]`d user-tier files), with `target`'s text replaced
/// by `new_text`. Matching is by normalized path so a fragment — or a user file the system
/// includes — lines up with its on-disk source, **preserving its tier** so the scope check
/// still fires. A `target` not present in the set (a brand-new system file) is appended as
/// system tier.
fn candidate_sources(
    policy_root: &PolicyRoot,
    target: &Path,
    new_text: &str,
    target_origin: &SourceOrigin,
) -> Result<Vec<PolicySource>> {
    use cordon_core::paths::normalize;
    // An empty conf.d directory (no `*.toml` yet) is a hard error from `load_policy`, but
    // here it just means "no siblings": the new fragment is the whole policy. Any other
    // load error must fail, or the candidate would silently drop the unreadable siblings
    // and the apply would replace the live policy with this one fragment.
    let mut sources = if policy_root.fragments()?.is_empty() {
        Vec::new()
    } else {
        policy::load_policy(policy_root.path())?
    };
    let tgt = normalize(target);
    match sources
        .iter_mut()
        .find(|s| normalize(Path::new(&s.name)) == tgt)
    {
        // Already in the set (a conf.d fragment, or an included user file) — keep its tier.
        Some(s) => s.text = new_text.to_string(),
        // Not present: a brand-new system file, or a `--user` bootstrap whose include
        // doesn't exist yet — tag it at the target's tier so the scope check still fires.
        None => sources.push(PolicySource {
            name: target.display().to_string(),
            text: new_text.to_string(),
            origin: target_origin.clone(),
        }),
    }
    Ok(sources)
}

/// Resolve a `--user` target. An existing `[[include]]` for the user wins (edit it in
/// place). Otherwise the file goes at the convention path and a [`Scaffold`] is returned to
/// register the binding once the edit validates and saves.
fn resolve_user_target(
    policy_root: &PolicyRoot,
    user: UserName,
) -> Result<(PathBuf, Option<Scaffold>)> {
    if let Some(path) = policy::user_include_path(policy_root.path(), user.as_str())? {
        return Ok((path, None));
    }
    let path = convention_user_path(policy_root, &user);
    let scaffold = Scaffold {
        fragment: include_fragment(policy_root),
        user,
        path: path.clone(),
    };
    Ok((path, Some(scaffold)))
}

/// Where a user's tier file lives when no `[[include]]` names it yet: a `users/<name>.toml`
/// sibling of the system policy — `/etc/cordon/conf.d` → `/etc/cordon/users/<name>.toml`.
/// Deliberately *outside* the conf.d directory, so it isn't auto-loaded as a system
/// fragment; only the include pulls it in.
fn convention_user_path(policy_root: &PolicyRoot, user: &UserName) -> PathBuf {
    let base = policy_root
        .path()
        .parent()
        .unwrap_or_else(|| Path::new("/"));
    base.join("users").join(format!("{}.toml", user.as_str()))
}

/// The system fragment a scaffolded `[[include]]` is appended to: a `00-users.toml` inside
/// the conf.d directory (so it loads as a system fragment), or the single policy file.
fn include_fragment(policy_root: &PolicyRoot) -> PathBuf {
    match policy_root {
        PolicyRoot::ConfD(dir) => dir.join("00-users.toml"),
        PolicyRoot::File(path) => path.clone(),
    }
}

/// A pending `[[include]]` registration — the `--user` bootstrap, registered by
/// [`Session::save`].
struct Scaffold {
    /// The system fragment to append the `[[include]]` to.
    fragment: PathBuf,
    /// The owning user (and the home its rules are scoped to).
    user: UserName,
    /// The included path (== the edited user file).
    path: PathBuf,
}

impl Scaffold {
    /// Append the `[[include]] user = … path = …` table to the system fragment (creating it
    /// if absent), atomically. Idempotent in practice: only constructed when no include for
    /// the user existed.
    fn register(&self) -> Result<()> {
        let mut text = match fs::read_to_string(&self.fragment) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(Error::msg(format!("read {}: {e}", self.fragment.display()))),
        };
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        // `{:?}` renders a TOML basic string for these ASCII login names / paths.
        text.push_str(&format!(
            "\n[[include]]\nuser = {:?}\npath = {:?}\n",
            self.user.as_str(),
            self.path.display().to_string(),
        ));
        install_atomically(&self.fragment, &text)
    }
}

/// Mode for a policy file this command creates (see [`install_atomically`]). `0644`
/// root-owned matches the rest of the tree and is what an unprivileged `cordon policy
/// check` needs to read; the file holds rules — paths and exe names — not credentials, and
/// the daemon already serves a summary of them to any local user (DESIGN §15.8).
const NEW_POLICY_MODE: u32 = 0o644;

/// Write `text` to `path` atomically: sibling temp file → fsync → rename → fsync of the
/// directory, creating parent directories. The temp file is removed on any failure.
///
/// **An existing file keeps its mode.** Both callers write root-owned policy files that an
/// admin may have tightened deliberately, and a save must not quietly widen (or narrow)
/// what they chose; only a file being created for the first time takes
/// [`NEW_POLICY_MODE`].
fn install_atomically(path: &Path, text: &str) -> Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let mode = fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(NEW_POLICY_MODE);
    let write = || -> io::Result<tempfile::NamedTempFile> {
        let mut staging = tempfile::NamedTempFile::new_in(parent)?;
        staging.write_all(text.as_bytes())?;
        staging
            .as_file()
            .set_permissions(Permissions::from_mode(mode))?;
        staging.as_file().sync_all()?;
        Ok(staging)
    };
    let staging = write().with_context(|| format!("write {}", path.display()))?;
    staging
        .persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("install {}", path.display()))?;
    // The rename is durable only once the directory entry is.
    fs::File::open(parent)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("sync {}", parent.display()))
}

fn print_diags(diags: &[Diagnostic]) {
    for d in diags {
        eprintln!("  {d}");
    }
}

/// visudo-style "what now?" after a rejected policy. `[e]dit again` loops; anything else
/// (including EOF on a non-interactive stdin) quits without saving.
fn reprompt() -> Result<Prompt> {
    eprint!("What now? [e]dit again, [Q]uit without saving: ");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(match line.trim() {
        "e" | "E" | "edit" => Prompt::Edit,
        _ => Prompt::Quit,
    })
}

/// A temp copy of the policy in a private (0700) directory, removed on drop. The editor
/// (running as the invoking user) edits this; the privileged parent reads it back.
struct TempEdit {
    dir: tempfile::TempDir,
    file: PathBuf,
}

impl TempEdit {
    /// Create the private dir + seeded temp file, chowned to the invoker (when we drop
    /// privileges) so the editor can read+write it. Keeps the target's basename (e.g.
    /// `policy.toml`) so the editor still gets TOML syntax highlighting.
    fn create(target: &Path, seed: &str, editor_as: &EditorAs) -> Result<TempEdit> {
        let dir = tempfile::Builder::new()
            .prefix("cordon-edit-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .context("create temp dir")?;
        let basename = target
            .file_name()
            .map(Path::new)
            .unwrap_or_else(|| Path::new("policy.toml"));
        let tmp = TempEdit {
            file: dir.path().join(basename),
            dir,
        };
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp.file)
                .context("create temp file")?;
            f.write_all(seed.as_bytes())?;
            // Hand the file over by fd while the dir is still root-owned 0700, so the fd is
            // still the one we created (see `sys::fchown`).
            if let EditorAs::User { uid, gid, .. } = editor_as {
                sys::fchown(&f, *uid, *gid).context("chown temp file")?;
            }
        }
        // The dir last, by path (see `sys::chown`), so the dropped editor can enter it.
        if let EditorAs::User { uid, gid, .. } = editor_as {
            sys::chown(tmp.dir.path(), *uid, *gid)
                .with_context(|| format!("chown {}", tmp.dir.path().display()))?;
        }
        Ok(tmp)
    }

    /// Install the edited text at `target`. The temp copy is user-owned while the editor
    /// runs; only this validated string crosses back, and it lands atomically.
    fn commit(&self, target: &Path, text: &str) -> Result<()> {
        install_atomically(target, text)
    }
}

/// Read the edited temp copy back for validation, **without following a symlink**. The temp
/// dir is owned by the invoking user while the editor runs, so a same-uid attacker could
/// replace the file with a symlink to a root-only file (e.g. `/etc/shadow`) — this read runs
/// as root, so following it would leak that file's contents (into the policy, or, on a parse
/// failure, the diagnostics). `O_NOFOLLOW` makes a symlinked final component fail the open,
/// and the regular-file check rejects a fifo/device swap; `O_NONBLOCK` keeps a fifo swap from
/// stalling the open before that check. A legitimate editor's atomic save renames a *regular*
/// file into place, which `O_NOFOLLOW` still accepts.
fn read_edited(path: &Path) -> Result<String> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .context("re-read edited file")?;
    if !f.metadata()?.file_type().is_file() {
        return Err(Error::msg(
            "edited file is not a regular file — refusing to read it back",
        ));
    }
    let mut edited = String::new();
    f.read_to_string(&mut edited)
        .context("re-read edited file")?;
    Ok(edited)
}

/// Read the current policy file into a [`Seed`], or a template for a not-yet-existing one.
fn read_seed(target: &Path) -> Result<Seed> {
    match fs::read_to_string(target) {
        Ok(s) => Ok(Seed::Existing(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Ok(Seed::New(NEW_POLICY_TEMPLATE.to_string()))
        }
        Err(e) => Err(Error::msg(format!("read {}: {e}", target.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The target table; the bare form resolves to the invoker's own tier.
    #[test]
    fn edit_target_resolution() {
        let args = |file: Option<&str>, user: Option<&str>, system: bool| EditTargetArgs {
            file: file.map(PathBuf::from),
            user: user.map(UserName::new),
            system,
        };
        let invoker = || Ok(UserName::new("alice"));
        // An explicit target never consults the invoker — proven by a resolver that panics.
        let no_invoker = || panic!("the invoker must not be resolved for an explicit target");

        assert!(matches!(
            args(None, None, true).resolve(no_invoker).unwrap(),
            EditTarget::System(None)
        ));
        assert!(matches!(
            args(Some("local"), None, false).resolve(no_invoker).unwrap(),
            EditTarget::System(Some(p)) if p == Path::new("local")
        ));
        assert!(matches!(
            args(None, Some("someone"), false).resolve(no_invoker).unwrap(),
            EditTarget::User(u) if u.as_str() == "someone"
        ));
        // Bare: the invoker's own tier.
        assert!(matches!(
            args(None, None, false).resolve(invoker).unwrap(),
            EditTarget::User(u) if u.as_str() == "alice"
        ));
        // …and a failure to resolve one is the caller's error, not a silent system edit.
        assert!(
            args(None, None, false)
                .resolve(|| Err(Error::msg("no invoker")))
                .is_err()
        );
    }

    /// Each row of [`invoker_uid`]'s contract.
    #[test]
    fn invoker_uid_prefers_sudo_then_self() {
        let root = Uid::from_raw(0);
        let nb = Uid::from_raw(1000);
        // Unprivileged: the caller themselves, SUDO_UID irrelevant.
        assert_eq!(invoker_uid(nb, None).unwrap(), nb);
        assert_eq!(invoker_uid(nb, Some("0")).unwrap(), nb);
        // Under sudo: the invoking user.
        assert_eq!(invoker_uid(root, Some("1000")).unwrap(), nb);
        // Real root, and root-sudo-ing-to-root: no "own tier".
        assert!(invoker_uid(root, None).is_err());
        assert!(invoker_uid(root, Some("0")).is_err());
        // A malformed SUDO_UID is loud, not silently ignored.
        assert!(invoker_uid(root, Some("not-a-number")).is_err());
    }

    /// Both policy writes, the edited file and the scaffolded `[[include]]` fragment, go
    /// through [`install_atomically`], so this guards both: a tightened
    /// `/etc/cordon/policy.toml` stays tight when a first bare `policy edit` appends its
    /// include, and only a brand-new file takes [`NEW_POLICY_MODE`].
    #[test]
    fn install_preserves_an_existing_mode_and_defaults_a_new_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let _ = fs::remove_dir_all(&dir);

        let fresh = dir.join("new.toml");
        install_atomically(&fresh, "# new\n").unwrap();
        assert_eq!(
            mode_of(&fresh),
            NEW_POLICY_MODE,
            "a new file takes the default"
        );

        let tightened = dir.join("tight.toml");
        install_atomically(&tightened, "# first\n").unwrap();
        fs::set_permissions(&tightened, Permissions::from_mode(0o600)).unwrap();
        install_atomically(&tightened, "# second\n").unwrap();
        assert_eq!(
            mode_of(&tightened),
            0o600,
            "an existing mode survives a rewrite"
        );
        assert_eq!(fs::read_to_string(&tightened).unwrap(), "# second\n");
    }

    fn mode_of(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn editor_command_splits_program_and_args() {
        let editor = EditorCommand("emacs -nw --no-init".to_string());
        let (prog, args) = editor.program_and_args();
        assert_eq!(prog, "emacs");
        assert_eq!(args.collect::<Vec<_>>(), ["-nw", "--no-init"]);
    }

    #[test]
    fn editor_command_blank_falls_back_to_default() {
        let editor = EditorCommand("   ".to_string());
        let (prog, mut args) = editor.program_and_args();
        assert_eq!(prog, DEFAULT_EDITOR);
        assert!(args.next().is_none());
    }

    #[test]
    fn user_tier_path_conventions() {
        let confd = PolicyRoot::ConfD(PathBuf::from("/etc/cordon/conf.d"));
        let file = PolicyRoot::File(PathBuf::from("/etc/cordon/policy.toml"));
        let alice = UserName::new("alice");

        // user file is a `users/` sibling of the policy, outside conf.d…
        assert_eq!(
            convention_user_path(&confd, &alice),
            PathBuf::from("/etc/cordon/users/alice.toml")
        );
        // …and the scaffolded include goes in a conf.d fragment (so it loads).
        assert_eq!(
            include_fragment(&confd),
            PathBuf::from("/etc/cordon/conf.d/00-users.toml")
        );
        // single-file policy: the include is appended to that file itself.
        assert_eq!(
            convention_user_path(&file, &alice),
            PathBuf::from("/etc/cordon/users/alice.toml")
        );
        assert_eq!(include_fragment(&file), file.path());
    }

    #[test]
    fn read_edited_reads_a_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let f = dir.join("policy.toml");
        std::fs::write(&f, "rules = '''\n'''\n").unwrap();
        assert_eq!(read_edited(&f).unwrap(), "rules = '''\n'''\n");
    }

    /// Guards the symlink swap: a same-uid attacker who owns the temp dir replaces the file
    /// with a symlink to a root-only file, and its contents must never surface (into the
    /// policy or the diagnostics).
    #[test]
    fn read_edited_refuses_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let secret = dir.join("secret");
        std::fs::write(&secret, "TOP-SECRET").unwrap();
        let link = dir.join("policy.toml");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let err = read_edited(&link).unwrap_err();
        assert!(
            !format!("{err}").contains("TOP-SECRET"),
            "symlinked file contents must not surface"
        );
    }

    /// …and a directory/fifo/device swapped in for the file is rejected by the regular-file
    /// check rather than read.
    #[test]
    fn read_edited_refuses_a_non_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let notfile = dir.join("policy.toml");
        std::fs::create_dir(&notfile).unwrap();
        assert!(read_edited(&notfile).is_err());
    }

    #[test]
    fn bare_name_resolves_to_confd_fragment() {
        let dir = PathBuf::from("/etc/cordon/conf.d");
        let confd = PolicyRoot::ConfD(dir.clone());
        // bare name → <dir>/<name>.toml; existing extension kept; a path is literal.
        assert_eq!(
            resolve_target(Some(Path::new("local")), &confd).unwrap(),
            dir.join("local.toml")
        );
        assert_eq!(
            resolve_target(Some(Path::new("local.toml")), &confd).unwrap(),
            dir.join("local.toml")
        );
        assert_eq!(
            resolve_target(Some(Path::new("/etc/cordon/x.toml")), &confd).unwrap(),
            PathBuf::from("/etc/cordon/x.toml")
        );
        // no argument on a directory → must name a fragment.
        assert!(resolve_target(None, &confd).is_err());
        // no argument on a single-file policy → that file.
        let file = PolicyRoot::File(PathBuf::from("/etc/cordon/policy.toml"));
        assert_eq!(resolve_target(None, &file).unwrap(), file.path());
    }

    /// An empty conf.d means the edited fragment is the whole policy. A sibling that fails
    /// to load must fail the edit, not vanish from the candidate the daemon applies.
    #[test]
    fn candidate_is_alone_in_empty_confd_and_refuses_unloadable_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let confd = dir.join("conf.d");
        std::fs::create_dir_all(&confd).unwrap();
        let target = confd.join("10-new.toml");
        let only = candidate_sources(
            &PolicyRoot::ConfD(confd.clone()),
            &target,
            "x",
            &SourceOrigin::System,
        )
        .unwrap();
        assert_eq!(only.len(), 1);

        // An include naming a directory reads as EISDIR, a load error that is not NotFound.
        std::fs::write(
            confd.join("00-users.toml"),
            format!(
                "[[include]]\nuser = \"u\"\npath = {:?}\n",
                dir.display().to_string()
            ),
        )
        .unwrap();
        assert!(
            candidate_sources(
                &PolicyRoot::ConfD(confd.clone()),
                &target,
                "x",
                &SourceOrigin::System
            )
            .is_err()
        );
    }
}
