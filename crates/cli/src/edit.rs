//! `cordon policy edit`, the sudoedit analog for the root-owned text policy
//! (DESIGN §15.8). Editing the policy that guards every secret has two hazards that a
//! plain `sudo $EDITOR /etc/cordon/policy.toml` walks straight into:
//!
//!  1. A same-uid escalation. cordon's in-scope adversary is a same-uid scraper
//!     (DESIGN §2), which can write your `~/.vimrc`, your editor plugins and `$EDITOR`.
//!     Run the editor as root and any of those execute as root. So the standard way to
//!     edit the policy hands a clean escalation to exactly the attacker that cordon
//!     exists to stop.
//!  2. Drift between the file and the live policy. `apply` is a separate step, so an edit
//!     that is never applied leaves the file ahead of the kernel. A syntactically broken
//!     file also persists, even though the daemon refuses to load it.
//!
//! This command closes both by borrowing from three tools. Like sudoedit, it keeps only a
//! plain byte copy privileged (see [`editor_identity`]). Like visudo, it validates before
//! it installs, and it rejects a broken policy and prompts again. Like `cordon policy
//! apply`, it pushes the validated result to the live kernel in the same step (see
//! [`Session::assess`]).
//!
//! Invoked as `sudo cordon policy edit`, the CLI stays root in the parent process, which
//! reads, validates, applies and writes the root-owned file. Only the forked editor child
//! drops privilege. There is no new IPC. The read is a direct file read, validation is the
//! in-process compiler that `policy check` also runs, and the commit reuses `PolicyApply`.

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

/// The editor to run when no editor variable is set, and the program to use when an
/// editor string is all whitespace.
const DEFAULT_EDITOR: &str = "vi";

/// The starting buffer for a policy file that does not exist yet. It is a comment header
/// over an empty `rules` block, which compiles to zero rules. Saving it untouched counts
/// as no change (see [`Seed`]), so seeding it never silently wipes enforcement.
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

/// Whether the editor may run as root when there is no unprivileged invoker. The
/// `--allow-root-editor` flag becomes this type at the CLI boundary, so the rest of the
/// module reasons over the intent rather than a bool.
#[derive(Clone, Copy)]
pub(crate) enum RootEditor {
    Refuse,
    Allow,
}

impl RootEditor {
    pub(crate) fn from_flag(allow_root_editor: bool) -> RootEditor {
        if allow_root_editor {
            RootEditor::Allow
        } else {
            RootEditor::Refuse
        }
    }
}

/// The editor to launch, as a command string such as `emacs -nw` rather than a bare path.
/// It is the one place that looks the editor up and splits it into program and arguments.
struct EditorCommand(String);

impl EditorCommand {
    /// Returns the editor named by the first non-empty variable among `$CORDON_EDITOR`,
    /// `$VISUAL` and `$EDITOR`, or [`DEFAULT_EDITOR`] when none is set. This is sudoedit's
    /// lookup with a cordon override on top.
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

    /// Returns the program and its arguments, split on whitespace so that
    /// `EDITOR="emacs -nw"` works. An all-whitespace string yields [`DEFAULT_EDITOR`] with
    /// no arguments.
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
    /// The editor child drops to this user while the parent stays root. The user's own
    /// home and name come along, so the editor reads that user's config and writes that
    /// user's state. Under `sudo`, the inherited `HOME` is still `/root`.
    User {
        uid: Uid,
        gid: Gid,
        home: PathBuf,
        name: UserName,
    },
    /// The editor runs as the current user, because the caller is already unprivileged or
    /// root explicitly opted in.
    Current,
}

/// The starting editor buffer, tagged by whether the policy file already existed. The
/// variant is the only record of a new file, so no separate bool can fall out of sync.
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

/// What to do with an edited buffer, as validation and the apply attempt decide.
enum Verdict {
    /// The daemon accepted the policy and swapped it live, so the file is saved.
    Apply,
    /// The daemon is unreachable but the policy is valid locally, so the file is saved
    /// with a warning that it is not enforced yet.
    SaveOnly,
    /// Local or daemon-reported errors were printed, so the user is offered another edit.
    Reedit,
}

/// The answer to the visudo-style re-edit prompt.
enum Prompt {
    Edit,
    Quit,
}

/// What `cordon policy edit` opens.
pub(crate) enum EditTarget {
    /// A system-tier policy file. `None` is the configured path, and `Some` holds a
    /// conf.d fragment name or a path.
    System(Option<PathBuf>),
    /// The user-tier policy that a system `[[include]]` binds to this user.
    User(UserName),
}

/// The mutually exclusive ways to name the policy to edit, which clap enforces. Naming
/// nothing edits your own tier.
#[derive(clap::Args, Clone, Debug)]
pub struct EditTargetArgs {
    /// System-tier policy file to edit. For a conf.d directory, name a fragment, so
    /// `local` edits `…/conf.d/local.toml`.
    pub file: Option<PathBuf>,
    /// Edit the user-tier policy that a system `[[include]]` binds to this user. Its rules
    /// are confined to that user's home.
    #[arg(long, conflicts_with = "file")]
    pub user: Option<UserName>,
    /// Edit the system policy at the configured path instead of your own user tier.
    #[arg(long, conflicts_with_all = ["file", "user"])]
    pub system: bool,
}

impl EditTargetArgs {
    /// Returns the policy these flags name. It calls `invoker` only when nothing is named,
    /// so an explicit target never depends on resolving the invoker. Errors when `invoker`
    /// errors.
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

/// Returns the login name of the account whose tier a bare `cordon policy edit` opens.
/// Errors as [`invoker_uid`] does, and when that uid has no passwd entry.
fn invoking_user() -> Result<UserName> {
    let uid = invoker_uid(
        Uid::from_raw(config::euid()),
        std::env::var("SUDO_UID").ok().as_deref(),
    )?;
    let (name, _home) = sys::user_identity(uid)
        .ok_or_else(|| Error::msg(format!("uid {uid} has no passwd entry")))?;
    Ok(name)
}

/// Returns the uid whose tier a bare `cordon policy edit` opens. That is `euid` when it is
/// not root, and the `sudo_uid` invoker when it is. Errors when `sudo_uid` is malformed,
/// or when root has no non-root `sudo_uid` (a root login, a cron job, sudo to root). Such
/// a caller has no tier of its own, so it must name `--system` or `--user` instead of
/// silently editing the system policy.
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

/// Runs `cordon policy edit` on `target` and returns the exit code. Any error is printed
/// and becomes a failure code.
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

/// One run of `cordon policy edit`, from the resolved target to the saved file. It holds
/// what each round of the edit loop reuses.
struct Session {
    /// The configured policy that the daemon reads on its next restart. The candidate is
    /// validated as part of this whole set.
    policy_root: PolicyRoot,
    /// The file opened in the editor. For a one-file policy it is that file, and
    /// otherwise it is one conf.d fragment or user-tier file.
    target: PathBuf,
    /// The tier that the edited file belongs to. It lets the candidate validate `target`
    /// with the right scope even before any `[[include]]` for it exists on disk.
    target_origin: SourceOrigin,
    /// The `[[include]]` that saving must register. It is `Some` only on a first
    /// user-tier edit, when no binding exists yet (see [`Session::save`]).
    scaffold: Option<Scaffold>,
    /// The home that `~` expands to in the local validation compile.
    home: PathBuf,
    socket: PathBuf,
    editor: EditorCommand,
    editor_as: EditorAs,
    seed: Seed,
    tmp: TempEdit,
}

impl Session {
    /// Opens a session on `target`, creates the temp copy that the editor will work on,
    /// and prints a banner naming the file and the editor. Errors when the target can't be
    /// resolved or is a directory, when [`editor_identity`] refuses, or when the config,
    /// the current file or the temp copy can't be read or created.
    fn open(target: EditTarget, root_editor: RootEditor, client: &Client) -> Result<Session> {
        let policy_root = PolicyRoot::at(&client.policy_path(None)?)?;
        let (target, target_origin, scaffold) = match target {
            EditTarget::System(file) => (
                resolve_target(file.as_deref(), &policy_root)?,
                SourceOrigin::System,
                None,
            ),
            // A user target is the file that a system `[[include]]` binds. With no include
            // yet, it is the convention path, and the include is registered on first save.
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

    /// Runs the visudo-style loop until the edit is saved, left unchanged or abandoned, and
    /// returns the exit code. A rejected policy offers another edit, and quitting there
    /// returns failure. Errors as [`Session::run_editor`], [`read_edited`],
    /// [`Session::assess`] and [`Session::save`] do.
    fn edit_loop(self) -> Result<ExitCode> {
        loop {
            self.run_editor()?;
            let edited = read_edited(&self.tmp.file)?;
            // An unchanged buffer is a no-op, unless an include registration is still owed.
            // Then even an untouched valid file is registered and applied.
            if edited == self.seed.text() && self.scaffold.is_none() {
                println!("cordon: no changes — policy left unchanged");
                return Ok(ExitCode::SUCCESS);
            }

            // The candidate is the whole policy with `target` substituted at its tier, so a
            // conf.d fragment or a user file is validated against the rest, not alone.
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

    /// Writes `edited` to the target file and registers any pending `[[include]]`. The
    /// include is registered only after the file is saved, so a cancelled or rejected edit
    /// never leaves a stale binding. Errors when either write fails.
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

    /// Runs the editor on the temp copy and waits for it to exit. Errors when the editor
    /// can't be run, or when it exits non-zero (as on vim's `:cq`) to discard the edit.
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

    /// Compiles `candidate` locally and, when it is clean, applies it live through the
    /// daemon. Prints every diagnostic and returns the [`Verdict`] for the file.
    ///
    /// The local compile is fast, and it is the only check when no daemon is listening
    /// (see [`is_daemon_down`]). The daemon's compile is authoritative because it knows the
    /// mounts. The file is saved only once the daemon has accepted the policy, so the file
    /// matches the live policy with no rollback. Errors when the daemon answers with an
    /// error or an unexpected reply, or fails mid-request.
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

/// Returns the file to open for `file` under `policy_root`:
///
/// - With no `file`, it is the policy path itself.
/// - A bare name such as `local` under a conf.d directory is the fragment
///   `<dir>/local.toml`. `.toml` is appended only when the name has no extension.
/// - Any other `file` is taken literally.
///
/// Errors when `file` is `None` and the policy is a conf.d directory, which has no single
/// file to open.
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

/// Checks whether `p` is a single-component relative path such as `local` or
/// `local.toml`, which names a fragment rather than a particular file.
fn is_bare_name(p: &Path) -> bool {
    !p.as_os_str().is_empty()
        && p.parent()
            .map(|parent| parent.as_os_str().is_empty())
            .unwrap_or(true)
}

/// Returns who the editor runs as, which is never root unless `root_editor` allows it. An
/// unprivileged caller edits as itself. Under `sudo`, the editor drops to `SUDO_UID` and
/// `SUDO_GID` with that user's own home and name.
///
/// Errors on any of these:
/// - Root has no non-root invoker (no `SUDO_UID` or `SUDO_GID`, or sudo to root) and
///   `root_editor` is [`RootEditor::Refuse`]. A root editor is the same-uid escalation
///   that the module doc describes.
/// - `SUDO_UID` or `SUDO_GID` does not parse.
/// - The invoking uid has no passwd home.
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

/// Runs `editor` on `file` as `editor_as` says and returns its exit status. An editor
/// that drops to another user also gets that user's `HOME`, `USER` and `LOGNAME`.
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

/// Returns the whole effective policy of `policy_root`, including its system fragments and
/// `[[include]]`d user-tier files, with the text of `target` replaced by `new_text`. The
/// source that is `target` keeps its own tier, so the scope check still applies to it. A
/// `target` that is not in the policy yet is added at `target_origin`. Errors when any
/// existing source fails to load.
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
    // Normalized paths, so that a fragment or an included user file matches its source.
    let tgt = normalize(target);
    match sources
        .iter_mut()
        .find(|s| normalize(Path::new(&s.name)) == tgt)
    {
        // Already in the set as a conf.d fragment or an included user file, which keeps
        // its tier.
        Some(s) => s.text = new_text.to_string(),
        // Not in the set yet. It is a new system file, or a user file whose include does
        // not exist yet, so it takes the target's tier for the scope check.
        None => sources.push(PolicySource {
            name: target.display().to_string(),
            text: new_text.to_string(),
            origin: target_origin.clone(),
        }),
    }
    Ok(sources)
}

/// Returns the file to edit for the tier of `user`, and a [`Scaffold`] that registers its
/// binding when none exists yet. An existing `[[include]]` for `user` names the file, and
/// otherwise it is at [`convention_user_path`]. Errors when the existing includes can't be
/// read.
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

/// Returns where the tier file of `user` goes when no `[[include]]` names it yet. It is
/// `users/<name>.toml` beside the system policy, so `/etc/cordon/conf.d` gives
/// `/etc/cordon/users/<name>.toml`. The file sits outside the conf.d directory on purpose,
/// so it never loads as a system fragment and only the include pulls it in.
fn convention_user_path(policy_root: &PolicyRoot, user: &UserName) -> PathBuf {
    let base = policy_root
        .path()
        .parent()
        .unwrap_or_else(|| Path::new("/"));
    base.join("users").join(format!("{}.toml", user.as_str()))
}

/// Returns the system file that a scaffolded `[[include]]` is appended to. For a conf.d
/// directory it is `00-users.toml` inside it, which loads as a system fragment. For a
/// one-file policy it is that file.
fn include_fragment(policy_root: &PolicyRoot) -> PathBuf {
    match policy_root {
        PolicyRoot::ConfD(dir) => dir.join("00-users.toml"),
        PolicyRoot::File(path) => path.clone(),
    }
}

/// The `[[include]]` that a first user-tier edit still owes. [`resolve_user_target`]
/// creates it when no binding exists yet, and [`Session::save`] registers it.
struct Scaffold {
    /// The system fragment to append the `[[include]]` to.
    fragment: PathBuf,
    /// The user that the include binds. That user's home scopes the included rules.
    user: UserName,
    /// The file that the include names, which is the edited user file.
    path: PathBuf,
}

impl Scaffold {
    /// Appends the `[[include]]` table for `user` and `path` to the fragment atomically,
    /// creating the fragment when it is absent. It is not idempotent, which is safe only
    /// because a `Scaffold` exists only while the user has no include yet. Errors when the
    /// fragment can't be read or written.
    fn register(&self) -> Result<()> {
        let mut text = match fs::read_to_string(&self.fragment) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(Error::msg(format!("read {}: {e}", self.fragment.display()))),
        };
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        // `{:?}` renders a TOML basic string for ASCII login names and paths.
        text.push_str(&format!(
            "\n[[include]]\nuser = {:?}\npath = {:?}\n",
            self.user.as_str(),
            self.path.display().to_string(),
        ));
        install_atomically(&self.fragment, &text)
    }
}

/// The mode of a policy file that this command creates (see [`install_atomically`]). A
/// root-owned `0644` file matches the rest of the tree, and an unprivileged `cordon policy
/// check` needs to read it. The file holds rules, which name paths and executables, not
/// credentials. The daemon already serves a summary of them to any local user
/// (DESIGN §15.8).
const NEW_POLICY_MODE: u32 = 0o644;

/// Replaces `path` with `text` atomically and durably, creating any missing parent
/// directories. A failure leaves the old file in place and no temp file behind.
///
/// An existing file keeps its mode, and only a new file takes [`NEW_POLICY_MODE`]. An
/// admin may have tightened a policy file on purpose, and a save must not quietly widen or
/// narrow that choice. Errors when a directory, the temp file or the rename fails.
fn install_atomically(path: &Path, text: &str) -> Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let mode = fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(NEW_POLICY_MODE);
    // The staging file is a sibling, so the rename stays on one filesystem and is atomic.
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

/// Asks the visudo-style "what now?" after a rejected policy and returns the answer. Only
/// `e`, `E` or `edit` means edit again. Anything else, including EOF on a non-interactive
/// stdin, means quit. Errors when stdin can't be read.
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

/// The temp copy of the policy that the editor works on, in a private 0700 directory that
/// is removed on drop. It is the only file the unprivileged editor touches, and the
/// privileged parent reads it back.
struct TempEdit {
    dir: tempfile::TempDir,
    file: PathBuf,
}

impl TempEdit {
    /// Creates the private directory and a temp file holding `seed`. When the editor drops
    /// to another user, both belong to that user so the editor can read and write them.
    /// The file keeps the basename of `target`, such as `policy.toml`, so the editor still
    /// highlights TOML syntax. Errors when either can't be created, written or chowned.
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
            // The file changes hands by fd while the directory is still root-owned 0700, so
            // nobody can have swapped it yet (see `sys::fchown`).
            if let EditorAs::User { uid, gid, .. } = editor_as {
                sys::fchown(&f, *uid, *gid).context("chown temp file")?;
            }
        }
        // The directory changes hands last, by path (see `sys::chown`), so that the
        // dropped editor can enter it.
        if let EditorAs::User { uid, gid, .. } = editor_as {
            sys::chown(tmp.dir.path(), *uid, *gid)
                .with_context(|| format!("chown {}", tmp.dir.path().display()))?;
        }
        Ok(tmp)
    }

    /// Installs `text` at `target` as [`install_atomically`] does. The temp copy belonged
    /// to the user while the editor ran, so only this validated string crosses back.
    fn commit(&self, target: &Path, text: &str) -> Result<()> {
        install_atomically(target, text)
    }
}

/// Returns the text of the edited temp copy at `path` without following a symlink.
/// Errors when `path` is a symlink or not a regular file.
///
/// The temp directory belongs to the invoking user while the editor runs, so a same-uid
/// attacker could replace the file with a symlink to a root-only file such as
/// `/etc/shadow`. This read runs as root, so following the link would leak that file into
/// the policy, or into the diagnostics on a parse failure. A legitimate editor's atomic
/// save renames a regular file into place, which still reads fine.
fn read_edited(path: &Path) -> Result<String> {
    let mut f = OpenOptions::new()
        .read(true)
        // O_NOFOLLOW fails the open on a symlinked final component. O_NONBLOCK keeps a
        // swapped-in fifo from stalling the open before the regular-file check rejects it.
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

/// Returns the current text of `target`, or [`NEW_POLICY_TEMPLATE`] when the file does not
/// exist yet. Errors when the file exists but can't be read.
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

    /// Checks each way to name a target, and that the bare form resolves to the invoker's
    /// own tier.
    #[test]
    fn edit_target_resolution() {
        let args = |file: Option<&str>, user: Option<&str>, system: bool| EditTargetArgs {
            file: file.map(PathBuf::from),
            user: user.map(UserName::new),
            system,
        };
        let invoker = || Ok(UserName::new("alice"));
        // A resolver that panics proves that an explicit target never consults the invoker.
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
        // The bare form opens the invoker's own tier.
        assert!(matches!(
            args(None, None, false).resolve(invoker).unwrap(),
            EditTarget::User(u) if u.as_str() == "alice"
        ));
        // A failure to resolve the invoker is an error, not a silent system edit.
        assert!(
            args(None, None, false)
                .resolve(|| Err(Error::msg("no invoker")))
                .is_err()
        );
    }

    /// Checks each case of the [`invoker_uid`] contract.
    #[test]
    fn invoker_uid_prefers_sudo_then_self() {
        let root = Uid::from_raw(0);
        let nb = Uid::from_raw(1000);
        // An unprivileged caller is the answer, and SUDO_UID is ignored.
        assert_eq!(invoker_uid(nb, None).unwrap(), nb);
        assert_eq!(invoker_uid(nb, Some("0")).unwrap(), nb);
        // Under sudo, the answer is the invoking user.
        assert_eq!(invoker_uid(root, Some("1000")).unwrap(), nb);
        // Real root and sudo to root have no tier of their own.
        assert!(invoker_uid(root, None).is_err());
        assert!(invoker_uid(root, Some("0")).is_err());
        // A malformed SUDO_UID is loud, not silently ignored.
        assert!(invoker_uid(root, Some("not-a-number")).is_err());
    }

    /// Checks that a rewrite keeps an existing file's mode and that only a new file takes
    /// [`NEW_POLICY_MODE`]. Both policy writes go through [`install_atomically`], so a
    /// tightened `/etc/cordon/policy.toml` stays tight when a first bare `policy edit`
    /// appends its include.
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

        // The user file goes in a `users/` directory beside the policy, outside conf.d.
        assert_eq!(
            convention_user_path(&confd, &alice),
            PathBuf::from("/etc/cordon/users/alice.toml")
        );
        // The scaffolded include goes in a conf.d fragment, so that it loads.
        assert_eq!(
            include_fragment(&confd),
            PathBuf::from("/etc/cordon/conf.d/00-users.toml")
        );
        // For a one-file policy, the include is appended to that file itself.
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

    /// Guards against the symlink swap. A same-uid attacker who owns the temp directory
    /// replaces the file with a symlink to a root-only file, and that file's contents must
    /// never surface in the policy or the diagnostics.
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

    /// Checks that a directory, fifo or device swapped in for the file is rejected rather
    /// than read.
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
        // A bare name becomes `<dir>/<name>.toml`, an existing extension is kept, and a
        // path is taken literally.
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
        // With no argument, a conf.d directory needs a fragment named.
        assert!(resolve_target(None, &confd).is_err());
        // With no argument, a one-file policy resolves to that file.
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

        // An include that names a directory fails with EISDIR, which is not NotFound.
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
