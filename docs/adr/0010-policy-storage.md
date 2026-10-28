# ADR 0010: Policy storage, editing and socket authorization

Status: Accepted

## Context

The policy decides who reads the user's secrets, so a same-uid scraper must not be able to
write it, and an edit in progress must never be half-enforced.

## Decision

- **The authoritative policy is a root-owned text file.** It is not writable by the user,
  because otherwise a scraper would write itself in. It can be versioned in git, reviewed and
  diffed, so the policy is code.
- **Two authoring surfaces share one model (✅ 2026-06-28).** Each rule is either a verbose
  `[[rule]]` TOML table or a line in a compact `rules = '''…'''` DSL block. The DSL has the
  form `POLICY SUBJECT ACTION OBJECT`, with one rule per line and columns aligned by
  whitespace. List items are separated by commas. `"…"` quotes a token that contains spaces,
  and it also forces `*` or `@` to be literal. `#` starts a comment. The block is a *literal*
  TOML string, so paths keep their backslashes and the DSL owns `"` and `\`. Its content is a
  verbatim slice of the source, so diagnostics map to an exact `line:col`. Both surfaces
  normalize to the same parsed rule and may be mixed in one file. The DSL is *only* surface
  syntax, and the kernel is unaffected. It is the natural form for the decision table that a
  policy actually is.
- **Per-user `~` (✅ 2026-06-28).** An optional `user = "name"` header expands `~` against that
  account's home, as NSS reports it. So a root-owned file for one user can write
  `~/.ssh` rather than `/home/<name>/.ssh`. The daemon runs as root, so without the header `~`
  would mean `/root`.
- **conf.d split (✅ 2026-06-28).** A policy path is either a single file or a directory of
  `*.toml` fragments, loaded in name order. Each fragment is parsed and resolved on its own,
  with groups local to the file and its own `user =` home. The resolved rules are then merged
  into one table and compiled together. Precedence (object and subject specificity, then deny
  over allow) does not depend on source order, so the load order of fragments can't change a
  verdict. A flat merge is safe, because every fragment is root-owned. A bad fragment fails
  the whole apply, and the diagnostic names it, so a load is never silently partial. `apply`
  ships the fragments it read (`Vec<PolicySource>`) to the daemon, which resolves their homes
  and merges them.
- **System and user tiers (✅ 2026-06-29).** The effective policy is the system tier combined
  with the user tier. A *system* fragment can pull in a *user-tier* file with an
  `[[include]]` directive that names the owning user. That file's rules are confined to that
  user's home. Every object path must resolve under `~user`, and the compiler enforces it, so
  a user can't write rules about `/etc` or about another home. The binding lives on the system
  side as an opt-in by the admin, so a user file can't declare its own scope. A user-tier file
  may not `[[include]]` anything itself. Each `PolicySource` now carries its tier as a
  [`SourceOrigin`]. `PolicyRoot::load` expands the includes, in the CLI on `apply` and in the
  daemon at startup.

  Precedence between the tiers is deferred. The intended semantics is that the system tier is
  a floor. A user may tighten it by adding denies, but may not loosen a system deny. That needs
  the kernel to evaluate the two tiers' buckets separately and combine them so that deny
  wins, which today's single first-match bucket cannot express. It only becomes a security
  boundary once user files move into homes that the users own, so it lands with that
  migration. For now the tiers merge flat, because both are root-owned and so equally
  trusted. The tier only drives the resolution of `~` and the home-scope lint.
  ```toml
  # /etc/cordon/conf.d/00-users.toml  (system tier, root-authored)
  [[include]]
  user = "alice"
  path = "/etc/cordon/users/alice.toml"   # later: ~alice/.config/cordon/policy.toml

  # /etc/cordon/users/alice.toml  (user tier — every object must be under ~alice)
  rules = '''
  allow  /usr/bin/ssh  read  ~/.ssh
  deny   *             read  ~/.config/my-secret
  '''
  ```
  Author it with `cordon policy edit --user alice`.
  > **Migration roadmap.** For now, user files are root-owned under `/etc`, so `sudo` gates
  > every edit. The target is to move them into `~user/.config/cordon/`. At that point cordon
  > must cordon its own user-policy file. The file must become a protected object that only an
  > authorized editor may write, so that a same-uid scraper can't author policy. That
  > self-protection *is* the mechanism for editing without sudo, and it is why the file belongs
  > in the home.
- **The policy is applied explicitly.** `cordon policy apply` parses, lints and compiles the
  policy, and then swaps the BPF maps atomically. There is no autoreload, and no inotify or
  SIGHUP watch. Changes take effect only on an explicit apply, so an edit in progress is never
  half-enforced.
- **`cordon policy check`** is the linter and compiler, and it needs no daemon. It reports
  unknown group references and cycles. It warns about exes that don't resolve and drops their
  rules. It marks objects that don't resolve yet as pending, and it checks the cap on rules per
  object. Lints for shadowed or unreachable rules, and for a deny shadowed by an allow, are not
  implemented yet.
- **`cordon policy edit`** is the sudoedit analog (✅ 2026-06-29). `sudo cordon policy edit`
  copies the root-owned file to a private temp file and runs `$EDITOR` as the invoking user,
  never as root. `sudo $EDITOR policy.toml` would run the editor as root. Then a same-uid
  scraper ([threat model](../threat-model.md)) that wrote your `.vimrc` or your editor
plugins would get root, which is a
  self-inflicted escalation in cordon's own threat model. After the editor exits, the command
  validates, applies and saves the policy in one step. Like visudo, it rejects a policy that
  won't compile, shows the diagnostics and prompts again, rather than saving a broken file. It
  writes the file only after the daemon accepts the policy, so the file on disk matches the
  live policy. If the daemon is down, the file is saved with a warning that it was not
  applied. The command manages its own privilege. The CLI stays root in the parent and drops
  privilege only in the editor child. It reuses `PolicyApply` and needs no new IPC.

  Bare `cordon policy edit` opens the invoker's own user tier. That is the common case, and
  it is why the dangerous target is the explicit one. `--system` edits the system policy.
  `cordon policy edit FILE` edits a system file, and a bare name means that conf.d fragment.
  `cordon policy edit --user NAME` edits the user-tier file that a system `[[include]]` binds
  to `NAME`, and that file is validated against the home scope. The invoker is `SUDO_UID`
  under sudo, and the caller's own euid when unprivileged, which is what the future posture of
  editing without sudo needs. Real root with neither has no tier of its own and must name a
  target. When no include exists yet, `--user` bootstraps itself. It opens the file at the
  conventional path (`…/users/NAME.toml`). Only after the edit validates and saves does it
  register the `[[include]]` in `…/conf.d/00-users.toml`. So a cancelled or rejected edit never
  leaves a stale binding. It reaches the daemon only through `PolicyApply`, so the socket
  authorization below covers it.

## Consequences

- **Socket authorization** (✅ B2). The gate is `authorize` in `crates/daemon/src/ipc.rs`. It
  is a pure table over the peer's uid from `SO_PEERCRED`, with an exhaustive match, so nobody
  can add a new verb without choosing a side. `PolicyApply` and `BlessApprove` (the
  human-presence step, [ADR 0013](0013-bless-authentication.md)) require root. The reads
(`Status`, `PolicyShow`, `BlessList`) are
  open. So is `BlessRequest`, which does nothing until a root peer approves it. `BlessRevoke`
  is open at the socket, and the backend checks ownership, because that is where the live
  table is. Root may revoke anything, and anyone else may revoke only what they minted.

  The socket mode is `0666`, and this is deliberate. `connect(2)` on a Unix socket needs
  *write* permission. So a `root:root` socket would make every verb root-only in practice, and
  `cordon bless list` would be unusable from a user account ([ADR 0012](0012-blessing.md)).
The file mode decides who
  can *reach* the daemon, and `authorize` decides what they may do.

  **Deployment posture.** `0666` makes `PolicyShow` world-readable, which discloses protected
  *paths* to any local account. On a single-user workstation that is the intent. A multi-user
  host that must not disclose them should use `0660` and a `cordon` group instead. Packaging
  creates the group, and members are added deliberately. The `authorize` table stays the same,
  and only the reach is narrower.
- **The swap in the kernel is atomic.** The rule maps are banked, so an `apply` has no visible
  window (the double buffer in [ADR 0002](0002-bpf-lsm-boundary.md), and `Maps::seed`).
- **Learned rules** live in a *separate* SQLite database, because they change often and a
  machine manages them. They have lower precedence and never override a hand-written deny.
  They are promoted into the text file on review ([ADR 0011](0011-autolearn.md)).
