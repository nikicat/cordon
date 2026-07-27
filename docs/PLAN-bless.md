# Implementation plan — blessing (`cordon bless`)

Concrete, reviewable plan for [`DESIGN.md` §16](DESIGN.md) — the runtime, human-authenticated
access grant. A blessing lets an *ad-hoc, interactive* invocation (`cat`/`find`/`du`/a shell)
and its descendants cross the cordon, under a class defined in policy. It is **additive** to
the §15 rule model and reuses it as much as possible: **a blessing is one more `SubjectMatch`
predicate** (`blessing = "<class>"`, §16.3), so a blessing rule is an ordinary rule —
action, object scope, conjunction, and precedence all come from the existing model. The only
new pieces are a carrier (a per-invocation root-owned cgroup), a tiny runtime indirection map
(`BLESSED: cgroup_id → ClassId`), a root-gated mint path in the daemon, and the `cordon bless`
CLI.

> **Status: B1 + B2 are done (2026-07-27).** B1a–B1f shipped the boundary; **B2 made it
> usable** and superseded B1's privilege model — `cordon bless` now runs *unprivileged*, and
> the root-first spawn described in B1d/B1e below is history (kept for the record; see the
> B2 section and DESIGN §16.5/§16.6 for what actually runs). VM-validated at 27/27 smoke
> scenarios. PAM mint remains **B3** below, and B2 did most of its structural work.

Guiding constraints (from §16):
- **Authorization is the whole feature.** The carrier is forgeable (§8.1); security rests
  entirely on (a) a human authenticating at mint and (b) root-owned `cgroup.procs` so only a
  root process places a task in a blessed cgroup. Build and test those two first.
- **Blessing is an ordinary rule.** The `blessing` predicate composes with the rest of
  `SubjectMatch`; scope is the rule's object column, precedence is §15.6 specificity. No
  bespoke grant table, no deny→allow flip — just first-match over the compiled buckets.
- **Decoupled from `policy apply`.** The static `@blessed-*` rules compile into the banked
  buckets like any rule; the *only* per-bless runtime state is the small, unbanked,
  single-writer `BLESSED` indirection map. A bless never recompiles policy; policy apply never
  disturbs a live bless.
- **Loud.** Every blessing-matched decision is journaled (the matched class on the record);
  blessings are enumerable and revocable.
- **No hardcode.** Classes are declared in policy (`blessing` predicate); class names (`ro`,
  `rw`, …) are conventions, not built-ins.
- **No grace window.** Every mint authenticates; repeat access is `bless`-a-shell. *(As
  shipped, sudo's timestamp cache is a grace window — see decision #8 and the sudoers note.)*

Milestones are sequenced so each is shippable and VM-validated on its own. **B1 is the
boundary** and ships the whole feature (scoped, fully customizable); B2 is ergonomics; B3 is
the PAM authenticator upgrade.

---

## Milestone B1 — Core grant path (the boundary), scoped ✅ *done 2026-07-26*
Text policy gains the `blessing` subject predicate; `sudo cordon bless` authenticates the
human, spawns the command into a fresh root-owned cgroup tagged with its class, and the kernel
matches the blessing predicate during its normal bucket scan. Delivers the whole feature
end-to-end, **scoped to the rule's object column** (no blanket).

### B1a. Shared types — `crates/bpf-common`
- **`SubjectMatch` gains a `blessing` predicate:** `blessing: ClassId (u32)` + a
  `FLAG_BLESSING_ANY` wildcard bit in `flags` (mirrors `exe`/`uid`/`cgroup`). Re-lay-out to
  stay padding-free (likely 40 bytes); update the layout unit tests. `ClassId(0)` = the
  "unblessed" sentinel — a process in no blessed cgroup resolves to `0`, which no concrete
  rule predicate ever names.
- New map name `MAP_BLESSED`, shape `HashMap<u64 /*cgroup_id*/, ClassId>` — **not banked**
  (runtime state, single-writer = the backend thread), a pure cgroup→class indirection.
- `DecisionEvent`: carry the **matched blessing class** (e.g. the `ClassId` + its name resolved
  in the daemon) so the journal shows bless-mediated access distinctly. `Display` stays canonical.

### B1b. eBPF program — `crates/bpf`
- **`subject_matches` gains the blessing check:** resolve the caller's class once per
  `decide()` — `current_class = BLESSED.get(bpf_get_current_cgroup_id()).unwrap_or(0)` — and a
  rule matches the blessing axis iff `flags & FLAG_BLESSING_ANY != 0 || subject.blessing ==
  current_class`. ANDed with the existing exe/uid/cgroup checks. No separate fast-path, no
  deny→allow flip; blessing rides the existing first-match scan, so copy-down + specificity
  give scope and precedence for free.
- **Verifier check (do first, in the VM):** confirm `bpf_get_current_cgroup_id` is callable
  from the `file_open` LSM hook on the pinned kernel (general helper, but validate). No new
  struct-offset injection — it's a helper, not a field read.

### B1c. Policy pipeline — `crates/core/src/policy/`
- **Parse/resolve:** accept a `blessing = "<class>"` predicate on `[group.subject.*]` (and the
  DSL equivalent), symmetric with the §15.7 group model and composable with `exe`/`uid`/… in
  one conjunctive subject.
- **Compile:** assign a dense `ClassId` to each declared class; **stamp it into the
  `SubjectMatch` of every rule referencing the class** (clearing `FLAG_BLESSING_ANY`) and emit
  those rules into the per-object buckets **like any rule** (copy-down, sort, dedup, cap all
  apply). Emit a `class-name → ClassId` **registry** on the compiled output (the daemon/CLI use
  it to validate `--class` and to write `BLESSED` at mint).
- Lint: unknown class named by `cordon bless` (checked against the registry), a declared class
  no rule references (unreachable), a `blessing` predicate naming an undeclared class.

### B1d. Daemon — `crates/daemon` ✅ *(shipped; sudo-gated, see the note below)*
> **Shipped design change (user-approved).** The authenticator is **sudo**, not PAM in the
> daemon, and the **CLI** (root, via sudo) is the spawner. Rationale + accepted deltas: DESIGN
> §16.5. Exploration found PAM-in-daemon much heavier than specced (conversation proxying as
> multi-frame IPC, stdio fd passing, degraded job control for daemon-spawned children), and
> the systemd-less smoke VM cannot test transient scopes. PAM mint is deferred to B3 below;
> the mint verb is authenticator-agnostic, so conversation frames slot in without reshaping
> IPC. What follows is what actually shipped.
- **IPC** (`proto.rs`/`ipc.rs`): `Request::{BlessMint { class }, BlessList, BlessRevoke { id }}`
  → `Response::{BlessMinted(BlessingView), Blessings(Vec<BlessingView>), BlessRevoked { id }}`.
  No `argv`/`cwd`/`env` on the wire — the CLI spawns, so nothing about the target crosses the
  socket. Peer creds read once per connection; a pure `authorize(req, peer_uid)` gate requires
  **uid 0** for mint/revoke (`BlessList` open, parity with `PolicyShow`).
- **Channel:** the backend thread's one control channel widens to
  `ControlMsg { Apply, Bless(BlessOp) }` — *one* channel, so applies and bless ops are strictly
  ordered and the apply-time remap can't race a mint.
- **Carrier:** validate `class` against the compiled registry (omitted `--class` → the sole
  declared class), create a fresh root-owned `cordon-bless-<id>.<class>` **under the daemon's
  own cgroup** (`Delegate=yes` in both units; identical code path with or without systemd, so
  the VM exercises the real thing). Register `BLESSED[st_ino] = ClassId` — on cgroup2, the
  directory's inode *is* the id `bpf_get_current_cgroup_id()` returns.
- **GC** (every 500ms tick): reap on `populated 0` **and** meaningful emptiness — it had
  members and they exited, it was revoked, or a **30s mint grace** expired (a fresh carrier is
  legitimately empty until the CLI's `pre_exec` join lands; the grace also cleans up after a
  CLI that died before joining).
- **Revoke:** write `cgroup.kill` (the whole tree dies), let the same GC finish the teardown.
- **Apply-time remap (the correctness keystone):** an apply renumbers `ClassId`s, so every
  apply re-points live `BLESSED` entries **by class name**; a vanished class is unregistered
  (blessing goes inert) and the tree is never killed.
- **Reconciliation:** on startup, scan for leftover `cordon-bless-*` carriers — empty ones are
  removed, populated ones re-registered if their class is still declared, populated ones of a
  vanished class adopted inert (GC only). Never fails startup.

### B1e. CLI — `crates/cli` ✅ *(shipped in B1; **superseded by B2** — see below)*
> **Superseded.** Everything in this section that concerns *privilege* was deleted in B2:
> `cordon bless` no longer requires root, no longer drops to `SUDO_UID`, and no longer opens
> the carrier by path. What survives is the shape — the CLI is the spawner, the join happens
> in `pre_exec` before `exec`, and the exit code is propagated. Kept verbatim for the record.
- `sudo cordon bless [--class NAME] [-- <cmd> <args…>]`: require root, mint, open the
  carrier's `cgroup.procs` **before fork**, then fork with a `pre_exec` that joins the carrier
  (still root) and *then* drops to `SUDO_UID`/`SUDO_GID` — join-before-drop is the boundary,
  and joining before `exec` is what makes the target run zero instructions unblessed. Natural
  tty/job control/signals; exit code propagated (`128 + signal` on signal death).
- Identity: the invoker's passwd `HOME`/`USER`/`LOGNAME` (sudo left root's) **and their full
  supplementary groups** (unlike the editor drop, which sheds all groups on purpose — a
  blessed shell is the user's normal session). No `<cmd>` ⇒ the invoker's **passwd** shell
  (`$SHELL` is reset by sudo), then `$SHELL`, then `/bin/sh`.
- `cordon bless list` (id, class, age, pids, cgroup) and `sudo cordon bless revoke <id>`, via
  clap `args_conflicts_with_subcommands` — so `bless list` is the subcommand and
  `bless -- list` runs a command named `list`.
- No CLI-side cleanup: daemon GC owns teardown.

### B1f. Validation — `packaging/test/bpf-lsm-smoke.sh` ✅ *(shipped: scenarios 18–23 of the then-23; B2 grew the suite to 27 and rewrote 23)*
- **Scope (18):** a blessed read is allowed against a `who="*"` deny on that object; the
  **same blessed exe is denied** on a second protected object the class doesn't name (scope =
  the rule's object column); the same exe **unblessed** stays denied. Also the end-to-end
  proof that the carrier's `st_ino` equals `bpf_get_current_cgroup_id()`.
- **Boundary (19):** a non-root uid writing the carrier's `cgroup.procs` fails (`EACCES`);
  `bless list` shows the live entry meanwhile.
- **Inheritance + GC (20):** a blessed bash's *grandchild* reads the secret; after exit,
  `bless list` drains **and** the carrier dir is gone (entry + table row + cgroup all reaped —
  "re-open denied" alone would hold regardless).
- **Revoke (21):** the blessed tree dies promptly via `cgroup.kill`; list + dirs drain.
- **Journal (22):** the blessed access logs `blessing=ro` (class by name).
- **Drop to the invoker (23):** the `sudo` shape. A non-root blessed child **still reads the
  secret** — true only if the carrier join preceded the privilege drop, which 18–22 cannot
  show since they leave the child as root — plus the invoker's uid, their surviving
  supplementary groups (`getgrouplist`), and their `$HOME`.
- **Neither systemd nor sudo is needed for any of this**, because in both cases the thing
  under test is a kernel-level property rather than the tool that arranges it:
  - `SUDO_UID`/`SUDO_GID` is the *entire* interface sudo gives the CLI, so setting it as root
    is byte-identical (the same substitution scenarios 16/17 make for `policy edit`). Real
    sudo would test sudo.
  - `Delegate=yes` buys "the daemon's own cgroup is a non-root cgroup it creates children
    in" — mkdir + write a pid. All six bless scenarios run the daemon in such a **nested
    cgroup**, which is *stricter* than the cgroup2 root they used to use (the root is exempt
    from cgroup-v2's "no internal processes" rule). Scenario 18 asserts the nesting actually
    engaged, so a silent fallback can't pass while testing nothing.
- No PAM test hook needed — the smoke runs as root, so the CLI is invoked directly and the
  daemon's uid-0 gate passes. Startup reconciliation gets incidental coverage (a scenario's
  daemon is killed with carriers live; the next one logs "removed empty leftover carrier").
- Out of scope, deliberately: real sudo's PAM prompt + timestamp cache, and systemd's own
  cgroup bookkeeping — neither is cordon code. (`vng --systemd` exists but is EXPERIMENTAL
  and boots the host's whole unit tree read-only.)

### B1 decisions (locked at impl start; annotated with what shipped)
1. **Blessing is a `SubjectMatch` predicate** (Wiring 2), not a separate grant table — scope
   and precedence reuse the rule model. *(Shipped as specced.)*
2. **Carrier = per-invocation root-owned cgroup via systemd transient scope** (delegated
   subtree as fallback). Per-invocation, not shared-per-class.
   → **Shipped with the fallback as the primary:** a delegated subtree (`Delegate=yes`), with
   the daemon creating `cordon-bless-<id>.<class>` under its own cgroup. One code path with or
   without systemd — which is also what lets the systemd-less smoke VM test it at all.
   Per-invocation, as specced.
3. **`BLESSED` is a small, unbanked, single-writer `cgroup_id → ClassId` map** (not in the
   §15.8 double-buffer). *(Shipped as specced — and the single-writer property is what makes
   the apply-time remap safe.)*
4. **Scoped, fully customizable:** a class's action, object scope, conjunction, and polarity
   are whatever its policy rules say (a class may even be `audit`). No blanket grant.
   *(Shipped as specced; smoke 18 + 22 prove scope and the `audit` case.)*
5. **Precedence:** a `blessing` predicate is **one** unit of subject specificity (like `exe`).
   A concrete blessing rule outranks a `who="*"` catch-all; a *targeted* `deny <exe>` ties a
   bare `allow @blessed-x` at equal specificity → `deny>allow` wins (deny-list beats blessing).
   Conjunctions (`{exe, blessing}` = 2) raise specificity normally. *(Shipped as specced;
   smoke 18 proves the catch-all case in-kernel.)*
6. **PAM in the daemon; conversation proxied to the tty; caller identity from `SO_PEERCRED`.**
   → **Superseded for B1: `sudo` is the authenticator**, and the daemon gates mint/revoke on
   `SO_PEERCRED` **uid 0**. Identity-from-peer-creds survives verbatim; only the human-presence
   check moved out of the daemon. PAM mint is B3 (DESIGN §16.5 keeps the full design).
7. **Child runs as the invoking user** with the caller's full env + cwd (privilege drop reused
   from `sys.rs`). → **Shipped, via the CLI rather than the daemon:** since the CLI forks the
   target itself, env and cwd are simply *inherited* (nothing ships over the socket) and the
   drop reuses `sys.rs`. Refinement: the blessed child keeps the invoker's **full
   supplementary groups** (the editor drop clears them — different threat shape).
8. **No grace / auth-cache window** — every mint authenticates.
   → **Not preserved as shipped:** sudo's timestamp cache is a grace window. Documented as an
   accepted delta with the `Defaults!/usr/bin/cordon timestamp_timeout=0` deployment note that
   restores the property; the PAM upgrade (B3) restores it by construction.

---

## Milestone B2 — Usable blessing → [`PLAN-bless3.md`](PLAN-bless3.md)
**Detailed plan: [`PLAN-bless3.md`](PLAN-bless3.md).** B1's real-system run exposed three
things the VM structurally cannot test (it has no unprivileged socket clients, no sudoedit
ergonomics, no logind/polkit):

- ~~`cordon bless list` is unusable from a user account~~ — **done**: the socket was
  `root:root` and `connect(2)` needs *write*, so B1 decision #1 ("`BlessList` ungated") was
  inert. Fixed by gating `PolicyApply` on uid 0 and opening the socket to `0666`, which
  *tightens* authorization (DESIGN §15.8).
- ~~`policy edit` defaults to the system policy~~ — **done**: bare `cordon policy edit` opens
  your own tier; `--system` names the system policy explicitly.
- ~~The blessed shell is barely usable~~ — **done**, and this was the milestone: no logind
  session (so polkit refused `run0`/`pkexec`) and a scrubbed environment (no `DISPLAY`), both
  because the blessed process was born in the wrong place — parented through a privilege tool
  and relocated into the daemon's cgroup. Under `run0` the environment cannot be recovered
  after the fact, so fixing it was **not separable** from fixing who spawns the target. The
  privilege flow is now inverted: `cordon bless` runs unprivileged as a child of the user's
  shell, the daemon passes back the carrier's `cgroup.procs` descriptor over `SCM_RIGHTS`,
  and the carrier is created in the requester's own `session-N.scope`. The entire
  privilege-drop path is deleted.

**What B2 shipped** (details in [`PLAN-bless3.md`](PLAN-bless3.md)):
1. Socket authorization — every write root-gated, socket `0666`, reads usable unprivileged.
2. `policy edit` defaults to the invoker's tier.
3. The daemon hands back the carrier's `cgroup.procs` as an `SCM_RIGHTS` descriptor
   (close-on-exec, so it never survives into the blessed process).
4. The unprivileged spawner + the two-connection mint handshake, with the daemon as the
   rendezvous and a client-side check that the daemon is root.
5. Carrier placement in the requester's session scope, gated on root ownership; reconcile
   scans session scopes too and adopts only root-owned leftovers.

Its B0 spike confirmed the two kernel/systemd assumptions on a real host, but the **script is
retired** (see PLAN-bless3 B0): one of its answers was true and irrelevant, so it would have
passed on a machine where blessing's polkit integration does not work. Smoke scenarios 26 and
27 cover the placement rules it was standing in for, and unlike the spike they fail when the
rule regresses.

---

## Milestone B3 — PAM authenticator (replaces the uid-0 gate) ← **next**
The upgrade B1 was deliberately shaped to accept: the mint verb is authenticator-agnostic, so
this adds frames beside it rather than reshaping the IPC. Full design in DESIGN §16.5.

- **PAM in the daemon** (new dep): authenticate the **peer uid's** user (from `SO_PEERCRED`,
  as today) against a `cordon` PAM service; the conversation function proxies prompt/info
  frames to the `cordon bless` front-end, which renders them on the tty and returns input. The
  front-end never asserts "I authed" — it relays only, so a scraper on the socket controls the
  I/O channel and never the verdict.
- **Relaxes the uid-0 gate to "the authenticated peer":** `authorize()` stops requiring root
  for mint, so **a non-sudoer can bless their own tools** — the property the sudo gate can't
  offer. Revoke follows the same rule (your own blessings).
- **Restores "no grace window" by construction** (every mint authenticates), retiring the
  sudoers `timestamp_timeout=0` note.
- **Mechanically, B2 already did the hard part.** The `SCM_RIGHTS` `cgroup.procs` hand-off
  this milestone would otherwise have had to invent ships in B2, along with an unprivileged
  CLI — so B3 reduces to swapping *what proves a human is present*: replace the
  `bless-helper`'s uid-0 approval with a PAM conversation against the requesting peer. The
  spawn path, the carrier placement and the boundary are unchanged.

---

## Milestone B4 — Ergonomics & observability
- Rich `cordon bless list` / structured journal; `revoke` polish; optional blessed-shell
  affordance (a prompt marker / hint **derived from cgroup membership**, never an env var
  *carrier* — env is forgeable as a carrier, §16.2; inheriting env into the child is fine).
- (Optional) per-invocation **narrowing** `--path P` that intersects the chosen class's scope
  down to `P` for this invocation (tighten-only; never widens past the policy class).
- Optional hardware-token-per-bless mode (`pam_u2f` touch *every* mint) for high-value classes
  — extra assurance the human is present at each grant.
- **An "uncondoned" blessing class** (raised on the host run): today a class's object scope
  must be enumerated, so every dir added to `@secrets` must also be added to the blessing's
  scope or a blessed session hits a surprise denial — two lists that drift. The cheap form is
  to allow `*` in the object column **for allow-polarity rules only**, with the compiler
  fanning the rule into every protected object's bucket: no kernel change, no new bypass in
  `decide()`, and "allow on every protected object" *is* the complete definition of
  uncordoned, since an unprotected path is already unmediated. `where = "*"` is currently
  rejected outright (`resolve.rs:173`) because it can't work for *deny*. Open questions: what
  a bare `*` means in a home-scoped user-tier fragment, and that a blanket class is a skeleton
  key that widens the §16.7 ptrace/open-fd exposure — so it must be an opt-in second class,
  never a change to what blessing means.

---

## Cross-milestone notes
- **Relation to M2 (§15.4 `cgroup` predicate):** B1 shares the `bpf_get_current_cgroup_id`
  read and the `SubjectMatch`-predicate pattern, but `blessing` is a *distinct* predicate (it
  matches *any cgroup currently registered as class X in `BLESSED`*, via indirection — not a
  fixed cgroup id like the raw `cgroup` predicate). B1 is otherwise independent of M2/M3/M4 and
  can land before them.
- **Interaction with M5 (fail-safe pinning):** pin the *policy* maps
  (`PROTECTED`/`RULES`/`RULE_COUNT`/`SETTINGS`) for fail-safe enforcement, but treat `BLESSED`
  as **ephemeral daemon state — do not pin it.** A pinned `BLESSED` with a dead daemon = grants
  that never expire (no GC) and a stale-id hazard. Fail-closed on daemon death (entries gone);
  rebuild via B1d reconciliation on restart.
- **cgroup v2 assumed** (unified hierarchy). v1/hybrid is out of scope; detect and refuse with
  a clear diagnostic.
- **Naming:** `bless` is reserved for this runtime grant; authoring flow A is observe →
  **admit** → enforce (§15.10). Threat-model "blessed binary/ancestor" (§8.1) is generic
  English for a statically-trusted binary, unrelated to this command.

## Appendix — shapes (proposed; refine during impl)
```
// bpf-common
SubjectMatch { exe: FileId, cgroup: u64, uid: u32, blessing: ClassId, flags: u32, _pad }
               // flags gains FLAG_BLESSING_ANY; ClassId(0) = unblessed sentinel
MAP_BLESSED:   HashMap<u64 /*cgroup_id*/, ClassId>      // unbanked, daemon-written
DecisionEvent { …, blessing: ClassId }                 // matched class → journal

// compiled policy (core)
CompiledPolicy { …, blessing_classes: [(ClassName, ClassId)] }   // registry for daemon/CLI

// IPC (proto)
Request::Bless       { class: String, argv: Vec<String>, cwd, env: Vec<EnvVar> }
EnvVar               { name: String, value: String }   // not an unnamed (String,String)
Request::BlessList
Request::BlessRevoke { id }
// + PAM conversation frames: daemon→client {prompt|info|error, echo}, client→daemon {response}
```

## Open questions
- systemd transient scope vs daemon-delegated subtree as the carrier (B1 decision #2).
- `DecisionEvent` blessing representation (`ClassId` only, resolved to a name in the daemon, vs
  carrying a short name inline).
- Whether to ship the per-invocation `--path` narrowing (B2) or leave scoping purely in policy.
- Caller authorization beyond authentication: `SO_PEERCRED` gives *who*; whether some users may
  bless without PAM (a `pam_u2f`-only or group-gated policy) ties into the still-open
  socket-authorization pass (§15.8 / `STATUS.md`).
