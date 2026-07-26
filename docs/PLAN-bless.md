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

> **Status: B1 is done (2026-07-26), sudo-gated.** B1a–B1f all shipped and are VM-validated
> (22/22 smoke scenarios). One design change during implementation: **`sudo` authenticates
> instead of PAM-in-the-daemon**, and the CLI (root via sudo) spawns the target instead of the
> daemon — see the B1d note and DESIGN §16.5 for the rationale and the accepted deltas. PAM
> mint moves to **B3** below.

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

### B1e. CLI — `crates/cli` ✅ *(shipped)*
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

### B1f. Validation — `packaging/test/bpf-lsm-smoke.sh` ✅ *(shipped: scenarios 18–22, 22/22 green)*
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
- No PAM test hook needed — the smoke runs as root, so the CLI is invoked directly and the
  daemon's uid-0 gate passes. Startup reconciliation gets incidental coverage (a scenario's
  daemon is killed with carriers live; the next one logs "removed empty leftover carrier").

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

## Milestone B2 — Ergonomics & observability
- Rich `cordon bless list` / structured journal; `revoke` polish; optional blessed-shell
  affordance (a prompt marker / hint **derived from cgroup membership**, never an env var
  *carrier* — env is forgeable as a carrier, §16.2; inheriting env into the child is fine).
- (Optional) per-invocation **narrowing** `--path P` that intersects the chosen class's scope
  down to `P` for this invocation (tighten-only; never widens past the policy class).
- Optional hardware-token-per-bless mode (`pam_u2f` touch *every* mint) for high-value classes
  — extra assurance the human is present at each grant.

---

## Milestone B3 — PAM authenticator (replaces the sudo gate)
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
- **Keeps the CLI as spawner.** Nothing in B1's join-then-drop `pre_exec` path depends on the
  authenticator; a PAM-authenticated non-root CLI cannot open the carrier's `cgroup.procs`,
  though, so this milestone must also decide the placement mechanism — most likely the daemon
  passing the CLI a **pre-opened `cgroup.procs` fd** over the socket (`SCM_RIGHTS`) after auth,
  preserving both the boundary and the natural tty/job-control the daemon-spawn design lost.

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
