# Implementation plan — blessing (`cordon bless`)

Concrete, reviewable plan for [`DESIGN.md` §16](DESIGN.md) — the runtime, PAM-authenticated
access grant. A blessing lets an *ad-hoc, interactive* invocation (`cat`/`find`/`du`/a shell)
and its descendants cross the cordon, under a class defined in policy. It is **additive** to
the §15 rule model and reuses it as much as possible: **a blessing is one more `SubjectMatch`
predicate** (`blessing = "<class>"`, §16.3), so a blessing rule is an ordinary rule —
action, object scope, conjunction, and precedence all come from the existing model. The only
new pieces are a carrier (a per-invocation root-owned cgroup), a tiny runtime indirection map
(`BLESSED: cgroup_id → ClassId`), a PAM mint path in the daemon, and the `cordon bless` CLI.

Guiding constraints (from §16):
- **Authorization is the whole feature.** The carrier is forgeable (§8.1); security rests
  entirely on (a) PAM at mint and (b) root-owned `cgroup.procs` so only the daemon places a
  task in a blessed cgroup. Build and test those two first.
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
- **No grace window.** Every mint authenticates; repeat access is `bless`-a-shell.

Milestones are sequenced so each is shippable and VM-validated on its own. **B1 is the
boundary** and ships the whole feature (scoped, fully customizable); B2 is ergonomics.

---

## Milestone B1 — Core grant path (the boundary), scoped
Text policy gains the `blessing` subject predicate; `cordon bless` authenticates via PAM,
spawns the command into a fresh root-owned cgroup tagged with its class, and the kernel matches
the blessing predicate during its normal bucket scan. Delivers the whole feature end-to-end,
**scoped to the rule's object column** (no blanket), **no grace window**.

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

### B1d. Daemon — `crates/daemon`
- **IPC** (`proto.rs`/`ipc.rs`): `Request::Bless { class, argv, cwd, env }` (the front-end
  ships its full `environ`; the child inherits it — safe, no uid elevation), plus PAM
  **conversation** frames (daemon→client prompt/info, client→daemon response) and a terminal
  result. `Request::BlessList` / `Request::BlessRevoke { id }`. Caller identity from
  **`SO_PEERCRED`**, never the request body.
- **PAM** (new dep): authenticate the peer uid's user against a `cordon` PAM service, with a
  conversation function that proxies prompts to the client over the socket (§16.5). Runs in the
  root daemon (needs `/etc/shadow`).
- **Carrier:** validate `class` against the compiled registry; create a fresh root-owned cgroup
  — **primary: a systemd transient scope** (`cordon-bless-<id>.scope` under a `cordon.slice`);
  **alt:** a subtree delegated to the daemon. Register `BLESSED[cgroup_id] = ClassId`.
- **Spawn:** `clone3(CLONE_INTO_CGROUP)` so the child is *born* in the cgroup (zero unblessed
  window), running **as the invoking user** — reuse the privilege-drop discipline from
  `crates/cli/src/sys.rs` (setgroups/setgid/setuid, the user's `$HOME`/`$USER`) — with the
  **caller's full environment + cwd** (no scrubbing; same-uid, no elevation).
- **GC:** watch the cgroup's `cgroup.events` `populated` flag; on `0`, remove the cgroup and
  drop the `BLESSED` entry (the grant evaporates with the tree).
- **Reconciliation:** on startup, adopt any pre-existing `cordon-bless-*` scopes, rebuild
  `BLESSED`, resume GC — so a daemon restart doesn't strand live blessings or leak entries.

### B1e. CLI — `crates/cli`
- `cordon bless --class NAME -- <cmd> <args…>`: connect, drive the PAM conversation on the
  **tty** (echo-off for passwords, render info for fingerprint), then the daemon spawns.
  `--class` is canonical; a policy may designate a default class so it can be omitted. (`ro`/`rw`
  are policy conventions, not built-in flags.)
- `cordon bless list` (live blessings: id, class, user, tty, started, argv, pids) and
  `cordon bless revoke <id>`.
- The front-end is the existing `cordon` binary; it never asserts "I authed" — it only relays
  the conversation (§16.5).

### B1f. Validation — `packaging/test/bpf-lsm-smoke.sh`
- **Scoped grant:** a class scoped to `~/.aws` lets `cordon bless --class … -- <reader>` read
  `~/.aws`, but the **same blessed reader is still denied** on another protected object the
  class doesn't name (proves scope = the rule's object column, not blanket).
- **Unblessed sibling** stays denied; the blessed access **outranks** the `who="*"` catch-all.
- **Boundary test:** a non-root, same-uid process trying to write the blessed cgroup's
  `cgroup.procs` (and `clone3(CLONE_INTO_CGROUP)` into it) fails (`EACCES`).
- **Inheritance:** `bless … -- sh -c '<child reads in-scope secret>'` — the child is allowed.
- **GC/teardown:** after the blessed tree exits, a fresh unblessed open is denied again, and
  `BLESSED` no longer contains the id.
- **Journal:** the bless-mediated access logs with the matched class.
- (PAM in the smoke: a permissive test PAM service, or a daemon test hook injecting an
  authenticated mint, so the e2e needs no real credential.)

### B1 decisions (to lock at impl start)
1. **Blessing is a `SubjectMatch` predicate** (Wiring 2), not a separate grant table — scope
   and precedence reuse the rule model.
2. **Carrier = per-invocation root-owned cgroup via systemd transient scope** (delegated
   subtree as fallback). Per-invocation, not shared-per-class.
3. **`BLESSED` is a small, unbanked, single-writer `cgroup_id → ClassId` map** (not in the
   §15.8 double-buffer).
4. **Scoped, fully customizable:** a class's action, object scope, conjunction, and polarity
   are whatever its policy rules say (a class may even be `audit`). No blanket grant.
5. **Precedence:** a `blessing` predicate is **one** unit of subject specificity (like `exe`).
   A concrete blessing rule outranks a `who="*"` catch-all; a *targeted* `deny <exe>` ties a
   bare `allow @blessed-x` at equal specificity → `deny>allow` wins (deny-list beats blessing).
   Conjunctions (`{exe, blessing}` = 2) raise specificity normally.
6. **PAM in the daemon; conversation proxied to the tty; caller identity from `SO_PEERCRED`.**
7. **Child runs as the invoking user** with the caller's full env + cwd (privilege drop reused
   from `sys.rs`).
8. **No grace / auth-cache window** — every mint authenticates.

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
