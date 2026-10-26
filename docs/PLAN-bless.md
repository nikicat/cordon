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

> **Status: B1 + B2 shipped (2026-07-27); the VM smoke is green.** What exists
> today is specified in DESIGN §16 and summarized in [`STATUS.md`](../STATUS.md); the
> detailed B1/B2 commit plans have been retired now that they are code.
>
> **Both remaining milestones are deferred behind the core (2026-07-28).** B1+B2 already make
> `bless` usable, so neither B3 nor B4 blocks anything: the queue is bugs → M3 → M5 → M6, and
> blessing resumes once the boundary underneath it is sound. **B3 is a nice-to-have**
> (it *relaxes* the mint gate — no one is locked out meanwhile, and the sudo grace window is
> an accepted delta, §16.5). **B4 waits on the core by its own logic** — a blanket
> "uncordoned" class is a skeleton key, and widening the grant surface before M5/M6 close the
> fail-open and confused-deputy holes gets the order backwards.

Guiding constraints (from §16) — these still bind B3 and B4:
- **Authorization is the whole feature.** The carrier is forgeable (§8.1); security rests
  entirely on (a) a human authenticating at mint and (b) root-owned `cgroup.procs` so only a
  root process places a task in a blessed cgroup.
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
- **No grace window.** Every mint authenticates; repeat access is `bless`-a-shell. *(Not true
  as shipped — sudo's timestamp cache is a grace window, documented as an accepted delta in
  DESIGN §16.5. B3 restores the property by construction.)*

> **One lesson from B2's derisk spike, kept because it cost a cycle.** The spike
> **constructed** the world that made its answer come out yes: it `mkdir`ed a cgroup under
> `session-3.scope` and confirmed logind saw the session, without ever asking *where the
> user's processes actually are* (under the delegated `user@UID.service`, with no session
> scope above them). A probe that builds its own premise proves only that the premise is
> self-consistent. The `bless_placement` and `bless_reconcile_ownership` smoke scenarios
> now cover the placement rule and fail when it regresses; the script is deleted.

---

## Milestone B3 — PAM authenticator (replaces the uid-0 gate) ← **deferred, nice to have**
The upgrade B1 was deliberately shaped to accept: the mint verb is authenticator-agnostic, so
this adds frames beside it rather than reshaping the IPC. Full design in DESIGN §16.5.

- **PAM in the daemon** (new dep): authenticate the **peer uid's** user (from `SO_PEERCRED`,
  as today) against a `cordon` PAM service; the conversation function proxies prompt/info
  frames to the `cordon bless` front-end, which renders them on the tty and returns input. The
  front-end never asserts "I authed" — it relays only, so a scraper on the socket controls the
  I/O channel and never the verdict.
- **Relaxes the uid-0 gate to "the authenticated peer":** `authorize()` stops requiring root
  for `BlessApprove`, so **a non-sudoer can bless their own tools** — the property the sudo
  gate can't offer. Revoke needs no change: it is already open to the minting uid
  (`may_revoke` in `crates/daemon/src/backend/bpf_lsm/bless.rs`).
- **Restores "no grace window" by construction** (every mint authenticates), retiring the
  sudoers `timestamp_timeout=0` note.
- **Mechanically, B2 already did the hard part.** The `SCM_RIGHTS` `cgroup.procs` hand-off
  this milestone would otherwise have had to invent ships in B2, along with an unprivileged
  CLI — so B3 reduces to swapping *what proves a human is present*: replace the
  `bless-helper`'s uid-0 approval with a PAM conversation against the requesting peer. The
  spawn path, the carrier placement and the boundary are unchanged.

---

## Milestone B4 — Ergonomics & observability ← **deferred until the core is sound**
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
  rejected outright in `resolve.rs` because it can't work for *deny*. Open questions: what
  a bare `*` means in a home-scoped user-tier fragment, and that a blanket class is a skeleton
  key that widens the §16.7 ptrace/open-fd exposure — so it must be an opt-in second class,
  never a change to what blessing means.

---

## Cross-milestone notes
- **Relation to M2 (§15.4 `cgroup` predicate):** blessing shares the
  `bpf_get_current_cgroup_id` read and the `SubjectMatch`-predicate pattern, but is a
  *distinct* predicate — it matches *any cgroup currently registered as class X in
  `BLESSED`*, via indirection, not a fixed cgroup id. The two stay independent.
- **Interaction with M5 (fail-safe pinning):** M5 pins the LSM links and no maps
  (`PinDir::pin_links`); `BLESSED` lives exactly as long as the program of its generation. A
  restarted daemon loads a fresh, empty `BLESSED` — fail closed — and `Blessings::reconcile`
  re-registers the leftover carriers whose class is still declared (§16.6). Pinning `BLESSED`
  separately would buy nothing: the old generation's program already holds it, so its entries
  would be no more or less stale, only reachable (see STATUS, *Settled*).
- **cgroup v2 assumed** (unified hierarchy). v1/hybrid is out of scope; detect and refuse with
  a clear diagnostic.
- **Naming:** `bless` is reserved for this runtime grant; authoring flow A is observe →
  **admit** → enforce (§15.10). Threat-model "blessed binary/ancestor" (§8.1) is generic
  English for a statically-trusted binary, unrelated to this command.

## Open questions
- Whether to ship the per-invocation `--path` narrowing (B4) or leave scoping purely in policy.
- Caller authorization beyond authentication: `SO_PEERCRED` gives *who*, and the socket gate
  (§15.8) settles *may they reach the verb*; whether some users may bless without a full PAM
  conversation (a `pam_u2f`-only or group-gated policy) is B3's to decide.
