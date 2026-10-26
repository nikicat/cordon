# Implementation plan — blessing (`cordon bless`)

This is the concrete, reviewable plan for [`DESIGN.md` §16](DESIGN.md), the runtime access
grant that a human authenticates. A blessing lets an ad-hoc, interactive invocation (`cat`,
`find`, `du` or a shell) and its descendants cross the cordon, under a class that the policy
defines. It adds to the §15 rule model and reuses it as much as possible. A blessing is one
more `SubjectMatch` predicate (`blessing = "<class>"`, §16.3), so a blessing rule is an
ordinary rule. Its action, object scope, conjunction and precedence all come from the
existing model. There are only four new pieces. One is a carrier, which is a root-owned
cgroup made for one invocation. Another is a tiny runtime indirection map
(`BLESSED`, from a cgroup id to a `ClassId`). The last two are a root-gated mint path in the
daemon and the `cordon bless` CLI.

> Status: B1 and B2 shipped on 2026-07-27, and the VM smoke is green. DESIGN §16 specifies
> what exists today, and [`STATUS.md`](../STATUS.md) summarizes it. The detailed B1 and B2
> commit plans were retired once they became code.
>
> Both remaining milestones were deferred behind the core on 2026-07-28. B1 and B2 already
> make `bless` usable, so neither B3 nor B4 blocks anything. The queue was bugs, then M3, then
> M5, then M6, and blessing resumes once the boundary underneath it is sound. B3 is a
> nice-to-have. It relaxes the mint gate, so no one is locked out in the meantime, and the
> sudo grace window is an accepted delta (§16.5). B4 waits on the core by its own logic. A
> blanket "uncordoned" class is a skeleton key, and widening the grant surface before M5 and
> M6 close the fail-open and confused-deputy holes gets the order backwards.

These guiding constraints come from §16, and they still bind B3 and B4:
- **Authorization is the whole feature.** The carrier is forgeable (§8.1). So security rests
  entirely on two things. One is a human authenticating at mint time. The other is that
  `cgroup.procs` is root-owned, so only a root process can place a task in a blessed cgroup.
- **Blessing is an ordinary rule.** The `blessing` predicate composes with the rest of
  `SubjectMatch`. The scope is the rule's object column, and precedence is the §15.6
  specificity. There is no bespoke grant table and no flip from deny to allow. There is just a
  first-match scan over the compiled buckets.
- **Decoupled from `policy apply`.** The static `@blessed-*` rules compile into the banked
  buckets like any other rule. The only runtime state for each bless is the `BLESSED`
  indirection map, which is small, unbanked and has a single writer. A bless never recompiles
  the policy, and a policy apply never disturbs a live bless.
- **Loud.** Every decision that a blessing matched is journaled, with the matched class on
  the record. Blessings can be listed and revoked.
- **No hardcoding.** Classes are declared in policy with the `blessing` predicate. Class names
  such as `ro` and `rw` are conventions, not built-ins.
- **No grace window.** Every mint authenticates, and repeated access means blessing a shell.
  *(This is not true as shipped. sudo's timestamp cache is a grace window, which DESIGN §16.5
  documents as an accepted delta. B3 restores the property by construction.)*

> One lesson from B2's derisk spike is kept here because it cost a cycle. The spike built the
> world that made its answer come out yes. It ran `mkdir` to make a cgroup under
> `session-3.scope` and confirmed that logind saw the session. It never asked where the
> user's processes actually are. They are under the delegated `user@UID.service`, with no
> session scope above them. A probe that builds its own premise proves only that the premise
> is self-consistent. The `bless_placement` and `bless_reconcile_ownership` smoke scenarios
> now cover the placement rule and fail when it regresses, and the spike script is deleted.

---

## Milestone B3 — PAM authenticator (replaces the uid-0 gate) ← **deferred, nice to have**
B1 was deliberately shaped to accept this upgrade. The mint verb does not depend on the
authenticator, so B3 adds frames beside it rather than reshaping the IPC. The full design is in
DESIGN §16.5.

- **PAM in the daemon** (a new dependency). The daemon authenticates the user behind the peer
  uid against a `cordon` PAM service, taking the uid from `SO_PEERCRED` as it does today. The
  conversation function proxies prompt and info frames to the `cordon bless` front-end. The
  front-end renders them on the tty and returns the input. The front-end never asserts that
  it authenticated, and it only relays. So a scraper on the socket controls the I/O channel
  and never the verdict.
- **It relaxes the uid-0 gate to "the authenticated peer".** `authorize()` stops requiring
  root for `BlessApprove`, so a non-sudoer can bless their own tools. The sudo gate can't offer
  that property. Revoke needs no change, because it is already open to the minting uid
  (`may_revoke` in `crates/daemon/src/backend/bpf_lsm/bless.rs`).
- **It restores "no grace window" by construction**, because every mint authenticates. That
  retires the sudoers `timestamp_timeout=0` note.
- **Mechanically, B2 already did the hard part.** B2 ships the `SCM_RIGHTS` hand-off of
  `cgroup.procs`, which this milestone would otherwise have had to invent, along with an
  unprivileged CLI. So B3 reduces to swapping what proves that a human is present. It replaces
  the `bless-helper`'s uid-0 approval with a PAM conversation against the requesting peer. The
  spawn path, the carrier placement and the boundary stay unchanged.

---

## Milestone B4 — Ergonomics & observability ← **deferred until the core is sound**
- A richer `cordon bless list`, a structured journal, and polish for `revoke`. Optionally, an
  affordance for a blessed shell, such as a prompt marker or hint. It must be derived from
  cgroup membership and never carried in an environment variable, because the environment is
  forgeable as a carrier (§16.2). Inheriting the environment into the child is fine.
- (Optional) A `--path P` option that narrows one invocation. It intersects the chosen class's
  scope down to `P` for that invocation. It can only tighten, and never widens past the policy
  class.
- An optional mode that asks for a hardware token on every bless (a `pam_u2f` touch on every
  mint) for high-value classes. It gives extra assurance that the human is present at each
  grant.
- **An "uncordoned" blessing class**, raised on the host run. Today a class must list its
  object scope. So every directory added to `@secrets` must also be added to the blessing's
  scope, or a blessed session hits a surprise denial, and the two lists drift. The cheap form
  is to allow `*` in the object column for allow-polarity rules only. The compiler would fan
  such a rule out into every protected object's bucket. That needs no kernel change and adds
  no new bypass in `decide()`. "Allow on every protected object" is the complete definition of
  uncordoned, because an unprotected path is already unmediated. `resolve.rs` currently
  rejects `where = "*"` outright, because it can't work for deny. Two questions are open. One
  is what a bare `*` means in a home-scoped user-tier fragment. The other is that a blanket
  class is a skeleton key that widens the ptrace and open-fd exposure of §16.7. So it must be
  an opt-in second class, and never a change to what blessing means.

---

## Cross-milestone notes
- **Relation to M2 (the §15.4 `cgroup` predicate).** Blessing shares the
  `bpf_get_current_cgroup_id` read and the `SubjectMatch` predicate pattern with it. But it is
  a distinct predicate. It matches any cgroup currently registered as class X in `BLESSED`,
  through the indirection, rather than one fixed cgroup id. The two stay independent.
- **Interaction with M5 (fail-safe pinning).** M5 pins the LSM links and no maps
  (`PinDir::pin_links`). So `BLESSED` lives exactly as long as the program of its generation.
  A restarted daemon loads a fresh, empty `BLESSED`, which fails closed.
  `Blessings::reconcile` then re-registers the leftover carriers whose class is still declared
  (§16.6). Pinning `BLESSED` separately would buy nothing. The old generation's program
  already holds it, so its entries would be no more and no less stale, only reachable (see
  STATUS, *Settled*).
- **cgroup v2 (the unified hierarchy) is assumed.** v1 and hybrid setups are out of scope.
  cordon should detect them and refuse with a clear diagnostic.
- **Naming.** `bless` is reserved for this runtime grant. Authoring flow A is observe, then
  admit, then enforce (§15.10). In the threat model, "blessed binary/ancestor" (§8.1) is
  generic English for a statically trusted binary, and it is unrelated to this command.

## Open questions
- Whether to ship the per-invocation `--path` narrowing (B4), or to leave scoping purely in
  the policy.
- How to authorize a caller beyond authenticating it. `SO_PEERCRED` says who the caller is,
  and the socket gate (§15.8) settles whether they may reach the verb. B3 decides whether some
  users may bless without a full PAM conversation, for example with a `pam_u2f`-only or a
  group-gated policy.
