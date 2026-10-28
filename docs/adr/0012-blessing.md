# ADR 0012: Blessing is a carrier-cgroup subject predicate

Status: Accepted. B1 and B2 shipped (2026-07-27); B3 and B4 are in
[todo.md](../../todo.md)

## Context

The rule model ([ADR 0005](0005-flat-rule-model.md)) keys the subject on `exe`, plus the
predicates of [ADR 0006](0006-subject-predicates.md). That is exactly
wrong for the tools you reach for *interactively over secrets*, such as `cat`, `find`, `du`,
`ls` or a shell. You can't write `allow /usr/bin/cat read @secrets`, because it would admit
every `cat`, including the one a scraper `exec`s. Generic exes like these are too coarse a
subject, and no static predicate fixes that. What you actually want to express is *"the `cat`
that I just launched, now"*. That is provenance, the fact that a human at the keyboard chose to
run this.

**Blessing is sudo for file reads.** `cordon bless --class <name> -- <cmd> <args>` runs `<cmd>`
with a runtime grant that a human authenticated. The grant lets the command and its descendants
cross the cordon, as a class defined *in the policy* allows. Nothing is hardcoded, and class
names like `ro` and `rw` are policy conventions, not built-ins. Blessing inverts the project's
stance of never confining the adversary ([threat model](../threat-model.md)). Here we elevate
the ally. It complements static rules and autolearn ([ADR 0011](0011-autolearn.md)) and does
not replace them. Those admit *known* exes durably, and bless covers the long tail of *ad-hoc,
interactive* use that a static rule can't name.

> **Terminology.** "Blessing" and `cordon bless` mean only this runtime grant. A binary that
> a *static* rule trusts is called *trusted*, never blessed.

### Why it must authenticate a human

A blessing is carried by something that descendants inherit. So by the construction attack
([ADR 0003](0003-exe-inode-identity.md)), it can be forged, unless *minting* it requires
something that the in-scope adversary cannot produce. That adversary ([threat
model](../threat-model.md)) is one-shot, non-interactive, same-uid and not root, with no
persistence and no targeted reverse-engineering. Here is what each candidate check would need
from it:

| Candidate distinguisher | Gates the scraper? |
|---|---|
| A secret in a file | ✗ A same-uid process reads it too, and the scheme is circular. |
| An agent or keyring that holds a secret | ✗ Its client has the same uid, so it can't tell you from the scraper without prompting a human. |
| Best-effort ancestry ("my shell launched it") | ✗ See [ADR 0003](0003-exe-inode-identity.md). The scraper is also your descendant, and ancestry can be constructed. |
| Controlling TTY plus foreground process group | ~ It kills the canonical `curl\|sh`, which has no tty, but it is not a boundary. |
| **A human at the keyboard** (PAM: password, fingerprint or token) | ✓ The one-shot automated scraper has no one to answer. |

Everything that isn't "a human acts" collapses when the attacker has the same uid. That is the
same wall that forced the object-centric model ([prior art](../prior-art.md)). So the
strength of a blessing is exactly the check for human presence at mint time, and nothing
else.

This is why an *unauthenticated* bless is rejected, even though the
[threat model](../threat-model.md) concedes targeted reverse engineering.
`cordon bless --` is a 15-character prefix from the README, not reverse
engineering. It would be a *generic* bypass, on the wrong side of the threat-model line. A
check for human presence puts it back on the right side, and the alignment is exact:
- **The one-shot scraper** is in scope. It has no human, so it can't mint, and it is defeated.
- **A resident adversary that acts against a *live* blessed process**, by ptracing it or by
  using its open fds ([limitations](../limitations.md)), is out of scope ([threat
model](../threat-model.md)). It is not defeated. But it was already
  conceded as the class of ptrace and already-open fds, and the blessed process's lifetime
  bounds it.

So the check defeats *exactly* the in-scope adversary and concedes *exactly* the out-of-scope
one, which is the strongest honest claim available. Ideally there is no authentication cache
and no grace window, so that every mint authenticates. The answer to "I need repeated access"
is to `bless` a shell and work in it, not to cache the credential. Dropping the cache also
removes the one window that a resident adversary could otherwise ride. The only residual risk
is acting against a blessed process that is *already live*
([limitations](../limitations.md)), and short-lived blesses
bound that.

> **As shipped ([ADR 0013](0013-bless-authentication.md)).** The check for human presence is
> `sudo`, which runs PAM itself. So this argument holds unchanged for the *presence* property.
> The one caveat is the cache. sudo caches its timestamp, so the shipped flow has a grace
> window, unless sudoers sets `Defaults!/usr/bin/cordon timestamp_timeout=0`. PAM in the daemon
> (B3) closes the window by construction.

## Decision

The mechanism and the authorization are orthogonal, and only the authorization (above) is hard.
The carrier must be readable by the kernel at `file_open`, inherited across fork and exec, and
matchable by policy. That is the cgroup id (`bpf_get_current_cgroup_id`). The `cgroup`
predicate of [ADR 0006](0006-subject-predicates.md) and M2 reads the same value. The key design
choice is that a blessing is not a separate grant table. It is one more `SubjectMatch`
predicate ([ADR 0006](0006-subject-predicates.md)), `blessing = "<class>"`, ANDed with the
rest. That makes grants fully customizable and scoped by policy, with no new precedence
machinery. A blessing rule is an ordinary rule. So its action, its object scope, its
conjunction with other predicates, and its precedence all come from the existing rule model.

- **A class is a named subject predicate, defined in the policy.** A
  `[group.subject.blessed-ro]` table with `blessing = "ro"` declares a class. Ordinary rules
  that reference it (`allow @blessed-ro read ~/.aws`) say exactly what it may do and where. The
  scope is just the rule's object column, and it is not blanket. Because the predicate composes
  in the kernel, a rule could also match "`cat`, but only when blessed", which is the precise
  fix for the coarse-exe problem (above) and does not grant every `cat`. The TOML cannot author
  that conjunction yet ([todo.md](../../todo.md)).
- **The cgroup is the carrier, and it lives for one invocation.** Each `cordon bless` gets a
  fresh, root-owned cgroup (`cordon-bless-<id>.<class>`), tagged with its class. A cgroup per
  invocation, rather than one shared cgroup per class, buys automatic teardown, a handle for
  auditing and revoking each bless, and a smaller standing surface ([ADR
0014](0014-blessing-lifecycle.md)). The two axes are orthogonal. The *class* is static, because
it is a name in the policy. The *cgroup* belongs to one invocation.
- **The `BLESSED` map is a tiny indirection from cgroup to class.** It is a BPF map
  `HashMap<cgroup_id u64, ClassId>`. The daemon writes it at mint and clears it at GC. The
  daemon derives the carrier's id from the directory's `st_ino`. On cgroup2 (kernfs) that *is*
  the id that `bpf_get_current_cgroup_id()` returns, and the smoke suite's scoped-grant
scenario proves it end to end rather than trusting it. The map is not part of the banked
compiled rule table ([ADR 0010](0010-policy-storage.md)). The static `@blessed-*` rules compile
into the per-object buckets like any rule, and they change only when a policy is applied. The
churn of each bless is confined to this one small map, which is not banked and has a single
writer. So a bless never recompiles the policy, and a policy apply never disturbs a live bless.
- **The compiler** assigns a dense `ClassId` to each named blessing class. It stamps the id
  into the `SubjectMatch` of every rule that references the class, and clears the predicate's
  wildcard flag. It also emits a registry from class name to `ClassId` with the compiled
  output. The daemon and the CLI use the registry to validate `--class` and to write `BLESSED`
  at mint. Nothing is hardcoded, and `ro` and `rw` are just whatever names the policy declares.

**How the kernel flow of [ADR 0005](0005-flat-rule-model.md) integrates it.** There is no
separate fast path and no flip from deny to allow. Blessing folds into the existing first-match
scan. `consult` resolves the caller's class once (`current_class`), as
`BLESSED[current_cgroup_id]` or a "not blessed" sentinel, and `subject_matches` compares it. A
rule's `blessing` predicate matches if and only if it is a wildcard or equals that class.
Everything else is unchanged. Copy-down resolves object precedence. Subject specificity already
ranks a concrete `blessing` rule above a `who="*"` catch-all ([ADR 0008](0008-precedence.md)),
so a blessing `allow` outranks the catch-all `deny` that protects the object, with no special
casing. Because a blessing rule is a real rule, it can also be `audit`, to observe a blessed
class. And it is logged like any decision. `DecisionEvent` carries the matched class, so the
journal shows access that went through a blessing. Bless is loud.

> **Precedence note.** A `blessing` predicate counts as one unit of subject specificity, like
> `exe`. So a *targeted* `deny <exe> …` and an `allow @blessed-ro …` on the same object are
> equally specific, and deny wins over allow. An explicit deny of a known-bad binary therefore
> beats a blessing, so you can deny-list a binary even inside blessed sessions. Conjunctions
> raise specificity the usual way. `{exe, blessing}` counts 2 and beats a bare `blessing`,
> which counts 1.

### Policy surface

A class is an ordinary subject group with a `blessing` predicate. That matches the group model
of [ADR 0009](0009-groups.md) and adds no new top-level concept. Blessings are fully
customizable by policy. Their action, object scope, polarity and conjunction with other
predicates are all ordinary rules. So the policy author declares as many classes as they like,
and says precisely what each one reaches.
```toml
[group.subject.blessed-ro]
blessing = "ro"
[group.subject.blessed-rw]
blessing = "rw"
[group.subject.aws-rw]
blessing = "aws"          # a narrow, single-target class
[group.object.secrets]
members = ["~/.aws", "~/.ssh", "~/.config/gcloud"]

# Ordinary rules — the object column IS the scope (no blanket grant):
rules = '''
allow  @blessed-ro   read,listdir   @secrets       # broad read across all secrets
allow  @blessed-rw   read,write      @secrets       # …and write
allow  @aws-rw       read,write      ~/.aws         # scoped to one dir only
'''
```
`cordon bless --class aws -- terraform apply` runs `terraform` in a cgroup of class `aws`. The
kernel matches the `blessing="aws"` predicate on those rules. So `terraform` can read and write
`~/.aws`, and nothing else that is protected, because the scope is exactly the rule's object
column. A class may even be `audit`, to observe a blessed cohort. Subject specificity ([ADR
0008](0008-precedence.md)) makes any concrete `blessing` rule outrank a `who="*"` catch-all on
the same object, and the precedence note above covers the tie with a targeted deny.

### The membership boundary

Unlike identity by exe or ancestry, this is a real boundary and not best-effort. It is plain
DAC on a root-owned kernfs file, backed by cgroup v2's delegation rule.

1. Root creates and owns the blessed cgroup. That is the daemon, or a systemd transient scope
   under a root `cordon.slice`. Its `cgroup.procs` is `root:root`, and the user cannot write
   it.
2. cgroup v2 moves a task when its PID is written to the destination's `cgroup.procs`. A
   non-root scraper with the same uid cannot open that file for writing, because the VFS
   permission check fails with `EACCES`. So the migration never begins.
3. As defense in depth, v2's "common ancestor" rule applies even with a writable fd. It also
   requires an unprivileged writer to hold `MAY_WRITE` on the `cgroup.procs` of the common
   ancestor. We never delegate the subtree to the user, so that is a second closed door.
4. `clone3(CLONE_INTO_CGROUP)` creates a child directly inside a cgroup, and it runs the same
   write-permission check on the target. So the scraper can't sidestep the check by spawning
   into the cgroup.
5. The kernel assigns the cgroup id, and it is unique to each directory. The scraper can't
   forge a cgroup whose id collides with a blessed one, and only ids that the daemon created
   are in `BLESSED`.
6. The only legitimate entry is at spawn, and only after the human authenticates. As shipped
   ([ADR 0014](0014-blessing-lifecycle.md)), the unprivileged `cordon bless` joins the
carrier in the child's `pre_exec`. That happens *before* `exec`, so the target runs zero
instructions unblessed, which is exactly the property `clone3(CLONE_INTO_CGROUP)` was specified
for. The CLI can do that without being root, because what it holds is the *descriptor* that the
root daemon opened after approval, not privilege (see the delegation note below). Children
inherit the membership automatically, and that is the intended behavior of `bless -- bash`.

The entire lock is that root owns `cgroup.procs` and opens it only after authentication. That
makes cgroup membership the *strongest* subject identity in the system, because a same-uid
process cannot forge it the way it forges ancestry.

> **Delegation by descriptor (B2).** The daemon does not hand back the carrier's *path*. It
> opens `cgroup.procs` itself, as root, and passes that descriptor over `SCM_RIGHTS`. cgroup v2
> checks migration permission against the credentials of whoever *opened* the file.
> `cgroup_procs_write_permission()` overrides the check with `of->file->f_cred`, precisely so
> that delegation by fd works. So the holder can join a task to the carrier without ever being
> root. That is what lets `cordon bless` run unprivileged, as an ordinary child of the user's
> shell. And that in turn gives the blessed process its natural environment, tty and logind
> session ([ADR 0014](0014-blessing-lifecycle.md)). Point 1 above is unchanged. The *fd* is
> delegated, but the *directory* is still root-owned, and only the daemon ever opens it, after
> authentication.
>
> **The honest cost.** The fd's holder can move any task it can name into the carrier, not just
> its own child. The check is on the opener, so the writer's own credentials are not
> consulted. This is not an escalation. The blessing grants only what the class's rules name,
> DAC still applies to every object, and the holder is the invoking user, who could already
> run those tasks. But it does widen "who can be blessed" from *this child* to *anything this
> user can name*. So the descriptor's reach is kept as short as the mechanism allows. It is
> received close-on-exec (`MSG_CMSG_CLOEXEC`, which is *not* the kernel's default for
> `SCM_RIGHTS`). So it dies at the `exec` that starts the blessed command, and it never becomes
> a standing capability held by the blessed process itself.

> **Mechanism wrinkle.** systemd owns the unified hierarchy. It is the single writer, and inner
> nodes hold no processes. The clean placement is a systemd transient scope created through the
> daemon, or a subtree delegated to the root daemon (`Delegate=yes`). A hand-rolled cgroup that
> systemd doesn't know about invites conflicts. Either way, the cgroup for each bless is
> root-owned.

## Consequences

- **Compared with "admit" in flow A ([authoring flows](../authoring.md)).** Admit adds a
  *durable static* `allow` for a *known* exe. Bless is a *runtime, authenticated* grant for an
  *ad-hoc* invocation. They have different lifetimes and a different basis for trust.
- **Compared with autolearn ([ADR 0011](0011-autolearn.md)).** Autolearn *observes* in order to
  *propose* durable rules. Bless *grants* immediately, under human authentication. The two are
  orthogonal.
- **Compared with `cordon policy edit` ([ADR 0010](0010-policy-storage.md)).** Both are
  privileged, authenticated changes to *what is allowed*. Edit changes the durable policy, and
  bless mints a transient grant. As shipped, both authenticate the same way (`sudo`), and in
  both the user's program runs as the invoking user, never as root: edit drops privilege for
  the editor child, and the bless CLI never holds privilege at all. There is one deliberate
  difference. The editor runs with *no* supplementary groups, because it processes hostile
  input. A blessed session keeps the user's full group list, because it is their normal
  session.

The blast radius and limits of a blessing are in [limitations](../limitations.md).
