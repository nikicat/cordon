# STATUS

> **Note.** This is the resume point: what exists, what is left, and the facts that cost
> real time to learn. It is deliberately not a changelog — finished work is described in
> present tense or not at all, and `git log` has the rest.

## Where things stand

The architecture is the flat **rule model** (DESIGN §15): a root-owned text policy of
`(who, where, action, policy)` rules, compiled in userspace, enforced **in-kernel** by the
`bpf-lsm` backend. **M1 is complete and VM-validated**, as is **blessing B1 + B2**
(DESIGN §16). The suite is 27 `bpf-lsm-smoke.sh` scenarios, green on the CI-pinned v6.12.
The earlier owner model was retired in the migration — see *Pre-rule-model history* below.

Milestones: [docs/PLAN-rule-model.md](docs/PLAN-rule-model.md) (M2–M5 ahead) and
[docs/PLAN-bless.md](docs/PLAN-bless.md) (B3 next).

## What's implemented

**The rule pipeline** — `parse` (TOML → spans; both the verbose `[[rule]]` surface and the
compact one-rule-per-line DSL, normalized to one `ParsedRule`) → `resolve` (group expansion
on all three axes, cycle/ref validation, `~`-expansion) → `compile` (cross-product →
**copy-down** object precedence → sorted, deduped, capped per-object buckets). Diagnostics
carry a source `Pos`. The compiled form is the contract in
`crates/bpf-common/src/policy_maps.rs`.

**Precedence** is object depth → **subject specificity** → deny>allow. There is **no global
mode**: the per-rule `policy` is the only enforcement level, so `audit` observes an object
and `deny` enforces it, per object — which is what makes the audit→admit→enforce flow
(§15.10) work one object at a time. "Off" is an empty policy or a stopped daemon.

**In-kernel** (`crates/bpf`, `file_open`): dentry walk → deepest `PROTECTED` object, action
from `f_mode`/`f_flags`, **first-match** scan of the packed `RULES` bucket, default-deny.
Records carry the **actual opened path**, reconstructed by walking `d_name` up to the matched
object (`bpf_d_path` is unavailable at `file_open`) through a per-CPU scratch map.

**Volume control**, because tools re-open one config hundreds of times per run (helm: 464×
`~/.kube/config`): an in-kernel LRU suppressor keyed by `(exe, ObjId, action, leaf)` emits at
most one event per key per second and folds the rest into a `suppressed` count, and the
daemon coalesces each drain batch into one journal line.

**Atomic apply.** The three rule maps are **banked**; `seed_policy` fills the inactive bank
and flips `Settings.active_bank` in one write, so a re-seed is never half-visible.
Single-writer by construction — the `&mut Ebpf` lives on one backend thread.

**Policy tiers.** Effective policy is system ⊕ user tier. A system fragment pulls in a
user-tier file via `[[include]] user = … path = …`; the included file is **home-scoped** (its
objects must resolve under that user's `~`) and may not itself include. A policy path may be
one file or a conf.d directory of fragments merged in name order, each able to expand `~`
against a `user =` header.

**CLI.** `policy check` (daemon-free lint), `apply`, `show`, `status`, and `policy edit` —
the sudoedit analog, which runs `$EDITOR` **as the invoking user** (a root editor on a
same-uid box is an escalation, DESIGN §2), then validates and, if it compiles, applies *and*
saves in one step. Bare `edit` opens your own tier; `--system` and `--user NAME` name the
others.

**Socket authorization.** Every write (`PolicyApply`, `BlessMint`, `BlessRevoke`) requires
peer uid 0 via `SO_PEERCRED`; every read is open. `authorize()` is a pure table with an
**exhaustive** match, so a new verb cannot be added without picking a side. The socket is
`0666` — the mode decides who can reach the daemon, the table decides what they may do.

**Blessing** (`cordon bless`) is one more `SubjectMatch` predicate, so a blessing rule is an
ordinary rule and its scope is the rule's object column. `cordon bless` runs **unprivileged**:
it verifies the daemon is root, sends a request, and holds the connection; a helper spawned
under `$CORDON_SUDO` reaches the daemon as uid 0, which is the entire proof of human
presence; the daemon mints a root-owned carrier cgroup **inside the requester's own user
subtree** and passes back its `cgroup.procs` descriptor over `SCM_RIGHTS`. The CLI forks and
joins in `pre_exec`, so the target never runs unblessed and the CLI never holds privilege.
Environment, cwd, tty, job control and session are inherited by construction.

## What's left

- **B3 — the PAM authenticator** ([PLAN-bless](docs/PLAN-bless.md)). Replaces the uid-0 gate
  with "the authenticated peer", so a **non-sudoer can bless their own tools**, and restores
  "no grace window" by construction (sudo's timestamp cache is one today; the deployment
  workaround is `Defaults!/usr/bin/cordon timestamp_timeout=0`). B2 did its structural work —
  the `SCM_RIGHTS` hand-off and the unprivileged CLI already ship — so it reduces to swapping
  *what proves a human is present*, and it **relaxes** the gate rather than tightening it.
- **M5 — fail-safe bpffs pinning**, the last M1 hardening item: pin program + maps + link so
  enforcement survives daemon death (until then it fails **open** on daemon exit). **Must
  ship with a singleton guard** (flock on the pin dir / refuse-if-pins-active): today two
  daemons cannot corrupt each other because each loads private maps, but two daemons sharing
  *pinned* maps would reintroduce a cross-process writer race. Pin the policy maps only —
  a pinned `BLESSED` with a dead daemon means grants that never expire.
- **B4 — the enumerated-scope gap.** A blessing class's object scope must be listed, so it
  drifts against `@secrets`: every dir added to one must be added to the other or a blessed
  session hits a surprise denial. An "uncordoned" class is sketched in PLAN-bless B4.
- **M2–M4** — subject predicates beyond exe, mutation/exec hooks, autolearn.
- Smaller carried-over notes live in [PLAN-rule-model](docs/PLAN-rule-model.md).

## Settled, do not redo

- **`PathBuf` → `Box<Path>` for stored path fields: tried wholesale, reverted.** The premise
  was that the type would say "built once, never mutated". It doesn't — anything holding
  `&mut self` can reassign a `Box<Path>` field just the same, so all it removes is in-place
  growth that nothing was calling. What it adds is real: `.into()` at every construction,
  `.to_path_buf()` at every owned read, `.as_os_str()` because `Box<Path>` is not
  `AsRef<OsStr>`, and a field-vs-transient rule to keep straight forever. If the intent needs
  recording, a doc line on the field costs nothing.

## Durable kernel facts

- `bpf_d_path` is **not allowed** at `file_open`, so identity is inode `(dev,inode)`, never a
  path — resolved by the daemon at seed time.
- The daemon takes the device from the **mount table** (`/proc/self/mountinfo`), which matches
  the kernel's `sb->s_dev` on overlayfs/btrfs where `stat`'s `st_dev` does not.
- Loading an LSM program needs `CAP_BPF` + `CAP_MAC_ADMIN` and `lockdown` off. An object built
  against one kernel runs on another via BTF-resolved field offsets injected at load (rustc
  can't emit CO-RE relocations).
- On cgroup2 (kernfs) a directory's `st_ino` **is** the id `bpf_get_current_cgroup_id()`
  returns — which is what lets the daemon key `BLESSED` by a carrier it just created.
- **logind is not needed to test carrier placement.** A session scope is a root-owned cgroup
  directory in the shape systemd makes, and everything under test is kernel mechanics; only
  "polkit is then satisfied" is host-only.

## Pre-rule-model history (retired)

Phases 0–3 built an **owner model** — explicit rules + TOFU creator-owns, a root-owned SQLite
store, and a privilege-agnostic core — on two enforcement backends: a root **`fanotify`**
`FAN_OPEN_PERM` backend (Phase 1) and an in-kernel `bpf-lsm` backend enforcing `subtrees` +
`owner_identities` (Phase 3), both VM-validated. The rule-model migration replaced all of it:
owners / TOFU / rules collapsed into one `(who, where, action, policy)` model; the SQLite
store and the `mock` + `fanotify` backends were removed; `bpf-lsm` is now the only backend.
The detail lives in git history and DESIGN §1–§14 (marked superseded there).
