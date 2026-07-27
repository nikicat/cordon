# STATUS

> **Note.** This is the resume point: what exists, what is left, and the facts that cost
> real time to learn. It is deliberately not a changelog — finished work is described in
> present tense or not at all, and `git log` has the rest.

## Where things stand

The architecture is the flat **rule model** (DESIGN §15): a root-owned text policy of
`(who, where, action, policy)` rules, compiled in userspace, enforced **in-kernel** by the
`bpf-lsm` backend. **M1 is complete and VM-validated**, as is **blessing B1 + B2**
(DESIGN §16). The `bpf-lsm-smoke.sh` suite is green on the CI-pinned v6.12.
The earlier owner model was retired in the migration — see *Pre-rule-model history* below.

Milestones: [docs/PLAN-rule-model.md](docs/PLAN-rule-model.md) — **finish M3, then M5 and M6**
(M3 is partly landed: the mutation hooks ship, `inode_mkdir`/`bprm_check_security` do not) —
and [docs/PLAN-bless.md](docs/PLAN-bless.md), whose B3/B4 are **deferred behind the core**.

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

**Sound directory objects** (`inode_link`/`inode_rename`/`inode_unlink`/`inode_rmdir`). A
directory protects its children by *ancestry*, so a second name for a protected inode — a
hardlink or a rename out — is an ancestry that avoids the object, and the file becomes
readable by everything, permanently and unlogged. The **escape** (a protected inode taking a
name outside its object) is refused unconditionally, with no rule lookup and no blessing
exemption; **clobber** and **destroy** are ordinary writes and take the subject's verdict, so
`audit` objects keep working. An internal rename short-circuits, which is what keeps
atomic-save alive inside a protected dir. `inode_mkdir` joins them by classifying off the
*parent*, since a to-be-created dentry is negative and matches nothing itself. Every mutation
program shares `find_object`, so entry is
a dentry rather than a `struct file`. A rename **over** an existing name is a fourth case,
classified off the destination *dentry* rather than its directory: it destroys that inode and
`inode_rename` is the only hook the kernel fires for it, so without it `mv anything secret`
did what `rm secret` is refused. DESIGN §15.5.

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

**Order (set 2026-07-28).** Bugs and doc drift first, then finish **M3**; then **M5** and
**M6**, which are the must-haves. Blessing work waits — B1+B2 already make `bless` usable, and
the core boundary is what the remaining holes are in. The rule: *soundness before ergonomics.*

### First — finish M3

- **M3 completion** — `bprm_check_security` (the `execute` action) is the one hook still
  missing, and it is the first to need a **new BTF offset** (`linux_binprm -> file`); every
  hook so far is handed a dentry the existing offsets already cover. `listdir` ≈ "open dir for
  read" still needs its coarseness documented. `inode_mkdir` now ships, and
  `RENAME_EXCHANGE` is **verified** rather than believed (see *Durable kernel facts*).

### Next — the must-haves

- **M5 — fail-safe bpffs pinning**, the last M1 hardening item: pin program + maps + link so
  enforcement survives daemon death (until then it fails **open** on daemon exit). **Must
  ship with a singleton guard** (flock on the pin dir / refuse-if-pins-active): today two
  daemons cannot corrupt each other because each loads private maps, but two daemons sharing
  *pinned* maps would reintroduce a cross-process writer race. Pin the policy maps only —
  a pinned `BLESSED` with a dead daemon means grants that never expire.
- **M6 — fixed code as the precondition for a grant**, the `exe`-identity fix, and the
  largest known hole. The invariant: a grant attaches only to a process that runs the code it
  shipped with, so anything executing foreign code *in its own address space* — a JIT, an
  interpreter running a script, a preloaded library — is not grantable. `exec` and the process
  boundary are what make that reachable: `ssh`'s `ProxyCommand` and `git`'s hooks spawn a new
  exe and lose the grant, a browser's renderers are separate sandboxed processes, but
  `python script.py` never is. Three enforcement points — an attestation lint in `policy
  check`, the runtime taint, and M2's `unsandboxed` predicate for privilege-separated apps.
  `exe` is `mm->exe_file`: what was exec'd, not what is running.
  `LD_PRELOAD=evil.so ssh -V` runs attacker code with ssh's identity and inherits its
  grants, so **every static `allow` is a confused-deputy grant**. No M2 predicate closes it,
  IMA exe-hash least of all — the exe genuinely *is* ssh, unmodified. Nor can it be detected
  at decision time: the attacker can launder the evidence, and `ptrace`/anonymous
  `PROT_EXEC` touch no file at all. So it must be a sticky taint set at *load* time and read
  as a predicate — the subject was never `exe`, it is `exe AND untainted`. The set is
  **enumerated per subject, not inferred from provenance** (a legitimate root-owned library
  preloaded into ssh defeats provenance) and **not derived statically** (`ldd` sees 17 libs;
  the real set includes `libnss_*` chosen by `/etc/nsswitch.conf` at runtime). Full design,
  policy surface, user flows and rejected alternatives in
  [PLAN-rule-model](docs/PLAN-rule-model.md) M6. Until it ships the deployment answer is
  `bless`: a per-invocation grant has no standing exe rule to inject into, so the lever is
  the ratio of static `allow` rules to blessings — and `bless` is the deliberate escape hatch
  from the invariant, not an instance of it, since it proves human presence rather than code
  identity. Expect the invariant to make static `allow` rules **rare**: it retires
  `allow /usr/bin/aws` (the CLI is Python) and most npm/Electron tooling with it. The taint's
  storage (per-task vs per-`mm`, and whether it survives `clone`) is the open question that
  decides the mechanism; PLAN M6 *Store*.

### Deferred — until the core is sound

- **B3 — the PAM authenticator** ([PLAN-bless](docs/PLAN-bless.md)): **nice to have,
  postponed.** It replaces the uid-0 mint gate with "the authenticated peer", so a
  **non-sudoer could bless their own tools**, and restores "no grace window" by construction.
  Nothing depends on it: B1+B2 ship a usable `bless`, and B2 already did the structural work
  (`SCM_RIGHTS` hand-off, unprivileged CLI), so it stays a swap of *what proves a human is
  present* whenever it is picked up — and it **relaxes** the gate rather than tightening one.
  Until then sudo's timestamp cache is an accepted grace window (DESIGN §16.5); the
  deployment workaround is `Defaults!/usr/bin/cordon timestamp_timeout=0`.
- **B4 — the enumerated-scope gap.** A blessing class's object scope must be listed, so it
  drifts against `@secrets`: every dir added to one must be added to the other or a blessed
  session hits a surprise denial. An "uncordoned" class is sketched in PLAN-bless B4 — but a
  blanket class is a skeleton key, so it waits until the boundary underneath it is sound.
- **M2 and M4 are no longer scheduled on their own.** M6 pulls in the parts it needs: M2's
  **`unsandboxed`** predicate *is* M6's enforcement point (3) (measured, but gated on a Chrome
  version check — see the browser fact below), and M4's learning machinery is how code sets
  get built (M6 task 6). The remainder — `uid`/`gid`/`cgroup`, IMA/fsverity, argv0/ancestor,
  autolearn for objects — is opportunistic, taken when a real policy needs it.

Smaller carried-over notes live in [PLAN-rule-model](docs/PLAN-rule-model.md).

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
- **Overlayfs does not bypass the ancestor walk** (measured 2026-07-27 on 7.1.4-zen, against
  the live `deny` on `~/.npmrc`). An unprivileged `unshare -Urm` + overlay over `$HOME`, read
  through the overlay, journaled `object=~/.config path=~/.config/dconf/user` — the *real*
  object and the *real* dentry chain. Overlayfs hands `security_file_open` the underlying
  dentry, so no `sb_mount` gating is needed. Do not re-derive this from first principles; the
  `f_path`-is-the-overlay-path argument predicts the opposite and is wrong here.
- **Browsers really do separate the JS from the secrets** (measured 2026-07-27 on
  7.1.5-zen1-1-zen; Firefox 153.0, Chrome 150.0.7871.46 headless). Firefox is clean: the
  parent holds `cookies.sqlite`/`key4.db`/`formhistory`/`places` and **no** content process
  holds any of them, with all 18 at `Seccomp 2` in a namespace each. Chrome splits the loot —
  `Login Data`/`Web Data` in the browser process, **`Cookies` in the network service** — and
  that service is only on the right side of an `unsandboxed` test because Linux runs it
  `--service-sandbox-type=none`; it is sandboxed on Windows/macOS, so this can break. Every
  web-JS process is excluded in both, by both signals. Use the conjunction
  `Seccomp == 0 && ns/user == init`: Chrome's renderer zygotes are `Seccomp 0` in the
  *sandboxed* namespace, so either signal alone lets them through. Details and the caveats in
  [PLAN-rule-model](docs/PLAN-rule-model.md) M2.
- **BPF passes at most five arguments in registers**, with no call stack for the rest, so a
  wider fn must be `#[inline(always)]` or it fails to *link* ("stack arguments are not
  supported"). And inlining is not merely a linkage workaround: outlining `emit` added a
  fifth call frame and the v6.12 verifier rejected the whole object with `E2BIG` and a
  `mark_precise: frame4` storm. `consult` sits exactly at the five-arg ceiling.
- **`RENAME_EXCHANGE` fires `inode_rename` twice** (verified 2026-07-28 in the VM, not
  reasoned from the source): `security_inode_rename` calls the hook once with the pair
  **swapped** before the ordinary call. Both directions therefore reach the escape check,
  which is the only reason an exchange cannot walk a protected inode out of its object. It
  matters *only* where the object allows write — otherwise the destroy or clobber check
  refuses first and hides whether the second call happened at all. The `rename_exchange`
  scenario is built around that case; do not "simplify" it to a denying object, which would
  make it pass without testing anything.
- At the mutation hooks the **trusted context argument is a dentry**, not a `file`. The
  verifier range-checks offsets applied to trusted pointers against `.rodata`, so the
  `dentry_d_*` offsets must stay real in `maybe_poison_offsets` or the failure-path test
  aborts at *load* instead of at the self-test.

## Pre-rule-model history (retired)

Phases 0–3 built an **owner model** — explicit rules + TOFU creator-owns, a root-owned SQLite
store, and a privilege-agnostic core — on two enforcement backends: a root **`fanotify`**
`FAN_OPEN_PERM` backend (Phase 1) and an in-kernel `bpf-lsm` backend enforcing `subtrees` +
`owner_identities` (Phase 3), both VM-validated. The rule-model migration replaced all of it:
owners / TOFU / rules collapsed into one `(who, where, action, policy)` model; the SQLite
store and the `mock` + `fanotify` backends were removed; `bpf-lsm` is now the only backend.
The detail lives in git history and DESIGN §1–§14 (marked superseded there).
