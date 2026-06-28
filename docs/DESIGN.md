# cordon — design

Working name: **cordon** (object-centric: you *cordon off* the secret dirs).
Deliberately outside the `gate`/`Gatekeeper` namespace.

Language: **Rust**. Policy: a **root-owned text file** compiled to in-kernel BPF maps (§15).

> **Reading guide.** **§15 is the current architecture** — the flat *rule model*,
> implemented in M1 (see [`PLAN-rule-model.md`](PLAN-rule-model.md) for the milestones).
> §1–§14 are the foundational design and its evolution: the v1 **owner model** (owners /
> TOFU / interactive prompts) and the **fanotify** backend they describe were **retired**
> in the rule-model migration and no longer exist in the code. Those sections are kept for
> the durable rationale they still carry (threat model, object-centric insight, identity
> forgeability, prior art). Read §2–§4 and §15 for the live design. Wherever a section
> still describes the owner model, TOFU, interactive prompts, or the fanotify backend, that
> is **history** — carried under a *superseded by §15* note (most concentrated in §5, §6,
> §8.2, §12).

---

## 1. Goal

Make secret-bearing config directories **readable only by the tool that owns
them**, transparently to that tool (it reads its config at the normal path,
unmodified). Everything else running as the same user sees the directories as
denied/empty.

## 2. Threat model

**In scope — defeat these:** one-shot **scrapers** — run once, scan paths,
exfiltrate, exit; same UID as you. Rungs: hardcoded path lists; directory
walkers / content greppers; `environ` readers following path-like values.

**Out of scope — conceded:** **root**, **resident/persistent** (ptrace, wait for
unlocks, replace binaries, kill the daemon, double-fork to launder ancestry),
**targeted** reverse-engineering of this setup. We raise cost and bound blast
radius, no more.

Enabling simplification: we **never confine the adversary**. We protect the
*resource* and serve the *owner*; the scraper finds nothing.

## 3. Key insights

1. **Unix DAC can't separate two same-UID processes.** Add an **object-centric
   authorizer**: protect the resource, deny all subjects by default, allow only
   the owning identity.
2. **Enforcement lives outside the confined process** → a privileged daemon, not
   an in-process `LD_PRELOAD` trick.
3. **Object-centric beats subject-centric.** One rule over the resource covers
   all subjects, including unknown future scrapers — vs. AppArmor/SELinux's
   profile-per-tool with unprofiled = unconfined.
4. **The gater alone meets the threat model — no crypto, no relocation.** Files
   stay plaintext in place; the gater denies non-owner `open()`. Because nothing
   is moved or encrypted, **transparency is automatic**. Encryption/broker/shim
   are an optional later bundle (§7), not v1.
5. **Identity is a predicate set, not exe alone.** Shebang tools exec as their
   interpreter (`python3`, not `aws`), and helpers/installers read configs they didn't
   create. The subject is a *conjunction* of cheap predicates — exe, uid, cgroup, and
   (opt-in) content hash / argv0 / ancestor — ANDed in-kernel (§15.4). The parent chain
   disambiguates the interpreter case but is best-effort (evadable by double-fork), so it
   raises cost, it isn't a boundary.

## 4. Architecture

### Core
```
┌──────────────────────────────────────────────────────────────┐
│  GATER — object-centric authorizer, in-kernel (root)          │
│    decide each open() against a flat per-object rule table     │
│    (§15.6 precedence), the verdict returned IN THE KERNEL.     │
│    Linux:  BPF-LSM file_open (policy in BPF maps)              │
│    macOS:  Endpoint Security AUTH_OPEN (planned; audit_token → │
│            SecCodeCheckValidity; native parent/responsible pid) │
├──────────────────────────────────────────────────────────────┤
│  POLICY — a root-owned TEXT FILE (§15.8)                      │
│    (who, where, action, policy) rules + groups; cordond        │
│    compiles it → BPF maps on `cordon policy apply`.            │
└──────────────────────────────────────────────────────────────┘
Files stay in place, plaintext. A rule allows → reads unmodified.
```

The gater is **not** an AppArmor analog — it's a programmable authorizer (cousin
of LSM-BPF). The AppArmor analog on macOS is Seatbelt/SBPL, unused.

**Enforcement posture.** With `bpf-lsm` the verdict is in-kernel, so it does **not**
depend on the daemon being up. Once the programs + maps are **bpffs-pinned** (the
remaining hardening increment) enforcement is **fail-safe** — it survives daemon
death; until then a daemon crash drops the program and fails open.

### Optional later bundle (only to cover un-gated reads — §7)
Relocate + encrypt → needs a **key** → held by a resident **broker** → needs a
**transparency layer** (`fuse-t`, or seccomp `ADDFD` under `cordon run`). All
three or none.

### Optional, orthogonal
**Capability brokering** for tools with a credential-helper seam (git, AWS
`credential_process`, docker, kube): hand back **short-lived** creds. Per-tool.

### Privilege model — pluggable backends
The **policy core** (the §15 compiler, IPC, the `cordon` CLI) is
**privilege-agnostic**. Only the *enforcement backend* — the thing that mediates opens
and carries out allow/deny — needs privilege, and it sits behind one interface:

| Backend | Privilege | Scope | Boundary? | Status |
|---|---|---|---|---|
| `bpf-lsm` | **root** (CAP_BPF + CAP_MAC_ADMIN) | system-wide | **yes** (fail-safe once pinned) | Linux production — **the boundary** |
| `endpoint-security` | **root** + entitlement | system-wide | **yes** | macOS — planned (§12, Phase 4) |
| `mock` / `fanotify` / `seccomp-unotify` | — | — | no | **removed / dropped** — see note |

The build splits along this seam: the stock workspace compiles the core + CLI on stable
with no kernel deps; the daemon is built `--features bpf-lsm` to link the aya loader and
enforce. macOS will add an ES backend behind the same interface.

> **Retired backends (history, kept as design contrast).** Earlier iterations shipped a
> `mock` backend (synthetic events for logic tests) and a root **`fanotify`**
> `FAN_OPEN_PERM` backend — a fast, portable MVP that enforced *while running* but was
> **never a boundary**: it fails open (daemon down ⇒ every open allowed), decides in
> userspace on the open-time path (the rename-out-of-zone bypass below), reads identity
> best-effort from `/proc`, and needs `CAP_SYS_ADMIN` for its system-wide veto power (the
> unprivileged `FAN_REPORT_FID` mode is notify-only — useless for gating). So **user-mode
> cannot enforce system-wide** — that motivated the move in-kernel. A `seccomp-unotify`
> `cordon run -- <tool>` sandbox was also evaluated and scoped out (subject-centric,
> opt-in, real `unsafe`). All three were removed in the rule-model migration; **`bpf-lsm`
> is the sole Linux backend.** The in-kernel LSM verdict (below) is the answer to
> fanotify's wrong shape for per-object policy.

### BPF-LSM — the hardened Linux boundary
**BPF-LSM is the Linux mechanism that fits per-object policy**, and is cordon's sole Linux
backend. eBPF programs attach to LSM hooks (`file_open`, `inode_create`/`inode_rename`/
`inode_unlink`, `sb_mount`, `bprm_check_security`) and **return the verdict in-kernel**
(`0` allow / `-EPERM` deny); policy lives in **BPF maps** the daemon fills from the compiled
text policy — *no recompile/reload per rule.* Mediating the operation itself means there
are no per-directory marks to keep race-free and no whole-filesystem funnel through
userspace (the wrong-shape traps of a userspace open-notifier).

cordon returns the verdict **in-kernel** (no synchronous block-and-ask), sidestepping the
*one* thing BPF-LSM can't do (suspend a syscall pending a userspace answer). What the
in-kernel LSM shape buys:
- **No marking → no recursive-mark race.** Hooks fire on the operation; a freshly
  `mkdir`'d / `mv`'d-in / `mount`-ed-in subtree is covered the instant it exists.
- **Structural ops are gateable** (`inode_rename`, `inode_create`, `sb_mount`…), closing
  the **rename-out-of-zone bypass**: a same-uid tool can't rename a secret out of a
  protected subtree and reopen it at an unprotected path — the rename itself is vetoed (and
  identity is keyed on the inode, not the path).
- **In-kernel matching → no funnel.** The program walks the opened file's dentry
  ancestors by **`(dev,inode)`** and allows non-zone opens *without leaving the
  kernel* — no whole-`/` funnel; the hot path never crosses into userspace. Path
  *strings* are out: `bpf_d_path` is **not allowed at the `file_open` hook** (a
  verifier discovery — `security_file_open` isn't in `btf_allowlist_d_path`), so
  matching is inode-based. The daemon resolves paths → `(dev,inode)` at seed time,
  taking the device from the **mount table** (`/proc/self/mountinfo` = the mount's
  `sb->s_dev`) so it agrees with the kernel on overlayfs/btrfs — *not* `stat`'s
  per-layer/-subvolume device.
- **Stronger identity, in-kernel.** Caller exe identity is its **`(dev,inode)`**,
  read straight from `task->mm->exe_file` — race-free, no `/proc` readlink. The
  hardening beyond that is a **content digest** of the opener via
  `bpf_ima_file_hash()` (IMA) or `bpf_get_fsverity_digest()` (fs-verity) —
  identifying the binary by *what it is*: surviving an inode change (package
  upgrade) and resisting copy-to-a-blessed-path, against a hash not a spoofable
  path. (IMA *appraisal* + a keyring gets "verified-signed-by-key," the closest
  Linux analog to ES code-signing — enterprise setup, not free.)
- **Fail-safe, not fail-open.** Pin the programs and their `bpf_link` to **bpffs**
  (`/sys/fs/bpf/…`) and enforcement persists with **no holding process** — the daemon can
  crash/restart with *zero* enforcement gap.

**Implemented (M1 — validated in a VM, see STATUS / [`PLAN-rule-model.md`](PLAN-rule-model.md)):**
the `file_open` verdict over the **flat rule table** — deepest protected object via the
`(dev,inode)` dentry walk, exe-`(dev,inode)` subject match, action from `f_mode`/`f_flags`
(read/write/create), first-match on the copy-down-resolved bucket, default-deny, the
per-rule `policy` the only enforcement level (no global mode, §15.6); the **text policy**
compiled + seeded at startup and re-seeded by `cordon policy apply` via an **atomic
double-buffer swap**; and the
ring-buffer learn path with **in-kernel event coalescing**. The **structural-op gating**
(closing the rename bypass), **content-digest identity** (§15.4), and **fail-safe pinning**
described above are the next increments, not yet shipped — so today's `bpf-lsm` enforces
open-time actions in-kernel and (until pinning) still fails open when the daemon dies.

**Deny/learn delivery — decoupled from the verdict.** The in-kernel program has already
decided; observability rides a **BPF ring buffer** (`BPF_MAP_TYPE_RINGBUF`): on a
`deny` or `audit` the hook emits a record (pid, exe `(dev,inode)`, object
`(dev,inode)`, the opened file's reconstructed leaf path, action, decision), **coalesced
by an in-kernel suppressor** (keyed on the opened file, so distinct leaves surface), and
the daemon
drains it asynchronously. It does **not** block the syscall. Lossy under flood = you drop
*observability records*, never *enforcement* (a discard counter bumps).

**Control plane vs data plane** — the daemon leaves the hot path entirely:
> **Data plane = in-kernel BPF** — every open, every verdict — *always on,
> daemon-independent.*
> **Control plane = the root-owned text policy (durable source of truth) + a thin,
> restartable daemon** that (a) compiles the policy and seeds the maps at startup and on
> `cordon policy apply`, and (b) **drains the ring buffer to the journal.** Off the hot
> path; its absence costs observability, **never** enforcement (and, once pinned, not even
> across a restart). *The daemon is still required* — to ship ring-buffer events to the
> journal and to apply policy changes.

**Map concurrency** is handled by map semantics + RCU, not hand-rolled locks: a
single-element `bpf_map_update_elem` is atomic (a reader sees old-or-new, never torn;
element lifetime is RCU). The atomic *multi-entry* policy swap on `apply` uses exactly the
**generation-counter / double-buffer** this called for — **now implemented** (§15.8): the
three rule maps are banked, and the daemon fills the inactive bank then flips
`Settings.active_bank` in one update, RCU-style. `bpf_spin_lock` is available if a value
ever needs in-program read-modify-write.

**Durability.** BPF maps are ephemeral (lost on reboot / program reload), but the **text
policy is the durable source of truth** — the daemon recompiles and re-seeds it at startup,
so nothing is lost. (The owner model's hazard of an in-kernel TOFU claim not yet persisted
is gone with TOFU itself; autolearn (§15.9) keeps its *proposals* in a separate db, never
the enforced source.)

**Requirements / cost.** `CONFIG_BPF_LSM=y` **and** `bpf` in the active LSM list
(`CONFIG_LSM=` / `lsm=` boot param — common but not universal); kernel ≥ 5.7 (the
content-hash helpers are ≥ 5.11 / 6.x); `CAP_BPF` + `CAP_MAC_ADMIN`. The program is
verifier-friendly, and — since rustc can't emit CO-RE relocations,
<https://github.com/rust-lang/rust/issues/158412> — a userspace shim reads the running
kernel's BTF and injects field offsets into the program's `.rodata`, so one object runs on
any kernel. **Additive** to existing LSMs — it can only *further* restrict, never loosen
(a SELinux/AppArmor deny still denies). So `bpf-lsm` is the hardened production boundary
where available; on older kernels (or with `bpf` absent from the LSM list) there is **no
hardened Linux boundary**. Real precedent for exactly this allow/deny use: **KubeArmor**,
**Tetragon**, **bpflock** (§13).

**Lineage is subsumed here (cancels the standalone cache, §8.2/§12).** Because the
backend already runs in-kernel, the §8.2 ancestry hardening is *folded in*, not a
separate proc-connector subsystem: a live `task->real_parent` walk gives the same
best-effort chain for free at decision time, and durable-across-exit lineage is
just `sched_process_{fork,exec}` tracepoints writing `(pid, starttime)`→parent
into a BPF map *within this backend*. Ceiling unchanged: a real `exec` of a
blessed binary (the **construction** attack, §8.1) is still faithfully recorded,
so ancestry stays best-effort, never the boundary.

Locations: the root system service listens on `/run/cordon.sock` and compiles
`/etc/cordon/policy.toml` (both root-owned). A user-session dev daemon can override these
to `$XDG_RUNTIME_DIR`/`$XDG_CONFIG_HOME` (the `cordon` CLI auto-detects), but it is **not**
a boundary — only the root service enforces.

**Operational config** is an optional TOML file (`backend`, `socket`, the eBPF-object /
policy-file paths), `${ENV}`-interpolated, precedence CLI > file > default. The
*enforcement policy* — the rules — is **not** here: it lives in the root-owned text policy
(§15.8), applied with `cordon policy apply`. There is no global mode; observe-vs-enforce is
the per-rule `audit`/`deny` choice (§15.6). See `packaging/cordon.example.toml` +
`cordon.example.policy.toml`.

Terminology: this daemon is the **gater**. The **broker** (§7) is the separate,
deferred key-holder.

## 5. Coverage & ownership model

> **Superseded by §15 — historical.** This section describes the v1 *owner* model as
> shipped in Phases 0–1. The flat **rule model** in §15 (shipped in M1) replaces it,
> subsuming owners, explicit rules, and TOFU into one concept (§15.1 explains why). The
> owner model — owners, the SQLite store, TOFU, interactive prompts — was **removed** in
> the migration; what follows is the record of what those phases did, not current behavior.

Two rule sources; explicit wins over auto.

### Explicit rules (highest precedence)
`identity → allowed paths/globs + modes`, e.g. `aws : rw ~/.aws/**`. Includes
both allow and **deny** (so a user can revoke an owner). Root-owned config.

### TOFU auto-ownership (creator-owns)
- **Zones** — configured *traversable-but-never-owned* roots (`~`, `~/.config`,
  `~/.local/share`, `~/.cache`). The first subtree level inside is claimable; the
  zone root itself never is. (Named "zones" in code — `container` was avoided as
  it reads as Docker/OCI.)
- **Claim on create, never on read.** An exe that *creates* a new path in an
  unclaimed zone subtree becomes its owner (`O_CREAT` / `FAN_CREATE`),
  **never on read** — stops a scraper claiming a pre-existing secret.
- **Pre-existing paths** have no auto-owner: handled by interactive mode (§6) or
  `cordon adopt`. Never auto-assigned on first access.
- **Inheritance** — files under an owned subtree inherit its owner group.

### Identity
- **Granularity (default `path`):** owner = exe path. Survives upgrades;
  weak only against replacing the binary file (root/resident → out of scope).
  Per-rule override to `path+inode` or `signature` for stricter dirs.
- **Ancestry (parent chain):** owner-match succeeds if the caller **or an
  ancestor within the session boundary** is in the owner group. Solves the
  interpreter problem (caller exe = `python3`; ancestor/launcher = the tool) and
  helper/creator≠reader. Captured at event time (pidfd + start-time validation),
  walk bounded at session leader / first uid change. **Best-effort:** double-fork
  launders ancestry; argv is *not* trusted (caller-controlled). macOS exposes
  parent + "responsible" pid natively in ES.
- **Tool-groups:** an owner is a named identity set, auto-seeded with the
  creator, expandable (`cordon claim <subtree> --add <id>`).

### Ownership / rules store
SQLite **owned by the daemon (root), not user-writable** — else a scraper writes
itself in as owner. Mutated only via the privileged `cordon` CLI → daemon IPC.

## 6. Decision flow & interactive mode

> **Superseded by §15.6 — historical.** The owner-model decision flow and interactive
> deny-and-learn below were **removed** with the owner model. The live decision flow is
> §15.6: most-specific protected object → first-match on the copy-down bucket →
> default-deny, the per-rule `policy` the only enforcement level (no global mode), with the
> verdict returned **in-kernel** (so there is no synchronous prompt). TOFU's successor is
> **autolearn**
> (§15.9) — an explicit, reviewed training mode, not a per-open prompt (the deadline-safety
> problem below is exactly why). Kept for that rationale and the prompt-UX design.

### Decision flow (evaluated per gated open)
1. Path not under any protected subtree → **allow** (unmediated).
2. Explicit rule matches → **allow/deny** (user rules win → revocation works).
3. Caller *or ancestor* in the subtree's owner group → **allow**.
4. `O_CREAT` of a new path in an unclaimed zone subtree → **TOFU claim** →
   allow.
5. Else (protected, unowned/non-matching, not a create) → **interactive prompt**
   if a session agent is present, else the configured default (**deny**).

### Interactive mode
On step 5, ask the user — but the AUTH path is **synchronous with a deadline**
(ES kills clients that miss it; blocking an `open()` on human reaction time hangs
tools and risks deadlock — Santa's ES authorizer survives this with a secondary
dispatch that returns the default just before the deadline, a pattern we reuse;
see `docs/SANTA.md`). So the model is **deny-and-learn**:

> Deny *this* access to meet the deadline, prompt the user **asynchronously**,
> **persist the choice**, honor it on subsequent accesses. Optional: a short
> synchronous hold (≤ a couple seconds, well under the deadline) so a fast answer
> lets even the first access through; deny-and-learn is the fallback.

Consequence: a brand-new tool errors *once* until approved, then works. TOFU
covers tools that create their own config (no prompt), so prompts mostly fire on
**pre-existing/ambiguous** paths — letting "approve permanently" subsume
`cordon adopt`.

**Prompt outcomes → rules:**
| Choice | Effect |
|---|---|
| Deny once | ephemeral; this event only |
| Deny permanently | explicit deny rule (identity → subtree) |
| Approve once | ephemeral allow (this process instance) |
| Approve for X min | TTL allow rule, expires at now+X |
| Approve permanently | explicit allow / add identity to owner group |

The prompt shows **who** (exe + ancestry chain), **what** (file/subtree), and the
proposed rule scope (per-subtree, not per-file, so it doesn't re-ask).

**Agent architecture:** the root daemon can't draw UI → delegates to an
**unprivileged per-session prompt agent** (polkit-agent style) over IPC, routed
to the user owning the triggering session. Notification channel is the
per-OS-specific bit (libnotify/dbus vs UserNotifications).

## 7. Do we encrypt anything? (what "keys" meant)

**v1: no.** The gater denies the live scraper's `open()`; plaintext-in-place is
fine. Encryption only protects reads the gater *doesn't* mediate:

| Un-gated read | In scope? | Already covered by |
|---|---|---|
| stolen / offline disk | physical → no | FileVault / LUKS |
| pre-daemon boot window | no (scraper is interactive, post-login) | — |
| gater bug / bypass | defense-in-depth only | — |

So it adds ~nothing in scope and drags in keys + broker + shim. Deferred. "Keys"
only exist if we later encrypt: a master key the broker holds in RAM, unlocked
once per session.

## 8. Caller identity (mechanics)

> **Mechanics updated by §15.4.** In the in-kernel backend the caller's identity is its
> exe `(dev,inode)` read straight from `task->mm->exe_file` — race-free, no `/proc`
> readlink, no `FAN_REPORT_PIDFD` — plus the other predicates in §15.4 (uid, cgroup, opt-in
> hash/argv0/ancestor). The fanotify pidfd / `/proc` mechanics below are the retired
> userspace path; the **forgeability analysis in §8.1 is model-agnostic and still
> load-bearing** — §15.4's argv0/ancestor predicates rest on it.

- **Race-free id:** Linux `FAN_REPORT_PIDFD` → pidfd → exe; macOS per-connection
  audit token → code requirement. Don't re-`readlink` `/proc/pid/exe` after the
  fact (PID may have exec'd).
- **Chain walk:** from the triggering pidfd, read ppid (`/proc/<pid>/stat`),
  validate each hop by start-time, bound at session leader / uid change. Snapshot
  at event receipt. Best-effort (see §5 caveats).
- **hardening-vs-injectability tension** & **confused-deputy ceiling**: relevant
  only if we ever add the transparency shim (§7); v1 gates only.

### 8.1 Caller vs. ancestry forgeability (sharpened)
Treat the **immediate caller** and the **ancestry chain** as different security
objects:
- **Immediate caller — strong & race-free.** It is suspended in the kernel
  awaiting our verdict, so it cannot exit/exec under us. Linux: exe path is
  kernel-truth (race-free while blocked). macOS: the per-event `audit_token`
  yields *cryptographic* code identity (`cdhash`/`team_id`/`signing_id`,
  validated via `SecCodeCheckValidity`) — strictly stronger than a path, and the
  real ES win.
- **Ancestry — best-effort, two distinct attacks:**
  - **Removal** (`double-fork` → reparent to init): erases the chain on Linux.
    macOS resists this — `original_ppid` and the *responsible* audit token survive
    reparenting.
  - **Construction** (`fork(scraper); exec(real blessed binary)` in the parent):
    builds *genuine* ancestry whose ancestor really is the blessed tool. This
    defeats ancestry on **both** platforms and is **not** fixed by stricter
    identity (`path+inode`/`signature` or macOS code-signing) — it is the
    authentic binary, attested truthfully. Only a liveness window (the blessed
    ancestor must be alive at access time) bounds it. macOS "responsible process"
    attribution is also launcher-influenceable (`posix_spawn` disclaim
    attributes), so it is not unforgeable either.
- **Interpreter problem persists on macOS:** a script tool surfaces as
  `/usr/bin/python3` (an Apple *platform binary*), so the strong code-identity is
  the interpreter's, not the tool's — pushing you back onto the weaker
  ancestry/responsible-pid link, as on Linux.
- **Conclusion:** ancestry **raises cost, is never a boundary**; the construction
  attacker is the conceded targeted-RE class (§2). The object-centric deny is the
  boundary.

### 8.2 Better Linux lineage sources (beyond the /proc snapshot)
The `/proc` ppid walk is a snapshot taken *after* reparenting has already
destroyed information. Stronger sources, weakest→strongest:
- **Start-time keying** (`/proc/<pid>/stat` field 22): key each hop by
  `(pid, starttime)`; a changed starttime ⇒ pid was recycled ⇒ reject. Kills
  pid-reuse. (Cheap; DESIGN already assumes this.)
- **pidfd**: free for the caller via `FAN_REPORT_PIDFD`; `pidfd_open(ppid)` +
  starttime recheck pins ancestors. Race-free, but still a decision-time snapshot.
- **`loginuid`/`sessionid`**: set at login, immutable without `CAP_AUDIT_CONTROL`,
  inherited by all descendants — a fence the scraper can't shed (unlike `setsid`).
  A robust *bound* on the walk, though it doesn't identify the tool.
- **Proc connector** (`NETLINK_CONNECTOR`/`CN_IDX_PROC`) **or eBPF**
  (`sched_process_{fork,exec}`, BPF-LSM): subscribe at startup, maintain a
  lineage cache keyed by `(pid, starttime)`. Recording the parent **at fork time**
  captures the *original* lineage **before** a later double-fork can erase it —
  defeating the **removal** attack. eBPF is the high-fidelity option (also gets
  argv/cwd/creds at exec); it's how Tetragon/Falco/Sysdig build process trees
  (§13). Root-only — already required.
- **Ceiling:** lineage tracking defeats *removal* + *reuse*, never *construction*
  (a real `exec` is faithfully recorded as a genuine blessed ancestor). Not log
  sources (`auditd` is async, log-only), not `/proc/.../children` (wrong
  direction), not cgroup/session grouping (CLI tools share the shell's cgroup).

> **Superseded as a standalone deliverable.** With the **BPF-LSM backend (§4)** this is
> *folded into the backend*, not a separate proc-connector subsystem: a live
> `task->real_parent` walk is free at decision time, and durable-across-exit lineage is
> just `sched_process_{fork,exec}` hooks writing `(pid, starttime)`→parent into a BPF map
> there (a later increment; ancestry is one of §15.4's opt-in predicates, never the
> boundary, §8.1). So the once-planned event-sourced **proc-connector lineage cache is
> dropped.** The in-kernel walk is *also* best-effort: a parent that already exited is
> already reparented, so only fork-time recording defeats **removal** — the
> **construction** ceiling stands regardless.

## 9. Cross-platform primitive map

| Need | Linux | macOS |
|---|---|---|
| Object-centric open authorizer | **BPF-LSM** `file_open` (in-kernel verdict) | **Endpoint Security** `AUTH_OPEN` |
| Testing without host root | **virtme-ng VM** runs the real `bpf-lsm` backend; `cargo test` covers the compiler/control plane | `mock` only (no unpriv intercept) |
| Caller id (race-free) | exe `(dev,inode)` from `task->mm->exe_file` (in-kernel) | per-conn audit token → code req |
| Parent chain | `task->real_parent` walk (in-kernel) + start-time | ES process struct (parent + responsible pid) |
| Create signal (autolearn / mutation) | `inode_create` hook (§15, M3) | ES create/exec events |
| Prompt channel (deferred — no interactive mode in the rule model) | per-session agent + dbus/libnotify | per-session agent + UserNotifications |
| Key custody (only if encrypting) | kernel keyring / Secret Service | Keychain / Secure Enclave |
| Declarative MAC we're *not* using | AppArmor / SELinux | Seatbelt / SBPL |

Same shape both OSes: a root **in-kernel authorizer** + a **root-owned text policy** +
the `cordon` CLI. Per-protected-dir cost = a rule, not a per-tool profile.

## 10. Honest limitations
- **Fail-open until pinned.** The verdict is in-kernel, but the daemon loads the program —
  until the programs + maps are **bpffs-pinned** (§4), a daemon crash drops enforcement
  (fail-open). Pinning makes it fail-safe; it is the remaining hardening increment. On
  kernels without BPF-LSM (`CONFIG_BPF_LSM` off, or `bpf` not in the LSM list) there is no
  hardened Linux boundary at all.
- **Open-time only (so far).** M1 mediates `file_open` (read/write/create); the structural
  ops (unlink/rename/… — closing the rename-out-of-zone bypass) and `execute` are later
  hooks (§15.5). Until then a same-uid tool can rename a secret out of a protected subtree
  and open it at an unprotected path.
- **Identity is best-effort beyond exe.** The exe `(dev,inode)` is race-free, but the
  parent chain is laundered by double-fork and argv is untrusted; interpreted tools surface
  as their interpreter (`python3`), needing the opt-in argv0/ancestor or hash predicates
  (§15.4). Ancestry raises cost, never the boundary (§8.1).
- **First-access friction.** A tool with no matching rule hitting a protected object is
  default-denied; granting access means editing the root-owned policy + `cordon policy
  apply` (autolearn, §15.9, is the assisted path). There is no interactive per-open prompt.
- **Confused-deputy:** gating ≠ stopping a tool's own export surface (out of scope).
- **Only the root `bpf-lsm` backend is a boundary** — a user-session dev daemon is for
  iteration, not protection; the boundary runs as a root service with `CAP_BPF` +
  `CAP_MAC_ADMIN` (macOS ES needs a restricted entitlement).
- **macOS backend (planned) shares ES's ceiling** — open()-time mediation only (no
  `read(2)` event), symlinks not followed, ES "default mute set" binaries unmediated.
  Same limits Santa's FAA hits (`docs/SANTA.md`); inherent to ES.

## 11. Testing strategy — internal fixtures
The kernel-backed smoke (`bpf-lsm-smoke.sh`) drives the rule model end-to-end with
distinct-inode exes (copies of `bash`, so each is its own subject) reading/writing secrets
under a protected subtree, against a policy file:
- an **owner** exe allowed to read its secret; a **scraper** with no matching rule →
  default-deny (`EPERM`), reported on the ring buffer with the object inode + action;
- per-action (read allowed, write default-denied on the same object), subject + object
  **groups**, **deny > allow** ties, **copy-down** precedence (subtree allow + a
  file-specific deny for one subject, the sibling still readable), **audit→deny** (observe
  with a catch-all, then enforce by flipping that one rule — no global mode), **silence**
  (denied, not logged), runtime **`policy apply`**, and **event coalescing**.

Asserts: the right subject reads, the wrong one is denied **in-kernel**, precedence
resolves as §15.6 says, and a tight open-loop collapses to a few records — all on a real
kernel (the unprivileged `cargo test` tier covers the parser + copy-down compiler).

### Test tiers (by privilege)
- **Unprivileged (no kernel backend):** the policy parser + copy-down compiler and the
  IPC types — `cargo test` (`--all-features` also builds and unit-tests the `bpf-lsm`
  control plane, incl. event coalescing), CI-friendly, no root. Covers everything but
  the in-kernel hook itself.
- **The `bpf-lsm` boundary in a VM, without host root → virtme-ng.** Loading the LSM
  program needs `CAP_BPF`+`CAP_MAC_ADMIN` plus `bpf` in the active LSM list — both come
  from a **virtme-ng VM** (`packaging/test/run-bpf-lsm-vm.sh`) booting a **pinned
  upstream kernel** (Ubuntu mainline, e.g. `v6.12`) as guest-root with `lsm=…,bpf`,
  needing only `/dev/kvm` (group `kvm`), no host root. The VM runs qemu **directly** (no
  container) and virtme-ng reuses the host userspace, so there is no rootfs to build and
  no glibc mismatch — the *same* harness + kernel run locally and in CI, so the kernel
  never diverges. (`CORDON_VM_KERNEL` selects the pinned version; unset = the host
  kernel for fast local iteration.)
- **Why not libkrun/krunvm:** evaluated and dropped — getting `krunvm` onto a CI runner
  means nesting it *inside a container*, stacking two user namespaces (`buildah unshare`)
  under the libkrun VMM, which fails **differently per environment** (`gid_map: operation
  not permitted` locally vs `memfd_create: EINVAL` on GitHub) — non-reproducible.
  virtme-ng collapses the stack to a single `/dev/kvm` dependency.
- `bpf-lsm-smoke.sh` proves the rule model end-to-end (allow/deny, per-action, subject +
  object groups, copy-down precedence, audit→deny, silence, runtime `policy apply`, event
  coalescing) through a real kernel — green in the virtme-ng VM (host kernel + pinned
  `v6.12`, booted `lsm=…,bpf`).

## 12. Phased plan

> **Superseded by [`PLAN-rule-model.md`](PLAN-rule-model.md) + §15.11 — historical.** The
> phases below are the *owner-model* roadmap. They shipped through Phase 1, after which the
> owner model + fanotify were **removed**; the **current** roadmap is the rule-model
> milestones M1–M5 (M1 done) in PLAN-rule-model.md, summarized in §15.11. Kept for the
> design history and the macOS/ES notes (Phase 4), which still apply.

- **Phases 0–3 (owner model — shipped, then retired).** Phase 0 built the
  privilege-agnostic core + a SQLite store + the `cordon` CLI on a `mock` backend; Phase 1
  added the root **`fanotify`** `FAN_OPEN_PERM` backend (TOFU-on-create read from
  `/proc/<pid>/syscall`, ancestry from `/proc`), VM-validated; Phase 3 moved the verdict
  **in-kernel** (the bpf-lsm backend, then keyed on `subtrees` + `owner_identities`). Phase
  2 (interactive deny-and-learn + ancestry hardening) was specced, not built. The
  rule-model migration (§15) replaced this whole line — detail in git history; the
  interactive/prompt design survives as the §6 record and **autolearn** (§15.9), the
  ancestry analysis as §8.1/§8.2.
- **Phase 4 — macOS gater.** Bespoke ES `AUTH_OPEN` client — **decided**: Santa's
  FAA can't do dynamic, reviewable policy + autolearn (`docs/SANTA.md`). Reuse Santa's
  Apache-2.0 source as a reference (deadline-safety dispatch, multi-ES-client
  layout, identity matching). Same policy + CLI abstraction behind the backend interface.
- **Phase 5 — (optional) at-rest bundle; capability brokering; canaries.**

## 13. Related work / prior art

References we draw from, and why none is a drop-in for "deny non-owner reads of
secret config dirs — transparently, cross-platform, zero per-tool policy."

### Closest architectural cousins (authorizer daemon + rule store)
- **Santa** (macOS, North Pole Security) — the closest existing tool. Its **File
  Access Authorization (FAA)** is a real object-centric, code-identity-keyed file
  gater on Endpoint Security (~80% of our macOS gater). But it's **macOS-only**
  (no cross-platform plans), and FAA is **static admin policy** — no interactive
  prompt, no TOFU, poll-reloaded (≥15s); its interactive TOFU (standalone mode) is
  **execution-only**. So it can't do cordon's dynamic creator-owns +
  deny-and-learn for files. **Full functionality + roadmap analysis and the
  reuse-vs-build decision: `docs/SANTA.md`.** (We borrow its ES deadline-safety
  pattern and identity-match schema; Apache-2.0.)
- **OpenSnitch** (Linux) / **Little Snitch**, **LuLu** (macOS) — interactive
  application *firewalls*. The reference for our deny-and-learn UX (allow once /
  for-X-min / forever, by-exe rules) and per-process attribution. But they gate
  **network egress**, not file reads: they'd catch an exfil *connection*, yet a
  scraper that stages to a local file, or leaves over an already-allowed channel
  (the browser, DNS), slips by. Complementary layer, not a substitute.

### Mandatory Access Control (the per-tool-policy family we reject as primary)
- **AppArmor / SELinux / macOS Seatbelt (`sandbox-exec`)** — see §3/§9.
  Subject-centric: a profile/policy **per program**, and unprofiled = unconfined
  (an unknown scraper is unrestricted). SELinux *can* be object-centric via
  labels, but it's compiled + per-domain-transition + Linux-only. We want one
  object-centric rule that covers all subjects, including unknown ones.
- **Landlock** (Linux, unprivileged LSM) — a process restricts **its own** (and
  children's) FS access. Modern and root-free, but it's *self*-confinement:
  useless against a scraper that won't opt in. The inverse of what we need.
- **bubblewrap / firejail / Flatpak** — namespace sandboxes; Flatpak even gives
  each app its own data dir (`~/.var/app/<id>`) — the per-app-isolation north
  star. But subject-centric and opt-in per app; CLI dev tools aren't packaged,
  and you can't wrap a scraper you've never seen.

### Secret brokers / keystores (our deferred §7 + orthogonal capability brokering)
- **ssh-agent / gpg-agent** — never release the key; perform the op. The broker
  pattern in miniature, but ssh/gpg-only and protocol-bound.
- **HashiCorp Vault (+agent), aws-vault, envchain, 1Password CLI,
  git-credential-manager** — short-lived-credential brokering with OS-keystore
  custody, several cross-platform. We borrow the short-lived-capability idea, but
  each needs **per-tool integration** and none transparently protects the long
  tail of existing flat config files.
- **OS keystores** (Keychain / Secret Service / kernel keyring) and **SOPS / age
  / git-crypt** — "the secret isn't a readable file" / encrypt-at-rest. Borrowed
  for the deferred at-rest bundle, but tools must adopt them and they don't gate
  live reads of dirs that already exist.

### Filesystem-view / redirection (evaluated and rejected earlier)
- **fakechroot / proot** — `LD_PRELOAD` / `ptrace` path remapping. Cooperative or
  same-UID-bypassable → not a boundary (see the preload discussion).
- **FUSE: bindfs / gocryptfs / fuse-t** — a userspace FS can gate on the caller's
  pid, and **fuse-t** does it on macOS without a kext. But the mount is global
  (not per-process), PID identity is racy, and macFUSE's kext *lowers* platform
  security. We use a kernel authorizer (bpf-lsm/ES) instead; `fuse-t` is kept
  only for the deferred transparency layer.

### Observability & eBPF enforcement
- **auditd / fanotify-notify / inotify** — can *watch* file access by path, but
  **cannot deny**. We need the permission (veto) path, not just logging.
- **Tetragon / Falco** (eBPF, LSM-BPF) — runtime security; Tetragon can even
  enforce (override/kill). Architecturally this **is** our LSM-BPF alternative
  backend — but it's container/k8s-oriented and heavyweight to drive as a
  per-user desktop secret gate.

### aya-ecosystem peers (our toolchain — pure-Rust eBPF via aya)
The eBPF enforcers above (Tetragon/Falco/KubeArmor/bpflock) are the **mechanism**
precedent but all **Go/libbpf**. The projects that share cordon's actual *toolchain*
— a `no_std` `aya-ebpf` kernel crate + an `aya` userspace loader, maps/ring-buffers,
and the same CO-RE/BTF offset problem (rustc can't emit CO-RE relocations,
<https://github.com/rust-lang/rust/issues/158412>) — live in
[`aya-rs/awesome-aya`](https://github.com/aya-rs/awesome-aya), and **every security
one is subject-centric, most observe-only**. None is an object-centric file
authorizer for a personal box, so cordon shares their plumbing, not their shape:
- **lockc** — eBPF **LSM-MAC** for *containers* (Docker/k8s), Rust/aya. Closest
  cousin by mechanism (LSM hooks → MAC), but **container/profile-centric** and
  audit-framed/experimental — it restricts the confined workload, not an *object*
  the way we protect a subtree.
- **suidsnoop** — aya **LSM programs**, the only peer that actually **denies**
  (audit-or-enforce) — but scoped to **suid `execve`** and keyed on **uid**
  (subject-centric); a research demo, not a file-read gate.
- **bombini** — aya **LSM-BPF**, but **observe-only**: modular "detectors"
  (exec / connect / file-access) emit JSON, no veto. Subject-centric, k8s runtime-sec.
- **kunai** — aya, kprobes/tracepoints (not LSM enforcement); **observe-only** host
  threat-hunting (Sysmon-for-Linux). The most mature of the set and the **least**
  like cordon — it logs events, it doesn't gate opens.

So in the aya world cordon's niche is empty: object-centric, enforcing,
personal-desktop, TOFU + interactive. The precedent for the *use* (allow/deny on LSM
hooks) is the Go tools above; the precedent for the *stack* is these — and they all
answer "what may this subject do?", never "who may touch this resource?"

### Authorization-agent architecture
- **polkit** — privileged daemon + **unprivileged per-session agent** that draws
  the prompt. Exactly our daemon/agent split (§6). But polkit authorizes D-Bus
  privileged *actions*, not file reads.

## 14. Open decisions
See `STATUS.md`.

## 15. The rule model — current architecture (supersedes §1–§14)

The flat **rule model** — `(who, where, action, policy)`, in the SELinux/AppArmor lineage
— is cordon's architecture, **shipped in M1**. It subsumes the v1 owner model's owners,
explicit rules, and TOFU (§5) into one concept, enforced uniformly in-kernel. This section
is the design; milestone-by-milestone status is in
[`PLAN-rule-model.md`](PLAN-rule-model.md) (M1 done; M2–M5 ahead).

### 15.1 Why
The owner entity is reducible to allow-rules: `owner_match` ≡ "an allow rule exists for
(caller-exe, subtree)." Owner groups bought grouping / dedup / naming — but a general
**group** mechanism (§15.7) gives that for *all* axes, symmetrically, so a dedicated
owner table was incidental complexity. Collapsing it also closed a real gap: the
owner-model bpf-lsm backend enforced only `subtrees` + `owner_identities`, **not** the
`rules` table, so `cordon add` allow/deny and TOFU were silently unenforced in-kernel.
One model, now enforced uniformly.

### 15.2 The rule
`(who, where, action, policy)`:
- **who** — subject: a *conjunction of predicates*, not just an exe (§15.4).
- **where** — object: a file, directory, or **subtree** (recursive). Matched in-kernel
  by the dentry ancestor walk (most-specific wins).
- **action** — `read | write | create | execute | listdir | unlink | mkdir | rmdir |
  rename` (extensible). Each maps to an LSM hook (§15.5).
- **policy** — `allow | deny | audit | silence` = `{allow,deny} × {log,silent}`:
  allow=allow+silent, audit=allow+log, deny=deny+log, silence=deny+silent.

### 15.3 The compile principle (load-bearing)
**Groups, nesting, defaults, and precedence are resolved entirely in userspace at
compile time; the kernel evaluates a flat, pre-resolved decision table.** cordond
parses the text policy → expands groups → resolves paths→`(dev,ino)` → flattens to a
per-object rule table → loads BPF maps. Like SELinux's `checkpolicy`: expressive
source, dumb-fast binary form. The eBPF program never sees a group or a nested ref,
so it stays small and verifier-friendly no matter how expressive authoring gets.

### 15.4 Subject = predicate set (the identity frontier)
`who` is a conjunction of cheap-to-check predicates, ANDed:
- `exe` — path/inode (cheap)
- `uid` / `gid` — cheap (`bpf_get_current_uid_gid`)
- `cgroup` / unit — cheap (`bpf_get_current_cgroup_id`); names a systemd service
- `exe-hash` — content identity via **IMA/fsverity** (kernel-measured), *not* hashed in
  BPF; survives upgrades, resists binary swap
- `argv0` / `ancestor-exe` — moderate cost; the only real fix for the **interpreter
  problem** (`~/.aws` is opened by `python3`, not `aws` — match "python3 whose
  argv0/ancestor is aws", not all python)

v1 ships `exe`+`uid`+`cgroup`; hash/argv/ancestor are opt-in later. No rule grammar
fixes identity granularity — this axis is where the security actually lives.

### 15.5 Action ↔ hook map (actions are not uniform)
| action | LSM hook | notes |
|---|---|---|
| read / write / create | `file_open` | one program; `f_flags`/`f_mode` already encode RDONLY/WRONLY/RDWR/`O_CREAT` — three actions free at open time |
| execute | `bprm_check_security` | exec of a binary |
| unlink / rmdir / mkdir / rename | `inode_unlink/_rmdir/_mkdir/_rename` | second program; fire on mutation (cheap) |
| listdir | `file_open` of a directory (coarse) | no clean per-`getdents` hook; finer needs the hot `file_permission` |

`file_permission` / `inode_permission` (per-I/O) are hot paths → any per-access action
is opt-in. `bpf_d_path` is unavailable at `file_open` (and inconsistent elsewhere), so
**identity is inode across all hooks** (the dentry walk), never path.

### 15.6 Precedence (pin it explicitly)
The kernel takes the **first matching rule** in the most-specific protected object's
bucket; the compiler pre-sorts each bucket so first-match = most-specific-wins:
1. Most-specific **where** — object depth (exact file > deeper subtree > ancestor).
2. Most-specific **who** — a concrete subject (an `exe`; later, more predicates) beats
   `who="*"`, so a specific `allow`/`deny` overrides a broad catch-all on the same object.
3. **deny > allow** — fail-safe, but only as the tie-break among rules of *equal*
   object+subject specificity (`allow X` vs `deny X` → deny; `allow *` vs `deny *` → deny).

A protected object with no matching rule → **default-deny** (logged with a distinct
`default-deny` cause, so it reads apart from an explicit `deny`). "Protected" = appears
in/under some rule; everything else is unmediated **allow** (you cannot default-deny the
whole filesystem).

**No global mode — the per-rule `policy` *is* the enforcement level.** `audit` (allow+log)
*observes* an object; `deny` (block+log) *enforces* it — so observe-vs-enforce is
per-object, flipped by editing that object's catch-all rule, not a system-wide switch. This
deliberately drops SELinux's `enforce|permissive|off`: cordon's user is their *own* policy
admin iterating live on one box, not an admin staging policy for a fleet, so a global
"permissive" preview + "enforce" cutover is just the **audit→deny** progression (§15.10).
"Off" is an empty policy (or a stopped daemon). *(M1 shipped a global enforce/permissive/off
mode; it has since been **removed** — the kernel now blocks iff `policy.denies()` — and the
subject-specificity precedence key in (2) above is implemented. See
[`PLAN-rule-model.md`](PLAN-rule-model.md).)*

### 15.7 Groups
Named, nestable, **symmetric across all three axes** (subject / object / action),
cycle-checked at load. The v1 "owner" becomes one ordinary *subject group*. Example
(TOML):
```toml
[group.subject.ssh-tools]  members = ["/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/git"]
[group.object.cloud-creds] members = ["~/.aws", "~/.config/gcloud", "~/.config/gh"]
[group.action.ro]          members = ["read", "listdir"]

[[rule]]  who = "@ssh-tools"  where = "~/.ssh"        action = "@ro"             policy = "allow"
[[rule]]  who = "*"           where = "@cloud-creds"  action = ["read", "write"] policy = "audit"
```

### 15.8 Storage
- **Authoritative policy = a root-owned text file.** Not user-writable, else a scraper
  writes itself in. Git-versionable, reviewable, diffable — policy as code.
- **Two authoring surfaces, one model (✅ 2026-06-28).** Each rule is either a verbose
  `[[rule]]` TOML table or a line in a compact `rules = '''…'''` **DSL** block —
  `POLICY SUBJECT ACTION OBJECT`, one rule per line, columns whitespace-aligned, list
  items comma-separated, `"…"` quoting a token with spaces (and forcing `*`/`@` literal),
  `#` comments. A *literal* TOML string so paths keep backslashes and the DSL owns `"`/`\`;
  its content is a verbatim source slice, so diagnostics map to exact `line:col`. Both
  surfaces normalize to the same parsed rule and may be mixed in one file — the DSL is
  *only* surface syntax (the kernel is unaffected), the natural form for the decision
  table a policy actually is.
- **Per-user `~` (✅ 2026-06-28).** An optional `user = "name"` header expands `~`
  against that account's home (via `/etc/passwd`), so a root-owned per-user file writes
  `~/.ssh` not `/home/<name>/.ssh` — the daemon runs as root, so absent the header `~`
  would be `/root`.
- **conf.d split (✅ 2026-06-28).** A policy path is a single file *or* a directory of
  `*.toml` fragments (loaded in name order). Each fragment parses/resolves independently
  — **file-local groups**, its own `user =` home — then the resolved rules are **merged**
  into one table and compiled together. Precedence (object/subject specificity, then
  deny>allow) is source-order-independent, so fragment load order can't change a verdict;
  a flat merge is safe because every fragment is root-owned (system-beats-user *tiers*
  remain an open question, only needed if a system baseline-deny must be unoverridable). A
  bad fragment fails the whole apply, named in the diagnostic — never a silent partial
  load. `apply` ships the read fragments (`Vec<PolicySource>`) to the daemon, which
  resolves their homes and merges.
- **Applied explicitly.** `cordon policy apply` parses → lints → compiles → atomically
  swaps the BPF maps. **No autoreload** (no inotify/SIGHUP watch): changes take effect
  only on an explicit apply, so an edit-in-progress is never half-enforced.
- **`cordon policy check`** — linter/compiler: unknown exes, group cycles, shadowed /
  unreachable rules, missing paths, deny-shadowed-by-allow.
- **Atomic swap** in-kernel — **implemented** as a generation-counter **double-buffer**:
  the rule maps are banked, the daemon fills the inactive bank and flips `active_bank` in
  one write (RCU-style), so an `apply` has no visible window.
- **Learned rules** live in a *separate* SQLite db (high-churn, machine-managed),
  **lower precedence**, never overriding a hand-written deny; promoted into the text
  file on review (§15.9).

### 15.9 Autolearn (the zones layer)
TOFU generalized: a bounded **training mode** (AppArmor complain-mode / fapolicyd
trust-DB lineage). `zones` = the scope where autolearn may propose rules.
- Explicit activation (`cordon learn`), bounded window; **the trust window is the whole
  vulnerability** (anything malicious running during learning gets blessed) — so never
  auto-enforce, review before promote.
- Generalize (collapse per-file opens into a subtree rule) + confidence (seen N times)
  + dedup, or you drown in candidates.
- Record the *rich* subject (argv0 / ancestor / hash) so promoted rules are tight, not
  just `exe=python3`.
- `cordon learn review` → diff of proposed rules → promote into the text file. The
  learned db is throwaway; the text file is durable.

### 15.10 Authoring flows
Both flows are just *edit the root-owned text policy → `cordon policy apply`*. There is no
global mode and no daemon-side wizard; the journal (`audit`/`deny`/`default-deny`, each with
the matched `exe`/`object`/`action`/`policy`) is the whole feedback loop.

**A. Protect a known dir — observe → bless → enforce.**
1. *Observe.* Add the dir with a `who="*" … policy="audit"` catch-all. Every access logs as
   `audit`, nothing blocks — the blast-radius preview.
2. *Bless.* For each legit `(exe → dir)` the log shows, add `who=<exe> … policy="allow"`.
   Subject-specificity (§15.6) makes the specific allow win over the `*` catch-all, so a
   blessed exe goes silent and the catch-all keeps logging only the not-yet-blessed.
3. *Enforce.* When the audit stream is quiet, flip the catch-all `policy="audit"` →
   `"deny"`: blessed exes stay silent, everything else is blocked **and logged** (`deny`),
   so a tool you broke surfaces and you add an allow. Per dir, on your own schedule.

**B. Discover where an app hides secrets — a "smart `strace -efile`".**
Audit one exe across your home: `who=<app> where="~" action="*" policy="audit"`. Two wins
over `strace`: the `where="~"` scope leaves `/usr/lib/*.so`, `/dev`, `/proc` *unprotected*
→ never logged (only home-subtree access surfaces), and coalescing prevents the flood. The
discovered paths then graduate into `@secrets` under flow A. *Implemented: the kernel
reconstructs the opened file's path by walking `d_name` (no `bpf_d_path` at `file_open`)
and the suppressor keys on the opened file, so each leaf surfaces with its real `path=` —
the same mechanism M4 autolearn needs to collapse per-file opens into a subtree rule.*

### 15.11 Phasing (M1–M5; full status in [`PLAN-rule-model.md`](PLAN-rule-model.md))
1. **Rule core** — **done.** Text policy + compiler (groups/precedence resolved in
   userspace) → flat maps; open-time read/write/create via `f_flags`/`f_mode`; the per-rule
   `policy` the only enforcement level (no global mode — `audit` observes, `deny` enforces);
   explicit `policy apply` via an atomic double-buffer swap; in-kernel event coalescing.
   Replaced the owner model and closed the in-kernel-rules gap.
2. **Subject predicates** beyond exe — uid, cgroup; then IMA/fsverity hash; then
   argv0/ancestor.
3. **Mutation + exec hooks** — unlink/mkdir/rmdir/rename + `bprm_check_security` as a
   second program (closes the rename-out-of-zone bypass).
4. **Autolearn** (separate sqlite db) + review/promote, scoped to zones.
5. **Fail-safe pinning** (orthogonal, already parked) so the compiled policy keeps
   enforcing across daemon restarts (must ship with a singleton guard — see the plan).
