# cordon — design

Working name: **cordon** (object-centric: you *cordon off* the secret dirs).
Deliberately outside the `gate`/`Gatekeeper` namespace.

Language: **Rust**. Store: **SQLite** (root-owned).

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
5. **Identity is "exe + best-effort ancestry," not exe alone.** Shebang tools
   exec as their interpreter (`python3`, not `aws`), and helpers/installers read
   configs they didn't create. The parent chain disambiguates both — but it's
   best-effort (evadable by double-fork), so it raises cost, it isn't a boundary.

## 4. Architecture

### Core (v1)
```
┌──────────────────────────────────────────────────────────────┐
│  GATER — object-centric authorizer daemon (root)              │
│    decide each open() under a protected subtree via §6 flow.   │
│    Linux:  fanotify FAN_OPEN_PERM (+ FAN_CREATE for TOFU,      │
│            FAN_REPORT_PIDFD for race-free caller id)            │
│    macOS:  Endpoint Security AUTH_OPEN (audit_token →          │
│            SecCodeCheckValidity; native parent/responsible pid) │
├──────────────────────────────────────────────────────────────┤
│  OWNERSHIP + RULES (SQLite, root-owned) — §5                  │
│    explicit rules + TOFU auto-ownership + interactive grants   │
├──────────────────────────────────────────────────────────────┤
│  PROMPT AGENT (unprivileged, per user session) — §6           │
│    daemon can't draw UI → delegates prompts here over IPC      │
└──────────────────────────────────────────────────────────────┘
Files stay in place, plaintext. Owner allowed → reads unmodified.
```

The gater is **not** an AppArmor analog — it's a programmable authorizer (cousin
of `fanotify`/LSM-BPF). The AppArmor analog on macOS is Seatbelt/SBPL, unused.

**Fail-open when the daemon is down** (no one to ask). Accepted in scope: a
one-shot interactive scraper runs while the daemon is up; killing the daemon
needs root. (The **`bpf-lsm`** backend inverts this to **fail-safe** — pinned
in-kernel programs keep enforcing if the daemon dies; see "BPF-LSM" below.)

### Optional later bundle (only to cover un-gated reads — §7)
Relocate + encrypt → needs a **key** → held by a resident **broker** → needs a
**transparency layer** (`fuse-t`, or seccomp `ADDFD` under `cordon run`). All
three or none.

### Optional, orthogonal
**Capability brokering** for tools with a credential-helper seam (git, AWS
`credential_process`, docker, kube): hand back **short-lived** creds. Per-tool.

### Privilege model — pluggable backends
The **policy core** (decision flow §6, ownership store §5, prompt routing,
`cordon` CLI/IPC) is **privilege-agnostic**. Only the *enforcement backend* — the
thing that feeds it open-events and carries out allow/deny — needs privilege.
Backends sit behind one interface:

| Backend | Privilege | Scope | Boundary? | Use |
|---|---|---|---|---|
| `mock`/`replay` | user | synthetic events | no | unit/logic tests |
| `seccomp-unotify` | user (`no_new_privs`) | descendants of `cordon run -- <tool>` | partial (launch-scoped) | dev; single-tool sandbox |
| `fanotify` | **root** (CAP_SYS_ADMIN) | system-wide | **yes** (fail-open) | Linux MVP / portable fallback |
| `bpf-lsm` | **root** (CAP_BPF + CAP_MAC_ADMIN) | system-wide | **yes** (fail-safe) | Linux production (hardened) |
| `endpoint-security` | **root** + entitlement | system-wide | **yes** | macOS production |

So the daemon runs **`systemctl --user`** in dev with the `mock` backend — no
root, fast iteration, the whole policy engine testable — and swaps to the
`fanotify`/ES backend (system service) for the real guarantee. (The real
`fanotify` backend is itself testable unprivileged via a virtme-ng VM — §11.)

**Why `fanotify` needs root:** permission events (`FAN_OPEN_PERM`) let you *block,
deny, and surveil* `open()` for *any* process on the box — a system-wide
interception/veto power (you could watch all I/O or deadlock the machine), so the
kernel guards it behind `CAP_SYS_ADMIN` (≈root), as it does the broad
`FAN_MARK_MOUNT`/`FAN_MARK_FILESYSTEM` marks. The unprivileged fanotify mode (≥5.1,
`FAN_REPORT_FID`) is *notification-only* — no deny — so it's useless for gating.
Hence user-mode **cannot enforce system-wide; it is a dev/debug harness, not a
boundary** (its store is user-writable too). (Nicety: we need the capability, not
uid 0 — a dedicated uid + systemd `AmbientCapabilities=CAP_SYS_ADMIN`.)

**What `seccomp-unotify` is:** a seccomp filter verdict (`SECCOMP_RET_USER_NOTIF`)
that, on a filtered syscall (e.g. `openat`), *suspends the calling thread* and
hands a notification to a **supervisor** process holding a listener fd. The
supervisor reads the syscall + args + target pid and responds: spoof a result
(deny via errno), `CONTINUE` (proceed), or `ADDFD` (inject an fd so the open
"succeeds" with a chosen file). It's **unprivileged** — installable without
`CAP_SYS_ADMIN` if the process first sets `no_new_privs`; the listener fd is passed
to a separate supervisor over a socket. Filters are inherited by descendants only,
so it covers just processes you *launch* (`cordon run -- <tool>`: set
`no_new_privs`, install filter, send fd to the daemon, exec the tool) — a
per-invocation sandbox, not the system-wide guarantee. Footgun: path args point
into the target's memory (racy with a hostile target → guard with
`SECCOMP_IOCTL_NOTIF_ID_VALID`); harmless for our own fixtures. Linux-only; macOS
unprivileged dev-mode is `mock` only (no seccomp equivalent; real interception
needs ES/root).

> **Re-evaluated (post-Phase-1): not planned.** `seccomp-unotify` had two jobs —
> (a) an *unprivileged test/dev* path, and (b) a `cordon run -- <tool>`
> single-tool sandbox. (a) is fully obsoleted: **virtme-ng** now runs the *real*
> `fanotify` backend unprivileged (no root, only `/dev/kvm`) for local dev and
> CI, and the `mock` backend covers pure logic. (b) is a genuine feature but
> **subject-centric and opt-in** — you only confine tools you *launch*, so it
> doesn't touch the threat model (an unknown scraper you didn't launch); it's a
> firejail-style sandbox orthogonal to the object-centric gater, at the cost of
> real `unsafe` (BPF + user-notif + the path-arg TOCTOU above). So it's **dropped
> from the plan** and kept only as an *optional future* sandbox mode, not a
> deliverable.

### BPF-LSM — the hardened Linux boundary (planned; supersedes `fanotify` for production)
`fanotify` got us a correct, portable MVP fast, but it is the *wrong shape* for
per-object policy — it was built for whole-volume AV/HSM scanning. It can only
veto `open`/`access`/`exec` (no structural-op gating), and per-directory marks
don't recurse and can't be kept race-free across `mkdir`/rename/mount, so
recursive coverage forces a **whole-filesystem mark → every `open()` on the fs
funnels through userspace**. **BPF-LSM is the Linux mechanism that actually
fits.** eBPF programs attach to LSM hooks (`file_open`, `inode_create`/
`inode_rename`/`inode_unlink`, `sb_mount`, `bprm_check_security`) and **return
the verdict in-kernel** (`0` allow / `-EPERM` deny). Policy lives in **BPF maps**
the daemon updates via the `bpf()` syscall — *no recompile/reload per rule.*

Our **deny-and-learn-only** decision (no synchronous block-and-ask — §6) removes
the *one* thing BPF-LSM can't do (it can't suspend a syscall pending a userspace
answer), making the trade one-sided. Versus `fanotify`:
- **No marking → no recursive-mark race.** Hooks fire on the operation; a freshly
  `mkdir`'d / `mv`'d-in / `mount`-ed-in subtree is covered the instant it exists.
- **Structural ops are gateable** (`inode_rename`, `inode_create`, `sb_mount`…),
  closing the `fanotify` **rename-out-of-zone bypass**: a same-uid tool renames a
  secret out of a protected subtree, then opens it at an unprotected path —
  `fanotify` decides on the open-time path and allows it; BPF-LSM vetoes the
  rename (or keys identity on the inode, not the path).
- **In-kernel zone filtering.** The program tests the path (`bpf_d_path`, or
  `(dev,inode)` / LPM-trie keying) and allows non-zone opens *without leaving the
  kernel* — no whole-`/` funnel; the hot path never crosses into userspace.
- **Stronger identity, in-kernel.** Caller exe from `task->mm->exe_file`
  (race-free, no `/proc` readlink); optional **content digest** of the opener via
  `bpf_ima_file_hash()` (IMA) or `bpf_get_fsverity_digest()` (fs-verity) —
  realizing the §5 `path+inode`/`signature` granularity against a hash, not a
  spoofable path. (IMA *appraisal* + a keyring gets "verified-signed-by-key," the
  closest Linux analog to ES code-signing — enterprise setup, not free.)
- **Fail-safe, not fail-open.** Pin the programs and their `bpf_link` to **bpffs**
  (`/sys/fs/bpf/…`) and enforcement persists with **no holding process** — the
  daemon can crash/restart with *zero* enforcement gap, inverting `fanotify`'s
  posture (kill the daemon → marks drop → fail-open).

**Deny/learn delivery — decoupled from the verdict.** Unlike `fanotify` (where
delivery to userspace *is* the decision), the in-kernel program has already
decided; learning rides a **BPF ring buffer** (`BPF_MAP_TYPE_RINGBUF`): on a deny
/ would-deny (audit) / TOFU-claim the hook emits a record (pid, exe-hash, inode,
op, reason, ts) and the daemon drains it asynchronously via `epoll`. It does
**not** block the syscall. Lossy under flood = you drop *observability records*,
never *enforcement* (a discard counter bumps).

**Control plane vs data plane** — the daemon leaves the hot path entirely:
> **Data plane = in-kernel BPF** — every open, every verdict, the TOFU map-write
> — *always on, daemon-independent.*
> **Control plane = SQLite (durable source of truth) + a thin, restartable
> daemon** that (a) loads+pins the programs and seeds maps from the store at boot,
> (b) applies `cordon` CLI policy changes as map updates, and (c) **drains the
> ring buffer to the journal/log and persists learned ownership to SQLite.** Off
> the hot path; its absence costs durability/observability, **never** enforcement.
> *The daemon is still required* — at minimum to ship ring-buffer events to the
> journal and to persist learning.

**Map concurrency** is handled by map semantics + RCU, not hand-rolled locks: a
single-element `bpf_map_update_elem` is atomic (a reader sees old-or-new, never
torn; element lifetime is RCU); multi-field values are swapped whole; an atomic
*multi-entry* policy snapshot uses a **generation-counter / double-buffer** (fill
the inactive version, flip the active-gen key in one update — RCU-style);
`bpf_spin_lock` is available if a value genuinely needs in-program
read-modify-write.

**Durability caveat.** BPF maps are ephemeral (lost on reboot / program reload),
so SQLite remains the backing and the ring-buffer drainer keeps them in sync. A
TOFU claim written in-kernel but not yet persisted is *enforced live* but *lost on
reboot* (re-learned on next create) — acceptable for creator-owns.

**Requirements / cost.** `CONFIG_BPF_LSM=y` **and** `bpf` in the active LSM list
(`CONFIG_LSM=` / `lsm=` boot param — common but not universal); kernel ≥ 5.7 (the
content-hash helpers are ≥ 5.11 / 6.x); `CAP_BPF` + `CAP_MAC_ADMIN`. Heavier to
ship than `fanotify` (libbpf + CO-RE + a verifier-friendly program; path-prefix
matching is the fiddly part). **Additive** to existing LSMs — it can only
*further* restrict, never loosen (a SELinux/AppArmor deny still denies). So
`fanotify` stays as the **portable fallback** (older kernels, or `bpf` absent from
the LSM list); `bpf-lsm` is the hardened production boundary where available. Real
precedent for exactly this allow/deny-by-path use: **KubeArmor**, **Tetragon**,
**bpflock** (§13).

**Lineage is subsumed here (cancels the standalone cache, §8.2/§12).** Because the
backend already runs in-kernel, the §8.2 ancestry hardening is *folded in*, not a
separate proc-connector subsystem: a live `task->real_parent` walk gives the same
best-effort chain for free at decision time, and durable-across-exit lineage is
just `sched_process_{fork,exec}` tracepoints writing `(pid, starttime)`→parent
into a BPF map *within this backend*. Ceiling unchanged: a real `exec` of a
blessed binary (the **construction** attack, §8.1) is still faithfully recorded,
so ancestry stays best-effort, never the boundary.

Locations: dev `--user` → socket `$XDG_RUNTIME_DIR/cordon.sock`, store
`$XDG_STATE_HOME/cordon/`; prod system → `/run/cordon.sock`, `/var/lib/cordon/`
(root-owned). The `cordon` CLI auto-detects.

**Operational config** is an optional TOML file (`mode`, `backend`, `socket`/
`store`, the initial `zones` seed), with `${ENV}` interpolation and precedence
CLI > file > default; dynamic policy (owners/rules/zones) stays in the store.
**Mode** is `enforce` (block) or `audit` (run the flow, log would-be denials,
allow) — the latter previews an ownership decision's blast radius before it
bites, mirroring the fail-open posture. See `packaging/cordon.example.toml`.

Terminology: this daemon is the **gater**. The **broker** (§7) is the separate,
deferred key-holder.

## 5. Coverage & ownership model

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

> **Superseded as a standalone deliverable.** With the **BPF-LSM backend (§4)**
> this is *folded into the backend*, not a separate proc-connector subsystem: the
> same `sched_process_{fork,exec}` hooks live there (writing `(pid, starttime)`→
> parent into a BPF map), and a live `task->real_parent` walk is free at decision
> time. So the once-planned event-sourced **proc-connector lineage cache is
> dropped** — the `fanotify` backend keeps its best-effort `/proc/<pid>/stat`
> snapshot (ancestry is never the boundary, §8.1), and the durable version arrives
> for free with `bpf-lsm`. Note the in-kernel walk is *also* best-effort: a parent
> that already exited is already reparented, so only fork-time recording (cache or
> BPF map) defeats **removal** — the **construction** ceiling stands regardless.

## 9. Cross-platform primitive map

| Need | Linux | macOS |
|---|---|---|
| Object-centric open authorizer | `fanotify FAN_OPEN_PERM` / LSM-BPF | **Endpoint Security** `AUTH_OPEN` |
| Unprivileged dev/testing | `mock` + **virtme-ng VM** (runs real `fanotify`, no root) | `mock` only (no unpriv intercept) |
| Caller id (race-free) | `pidfd` (`FAN_REPORT_PIDFD`, ≥5.15) | per-conn audit token → code req |
| Parent chain | `/proc/<pid>/stat` walk + start-time | ES process struct (parent + responsible pid) |
| TOFU create signal | `FAN_CREATE` (FID/DFID) | ES create/exec events |
| Prompt channel | per-session agent + dbus/libnotify | per-session agent + UserNotifications |
| Key custody (only if encrypting) | kernel keyring / Secret Service | Keychain / Secure Enclave |
| Declarative MAC we're *not* using | AppArmor / SELinux | Seatbelt / SBPL |

Same shape both OSes: root authorizer daemon + shared SQLite store + per-session
prompt agent + `cordon` CLI. Per-tool cost = a row, not a profile.

## 10. Honest limitations
- Fail-open when the daemon is down (accepted in scope) — **except the `bpf-lsm`
  backend**, which fails *safe*: pinned in-kernel programs survive daemon death (§4).
- Parent chain is best-effort — double-fork launders ancestry; argv untrusted.
- Interpreted tools surface as their interpreter → need ancestry or explicit rule.
- Interactive mode: first-access denial friction; prompt-fatigue/habituation risk
  (mitigate: prompt only on protected subtrees, first touch, rich context).
- Confused-deputy: gating ≠ stopping a tool's own export surface (out of scope).
- `fanotify` needs `CAP_SYS_ADMIN`; ES needs a restricted entitlement (SIP
  relaxation for personal use). Both production backends run as root.
- **User-mode is not a boundary** — the `--user` dev daemon (`mock` backend) is
  for development/CI only; real protection needs the root
  `fanotify`/ES backend.
- **macOS backend shares ES's ceiling** — open()-time mediation only (no
  `read(2)` event), symlinks not followed, ES "default mute set" binaries
  unmediated. Same limits Santa's FAA hits (`docs/SANTA.md`); inherent to ES.

## 11. Testing strategy — internal fixtures
Hermetic, throwaway `$HOME` as the only zone root. Distinct exe paths to
exercise *identity* gating:
- `testtool-oldstyle` → `$HOME/.ctest-old/secret` (dotfile; zone = home)
- `testtool-xdg` → `$HOME/.config/ctest-xdg/secret` (XDG; zone = `~/.config`)
- `testscraper` → walks & tries to read both; must be denied.
- (later) an interpreted fixture (`python testtool.py`) to exercise the chain.

Asserts: each tool reads its own secret across runs (TOFU); scraper denied on
both; store shows expected owners; cross-owner read denied; (Phase 2) prompt
fires on a pre-existing unowned path and "approve permanently" persists.

### Test tiers (by privilege)
- **Unprivileged (mock backend):** the policy core, store, decision flow, and IPC
  e2e — `cargo test`, CI-friendly, no root. Covers everything but the kernel hook.
- **Privileged boundary (fanotify), without host root → virtme-ng VM.** The real
  `fanotify` backend needs `CAP_SYS_ADMIN`, but we get it from a **virtme-ng VM**
  (`packaging/test/run-in-vm.sh`) booting a **pinned upstream kernel** (Ubuntu
  mainline, e.g. `v6.12`) as guest-root — needs only `/dev/kvm` (group `kvm`), no
  host root. The VM runs qemu **directly** (no container), and virtme-ng reuses
  the host userspace, so there is no rootfs to build and no glibc mismatch. The
  *same* harness + kernel run locally and in CI, so the kernel never diverges.
  (`CORDON_VM_KERNEL` selects the pinned version; unset = the host kernel for fast
  local iteration.) Rootless podman is *not* an option for the backend itself:
  `FAN_OPEN_PERM` checks init-userns `CAP_SYS_ADMIN`; userns-root isn't enough.
- **Why not libkrun/krunvm:** it was evaluated and proven to *boot* fanotify
  (libkrunfw's kernel enables `FANOTIFY_ACCESS_PERMISSIONS`), but getting `krunvm`
  onto a CI runner means nesting it *inside a container*, which stacks two user
  namespaces (`buildah unshare`) under the libkrun VMM. That nesting fails
  **differently per environment** (`gid_map: operation not permitted` locally vs
  `memfd_create: EINVAL` on GitHub) — non-reproducible, so undebuggable across
  environments. virtme-ng collapses the stack to a single `/dev/kvm` dependency.
- The Phase 1 smoke test (`packaging/test/phase1-fanotify-smoke.sh`) proves
  owner-allow + scraper-deny (`EPERM`) through the real backend — green in the
  virtme-ng VM on both the host kernel and pinned `v6.12`.

## 12. Phased plan
- **Phase 0 — skeleton + user-mode daemon.** Rust workspace; SQLite store +
  rules/ownership schema; `cordon` CLI (`add/rm/status/owners/adopt/claim/disown`)
  over IPC; daemon as `systemctl --user` with the `mock` backend — decision-flow,
  TOFU, and store unit-tested **without root**, CI-friendly. (Real fixtures run
  once an interception backend lands in Phase 1.)
- **Phase 1 — Linux fanotify backend (root).** *Done + validated.*
  `fanotify FAN_OPEN_PERM` backend (via `nix`, no hand-written `unsafe`) behind
  the same core: marks zone/subtree filesystems, resolves caller via `/proc`, runs
  the decision flow, answers ALLOW/DENY. **All of steps 1–5 enforced
  system-wide**, incl. **TOFU-on-create (step 4)**: rather than the FID-based
  `FAN_CREATE` group (racy/`unsafe`), the backend reads the suspended caller's
  in-flight open flags from `/proc/<pid>/syscall` — safe, register-based,
  race-free for `open`/`openat`/`creat` (`openat2` logs a warning + falls back to
  `Read`). Proven owner-allow + scraper-deny (`EPERM`) for both `adopt` and TOFU
  in a virtme-ng VM (§11). Ancestry is the best-effort `/proc/<pid>/stat` snapshot
  (upgraded in Phase 2). (The once-planned `seccomp-unotify` dev extra is
  **dropped** — virtme-ng obsoleted the unprivileged-testing rationale; see the §4
  re-evaluation.)
- **Phase 2 — interactive + ancestry hardening.** (Basic parent-chain
  owner-match — step 3 — already landed in Phase 1: `proc::ancestry` + the
  engine's chain check. Phase 2 makes it *interactive* and *robust*.)
  - **Interactive deny-and-learn (step 5) — the headline.** A per-session,
    unprivileged **prompt agent** (polkit-style) that the root daemon routes
    prompts to; the AUTH path stays synchronous-with-deadline (Santa's
    deadline-safety dispatch, `docs/SANTA.md`) and **denies-then-learns** —
    persist the user's choice, honor it next time. Prompt outcomes → rules:
    deny-once / deny-perm / allow-once / allow-for-X-min (TTL) / allow-perm; the
    last **subsumes `adopt`**. *Protocol work:* the IPC gains a **server-initiated
    push channel** (today it's request/response only) so the daemon can deliver
    prompts on the agent's long-lived connection; authenticate the agent via
    `SO_PEERCRED`.
  - **Ancestry hardening — folded into the `bpf-lsm` backend, not a standalone
    cache.** The once-planned event-sourced **proc-connector lineage cache is
    cancelled**: the `bpf-lsm` backend (Phase 3, §4) has in-kernel access, so
    durable lineage is just `sched_process_{fork,exec}` → a BPF map *inside that
    backend*, and a live `task->real_parent` walk is free at decision time. Until
    then the `fanotify` backend keeps its best-effort `/proc/<pid>/stat` snapshot
    (Phase 1) — ancestry is never the boundary (§8.1), so there's no urgency.
    (Ceiling unchanged: the **construction** attack survives any lineage source.)
  - **Carry-over hardening from Phase 1:** `FAN_REPORT_TID` so op/identity
    attribution reads the *triggering thread* (today `/proc/<tgid>/syscall` can
    miss a non-main-thread create → falls back to `Read`); optional `openat2`
    flag decode. The interpreter fixture (`python testtool.py`) lands here to
    exercise the chain end-to-end.
- **Phase 3 — `bpf-lsm` backend (the hardened Linux boundary) + full ownership.**
  The production Linux backend that supersedes `fanotify` (kept as the portable
  fallback): in-kernel verdicts on LSM hooks, policy in BPF maps, a ring-buffer
  learn path, **fail-safe** pinned enforcement, in-kernel zone filtering, and
  structural-op gating (closes the rename-out-of-zone bypass) — full design in §4.
  This also realizes **full ownership**: identity granularity (path / `path+inode`
  / `signature`) keyed on an in-kernel **content digest** (`bpf_ima_file_hash` /
  `bpf_get_fsverity_digest`), tool-groups, and the override CLI fully wired; and
  **subsumes** the §8.2 lineage hardening (fork/exec → BPF map). Ancestry stays
  best-effort (construction attack).
- **Phase 4 — macOS gater.** Bespoke ES `AUTH_OPEN` client — **decided**: Santa's
  FAA can't do dynamic TOFU / interactive prompts (`docs/SANTA.md`). Reuse Santa's
  Apache-2.0 source as a reference (deadline-safety dispatch, multi-ES-client
  layout, identity matching). Same store/CLI/agent abstraction.
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
  security. We use a kernel authorizer (fanotify/ES) instead; `fuse-t` is kept
  only for the deferred transparency layer.

### Observability & eBPF enforcement
- **auditd / fanotify-notify / inotify** — can *watch* file access by path, but
  **cannot deny**. We need the permission (veto) path, not just logging.
- **Tetragon / Falco** (eBPF, LSM-BPF) — runtime security; Tetragon can even
  enforce (override/kill). Architecturally this **is** our LSM-BPF alternative
  backend — but it's container/k8s-oriented and heavyweight to drive as a
  per-user desktop secret gate.

### Authorization-agent architecture
- **polkit** — privileged daemon + **unprivileged per-session agent** that draws
  the prompt. Exactly our daemon/agent split (§6). But polkit authorizes D-Bus
  privileged *actions*, not file reads.

## 14. Open decisions
See `STATUS.md`.
