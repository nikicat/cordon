# ADR 0002: BPF-LSM is the boundary, and it outlives the daemon

Status: Accepted

## Context

The gate must decide every open of a protected object, outside the confined process ([ADR
0001](0001-object-centric-gating.md)), and it must not fail open when its daemon dies.

> **Alternatives tried.** Earlier iterations shipped a
> `mock` backend, which produced synthetic events for logic tests. They also shipped a root
> `fanotify` `FAN_OPEN_PERM` backend. It was a fast, portable MVP that enforced while it ran,
> but it was never a boundary. It fails open, so every open is allowed while the daemon is
> down. It decides in userspace on the open-time path, which allows the rename-out-of-zone
> bypass described below. It reads identity best-effort from `/proc`. And it needs
> `CAP_SYS_ADMIN` for its system-wide veto power, because the unprivileged `FAN_REPORT_FID`
> mode only notifies and is useless for gating. So user mode cannot enforce system-wide, and
> that motivated the move into the kernel. A `seccomp-unotify` sandbox (`cordon run --
> <tool>`) was also evaluated and scoped out. It was subject-centric and opt-in, and it needed
> real `unsafe` code. All three were removed in the rule-model migration, and `bpf-lsm` is the
> sole Linux backend. The in-kernel LSM verdict described below answers fanotify's wrong shape
> for per-object policy.

## Decision

```
┌──────────────────────────────────────────────────────────────┐
│  GATER — object-centric authorizer, in-kernel (root)          │
│    decide each open() against a flat per-object rule table     │
│    ([ADR 0008](0008-precedence.md) precedence), the verdict returned IN THE KERNEL.     │
│    Linux:  BPF-LSM file_open (policy in BPF maps)              │
│    macOS:  Endpoint Security AUTH_OPEN (planned; audit_token → │
│            SecCodeCheckValidity; native parent/responsible pid) │
├──────────────────────────────────────────────────────────────┤
│  POLICY — a root-owned TEXT FILE ([ADR 0010](0010-policy-storage.md))                      │
│    (who, where, action, policy) rules + groups; cordond        │
│    compiles it → BPF maps on `cordon policy apply`.            │
└──────────────────────────────────────────────────────────────┘
Files stay in place, plaintext. A rule allows → reads unmodified.
```

The gater is not an AppArmor analog. It is a programmable authorizer, a cousin of LSM-BPF.
The AppArmor analog on macOS is Seatbelt/SBPL, and cordon does not use it.

**Enforcement posture.** With `bpf-lsm` the verdict is made in the kernel, so it does not
depend on the daemon being up. The links are pinned to bpffs (M5), so enforcement is
fail-safe. It survives the daemon's death, and a crash or a restart leaves the boundary
standing with no gap.

### Privilege model

The policy core (the [ADR 0005](0005-flat-rule-model.md) compiler, IPC and the `cordon` CLI)
is privilege-agnostic. Only the
enforcement backend needs privilege. The backend is the part that mediates opens and carries
out allow and deny, and it sits behind one interface:

| Backend | Privilege | Scope | Boundary? | Status |
|---|---|---|---|---|
| `bpf-lsm` | root (CAP_BPF + CAP_MAC_ADMIN) | system-wide | yes (fail-safe, because it is pinned to bpffs) | Linux production, and the boundary |
| `endpoint-security` | root plus an entitlement | system-wide | yes | macOS, planned (see below) |
| `mock` / `fanotify` / `seccomp-unotify` | — | — | no | removed or dropped (see Context) |

The build splits along this seam. The core and the CLI compile on stable Rust with no kernel
dependencies. The daemon's `bpf-lsm` feature, which is on by default and Linux-only, links the
aya loader and enforces. macOS will add an ES backend behind the same interface.

### Why BPF-LSM

BPF-LSM is the Linux mechanism that fits per-object policy, and it is cordon's sole Linux
backend. eBPF programs attach to LSM hooks (`file_open`, `inode_create`, `inode_rename`,
`inode_unlink`, `sb_mount`, `bprm_check_security`) and return the verdict in the kernel (`0`
to allow, `-EPERM` to deny). The policy lives in BPF maps that the daemon fills from the
compiled text policy, so a rule change needs no recompile or reload. Because the hooks
mediate the operation itself, there are no per-directory marks to keep race-free, and there is
no funnel of the whole filesystem through userspace. Those are the traps that a userspace
open-notifier falls into because of its shape.

cordon returns the verdict in the kernel and never blocks a syscall to ask userspace. That
sidesteps the one thing BPF-LSM can't do, which is to suspend a syscall until userspace
answers. The in-kernel LSM shape buys the following:
- **No marking, so no recursive-mark race.** Hooks fire on the operation. A subtree is
  covered the instant it exists, whether it was just made by `mkdir`, moved in with `mv`, or
  mounted.
- **Structural operations are gateable** (`inode_rename`, `inode_create`, `sb_mount` and so
  on). That closes the rename-out-of-zone bypass. A same-uid tool can't rename a secret out of
  a protected subtree and reopen it at an unprotected path, because the rename itself is
  vetoed. Identity is also keyed on the inode, not on the path.
- **Matching happens in the kernel, so there is no funnel.** The program walks the ancestors
  of the opened file's dentry by `(dev,inode)`, and it allows opens outside any zone without
  leaving the kernel. There is no funnel of all of `/`, and the hot path never crosses into
  userspace. Path strings are ruled out, because `bpf_d_path` is not allowed at the
  `file_open` hook. That was a verifier discovery, since `security_file_open` isn't in
  `btf_allowlist_d_path`. So matching is inode-based. The daemon resolves paths to
  `(dev,inode)` at seed time. It takes the device from the mount table, so the device agrees
  with the kernel's `sb->s_dev` on overlayfs and btrfs. There, `stat` reports a device for
  each layer or subvolume, which does not agree (`proc::file_id` in
  `crates/daemon/src/proc.rs`).
- **Identity is stronger and lives in the kernel.** The caller's exe identity is its
  `(dev,inode)`, read straight from `task->mm->exe_file`. That is race-free and needs no
  `/proc` readlink. The hardening beyond that is a content digest of the opener, made with
  `bpf_ima_file_hash()` (IMA) or `bpf_get_fsverity_digest()` (fs-verity). It identifies the
  binary by what it is. So the identity survives an inode change such as a package upgrade,
  and it resists a copy to a blessed path, because it checks a hash rather than a path that
  can be spoofed. IMA appraisal plus a keyring gets "verified as signed by this key", which is
  the closest Linux analog to ES code signing. That is an enterprise setup, and it is not
  free.
- **Fail-safe, not fail-open, as implemented in M5.** The `bpf_link`s are pinned to bpffs,
  and enforcement persists with no process holding it. So the daemon can crash or restart
  with zero gap in enforcement. Only the links are pinned. A link holds its program and a
  program holds its maps, so the seeded policy stays resident too, and no map is ever shared
  between processes. `PinDir::pin_links` in `crates/daemon/src/backend/bpf_lsm/pin.rs` owns
  the layout and the handover. Turning enforcement off is the explicit `cordond --teardown`.

## Consequences

### What shipped

**Implemented in M1, and validated in a VM (see [STATUS](../../STATUS.md)).**
M1 delivers the `file_open` verdict over the flat rule table. The program finds the deepest
protected object with the `(dev,inode)` dentry walk, matches the subject by the exe's
`(dev,inode)`, and derives the action (read, write or create) from `f_mode` and `f_flags`. It
takes the first match in the bucket that copy-down resolved, and denies by default. The
per-rule `policy` is the only enforcement level, and there is no global mode ([ADR
0008](0008-precedence.md)). M1 also
delivers the text policy, which is compiled and seeded at startup and re-seeded by
`cordon policy apply` with an atomic double-buffer swap. And it delivers the ring-buffer learn
path, with event coalescing in the kernel. Structural-operation gating (M3, which closes the
rename bypass and adds `execute`) and fail-safe pinning (M5) have shipped since. So `bpf-lsm`
mediates opens and mutations, and it keeps enforcing when the daemon dies. Content-digest
identity ([ADR 0006](0006-subject-predicates.md)) remains unshipped, and it is not what
closes the `LD_PRELOAD` hole (see [ADR 0015](0015-fixed-code-grants.md)).

**Deny and learn records are delivered separately from the verdict.** The in-kernel program
has already decided, and observability rides on a BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`).
On a `deny` or an `audit`, the hook emits a record. The record holds the pid, the exe's
`(dev,inode)`, the object's `(dev,inode)`, the reconstructed leaf path of the opened file, the
action and the decision. An in-kernel suppressor coalesces the records. Its key,
`SuppressKey`, includes the opened file, so distinct leaves surface separately. The daemon
drains the ring asynchronously, and it does not block the syscall. Under a flood, the losses
are observability records and never enforcement. A full ring loses the record silently
(`emit` in `crates/bpf/src/kernel.rs`).

**Control plane and data plane.** The daemon leaves the hot path entirely:
> The data plane is in-kernel BPF. It handles every open and every verdict, and it is always
> on and independent of the daemon.
> The control plane is the root-owned text policy, which is the durable source of truth, plus
> a thin daemon that can restart. The daemon (a) compiles the policy and seeds the maps at
> startup and on `cordon policy apply`, and (b) drains the ring buffer to the journal. It is
> off the hot path. Its absence costs observability and never enforcement, not even across a
> restart, because the links are pinned. The daemon is still required, to ship ring-buffer
> events to the journal and to apply policy changes.

**Map concurrency** is handled by map semantics and RCU, not by hand-rolled locks. A
single-element `bpf_map_update_elem` is atomic. A reader sees the old value or the new one,
never a torn one, and element lifetime is managed by RCU. The atomic multi-entry policy swap
on `apply` uses exactly the generation counter, or double buffer, that this design called for
([ADR 0010](0010-policy-storage.md)). The three rule maps are banked. `Maps::seed` fills the
inactive bank and then flips
`Settings.active_bank` in one update, in the style of RCU. `bpf_spin_lock` is available if a
value ever needs an in-program read-modify-write.

**Durability.** BPF maps are ephemeral, and they are lost on a reboot or a program reload. But
the text policy is the durable source of truth, and the daemon recompiles and re-seeds it at
startup, so nothing is lost. Autolearn ([ADR 0011](0011-autolearn.md)) keeps its
proposals in a separate database, which is never the enforced source.

**Requirements and cost.** The kernel needs `CONFIG_BPF_LSM=y`, and `bpf` in the active LSM
list (`CONFIG_LSM=` or the `lsm=` boot parameter). That is common but not universal. The
kernel must be 5.7 or later, and the content-hash helpers need 5.11 or 6.x. The daemon needs
`CAP_BPF` and `CAP_MAC_ADMIN`. The program is friendly to the verifier. rustc can't emit CO-RE
relocations (<https://github.com/rust-lang/rust/issues/158412>), so a userspace shim reads
the running kernel's BTF and injects field offsets into the program's `.rodata`. That way one
object runs on any kernel. BPF-LSM adds to the existing LSMs. It can only restrict further and
never loosens, so a SELinux or AppArmor deny still denies. So `bpf-lsm` is the hardened
production boundary where it is available. On older kernels, or with `bpf` absent from the LSM
list, there is no hardened Linux boundary. KubeArmor, Tetragon and bpflock are real precedent
for exactly this allow and deny use ([prior art](../prior-art.md)).

**Locations.** The root system service listens on `/run/cordon.sock`. It compiles its policy
from `/etc/cordon/policy.toml`, or from a `/etc/cordon/conf.d/` directory of per-user fragments
([ADR 0010](0010-policy-storage.md)), and both are root-owned. Operational settings live in
`/etc/cordon/config.toml`. A
dev daemon in a user session can move these to `$XDG_RUNTIME_DIR` and `$XDG_CONFIG_HOME`, and
the `cordon` CLI detects that automatically. But such a daemon is not a boundary, and only the
root service enforces.

**Operational config** is an optional TOML file. It holds `backend`, `socket`, and the paths
of the eBPF object and the policy file. Values are interpolated from `${ENV}`, and the
precedence is the CLI first, then the file, then the default. The enforcement policy, meaning
the rules, is not here. It lives in the root-owned text policy ([ADR
0010](0010-policy-storage.md)), and
`cordon policy apply` applies it. There is no global mode. Whether to observe or enforce is
the per-rule choice between `audit` and `deny` ([ADR 0008](0008-precedence.md)). See
`packaging/cordon.example.toml`
and `cordon.example.policy.toml`.

### macOS

The macOS gater will be a bespoke ES `AUTH_OPEN` client. That is decided,
  because Santa's FAA can't do dynamic, reviewable policy or autolearn
([SANTA.md](../SANTA.md)). We
  reuse Santa's Apache-2.0 source as a reference for the deadline-safety dispatch, the layout
  with several ES clients, and identity matching. The policy and the CLI abstraction stay the
  same, behind the backend interface.

### Cross-platform primitive map

| Need | Linux | macOS |
|---|---|---|
| Object-centric open authorizer | BPF-LSM `file_open` (in-kernel verdict) | Endpoint Security `AUTH_OPEN` |
| Testing without host root | a virtme-ng VM runs the real `bpf-lsm` backend, and `cargo test` covers the compiler and the control plane | none yet (no unprivileged intercept) |
| Caller id (race-free) | exe `(dev,inode)` from `task->mm->exe_file` (in the kernel) | the audit token of each connection, checked against a code requirement |
| Parent chain | a `task->real_parent` walk (in the kernel) plus start time | the ES process struct (parent and responsible pid) |
| Create signal (autolearn / mutation) | the `inode_create` hook ([ADR 0005](0005-flat-rule-model.md), M3) | ES create and exec events |
| Key custody (only if encrypting) | kernel keyring / Secret Service | Keychain / Secure Enclave |
| Declarative MAC we're *not* using | AppArmor / SELinux | Seatbelt / SBPL |

Both OSes have the same shape: a root in-kernel authorizer, a root-owned text policy, and the
`cordon` CLI. Protecting a directory costs one rule, not a profile for each tool.
