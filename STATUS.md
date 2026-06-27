# STATUS

**Phase: 3 (bpf-lsm) — in-kernel boundary enforcing, VM-validated.** Phase 0
(core/store/daemon/CLI/mock) and Phase 1 (the Linux `fanotify` backend —
decision-flow steps 1–5 incl. TOFU-on-create, in a virtme-ng VM) are done. Note
`fanotify` is a **dev/test backend, not a security boundary** (fail-open + path-
bypass); the real Linux boundary is **`bpf-lsm`**, which Phase 3 adds — in-kernel
verdicts, validated end-to-end in a VM (owner allowed, non-owner `EPERM`). This file
is the resume point.

## Rule model (target architecture, DESIGN §15) — M1 core complete
The owner model (Phase 3 below) has been replaced by the flat **rule model**
(`(who, where, action, policy)`), per [`docs/PLAN-rule-model.md`]. M1 decisions are
locked there (copy-down object precedence, `MAX_RULES_PER_OBJ = 32`, packed-array rule
encoding, recompile + double-buffer swap, default-deny, owner CLI verbs removed). All of
M1 1a–1h plus 1g coalescing and the atomic double-buffer swap are implemented and
VM-validated; only fail-safe bpffs pinning (M5) remains as deferred hardening.

**Landed (M1 1a + 1b — userspace core, pure + unit-tested, no kernel changes yet):**
- **`crates/bpf-common/src/policy_maps.rs`** — the compiled-form contract shared with
  the eBPF program: `ObjId`, `Action` (a `bitflags` bitset, `#[repr(transparent)]` for
  POD/map-layout soundness — validated compiling for `bpfel-unknown-none`), `Policy`,
  `SubjectMatch`, `CompiledRule`, and the `PROTECTED`/`RULES`/`RULE_COUNT` map names.
  (The v1 `SUBTREES`/`OWNER_IDS` schema was removed in 1c, below.)
- **`crates/core/src/policy/`** — the three-stage userspace pipeline:
  `parse` (TOML → spans via `toml::Spanned`; serde + `deny_unknown_fields` for structure),
  `resolve` (group expansion on all three axes, cycle/ref/name validation, `~`-expansion;
  the `@ref`/`*`/leaf lexical layer is a `Token`, leaf *semantics* stay here), and
  `compile` (cross-product → **copy-down** object precedence → sorted, deduped, capped
  per-object buckets, paths resolved via an injected resolver). Diagnostics carry a
  source `Pos` (rule/group granularity). 27 unit tests incl. both copy-down exception
  scenarios.

**Landed (M1 1c + 1d + 1e + 1f + 1h — the in-kernel enforcement path + authoring CLI,
VM-validated):** The rule-model `file_open` boundary is proven end-to-end in a
virtme-ng VM (`lsm=capability,bpf`, host kernel) — all 11 `bpf-lsm-smoke.sh` scenarios
green: allow + default-deny + learn record, self-test-negative abort, per-action (read
allowed / write default-denied), subject group, object group, deny>allow, **copy-down**
(subtree allow + a file-specific deny for one subject; the sibling stays readable),
permissive (logged, not blocked), silence (denied, not logged), **runtime `policy
apply` + `show`** (a previously-unprotected dir becomes protected without a restart), and
**coalescing** (a 41-open burst collapses to ~2 records with the folded count carried).
- **1c shared types** — `Offsets` gains `file_f_mode`/`file_f_flags` (read/write/create
  intent at open); the global `Mode` is now `enforce`/`permissive`/`off`; the ring-buffer
  record is reshaped + renamed `LearnEvent` → **`DecisionEvent`** (it records a decision
  for the journal; autolearn is a later M4 consumer) carrying `action` + matched `policy`;
  the v1 owner maps (`SUBTREES`/`OWNER_IDS`/`OwnerKey`/`OwnerId`) are removed. `FileId` and
  `Action` gained `Display` (canonical human forms — the daemon journals typed values, no
  `String` helpers).
- **1d eBPF program** (`crates/bpf`) — rewritten for the rule model: global-mode/daemon
  fast-allow, dentry walk → deepest `PROTECTED` object, action from `f_mode`/`f_flags`
  (empty ⇒ allow, e.g. `O_PATH`), **first-match** scan of the packed `RULES` bucket
  (`RULE_COUNT`-bounded), default-deny, emit on `policy.logs()`. Builds + links for
  `bpfel-unknown-none`.
- **1e daemon backend** (`backend/bpf_lsm/`) — split into `mod.rs` (lifecycle: load →
  attach → self-test → seed → drain), `seed.rs` (compile-policy → packed maps), and
  `events.rs` (ring drain → journal). Compiles the **text policy file** at startup
  (`proc::file_id` resolver) and seeds `PROTECTED`/`RULES`/`RULE_COUNT`/`SETTINGS`; refuses
  on error diagnostics; self-test adapted to a deny-all rule. `config.policy` path added.

- **1f CLI + owner-model retirement** — `cordon policy check` (local lint, daemon-free),
  `policy apply` (send text → daemon recompiles with the mount-aware resolver → re-seed →
  reply with diagnostics), `policy show` / `status` (read the effective policy via a
  `PolicyControl` shared between IPC and the backend thread). The owner model was
  **retired**: removed the `engine`, the SQLite `store` (+ `rusqlite`),
  `event`/`identity`/`decision`, the `mock` + `fanotify` backends, the owner CLI/IPC verbs
  + `Submit`, and `config.mode`/`store`. `bpf-lsm` is now the only backend (so a stock,
  no-feature build compiles but the daemon needs `--features bpf-lsm` to run).
- **1h validation** — `packaging/test/bpf-lsm-smoke.sh` rewritten for the rule model
  (policy-file driven, no runtime adopt) + `packaging/cordon.example.policy.toml` (a
  documented example, regression-tested through parse→resolve in `cargo test`). The
  smoke caught + fixed a real bug: the self-test seeded a `DENY` (logging) probe rule,
  spamming a spurious deny record on every startup → now `SILENCE` (block, no log).

**Landed (M1 1g event coalescing + atomic double-buffer swap — VM-validated, 11/11
smoke scenarios green):**
- **1g coalescing** — the audit found tools re-open one config hundreds of times per run
  (helm: 464× `~/.kube/config`). Two layers now collapse that: an **in-kernel suppressor**
  (`SUPPRESS`, a `BPF_MAP_TYPE_LRU_HASH` keyed by `(exe, ObjId, action)`) emits at most one
  `DecisionEvent` per key per 1s window and folds the rest into a `suppressed` count carried
  on the next emit (LRU so a full map evicts the coldest key, never refuses a hot one); and
  **daemon-side batch coalescing** (`events.rs::coalesce`) collapses each drain to one
  journal line per `(exe, object, action)` with the summed `count`/`suppressed`. The smoke
  proves a 41-open burst collapses to ~2 records with the count carried.
- **Atomic double-buffer swap** — the three rule maps (`PROTECTED`/`RULES`/`RULE_COUNT`) are
  **banked**: each holds two generations, keyed/indexed by a `Bank` (via `BankedFile`/
  `BankedObj`/`rule_slot`), with `Settings.active_bank` selecting the live one. `seed_policy`
  fills the inactive bank then flips `active_bank` in one `SETTINGS` write (RCU-style), so a
  `policy apply` re-seed is never half-visible — replacing the old clear-then-insert window.
  Single-writer by construction (the `&mut Ebpf` lives on one backend thread; CLI applies
  serialize through one channel).

**Next (M1 hardening — the last deferred item):** fail-safe **bpffs pinning** — pin program
+ maps + link so enforcement survives daemon death (until then it fails open on daemon exit).
**Pinning must ship with a singleton guard** (flock on the pin dir / refuse-if-pins-active):
today two daemons can't corrupt each other (each loads private maps), but two daemons sharing
*pinned* maps would reintroduce a cross-process writer race.

The Phase-3 section below is **historical** — it describes the now-retired owner model.

## Phase 3 (bpf-lsm — in progress)
The hardened Linux boundary (DESIGN §4): the verdict is returned **in-kernel** by an
eBPF program on the `file_open` LSM hook, reading policy from BPF maps the daemon
seeds from the store. Control-plane / data-plane split — the daemon is still
required (load + seed maps + re-sync on policy change + drain the learn ring
buffer), but the verdict no longer waits on it.

**Done — validated end-to-end in a virtme-ng VM (`lsm=capability,bpf`): owner
allowed, non-owner gets `EPERM`, in-kernel. Pure-Rust via aya, no clang/libbpf:**
- **`crates/bpf-common`** — `#![no_std]` POD types shared byte-for-byte by the eBPF
  program and the loader: map names, the `FileId`/`OwnerKey`/`Settings`/`LearnEvent`
  records, and the `Dev`/`Ino`/`OwnerId`/`Pid`/`Mode`/`Decision` newtypes. `user`
  feature adds the `aya::Pod` impls.
- **`crates/bpf`** — the eBPF data plane (`aya-ebpf`, standalone crate, pinned
  nightly via its own `rust-toolchain.toml` + `.cargo/config.toml`). `file_open`
  hook: fast-allow self, dentry **(dev, inode)** ancestor walk → most-specific
  protected subtree, caller exe **(dev, inode)** → owner-identity lookup,
  `-EPERM`/allow by mode, `LearnEvent` to a ring buffer. All `unsafe` (kernel reads,
  ring writes) is confined to `kernel.rs` behind safe typed handles; `main.rs` is the
  unsafe-free decision flow. **No committed `vmlinux.rs`**: rustc can't emit CO-RE
  relocations (<https://github.com/rust-lang/rust/issues/158412>), so each kernel field
  is read at a byte offset taken from an `OFFSETS` `.rodata` global the daemon fills
  from the *running* kernel's BTF and injects at load — one object enforces on any
  kernel (validated on `v6.12` with an object built against `6.18`).
- **`crates/daemon` `bpf-lsm` feature** (`backend/bpf_lsm.rs`) — the aya loader:
  resolve the running kernel's field offsets from its BTF (`btf.rs`, a minimal
  read-only BTF parser — descends anonymous unions, fails loud on a missing field)
  and inject them (`override_global("OFFSETS", …)`), `load_file` the object, attach
  `file_open`, then **self-test** (protect a probe dir under an identity-less owner
  and confirm our *own* open is denied — so a wrong-offset silent no-op aborts loudly
  rather than pretending to enforce), seed `SUBTREES`/`OWNER_IDS`/`SETTINGS` from the
  store (resolve each subtree + owner exe to a `FileId` — mount-table device + `stat`
  inode, so it matches the kernel on overlayfs/btrfs), then `poll`+drain the ring
  buffer into the journal (enforce → `info` deny, audit → `warn` would-deny, exe path
  enriched from `/proc` only when the inode still matches). **Map-sync-on-adopt**: a
  runtime `adopt`/`disown`/`claim` bumps the
  engine's `PolicyClock`; the serve loop re-seeds the maps within a poll interval —
  no restart. Off by default so the stock build stays on stable with no aya/eBPF
  deps. `BackendKind::BpfLsm` wired through config/CLI/`select`. `kernel_dev`
  glibc→kernel `dev_t` re-encoding is unit-tested.
- **`just build-ebpf`** stages the object; `bpf_object`/`bpf_pin_dir` config keys.
  `packaging/test/bpf-lsm-smoke.sh` + `run-bpf-lsm-vm.sh` are the e2e — a suite run in
  one VM boot: enforce (owner-allow + scraper-deny + learn-path report), self-test
  *negative* (poisoned offsets must abort, not silently allow), audit (would-deny
  logged), nested subtrees (deepest match wins), multiple identities, disown re-sync,
  and live-caller exe enrichment.

**Key findings from the VM (these shaped the design):**
- `bpf_d_path` is **not allowed** at the `file_open` LSM hook (`security_file_open`
  isn't in the kernel's `btf_allowlist_d_path`), so there is **no in-kernel path
  resolution**. Identity is therefore **inode (dev, inode)**, not a path hash —
  resolved from paths by the daemon at seed time (the FNV-hash approach was removed).
- `(dev, inode)` identity requires the daemon to compute the same device the
  kernel's `inode->i_sb->s_dev` holds. `stat(2)`'s `st_dev` is **not** that on
  overlayfs (containers) or btrfs (per-subvolume anon device) — so the daemon
  resolves the device from the **mount table** (`/proc/self/mountinfo` reports the
  mount's `sb->s_dev` verbatim; `proc::file_id`), which agrees with the kernel
  everywhere. The inode number from `stat` already matches `i_ino`. The e2e runs on
  the overlay `/tmp` to exercise exactly this.
- Loading an LSM program needs `CAP_BPF` **+ `CAP_MAC_ADMIN`**, and `lockdown` in a
  restrictive mode blocks `BPF_PROG_LOAD` — so the VM boots a minimal `lsm=…,bpf`.

**Next increment:**
- **Fail-safe pinning** — pin program + maps + link to bpffs so enforcement survives
  daemon death (the headline property; until then it fails open like fanotify).
- **TOFU-on-create** via the learn path (the daemon claims, then re-syncs the maps).
- **Atomic map re-sync** (double-buffer) — today's clear-then-insert has a brief
  window; and **content-digest identity** (fsverity/IMA) so identity survives an
  inode change (package upgrade) and resists path-spoofing — the `(dev, inode)`
  remaining caveat now that the overlay/btrfs device mismatch is handled.

## Phase 1 (done)
- **`fanotify` backend** (`crates/daemon/src/backend/fanotify.rs`) via the `nix`
  crate — **no hand-written `unsafe`**. Marks zone/subtree *filesystems*
  (`FAN_MARK_FILESYSTEM`), poll+drain loop, resolves caller exe + best-effort
  ancestry from `/proc`, runs the engine, answers `FAN_ALLOW`/`FAN_DENY`. Fails
  open on resolution errors; fast-allows the daemon's own pid (deadlock safety).
- **TOFU-on-create** — `proc::access_op` reads the suspended caller's open flags
  from `/proc/<pid>/syscall` (safe/race-free for open/openat/creat; openat2 warns
  + falls back). `O_CREAT` → `Op::Create` → engine auto-claims. Also yields
  write-detection. See the [why a miss is safe] reasoning in `proc.rs`.
- **Backend selection** (`backend::select`) — `mock` | `fanotify` (Linux).
- **Config file** (`core::config::Config`) — optional TOML holding the
  *operational* settings (`mode`, `backend`, `socket`/`store`, initial `zones`
  seed) with `${ENV}` interpolation; precedence CLI > file > default. Dynamic
  policy stays in the store. `packaging/cordon.example.toml`. (Replaced the old
  `CORDON_*` env overrides; tests/smoke now write a config file.)
- **Enforce / audit mode** — `mode = "audit"` (or `--mode audit`) runs the full
  decision flow but allows everything, logging would-be denials at `warn` — to
  preview an ownership decision's blast radius. Default `enforce`. Validated in
  the VM (scraper allowed + `would deny` logged).
- **Typed boundaries** (review-driven): `BackendKind`/`Mode` enums (not strings),
  a core `Pid` newtype + `nix::Pid` only at the syscall boundary, wire structs
  carry `PathBuf`/enums so serde (not `.display()`) serializes them, and
  `UnixSecs`/`Secs`/`Count`/`OwnerId`/`RuleId` aliases for the integers. `Ctx`
  holds typed fields; the IPC server is `impl Ctx` methods.
- **`tracing`** logging in the daemon (denials at `info`, allows at `trace`,
  would-deny at `warn`); the CLI keeps plain stderr (one-shot tool, not a service).
- **Caller identity** (`crates/daemon/src/proc.rs`) — `/proc/<pid>/exe` +
  ppid-chain walk; the `parse_ppid` parser is unit-tested.
- **Validated unprivileged via virtme-ng VM** — `packaging/test/run-in-vm.sh`
  boots a kernel as guest-root (host kernel locally, pinned `v6.12` Ubuntu mainline
  in CI) and runs `phase1-fanotify-smoke.sh`: owner reads its secret, scraper gets
  `EPERM`. Green on both. No host root — only `/dev/kvm`. qemu runs directly (no
  container), so it's reproducible local↔CI.
- **CI** (`.github/workflows/ci.yml`) — unprivileged `cargo test`/clippy/fmt job
  (blocking) + a **blocking** virtme-ng fanotify job on pinned `v6.12`. (libkrun/
  krunvm was dropped: nesting it in a CI container fails per-environment —
  `gid_map` locally, `memfd_create` on GitHub; see DESIGN §11.)

- **TOFU-on-create wired (decision-flow step 4).** Instead of the FID-based
  `FAN_CREATE` group (raw libc + `open_by_handle_at`, racy/`unsafe`), the backend
  reads the suspended caller's in-flight open flags from `/proc/<pid>/syscall`
  (`proc::access_op`) — **safe, register-based, race-free** for `open`/`openat`/
  `creat`. `O_CREAT` → `Op::Create` → the engine auto-claims. Validated in the
  virtme-ng VM (create → owner-read allowed without `adopt`; scraper denied).
  Known gap: `openat2` (flags behind a pointer) isn't decoded → logs a warning,
  falls back to `Read` (use `adopt`). A miss is never a security issue — the op
  only drives convenience; the boundary is op-independent.

### Phase 1 remaining
- (Optional) `seccomp-unotify` backend + `cordon run -- <tool>` — lower priority
  since virtme-ng gives unprivileged fanotify testing.

## Where we are
- Design converged + iterated. Captured in `docs/DESIGN.md`.
- Researched **Santa** (closest existing tool) → `docs/SANTA.md`. Verdict: not a
  drop-in (macOS-only; FAA static, non-TOFU, non-interactive, poll-reloaded).
- **Phase 0 implemented** — Rust workspace, three crates, 22 tests green
  (`cargo test`), clippy clean (`-D warnings`), rustfmt clean.

## Built so far (Phase 0)
- **`crates/core` (`cordon-core`)** — privilege-agnostic policy core:
  - `identity` (caller + best-effort ancestry chain), `event` (Op = read/write/
    create), `decision` (Allow/Deny + machine-readable `Reason`).
  - `paths` — lexical normalize, component-wise prefix, `claimable_subtree`.
  - `store` — SQLite via `rusqlite`, **versioned migrations** via
    `rusqlite_migration` (`sql/V1__init.sql`; append V2/V3 in later phases).
  - `engine` — the §6 decision flow incl. TOFU creator-owns.
  - `proto` — newline-delimited JSON IPC types + framing helpers.
  - `backend` — `Backend` trait + `Shutdown`; `MockBackend` (parks; events come
    via IPC `Submit`).
  - `config` — dev/prod path resolution (socket/store/zones) with env overrides.
- **`crates/daemon` (`cordond`)** — opens store, seeds zones, runs the backend on
  its own thread, serves IPC over a Unix socket (**blocking thread-per-conn**),
  engine behind a `Mutex`.
- **`crates/cli` (`cordon`)** — `status`, `owners`, `rules`, `add`, `rm`,
  `adopt`, `claim`, `disown`, `zone add`, and `submit` (drives a synthetic event;
  exits 13 on a deny). All over IPC.
- **Tests** — core unit tests (paths, store, migrations) + `decision_flow.rs`
  (TOFU, scraper-denied, cross-owner, ancestry, explicit deny/allow, TTL expiry,
  claim-on-create-never-on-read) + daemon `e2e.rs` (spawns real `cordond`, drives
  the three DESIGN §11 fixtures + adopt/disown/deny-rule over the socket).
- **`packaging/systemd/cordond.service`** — dev `--user` unit (mock; not a
  boundary).

## Decisions made this phase
- **Edition 2024 / Rust 1.95**, latest deps.
- **Store:** raw `rusqlite` + `rusqlite_migration` (NOT a full ORM — async/codegen
  weight unjustified for ~5 tiny tables; the real query logic is in Rust anyway).
- **IPC:** blocking thread-per-connection (control plane only, C10-scale, composes
  with the sync store + the Phase-1 blocking fanotify loop). Wire format + handler
  are runtime-agnostic, so swapping to async later is ~30 lines.
- **Naming:** `container` → **`zone`** everywhere in code (avoids Docker/OCI
  confusion). DESIGN/SANTA prose updated to match.

## Decisions settled
- **Project name `cordon` — final.**
- **Privileged testing → virtme-ng VM** (qemu+KVM, pinned kernel), no host root.
  (libkrun/krunvm evaluated + dropped — container-nesting too fragile; DESIGN §11.)
- **fanotify bindings → `nix`** (not hand-rolled libc); daemon logging → `tracing`.

## Next action
**Phase 1 is functionally complete** (enforcement + TOFU + CI, all validated).
Next: **Phase 2** — interactive deny-and-learn (prompt agent, step 5) + the
event-sourced lineage cache (DESIGN §8.2/§12). Nothing in `core`/`proto`/`cli`
should need to change. (Optional Phase 1 extra: `seccomp-unotify` + `cordon run`.)
