# STATUS

**Phase: 1 functionally complete.** Phase 0 (core/store/daemon/CLI/mock) is done;
the real Linux `fanotify` backend now enforces all of decision-flow steps 1–5
(incl. TOFU-on-create) system-wide, with a fully-green CI that validates it in a
virtme-ng VM on a pinned kernel. This file is the resume point.

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
- **`tracing`** logging in the daemon (denials at `info`, allows at `trace`);
  the CLI keeps plain stderr (one-shot tool, not a service).
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
