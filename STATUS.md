# STATUS

**Phase: 1 in progress — fanotify enforcement done + validated.** Phase 0
(core/store/daemon/CLI/mock) is complete; the real Linux `fanotify` backend now
enforces non-owner read denial and is proven end-to-end in a libkrun microVM.
This file is the resume point.

## Phase 1 (this phase)
- **`fanotify` backend** (`crates/daemon/src/backend/fanotify.rs`) via the `nix`
  crate — **no hand-written `unsafe`**. Marks zone/subtree *filesystems*
  (`FAN_MARK_FILESYSTEM`), poll+drain loop, resolves caller exe + best-effort
  ancestry from `/proc`, runs the engine, answers `FAN_ALLOW`/`FAN_DENY`. Fails
  open on resolution errors; fast-allows the daemon's own pid (deadlock safety).
- **Backend selection** (`backend::select`) — `mock` | `fanotify` (Linux).
- **`tracing`** logging in the daemon (denials at `info`, allows at `trace`);
  the CLI keeps plain stderr (one-shot tool, not a service).
- **Caller identity** (`crates/daemon/src/proc.rs`) — `/proc/<pid>/exe` +
  ppid-chain walk; the `parse_ppid` parser is unit-tested.
- **Validated unprivileged via libkrun microVM** — `packaging/test/run-in-vm.sh`
  boots a fixed-kernel (libkrunfw 6.12.91) microVM via `krunvm`, runs
  `phase1-fanotify-smoke.sh`: owner reads its secret, scraper gets `EPERM`. Green.
  No host root — only `/dev/kvm`. (Verified libkrunfw enables
  `FANOTIFY_ACCESS_PERMISSIONS` + `FAN_MARK_FILESYSTEM`.)
- **CI** (`.github/workflows/ci.yml`) — unprivileged `cargo test`/clippy/fmt job
  + a libkrun fanotify job (the GHA libkrun-install line is the one piece not yet
  validated on a real runner).

### Phase 1 remaining
- **TOFU-on-create (decision-flow step 4)** under fanotify needs the `FAN_CREATE`
  notify group (FID-based, second group). Until then, ownership for the fanotify
  backend comes from `cordon adopt`. The engine already implements TOFU; only the
  backend create-signal is missing.
- (Optional) `seccomp-unotify` backend + `cordon run -- <tool>` — now lower
  priority since libkrun gives unprivileged fanotify testing.

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
- **Privileged testing → libkrun microVM** (`krunvm`), fixed kernel, no host root.
- **fanotify bindings → `nix`** (not hand-rolled libc); daemon logging → `tracing`.

## Next action
1. **Finish Phase 1: TOFU-on-create under fanotify** — add the `FAN_CREATE`
   notify group (FID/DFID, second fanotify group) so a tool that *creates* its
   config auto-claims ownership, matching the engine's existing step-4. Validate
   in the libkrun harness.
2. Then **Phase 2** — interactive deny-and-learn + the event-sourced lineage cache
   (DESIGN §8.2/§12). Nothing in `core`/`proto`/`cli` should need to change.
