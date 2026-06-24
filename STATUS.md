# STATUS

**Phase: 0 built (user-mode, mock backend).** The policy core, store, daemon,
and CLI exist, build clean, and pass tests. This file is the resume point.

## Where we are
- Design converged + iterated. Captured in `docs/DESIGN.md`.
- Researched **Santa** (closest existing tool) → `docs/SANTA.md`. Verdict: not a
  drop-in (macOS-only; FAA static, non-TOFU, non-interactive, poll-reloaded).
- **Phase 0 implemented** — Rust workspace, three crates, 18 tests green
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

## Decisions still open
1. **Project name** — working name `cordon` is in use throughout code + docs
   (alts: `ward`, `obscura`, `hush`). Not yet finalized, but a rename is now a
   find-replace.

## Next action — Phase 1 (Linux fanotify backend, root)
Implement a `fanotify FAN_OPEN_PERM` + `FAN_CREATE` + `FAN_REPORT_PIDFD` backend
behind the existing `Backend` trait: read events, map to `AccessEvent`, call
`engine.evaluate`, write the verdict. Decision-flow steps 1–4 enforced
system-wide; run the hermetic fixtures as a *real* boundary (root, CI note).
Optional dev extra: `seccomp-unotify` backend + `cordon run -- <tool>`.
Nothing in `core`/`proto`/`cli` should need to change.
