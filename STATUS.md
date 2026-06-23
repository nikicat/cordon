# STATUS

**Phase: planning sketch.** No code yet. This file is the resume point.

## Where we are
- Design converged + iterated several times. Captured in `docs/DESIGN.md`.
- Researched **Santa** (closest existing tool) thoroughly → `docs/SANTA.md`.
  Verdict: not a drop-in (macOS-only; FAA is static, non-TOFU, non-interactive,
  poll-reloaded). macOS backend = **bespoke ES client**, Santa as reference.
- Directory + git initialised. Nothing committed yet.

## Locked
- **Language:** Rust. **Store:** SQLite (root-owned in prod, user-owned in dev).
- **Core scope:** gater + ownership model only. No crypto/keys/broker/shim in v1
  — files stay plaintext in place; transparency is automatic.
- **Coverage:** explicit rules + **TOFU auto-ownership** (creator-owns). Safety
  rules: claim-on-create-never-on-read, container-vs-owned-subtree, pre-existing
  needs `adopt`/prompt, owner = tool-group.
- **Identity:** `path` default (per-rule override to `path+inode`/`signature`) +
  **best-effort parent-chain** ancestry in owner-match (interpreter & helper case).
- **Interactive mode:** deny-and-learn (deadline-safe) via an unprivileged
  per-session prompt agent; "approve permanently" subsumes `adopt`.
- **Privilege:** privilege-agnostic core + pluggable backends.
  - dev: `mock` (logic/CI) and `seccomp-unotify` (`cordon run`, real but
    launch-scoped) via `systemctl --user` — **not a boundary**.
  - prod: root `fanotify` (Linux) / Endpoint Security (macOS).
  - **`preload` backend dropped.**
- **macOS backend:** bespoke ES `AUTH_OPEN` client (not driving Santa FAA);
  borrow Santa's Apache-2.0 deadline-safety pattern + identity-match schema.
- **Tests:** internal fixtures (`testtool-oldstyle`, `testtool-xdg`,
  `testscraper`) + throwaway `$HOME`.
- **Encryption/broker:** deferred (optional Phase 5) — adds ~nothing in scope.

## Decisions still open
1. **Name** — working name `cordon` (alts: `ward`, `obscura`, `hush`).

## Next action
Confirm name, then build **Phase 0** (Rust workspace, SQLite store, `cordon` CLI,
`mock` backend, fixtures — all unprivileged) → **Phase 1** (Linux `fanotify`
backend, root; hermetic harness green). See phased plan in `docs/DESIGN.md`.
