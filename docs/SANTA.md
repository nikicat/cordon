# Santa vs. cordon — analysis & reuse-vs-build

Research date 2026-06-23. Santa = the macOS binary/file authorization system, now
maintained by **North Pole Security (NPS)** (forked from Google 2024). Repo
`github.com/northpolesec/santa`, docs `northpole.dev`, license **Apache-2.0**,
latest **2026.5 (2026-06-08)**, monthly CalVer cadence. This is the closest
existing tool to cordon; this doc records what it does, where it overlaps, and why
we still build.

## TL;DR verdict
- **Linux:** Santa is **macOS-only with no cross-platform plans** → irrelevant;
  cordon's Linux (bpf-lsm) backend must be built regardless. This alone justifies
  the project.
- **macOS:** Santa's **File Access Authorization (FAA)** is a genuine
  object-centric, code-identity-keyed file gater on Endpoint Security — ~80% of
  cordon's macOS *gater*. **But** FAA is **static admin policy**: no interactive
  prompt, no TOFU/auto-ownership, poll-reloaded (≥15s). cordon's differentiators
  (dynamic creator-owns + interactive deny-and-learn **for files**) are precisely
  what FAA does not do, and Santa's interactive TOFU (standalone mode) is
  **execution-only**.
- **Decision:** macOS backend = **bespoke ES client**, with Santa's Apache-2.0
  source as a **reference** (and a few patterns worth lifting). Not "drive FAA."

## 1. What Santa does (functionality map)
- **Execution authorization** (the original feature): allow/block process exec by
  rule type, most-specific-wins: **CDHash → Binary(SHA-256) → SigningID
  (`TEAMID:bundle-id`) → Certificate(leaf SHA-256) → TeamID**. Modes: **Monitor**
  (default-allow + blocklist), **Lockdown** (default-deny + allowlist),
  **Standalone** (hold unknown exec → user approves via **TouchID/password** →
  auto-create local allow rule). Transitive/compiler rules auto-allow build
  outputs.
- **File Access Authorization (FAA)** — see §2. The directly-overlapping feature.
- **Device control** — block/force-remount (rdonly/noexec/…) USB mass storage via
  `ES_EVENT_TYPE_AUTH_MOUNT`/`REMOUNT`.
- **CEL rules** (2025.6+) — Common Expression Language predicates evaluated at exec
  time (signing-time windows, args, `euid`/`cwd`, **process-tree/ancestors** in
  2026.2+, `AUDIT` return in 2026.5). NPS's main programmable-policy vector. Richest
  helpers (`today()`, `ancestors`) are **Workshop-gated**.
- **Seatbelt sandboxing** (2026.5 **beta**, Workshop-gated) — attach a macOS
  Seatbelt (`sandbox-exec`) profile to a binary rule; violations kill the process.
- **Network flow** (`santanetd`, 2026.2 **beta**) — content-filter + DNS-proxy
  system extension; `network_flow_rules` machinery exists (parsed/persisted/synced)
  → egress control emerging. **Requires Workshop** to activate.
- **Telemetry** — rich ES event logging (exec/fork/exit/file-access/disk/auth/…),
  formats `filelog`/`syslog`/`protobuf`/`json`.

### Architecture (worth knowing)
Multiple ES clients in one root daemon (`santad`): Authorizer (`AUTH_EXEC`),
Recorder (NOTIFY + transitive rules), **File Access Authorizer**, Device Manager,
**Tamper Resistance**. Plus GUI agent (user), `santactl` (CLI), `santasyncservice`,
`santabundleservice`. XPC with code-signature validation between components. Rules
in **SQLite** at `/var/db/santa/rules.db` (+ `events.db`). KEXT fully removed
2022.3 — ES-only since.

## 2. FAA in detail (the overlapping feature)
- **Object-centric**: `FileAccessPolicy` plist defines `WatchItems` (named rules),
  each with `Paths` (literal / `glob(3)` single-`*` / `IsPrefix` subtree;
  **globs expanded at apply-time, not live**; longest-match wins) + `Processes` +
  `Options`.
- **Process allow-listing** (per entry, **AND within / OR across**):
  `BinaryPath` (exact, "last resort"), `SigningID`, `TeamID`, `CDHash`,
  `CertificateSha256` (leaf), `PlatformBinary`. Unsigned procs only match
  path/platform entries. — This validates cordon's identity-granularity design.
- **Polarity** via `RuleType`: `PathsWithAllowedProcesses` (default; allow-list) /
  `…DeniedProcesses` / process-centric `ProcessesWith{Allowed,Denied}Paths`
  (beta 2025.2).
- **Enforce vs audit**: `AuditOnly` (default **true** = log-only — fail-safe);
  `AllowReadAccess` (default **false** in source ⇒ rule covers reads+writes unless
  set true). Global override `OverrideFileAccessAction` (`AUDIT_ONLY`/`DISABLE`).
- **ES events** (9, AUTH): `OPEN, CLONE, COPYFILE, CREATE, EXCHANGEDATA, LINK,
  RENAME, TRUNCATE, UNLINK`. Mediates **at open()-time**; write detected via
  `FWRITE|O_APPEND|O_TRUNC`. **Cannot mediate reads on an already-open fd**
  (no ES event for `read(2)`). A per-process **reads cache** fast-allows repeat
  non-write opens.
- **Reload**: poll interval `FileAccessPolicyUpdateIntervalSec` (**default 600s,
  min 15s**) — re-reads policy + re-expands globs. **Not event-driven.**
- **Path resolution**: configured paths must be **fully resolved — symlinks not
  followed** (`/var/audit`→use `/private/var/audit`); pre-existing hardlinks can
  bypass; case-sensitive.
- **No interactivity**: violation shows an **informational** notification only —
  **no allow/deny button, no TouchID, no auto-rule**. Standalone mode does **not**
  apply to FAA. No `ASK`/`PROMPT` action exists.
- **Caveat**: ES "default mute set" — some system binaries have very low ES
  deadlines; their file accesses aren't logged/mediated.

## 3. Santa vs cordon — the gap

| Dimension | Santa FAA | cordon |
|---|---|---|
| Platforms | **macOS only** (no Linux/Windows ever) | Linux + macOS, one model |
| Policy authoring | **static**, admin/MDM (or local profile) | explicit rules **+ TOFU creator-owns** |
| Owner discovery | none — you enumerate processes | **auto-claim on create** |
| Interactive prompt (files) | **none** (informational only) | **deny-and-learn** per-session agent |
| Rule reload | **poll, ≥15s**, glob snapshot | event-driven (per-create) |
| Mediation point | open()-time, 9 AUTH_* events | same on macOS (shared ES ceiling) |
| Identity | rich (CDHash/SigningID/TeamID/cert/path/platform) | path default + chain + (sig optional) |
| Personal/local use | yes (local profile, no MDM) | yes (primary target) |
| Interactive TOFU | **execution only** (standalone) | **for files** (the whole point) |

The decisive ones: **macOS-only** (kills it for our Linux box) and **static,
non-interactive, non-TOFU for files** (kills it as a drop-in for our model). Note
the macOS *mechanism* ceiling is shared — a bespoke ES client hits the same
open()-time / no-symlink / default-mute-set limits, because it's the same ES API.
The difference is the **policy model**, not the kernel hook.

## 4. Roadmap & strategy (NPS)
- **No public forward roadmap** (empty monthly milestones); direction inferred from
  releases + blog + the open/commercial split.
- **Trajectory (confirmed):** from "can this run?" → "what can it do while
  running?" — exec control + FAA + **Seatbelt sandboxing** + **network egress
  (netd)** + **CEL** as the unifying programmable layer. Recurring stated
  motivation: **constrain AI agents / reduce blast radius of compromised tools**
  (e.g. "Blocking OpenClaw", Mar 2026) — adjacent to cordon's threat space.
- **Open-core monetization (confirmed):** Apache-2.0 agent stays open; advanced
  features (network extension, Seatbelt authoring, richest CEL, multiparty
  approval) are gated behind **Workshop** (paid control plane, launched Jul 2025;
  $4M a16z seed) + a **proprietary private sync protocol** (Oct 2025). Public sync
  protocol stays maintained.
- **Governance:** single-vendor (NPS), CLA-gated contributions, Apache-2.0.
- **Cross-platform:** none. Strongly-supported assumption: **stays macOS-only.**

## 5. What cordon should borrow (Apache-2.0 — attribute)
- **ES deadline-safety pattern**: schedule a secondary async dispatch that fires
  just before the ES deadline returning the configured default response → never
  blow the deadline. This is exactly what makes our **deny-and-learn** correct, and
  what a bespoke macOS backend needs.
- **Multi-ES-client structure** + a **tamper-resistance** client protecting our own
  daemon/store.
- **SQLite rule store** (validates our choice) and local-profile/`santactl rule`
  style on-the-fly local mutation (validates that a personal, no-MDM macOS
  deployment is viable).
- **Standalone mode UX** (TouchID approval + auto local rule) as the design
  reference for cordon's interactive approval — except we extend it to **files**.
- **Identity-match schema** (AND-within/OR-across; SigningID = `TEAMID:id`; leaf
  cert) for cordon's macOS `signature` granularity.

## 6. Strategic risk (watch)
NPS is well-funded, fast (monthly), and circling the same "constrain tools /
limit blast radius" framing. Residual risk: they add interactive + TOFU to FAA and
shrink cordon's macOS edge. Mitigants: (a) **Linux is an unchallenged moat** — they
have stated no cross-platform intent; (b) interactive per-user prompting is
**anti-fleet**, against their enterprise/Workshop business model, so unlikely to be
prioritized; (c) their advanced direction is increasingly **commercial/Workshop-
gated**, not free-and-local. cordon's niche — *personal, local, cross-platform,
zero-config TOFU + interactive file protection* — stays distinct.

## Sources
GitHub `northpolesec/santa` (source + releases), `northpole.dev` (features/faa,
binary-authorization, configuration/keys, deployment), `northpole.security/blog`
(one-year retro, private-sync-protocol, Santa 2026.2/2026.5, Workshop 2026.5,
blocking-openclaw, edr-freeze), MacAdmins Podcast Ep.389, MacDevOpsYVR 2025
("Santa in the Summer"). Verified against source at HEAD where docs were stale
(e.g. `AllowReadAccess` default, reload-interval constants).
