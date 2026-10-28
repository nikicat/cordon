# Santa vs. cordon — analysis & reuse-vs-build

> **Historical (2026-06-23).** The cordon side of this comparison is the retired owner model,
> with TOFU creator-owns, interactive deny-and-learn, event-driven reload and a SQLite rule
> store. None of that describes cordon today: the rule model
> ([ADR 0005](adr/0005-flat-rule-model.md)) is a static root-owned text policy plus the
> runtime `cordon bless` grant ([ADR 0012](adr/0012-blessing.md)). FAA's
> static-policy model is much closer to that than the tables below suggest. The Santa findings
> stand; [prior art](prior-art.md) has the current comparison.

The research date is 2026-06-23. Santa is the macOS system for authorizing binaries and file
access. North Pole Security (NPS) now maintains it, after forking it from Google in 2024. The
repo is `github.com/northpolesec/santa`, the docs are at `northpole.dev`, and the license is
Apache-2.0. The latest release is 2026.5 (2026-06-08), on a monthly CalVer cadence. Santa is
the closest existing tool to cordon. This doc records what it does, where it overlaps with
cordon, and why we still build cordon.

## TL;DR verdict
- **Linux:** Santa is macOS-only and has no cross-platform plans, so it is irrelevant here.
  cordon's Linux (bpf-lsm) backend must be built regardless, and that alone justifies the
  project.
- **macOS:** Santa's File Access Authorization (FAA) is a genuine object-centric file gater on
  Endpoint Security, keyed by code identity. It is about 80% of cordon's macOS gater. But FAA
  is a static admin policy. It has no interactive prompt and no TOFU auto-ownership, and it
  reloads by polling, at most every 15 seconds. cordon's differentiators are dynamic
  creator-owns and interactive deny-and-learn for files, and those are precisely what FAA does
  not do. Santa's interactive TOFU (standalone mode) covers execution only.
- **Decision:** the macOS backend is a bespoke ES client. Santa's Apache-2.0 source serves as
  a reference, and a few of its patterns are worth lifting. The backend does not drive FAA.

## 1. What Santa does (functionality map)
- **Execution authorization** is the original feature. It allows or blocks a process exec by
  rule type, and the most specific rule wins. From most to least specific, the rule types are
  CDHash, Binary (SHA-256), SigningID (`TEAMID:bundle-id`), Certificate (leaf SHA-256) and
  TeamID. There are three modes. Monitor mode allows by default and has a blocklist. Lockdown
  mode denies by default and has an allowlist. Standalone mode holds an unknown exec until the
  user approves it with TouchID or a password, and then creates a local allow rule
  automatically. Transitive (compiler) rules automatically allow build outputs.
- **File Access Authorization (FAA)** is described in §2. It is the feature that overlaps
  directly with cordon.
- **Device control** blocks USB mass storage, or forces a remount with options such as rdonly
  or noexec, through `ES_EVENT_TYPE_AUTH_MOUNT` and `REMOUNT`.
- **CEL rules** (2025.6 and later) are Common Expression Language predicates evaluated at exec
  time. They can test signing-time windows, args, `euid` and `cwd`. The process tree and
  ancestors arrived in 2026.2, and an `AUDIT` return value in 2026.5. CEL is NPS's main vector
  for programmable policy. The richest helpers (`today()`, `ancestors`) are gated behind
  Workshop.
- **Seatbelt sandboxing** (a 2026.5 beta, gated behind Workshop) attaches a macOS Seatbelt
  (`sandbox-exec`) profile to a binary rule. A violation kills the process.
- **Network flow** (`santanetd`, a 2026.2 beta) is a system extension with a content filter
  and a DNS proxy. The `network_flow_rules` machinery exists, and the rules are parsed,
  persisted and synced, so egress control is emerging. Activating it requires Workshop.
- **Telemetry** is rich ES event logging, covering exec, fork, exit, file access, disk, auth
  and more. The formats are `filelog`, `syslog`, `protobuf` and `json`.

### Architecture (worth knowing)
One root daemon (`santad`) runs several ES clients. They are the Authorizer (`AUTH_EXEC`),
the Recorder (NOTIFY events and transitive rules), the File Access Authorizer, the Device
Manager, and Tamper Resistance. Alongside the daemon there are a GUI agent that runs as the
user, `santactl` (the CLI), `santasyncservice` and `santabundleservice`. The components talk
over XPC and validate each other's code signatures. Rules live in SQLite at
`/var/db/santa/rules.db`, with events in `events.db`. The KEXT was fully removed in 2022.3,
and Santa has used only ES since.

## 2. FAA in detail (the overlapping feature)
- **Object-centric.** A `FileAccessPolicy` plist defines `WatchItems`, which are named rules.
  Each one has `Paths`, `Processes` and `Options`. A path is a literal, a `glob(3)` pattern
  with a single `*`, or an `IsPrefix` subtree. Globs are expanded when the policy is applied,
  not live, and the longest match wins.
- **Process allow-listing.** Within one entry the conditions are ANDed, and across entries
  they are ORed. The keys are `BinaryPath` (an exact path, documented as a "last resort"),
  `SigningID`, `TeamID`, `CDHash`, `CertificateSha256` (the leaf) and `PlatformBinary`.
  Unsigned processes only match path and platform entries. This validates cordon's design for
  identity granularity.
- **Polarity** is set by `RuleType`. `PathsWithAllowedProcesses` is the default and is an
  allow-list. There is also `…DeniedProcesses`, and the process-centric
  `ProcessesWith{Allowed,Denied}Paths` (a 2025.2 beta).
- **Enforce versus audit.** `AuditOnly` defaults to true, which means log-only and is
  fail-safe. `AllowReadAccess` defaults to false in the source, so a rule covers both reads
  and writes unless it is set to true. The global override `OverrideFileAccessAction` takes
  `AUDIT_ONLY` or `DISABLE`.
-  **ES events.** FAA uses nine AUTH events:
  `OPEN, CLONE, COPYFILE, CREATE, EXCHANGEDATA, LINK, RENAME, TRUNCATE, UNLINK`. It mediates at
  open() time and detects a write from `FWRITE|O_APPEND|O_TRUNC`. It cannot mediate reads on an
  fd that is already open, because ES has no event for `read(2)`. A reads cache kept for each
  process fast-allows repeated opens that do not write.
- **Reload.** FAA polls at the interval `FileAccessPolicyUpdateIntervalSec`, which defaults to
  600 seconds and has a minimum of 15. Each poll re-reads the policy and re-expands the globs.
  Reload is not event-driven.
- **Path resolution.** Configured paths must be fully resolved, because symlinks are not
  followed. For example, `/var/audit` must be written as `/private/var/audit`. Hardlinks that
  already exist can bypass a rule, and matching is case-sensitive.
- **No interactivity.** A violation shows only an informational notification. There is no
  allow or deny button, no TouchID, and no automatic rule. Standalone mode does not apply to
  FAA, and there is no `ASK` or `PROMPT` action.
- **Caveat.** ES has a "default mute set". Some system binaries have very short ES deadlines,
  and their file accesses are neither logged nor mediated.

## 3. Santa vs cordon — the gap

| Dimension | Santa FAA | cordon |
|---|---|---|
| Platforms | macOS only (never Linux or Windows) | Linux and macOS, with one model |
| Policy authoring | static, by an admin or MDM (or a local profile) | explicit rules plus TOFU creator-owns |
| Owner discovery | none, because you enumerate the processes | automatic claim on create |
| Interactive prompt (files) | none (informational only) | deny-and-learn through a per-session agent |
| Rule reload | polling, at most every 15 s, over a glob snapshot | event-driven (on each create) |
| Mediation point | open() time, through 9 AUTH_* events | the same on macOS (a shared ES ceiling) |
| Identity | rich (CDHash, SigningID, TeamID, cert, path, platform) | path by default, plus the chain, plus an optional signature |
| Personal/local use | yes (a local profile, with no MDM) | yes (the primary target) |
| Interactive TOFU | execution only (standalone mode) | for files (the whole point) |

Two rows decide it. Santa is macOS-only, which rules it out for our Linux box. And for files it
is static, non-interactive and has no TOFU, which rules it out as a drop-in for our model. Note
that the macOS mechanism has a shared ceiling. A bespoke ES client hits the same limits (open()
time only, no symlinks, the default mute set), because it uses the same ES API. The difference
is the policy model, not the kernel hook.

## 4. Roadmap & strategy (NPS)
- **No public forward roadmap.** The monthly milestones are empty. The direction is inferred
  from the releases, the blog and the split between the open and the commercial parts.
- **Trajectory (confirmed).** Santa is moving from "can this run?" to "what can it do while
  running?". It combines exec control, FAA, Seatbelt sandboxing and network egress (netd), with
  CEL as the layer that unifies them. The recurring stated motivation is to constrain AI agents
  and reduce the blast radius of compromised tools (for example "Blocking OpenClaw", March
  2026). That is adjacent to cordon's threat space.
- **Open-core monetization (confirmed).** The Apache-2.0 agent stays open. Advanced features
  are gated behind Workshop and a proprietary private sync protocol (October 2025). Those
  features are the network extension, Seatbelt authoring, the richest CEL helpers and
  multiparty approval. Workshop is the paid control plane, launched in July 2025 on a $4M a16z
  seed round. The public sync protocol stays maintained.
- **Governance.** Santa has a single vendor (NPS), contributions go through a CLA, and the
  license is Apache-2.0.
- **Cross-platform.** There is none. The well-supported assumption is that Santa stays
  macOS-only.

## 5. What cordon should borrow (Apache-2.0 — attribute)
- **The ES deadline-safety pattern.** It schedules a second async dispatch that fires just
  before the ES deadline and returns the configured default response, so the deadline is never
  missed. This is exactly what makes our deny-and-learn correct, and a bespoke macOS backend
  needs it.
- **The structure of several ES clients**, plus a tamper-resistance client that protects our
  own daemon and store.
- **The SQLite rule store**, which validates our choice. And the local profile, with
  `santactl rule`-style local changes on the fly. That validates that a personal macOS
  deployment with no MDM is viable.
- **The standalone mode UX** (TouchID approval plus an automatic local rule), as the design
  reference for cordon's interactive approval. The difference is that we extend it to files.
- **The identity-match schema** (AND within an entry, OR across entries, SigningID as
  `TEAMID:id`, and the leaf cert) for cordon's macOS `signature` granularity.

## 6. Strategic risk (watch)
NPS is well funded and fast (monthly releases), and it is circling the same framing of
constraining tools and limiting blast radius. The residual risk is that NPS adds an
interactive prompt and TOFU to FAA, and so shrinks cordon's edge on macOS. Three things
mitigate it. First, Linux is an unchallenged moat, because NPS has stated no cross-platform
intent. Second, interactive per-user prompting works against fleets, and so against NPS's
enterprise and Workshop business model, so it is unlikely to be prioritized. Third, NPS's
advanced direction is increasingly commercial and gated behind Workshop, rather than free and
local. cordon's niche stays distinct. That niche is *personal, local, cross-platform,
zero-config TOFU plus interactive file protection*.

## Sources
GitHub `northpolesec/santa` (the source and the releases), `northpole.dev` (features/faa,
binary-authorization, configuration/keys, deployment), `northpole.security/blog` (the
one-year retro, private-sync-protocol, Santa 2026.2 and 2026.5, Workshop 2026.5,
blocking-openclaw, edr-freeze), MacAdmins Podcast Ep.389, and MacDevOpsYVR 2025 ("Santa in
the Summer"). Where the docs were stale, the findings were verified against the source at
HEAD (for example the `AllowReadAccess` default and the reload-interval constants).
