# STATUS

**Current architecture: the flat rule model (DESIGN §15), enforced in-kernel by the
`bpf-lsm` backend.** M1 is implemented and VM-validated; only fail-safe bpffs pinning
(M5) remains. The earlier **owner model** (owners / TOFU / a SQLite store, on `mock` +
`fanotify` backends) was retired in the migration — see *Pre-rule-model history* at the
bottom. This file is the resume point.

## Rule model (DESIGN §15) — M1 core complete
The owner model has been replaced by the flat **rule model**
(`(who, where, action, policy)`), per [docs/PLAN-rule-model.md](docs/PLAN-rule-model.md). M1
decisions are locked there (copy-down object precedence, `MAX_RULES_PER_OBJ = 32`,
packed-array rule encoding, recompile + double-buffer swap, default-deny, owner CLI verbs
removed). All of M1 1a–1h plus 1g coalescing and the atomic double-buffer swap are
implemented and VM-validated; only fail-safe bpffs pinning (M5) remains as deferred
hardening.

**Landed (M1 1a + 1b — userspace core, pure + unit-tested, no kernel changes yet):**
- **`crates/bpf-common/src/policy_maps.rs`** — the compiled-form contract shared with
  the eBPF program: `ObjId`, `Action` (a `bitflags` bitset, `#[repr(transparent)]` for
  POD/map-layout soundness — validated compiling for `bpfel-unknown-none`), `Policy`,
  `SubjectMatch`, `CompiledRule`, and the `PROTECTED`/`RULES`/`RULE_COUNT` map names.
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
virtme-ng VM (`lsm=capability,bpf`) on both the host kernel and the CI-pinned **v6.12** —
all 13 M1 `bpf-lsm-smoke.sh` scenarios
green: allow + default-deny + learn record, self-test-negative abort, per-action (read
allowed / write default-denied), subject group, object group, deny>allow,
**subject-specificity** (a concrete allow outranks a `who="*"` deny), **copy-down**
(subtree allow + a file-specific deny for one subject; the sibling stays readable),
audit→deny (observe with a `who="*"` catch-all, then enforce by flipping that one rule —
no global mode), silence (denied, not logged), **runtime `policy
apply` + `show`** (a previously-unprotected dir becomes protected without a restart),
**coalescing** (a 41-open burst collapses to ~2 records with the folded count carried),
and **leaf-path reconstruction** (distinct files under one audited root surface with
their real paths).
- **1c shared types** — `Offsets` gains `file_f_mode`/`file_f_flags` (read/write/create
  intent at open); the ring-buffer record is reshaped + renamed `LearnEvent` →
  **`DecisionEvent`** (it records a decision for the journal; autolearn is a later M4
  consumer) carrying `action` + matched `policy`. *(1c originally shipped a global
  `enforce`/`permissive`/`off` `Mode`; refinement (1) below has since removed it.)*
  `FileId` and `Action` gained `Display` (canonical human forms — the daemon journals typed
  values, no `String` helpers).
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

**Landed (M1 1g event coalescing + atomic double-buffer swap — VM-validated, 13/13
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

**Decided refinements (see PLAN "Decided refinements" + DESIGN §15.6/§15.10):**
- **(1) Drop the global mode — ✅ done.** The `enforce/permissive/off` mode is gone
  (`ids::Mode`, `Settings.mode`, the `mode=` policy key, and `Decision::WOULD_DENY` all
  removed; the kernel blocks iff `policy.denies()`). The per-rule `policy` is the only
  enforcement level — `audit` observes an object, `deny` enforces it, per object; "off" is
  an empty policy or a stopped daemon. The smoke's permissive scenario became an
  **audit→deny** one; `parse` now rejects a leftover top-level `mode =` key.
- **(2) Subject-specificity in precedence — ✅ done.** `sort_bucket` now ranks by object
  depth → **subject specificity** (count of non-wildcard predicates, via the `Specificity`
  newtype) → deny>allow (`Polarity`), so `allow exe=X` beats an `audit`/`deny` `who="*"`
  catch-all on the same object — the basis of the audit→admit→enforce flow A. VM-validated
  (smoke scenario 7: a concrete `allow` outranks a `who="*"` deny).
- **(3) Leaf-path reconstruction — ✅ done.** On an emitted record the kernel walks
  `d_name` from the opened file up to the matched protected object (`bpf_d_path` is
  unavailable at `file_open`), filling a fixed leaf-first component array (`PathComp`,
  `[[u8;32];8]`) assembled in a **per-CPU scratch** map (the record is too big for the BPF
  stack) and mem-copied into the ring. The suppressor + daemon coalescing now key on the
  **opened file's inode** (`leaf`), so distinct files under one audited root surface
  separately; the daemon joins the reversed components onto the object's path → `path=…`.
  Enables flow B (discovery) + M4 autolearn's per-file→subtree generalization. VM-validated
  (smoke scenario 13: siblings + a depth-2 nested file each surface with their real path).

**Authoring ergonomics (2026-06-28) — from rewriting the real-system audit policy by hand:**
- **(4) Compact rule DSL — ✅ done.** A `rules = '''…'''` literal block, one rule per line
  (`POLICY SUBJECT ACTION OBJECT`), accepted *alongside* `[[rule]]` tables and normalized to
  the same `ParsedRule` — only surface syntax, so resolve/compile/kernel are untouched. New
  `crates/core/src/policy/ruleline.rs` (a quote-aware lexer with `Item`/`Sep` types); `parse`
  normalizes both surfaces; `PolicyName::parse` added; literal-string content is a verbatim
  source slice so diagnostics give exact `line:col`. 11 unit tests + a regression-tested
  `packaging/cordon.example.dsl.policy.toml`. The hand audit policy went 129→76 lines, proven
  to compile to the identical table.
- **(5) Per-user `~` via `user =` header — ✅ done.** A `user = "name"` header expands `~`
  against that account's `/etc/passwd` home, so a root-owned per-user file uses `~/.ssh`
  (the root daemon's `$HOME` is `/root`). New `UserName` newtype + `policy::home_for`, wired
  into the resolve choke point (`compile_sources` for startup + apply; CLI `check`).
- **(6) conf.d split — ✅ done.** A policy path may be a single file or a directory of
  `*.toml` fragments (name-sorted), each parsed/resolved independently (file-local groups,
  own `user =` home) then **merged** before compile via `policy::compile_fragments`; a bad
  fragment fails the apply, named. `apply` now ships the read fragments to the daemon
  (`Request::PolicyApply { sources: Vec<PolicySource> }` replaced the single `text`), which
  resolves homes + merges; `read_sources` does the file-or-dir read for both daemon startup
  and CLI `check`/`apply`. *Known gap:* compile-stage diagnostics (e.g. pending-path
  warnings) carry `line:col` but not yet the fragment name (parse/resolve errors do).
- **(7) `cordon policy edit` — ✅ done (2026-06-29).** The sudoedit analog for the
  root-owned policy: `sudo cordon policy edit [FILE]` copies the file to a private temp,
  runs `$EDITOR` (`$CORDON_EDITOR`→`$VISUAL`→`$EDITOR`→`vi`) **as the invoking user** —
  closing the `sudo $EDITOR` same-uid escalation (DESIGN §2: the scraper can write your
  `.vimrc`) — then validates and, on success, applies *and* saves in one step. visudo-style:
  a broken policy is rejected with diagnostics and re-prompts `[e]dit again / [Q]uit`. No new
  IPC — the read is direct, validation is the in-process compiler (the `check` path), the
  commit reuses `PolicyApply`; the file is written **only after** the daemon accepts it, so
  on-disk == live with no rollback (daemon down ⇒ saved + warned "not applied"). New
  `crates/cli/src/edit.rs` (privilege model **A**, self-privileged) + `crates/cli/src/sys.rs`
  (the privileged ops as safe `nix` wrappers over typed `Uid`/`Gid` — `chown` the temp to the
  invoker, passwd lookup for their `$HOME`/`$USER`, `setgroups`+`setgid`+`setuid` drop in the
  editor child; the crate's `unsafe` is the two `pre_exec` registrations — the editor drop and
  the bless carrier join). The editor runs with the **invoking user's** own `$HOME`/`$USER`
  (not root's, which `sudo` leaves as `/root` — else e.g. nvim can't write its state).
  *Authorization is partly open:* the socket now gates **bless mint/revoke** on `SO_PEERCRED`
  uid 0 (the first real socket authorization here), but `apply`/`show`/`status` remain
  ungated — whoever can reach the socket can `apply`. `edit` inherits root via `sudo` for now,
  with the rest deferred to a later CLI-authorization pass.

- **(8) System / user policy tiers — ✅ done (2026-06-29).** The effective policy is now
  **system ⊕ user tier** (DESIGN §15.8). A system fragment pulls in a user-tier file via an
  `[[include]] user = "…" path = "…"` directive; the included file is loaded
  `SourceOrigin::User` and **home-scoped** — every object path must resolve under that user's
  `~` (compile error otherwise, so a user can't write rules about `/etc` or another home),
  and it may not itself `[[include]]`. New `policy::{load_policy, user_include_path}` (include
  expansion at read time; CLI on `apply`/`check`, daemon at startup), `PolicySource.origin`
  (over IPC), tier-aware `compile_fragments`, and `cordon policy edit --user NAME` (edits the
  bound file; `UserName` parsed straight from the flag via `FromStr`). `--user` is
  **self-bootstrapping**: with no include yet it opens `…/users/NAME.toml` and registers the
  `[[include]]` in `…/conf.d/00-users.toml` *only after* the edit validates + saves — a
  cancelled/rejected edit writes neither the file nor the include (no stale binding). VM
  coverage: a 14th `bpf-lsm-smoke.sh` scenario (`user_tier`) proves a system-tier rule and an
  `[[include]]`d user-tier rule both enforce in-kernel (the tier assembly reaches the maps).
  **Precedence is flat
  for now** — the *system-is-a-floor* semantics (user tightens, never loosens) isn't
  expressible in the single first-match bucket and only matters once user files are
  user-owned, so it's sequenced with the home-migration (below). Files are root-owned under
  `/etc` for now; **roadmap:** move them to `~user/.config/cordon/` and have cordon *cordon*
  its own user-policy file (a protected object only an authorized editor may write) — that
  self-protection is the future "edit without sudo".

**Next (M1 hardening — the last deferred item):** fail-safe **bpffs pinning** — pin program
+ maps + link so enforcement survives daemon death (until then it fails open on daemon exit).
**Pinning must ship with a singleton guard** (flock on the pin dir / refuse-if-pins-active):
today two daemons can't corrupt each other (each loads private maps), but two daemons sharing
*pinned* maps would reintroduce a cross-process writer race.

## Blessing (`cordon bless`) — ✅ B1 done (2026-07-26), sudo-gated
The runtime, human-authenticated access grant ships: [`DESIGN.md` §16](docs/DESIGN.md)
(design) + [`docs/PLAN-bless.md`](docs/PLAN-bless.md) (B1 done; B2 ergonomics, B3 the PAM
upgrade). It's additive to the rule model: **a blessing is one more `SubjectMatch` predicate**
(`blessing = "<class>"`), so a blessing rule is an ordinary rule — its action, **object
scope**, and precedence all reuse the §15 model (scope = the rule's object column; **fully
customizable in policy**, not blanket).

`sudo cordon bless [--class NAME] [-- <cmd>]` mints a per-invocation **root-owned cgroup**
carrier (`cordon-bless-<id>.<class>`, under the daemon's own cgroup via `Delegate=yes`),
registers it in the tiny unbanked `BLESSED: cgroup_id → ClassId` map, and the CLI forks the
target into it: `pre_exec` joins the carrier **while still root**, then drops to `SUDO_UID`
(full supplementary groups, passwd `HOME`/`USER`), then execs — the target never runs
unblessed, and keeps a natural tty, job control, and exit code. Descendants inherit. The
daemon GCs the carrier when the tree drains (`cgroup.events populated 0`, with a 30s mint
grace), `bless revoke <id>` kills it via `cgroup.kill`, and startup reconciles leftovers.
Every apply **remaps live entries by class name** (`ClassId`s renumber on recompile — without
this a live blessing would silently change meaning). Blessed decisions journal
`blessing=<name>`. Validated by 5 VM smoke scenarios (18–22 of 22): scope, membership
boundary, inheritance + full GC, revoke, journal.

**Design change from the original spec** (DESIGN §16.5): the authenticator is **sudo**, not
PAM-in-the-daemon — PAM proved far heavier than specced (conversation proxying as multi-frame
IPC, stdio fd passing, degraded job control) and the systemd-less smoke VM can't test
transient scopes. Two accepted deltas, both documented: sudo's **timestamp cache is a grace
window** (deployment note: `Defaults!/usr/bin/cordon timestamp_timeout=0`), and blessing is
**sudoer-only** until the B3 PAM upgrade, which the authenticator-agnostic mint verb is shaped
to accept.

(Authoring flow A was renamed observe → **admit** → enforce to reserve "bless" for this; the
§8.1 threat-model "blessed binary" is unrelated generic usage.)

## Pre-rule-model history (retired)
Phases 0–3 built an **owner model** — explicit rules + TOFU creator-owns, a root-owned
SQLite store, and a privilege-agnostic core — on two enforcement backends: a root
**`fanotify`** `FAN_OPEN_PERM` backend (Phase 1) and an in-kernel `bpf-lsm` backend
enforcing `subtrees` + `owner_identities` (Phase 3), both VM-validated. The rule-model
migration (above) replaced all of it: owners / TOFU / rules collapsed into one
`(who, where, action, policy)` model; the SQLite store and the `mock` + `fanotify` backends
were removed; `bpf-lsm` now enforces the flat rule table. The full detail lives in git
history and `DESIGN.md` §1–§14 (marked superseded there).

**Durable kernel facts from that work** (still true for the current backend):
- `bpf_d_path` is **not allowed** at `file_open`, so identity is inode `(dev,inode)`, never
  a path — resolved by the daemon at seed time.
- The daemon takes the device from the **mount table** (`/proc/self/mountinfo`), which
  matches the kernel's `sb->s_dev` on overlayfs/btrfs where `stat`'s `st_dev` does not.
- Loading an LSM program needs `CAP_BPF` + `CAP_MAC_ADMIN` and `lockdown` off — the VM boots
  a minimal `lsm=…,bpf`; an object built against one kernel runs on another via BTF-resolved
  field offsets injected at load (rustc can't emit CO-RE relocations).
