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
virtme-ng VM (`lsm=capability,bpf`, host kernel) — all 11 `bpf-lsm-smoke.sh` scenarios
green: allow + default-deny + learn record, self-test-negative abort, per-action (read
allowed / write default-denied), subject group, object group, deny>allow, **copy-down**
(subtree allow + a file-specific deny for one subject; the sibling stays readable),
audit→deny (observe with a `who="*"` catch-all, then enforce by flipping that one rule —
no global mode), silence (denied, not logged), **runtime `policy
apply` + `show`** (a previously-unprotected dir becomes protected without a restart), and
**coalescing** (a 41-open burst collapses to ~2 records with the folded count carried).
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
  catch-all on the same object — the basis of the audit→bless→enforce flow A. VM-validated
  (smoke scenario 7: a concrete `allow` outranks a `who="*"` deny).
- **(3) Leaf-path reconstruction — pending.** In-kernel `d_name` walk so a discovery audit
  shows the actual file, not the protected root (enables flow B + M4 autolearn).

**Next (M1 hardening — the last deferred item):** fail-safe **bpffs pinning** — pin program
+ maps + link so enforcement survives daemon death (until then it fails open on daemon exit).
**Pinning must ship with a singleton guard** (flock on the pin dir / refuse-if-pins-active):
today two daemons can't corrupt each other (each loads private maps), but two daemons sharing
*pinned* maps would reintroduce a cross-process writer race.

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
