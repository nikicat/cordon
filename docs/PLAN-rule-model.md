# Implementation plan — the rule model

Concrete, reviewable plan for the architecture in [`DESIGN.md` §15](DESIGN.md). Replaces
the v1 owner model (`owners` / `owner_identities` / `subtrees` + the unenforced `rules`
table) with one flat rule model, compiled in userspace and enforced in-kernel.

Guiding constraints (from §15):
- **Compile in userspace, flat in kernel.** Groups/nesting/precedence resolve at compile
  time; the eBPF program evaluates a pre-resolved per-object rule table.
- **Explicit apply, no autoreload.** Policy takes effect only on `cordon policy apply`.
- **Identity stays inode-based** across hooks (no `bpf_d_path`); subjects gain predicates
  over time, not a new matching mechanism.

The milestones are sequenced so each is shippable and VM-validated on its own.

---

## Milestone 1 — Rule core

The big one: text policy → compiler → flat maps → in-kernel per-object evaluation, for the
open-time actions (`read`/`write`/`create`) already reachable at `file_open`. Delivers the
whole model end-to-end and closes the in-kernel-rules gap.

> **From the first real audit run** (~1031 events in 70s of normal dev work): tools re-open
> the *same* config file dozens–hundreds of times per invocation (one `helm` run = 464 opens
> of `~/.kube/config`; `gopass` 261×, `gpg` 146×). So **event coalescing is a hard M1
> requirement** (§1g), not an M4 nicety. The run also confirmed multi-reader dirs are the
> norm (`~/.kube` ← helm+kubectl+kubelogin; `~/.npmrc` ← node+deno), validating subject
> groups, and that every match landed at the subtree level (no file-vs-subtree collisions) —
> a signal for open decision #1.

### 1a. Policy file + parser — `crates/core/src/policy/`
- TOML schema (see Appendix A): `mode`, `[group.{subject,object,action}.*]`, `[[rule]]`.
- serde structs + a resolver: expand `@group` refs (all three axes), detect group cycles,
  validate action names, normalise wildcards (`*`), expand `~` against a configured home.
- Output: a **resolved policy** (groups flattened to concrete member lists), still
  path-based, not yet inode-resolved.
- Unit tests: nesting, cycle rejection, unknown-ref rejection, wildcard, multi-value
  `who/where/action`.

### 1b. Compiler: resolved policy → flat IR — `crates/core/src/policy/compile.rs`
- Cross-product `who × where × action` → concrete `(subject, object, action, policy)` rules.
- Resolve each object path → `FileId` via `proc::file_id`; collect **pending** paths
  (don't exist yet) separately (re-resolved on a later apply / `inode_create` in M3).
- Assign `ObjId`s; bucket rules per object; **sort by precedence** (§15.6: deny>allow within
  an object; object-level specificity is handled by the kernel walk, not here).
- Emit `CompiledPolicy { mode, protected: [(FileId, ObjId)], rules: [(ObjId, CompiledRule)],
  pending: [(PathBuf, …)] }` (Appendix B).
- Unit tests: expansion counts, precedence ordering, pending-path handling, dedup.

### 1c. Shared map/record types — `crates/bpf-common`
- New module `policy_maps.rs`: map-name consts `MAP_PROTECTED`, `MAP_RULES`,
  `MAP_RULE_COUNT`, reuse `MAP_SETTINGS` (carries global `mode`), `MAP_EVENTS`.
- POD types: `ObjId(u32)`, `Action(u32)` bitset (READ/WRITE/CREATE/…), `Policy(u8)`
  (ALLOW/DENY/AUDIT/SILENCE), `SubjectMatch { exe: FileId, uid: u32, cgroup: u64, flags }`
  (flags mark which predicates are wildcards), `CompiledRule { subject, action_mask, policy }`.
- Extend `Offsets` with `file_f_flags`, `file_f_mode` (read/write/create intent at open).
- Extend `LearnEvent` with `action` + matched `policy`.

### 1d. eBPF program — `crates/bpf`
- `file_open` `decide()`:
  1. Resolve **object**: dentry ancestor walk → deepest `FileId` in `MAP_PROTECTED`
     (the existing `find_subtree`, returning `ObjId`). None ⇒ unprotected ⇒ allow.
  2. Compute **caller subject**: `exe` `FileId` (existing `caller_exe`), `uid`
     (`bpf_get_current_uid_gid`), `cgroup` (`bpf_get_current_cgroup_id`).
  3. Requested **action** from `f_mode` (READ/WRITE) + `f_flags` (`O_CREAT`).
  4. Iterate the object's rules (`MAP_RULE_COUNT[obj]`, bounded `MAX_RULES_PER_OBJ`),
     match `action_mask` ∧ subject predicates; pick by precedence; apply.
  5. Apply global `mode` (permissive downgrades deny→audit); emit `LearnEvent` unless the
     resolved policy is silent.
- Keep: offset injection, fail-open on unreadable, GPL license, panic handler.
- Self-test: unchanged in spirit (protect a probe object with a deny-all rule; confirm our
  own open is denied).

### 1e. Daemon backend — `crates/daemon/src/backend/bpf_lsm.rs`
- Replace `snapshot_policy`/`seed_subtrees`/`seed_owner_ids` with `seed_compiled_policy`
  (load `PROTECTED` + `RULES` + `RULE_COUNT` from a `CompiledPolicy`).
- `policy apply` path: read text file → `core` compile → **atomic swap** (double-buffer the
  rule maps, or a generation field gating reads; §15.8) → bump `PolicyClock`.
- Drop the engine's owner/TOFU evaluate path from the bpf control plane; keep self-test,
  BTF offset injection, ring-buffer drain (now logs action+policy).
- Global mode (`enforce|permissive|off`) → `SETTINGS`.

### 1f. CLI — `crates/cli`
- `cordon policy check [FILE]` — parse + lint; print diagnostics; nonzero on error.
- `cordon policy apply [FILE]` — compile + push over IPC → atomic swap.
- `cordon policy show` — the effective compiled policy (objects, rules, mode).
- **Remove** `adopt`/`claim`/`disown`/`add`/`rm` (replaced by editing the text file +
  `apply`). `zones` config moves to autolearn scope (M4).

### 1g. Event coalescing (from audit findings)
Tools re-open the same file hundreds of times per run, so raw 1-event-per-open floods the
ring buffer (lossy under enforce) and the learn path (duplicate candidates).
- **In-kernel suppressor**: a small `HashMap<(exe FileId, ObjId, action), u64 last_ns>` (or
  an LRU) — emit a `LearnEvent` only if `now - last > window` (e.g. 1s); bump a per-key
  `suppressed` counter otherwise. Keeps the ring quiet without losing the *first* occurrence.
- **Daemon-side coalescing**: collapse drained events to one record per
  `(exe, object, action)` with a count + first/last timestamp before logging/learning.
- Carry the suppressed count into the (coalesced) record so volume is still visible.
- Decide the window + map size during impl; both are bounded, verifier-friendly.

### 1h. Validation
- Unit: 1a/1b above; daemon-side coalescing (N identical events → 1 record + count).
- VM e2e (extend `bpf-lsm-smoke.sh`): per-action (read-allow + write-deny on one object),
  subject group (two exes allowed, third denied), object group, `deny>allow` precedence,
  most-specific object, **permissive** mode (deny logged but allowed), `silence` (denied,
  not logged), and **coalescing** (a tight open-loop yields one event, not thousands). Keep
  the self-test-negative (poison offsets) scenario.

### M1 open decisions (confirm before coding)
1. **Object precedence**: *wholesale-at-deepest* (deepest protected object's rules are the
   only ones consulted) vs *layered* (per-action most-specific across all protected
   ancestors). Proposed: **wholesale** for v1 (matches today's walk; simpler kernel),
   layering deferred. Flag because a file-specific rule then *shadows* an ancestor subtree's
   rules entirely. *Audit signal:* the first real run had **zero** file-vs-subtree
   collisions (every match was at the subtree level) — so wholesale looks safe in practice.
2. **Default for a protected object with no matching rule**: global **default-deny**
   (proposed) vs per-object default. Per-object deferred.
3. **CLI surface**: remove the owner verbs (proposed) vs keep as text-file-editing sugar.
4. **Map encoding** for per-object rule lists: `HashMap<(ObjId, idx), CompiledRule>` +
   `HashMap<ObjId, count>` (proposed) vs a packed `Array`. Affects the kernel scan.
5. **Atomic swap** mechanism: double-buffered rule maps vs a generation field read-gate.

---

## Milestone 2 — Subject predicates beyond exe
- Add `uid`/`gid`, `cgroup` matching to `SubjectMatch` + kernel checks (cheap helpers).
- **IMA/fsverity** content identity: match via `bpf_ima_inode_hash`/`bpf_ima_file_hash`
  (needs `CONFIG_IMA`/policy); userspace records expected hashes. Survives upgrades, resists
  binary swap.
- `argv0` (read `mm->arg_start..arg_end`, bounded) and `ancestor-exe` (`task->real_parent`
  chain, bounded) — the interpreter fix; document forgeability (double-fork, argv rewrite).
- Compiler + TOML extended to author predicate conjunctions (Appendix A shows the object form).

> *Audit signal:* this is **targeted, not universal**. In the first run almost every opener
> was a compiled binary (helm, kubectl, gpg, gh, ssh, gopass) — fine at plain `exe`
> granularity. Only shared runtimes needed it: `node`/`deno` on `~/.npmrc` (and `python` on
> `~/.aws` once exercised). So argv0/ancestor matters per-interpreter-fronted-dir, not for
> the policy as a whole — keep `exe`-only the default and opt into argv/ancestor where a
> dir's opener is an interpreter.

## Milestone 3 — Mutation + exec hooks
- Second eBPF program attaching `inode_unlink/_rmdir/_mkdir/_rename` and
  `bprm_check_security` (execute); object resolved from the hook's dentry/inode arg.
- Extend offset injection for any new struct fields; reuse the rule maps.
- `listdir` ≈ "open dir for read" (coarse) — note the limitation; finer (`file_permission`)
  stays opt-in for cost.

## Milestone 4 — Autolearn (the zones layer)
- Separate `learned.db` (SQLite); `zones` config = where learning may propose rules.
- `cordon learn [--for ZONE] [--ttl T]` (bounded window) → ring events become candidate
  rules; **generalize** (per-file → subtree), **confidence** (seen N), **dedup**; record the
  rich subject (argv0/ancestor/hash).
- `cordon learn review` → diff of proposals → `promote` writes them into the text policy.
- Learned rules are **lower precedence** and never override a hand-written deny.

## Milestone 5 — Fail-safe pinning (orthogonal, already parked)
- Pin program + maps + link to bpffs so the compiled policy keeps enforcing across daemon
  restarts; adopt-existing-pins on startup; explicit teardown. (DESIGN §4.)

---

## Appendix A — policy TOML (proposed)
```toml
mode = "permissive"                       # enforce | permissive | off

[group.subject.ssh-tools]  members = ["/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/git"]
[group.object.cloud-creds] members = ["~/.aws", "~/.config/gcloud", "~/.config/gh"]
[group.action.ro]          members = ["read", "listdir"]

# conjunctive subject (M2): python only when launched as the aws cli
[group.subject.aws-cli]    exe = "/usr/bin/python3"   argv0 = "aws"

[[rule]]  who = "@ssh-tools"  where = "~/.ssh"        action = "@ro"             policy = "allow"
[[rule]]  who = "@aws-cli"    where = "~/.aws"        action = ["read","write"]  policy = "allow"
[[rule]]  who = "*"           where = "@cloud-creds"  action = "read"            policy = "audit"
[[rule]]  who = "/tmp/sketchy" where = "~/.aws"       action = "*"               policy = "deny"
```

## Appendix B — compiled shapes (proposed; refine during impl)
```
CompiledPolicy { mode: Mode,
                 protected: [(FileId, ObjId)],         // → MAP_PROTECTED
                 rules:     [(ObjId, CompiledRule)],   // → MAP_RULES (+ MAP_RULE_COUNT)
                 pending:   [(PathBuf, ObjId)] }        // unresolved paths, re-tried on apply

CompiledRule  { subject: SubjectMatch, action_mask: u32 /*bitset*/, policy: u8 }
SubjectMatch  { exe: FileId, uid: u32, cgroup: u64, flags: u32 /*which fields are wildcard*/ }
```
Kernel maps: `MAP_PROTECTED: HashMap<FileId, ObjId>`,
`MAP_RULE_COUNT: HashMap<ObjId, u32>`, `MAP_RULES: HashMap<(ObjId,u32), CompiledRule>`,
`MAP_SETTINGS: Array<Settings{ daemon_pid, mode }>`, `MAP_EVENTS: RingBuf`.
