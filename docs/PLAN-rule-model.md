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
- Assign `ObjId`s; build the protected-object **prefix forest**; **copy-down** — fold each
  ancestor object's rules into every protected descendant's bucket (decision #1), so the
  kernel consults only the deepest object's (pre-merged) bucket. **Sort each bucket**
  most-specific-object-first, then **deny>allow** within a specificity level (§15.6); dedup;
  enforce `MAX_RULES_PER_OBJ` (32 to start). The kernel does a dumb **first-match** scan of
  one bucket — all precedence/inheritance resolved here (§15.3).
- Emit `CompiledPolicy { mode, protected: [(FileId, ObjId)], rules: [(ObjId, CompiledRule)]
  (packed per-object array), pending: [(PathBuf, …)] }` (Appendix B).
- Unit tests: expansion counts, copy-down inheritance (both exception scenarios below),
  precedence ordering, pending-path handling, dedup, per-object cap.

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

### 1g. Event coalescing (from audit findings) — ✅ done (VM-validated)
Tools re-open the same file hundreds of times per run, so raw 1-event-per-open floods the
ring buffer (lossy under enforce) and the learn path (duplicate candidates).

> **Implemented:** in-kernel suppressor as a `BPF_MAP_TYPE_LRU_HASH` keyed by `(exe,
> ObjId, action)` (1s window; LRU so a full map evicts the coldest key rather than refusing
> a new hot one), folding suppressed repeats into a `suppressed` count carried on the next
> `DecisionEvent`; daemon-side `coalesce()` collapses each drain batch to one journal line
> per `(exe, object, action)` summing `count`/`suppressed`. Smoke scenario 11 proves a
> 41-open burst → ~2 records with the count carried.
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

### M1 decisions (locked 2026-06-26)
1. **Object precedence → copy-down (compile-time layering).** Neither literal-wholesale nor a
   runtime layered walk: the compiler folds each ancestor object's rules **down** into every
   protected descendant's bucket, sorted most-specific-first then deny>allow; the kernel stays
   dumb (deepest protected object → **first-match** scan of its one pre-merged bucket).
   Satisfies §15.3 (*precedence resolved in userspace, flat in kernel*) **and** supports
   per-subject sub-object exceptions, which literal-wholesale breaks. The two motivating cases:
   - *broad-allow + narrow-deny* — `allow {A,B,S} read ./d` + `deny S read ./d/f`: A/B keep
     reading `f`, only S denied. (Literal-wholesale would default-deny A/B on `f`.)
   - *broad-deny + narrow-allow* — `deny {A,B,S} read ./d` + `allow S read ./d/f`: only S
     reads `f`. (Both work under copy-down via the sorted first-match.)
   - **Cost** (evaluated): total entries `= Σ_rule subtree_size(target)` — quadratic only in
     *object-nesting depth* (≈1–2 here; the first real audit had **zero** file-vs-subtree
     nesting ⇒ zero duplication). Binding constraint is the per-bucket cap, not memory; the
     scan is paid only on protected-object opens (the unprotected majority short-circuits in
     the dentry walk). Watch subject-group expansion × deep nesting; lever = keep groups as a
     `(GroupId, exe)` membership map instead of expanding (deferred).
2. **Default for a protected object with no matching rule → global default-deny** (§15.6.3).
   Per-object default deferred.
3. **CLI surface → remove the owner verbs** (`adopt`/`claim`/`disown`/`add`/`rm`) and their IPC
   requests. Authoring is solely: edit the root-owned text policy + `cordon policy
   check`/`apply`/`show`. One model (§15.8).
4. **Map encoding → packed per-object array** (not `HashMap<(ObjId, idx)>`): one base + index
   scan, cache-friendly, cheaper per-iteration now that copy-down can lengthen buckets.
5. **Atomic swap → recompile whole table + double-buffer swap** on apply (copy-down makes a
   single edit touch many buckets, so incremental in-place patching is out). **✅ done:** the
   three rule maps are banked (`BankedFile`/`BankedObj`/`rule_slot`, `NUM_BANKS = 2`);
   `seed_policy` fills the inactive bank and flips `Settings.active_bank` in one write.

`MAX_RULES_PER_OBJ = 32` to start (raise toward 64 if the verifier log demands; `cordon policy
check` errors if a compiled bucket exceeds it).

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
- **Singleton guard (required with pinning).** Today two daemons can't corrupt the rule
  table — each `EbpfLoader::load_file` creates *private* maps, and the single backend
  thread owns the only `&mut Ebpf`, so there is exactly one writer. Pinning shares maps
  across processes, which reintroduces a cross-process write/write race (one daemon's bank
  fill interleaving another's flip → a torn table). So adopting shared pins must take a
  singleton lock first (flock on the pin dir, or refuse-to-start when live pins exist).

---

## Decided refinements (2026-06-27)
From working the real-system audit UX (DESIGN §15.6, §15.10). M1 shipped without these;
DESIGN documents them as the target. **All three (1)–(3) are now done.**

1. **Drop the global mode — ✅ done.** Removed `enforce|permissive|off` entirely — the
   `mode=` policy key, `ids::Mode`, `Settings.mode`, and `Decision::WOULD_DENY` are gone.
   The per-rule `policy` is the *only* enforcement control: the kernel blocks iff
   `policy.denies()`; `audit` observes an object, `deny` enforces it, per object. "Off" =
   an empty policy or a stopped daemon. *Why:* the user is their own policy admin on one
   box, not an admin staging policy for a fleet — SELinux's global permissive→enforce
   cutover is the per-object **audit→deny** progression here (§15.10 flow A). *Touched:*
   bpf-common (ids/maps/Settings — `Settings` is now `{daemon_pid, active_bank}`), bpf
   kernel (`blocked = policy.denies()`, no off/permissive branches), core (config + parse
   drop `mode`; `parse` now *rejects* a leftover top-level `mode =` key; compile drops
   `Mode`), daemon (`bpf_mode`/`mode_str` gone, `seed_policy`/`set_settings` lose the mode
   arg), cli (no mode in `check`/status/show), the smoke (permissive scenario → audit→deny),
   docs.

2. **Subject-specificity in precedence — ✅ done.** `sort_bucket` gained a key between
   object-depth and deny>allow: a concrete subject (exe; the count of non-wildcard
   predicates, via a `Specificity(u32)` newtype) outranks `who="*"`. So `allow exe=X` wins
   over an `audit`/`deny` `who="*"` catch-all on the same object (§15.10 flow A, step 2).
   The existing copy-down tests differ by object depth, so they were unaffected; added
   `concrete_subject_beats_wildcard_catchall` + `concrete_allow_beats_wildcard_deny` units
   and VM smoke scenario 7. (The sort keys are now the `Polarity` enum / `Specificity`
   newtype, not bare ints.)

3. **Leaf-path reconstruction (discovery) — ✅ done.** The kernel emits the *actual opened
   path*, not just the matched protected root, by walking `d_name` up the dentry chain
   (bounded by `PATH_MAX_DEPTH = 8`; `bpf_d_path` is disallowed at `file_open`). The record
   carries a leaf-first fixed component array (`PathComp`, `[[u8;32];8]` + `depth`/`trunc`)
   built in a **per-CPU scratch** map and mem-copied to the ring (it overflows the BPF
   stack otherwise). The suppressor + daemon coalescing rekeyed to the **opened file's
   inode** (`leaf`) so distinct files under one audited root don't collapse; the daemon
   reverses + joins the components onto the object's path → the `path=` journal field.
   Enables §15.10 flow B (per-app discovery) and M4 autolearn's per-file→subtree
   generalization. VM-validated (smoke scenario 13: siblings + a depth-2 nested file).

## Authoring ergonomics (2026-06-28)
From rewriting the real-system audit policy by hand — TOML's `[[rule]]` tables make a
decision table cost ~5 lines/rule, and a root daemon can't use `~`. Both addressed (DESIGN
§15.8); neither touches the compiler IR or the kernel.

4. **Compact rule DSL — ✅ done.** A `rules = '''…'''` **literal** block, one rule per
   line — `POLICY SUBJECT ACTION OBJECT`, whitespace-aligned columns, comma lists, `"…"`
   quoting (spaces; and `*`/`@` forced literal — which also lets an object path start with
   those sigils), `#` comments. Accepted *alongside* `[[rule]]` and normalized to the same
   `ParsedRule`, so it is **surface syntax only**. New `policy/ruleline.rs` (quote-aware
   lexer, `Item`/`Sep` types), `PolicyName::parse`; the literal content is a verbatim source
   slice so a diagnostic carries exact `line:col` (better than `[[rule]]`, which points at
   the table header). 11 units + a regression-tested `cordon.example.dsl.policy.toml`. Hand
   audit policy: 129→76 lines, **proven** to compile to the identical per-object table.
5. **Per-user `~` via `user =` header — ✅ done.** `user = "name"` expands `~` against that
   account's `/etc/passwd` home (the root daemon's `$HOME` is `/root`). New `UserName`
   newtype + `policy::home_for(user, fallback)`, wired into the one resolve choke point
   (`compile_text` for startup + `apply`; CLI `check`). A named-but-missing account is a hard
   error. **Next:** the conf.d split — a *directory* of per-user fragments, each with its own
   `user`, merged before compile. Deferred because `apply` ships a single file's text today,
   so the apply path (and `policy show`) need a multi-source redesign; precedence stays
   source-order-independent (specificity + deny>allow), so a flat merge is safe (all
   fragments root-owned), with system-beats-user *tiers* an open question for a baseline deny.

## Appendix A — policy TOML (proposed)
```toml
# No global mode: the per-rule `policy` is the only enforcement level (use `audit` to
# observe, `deny` to enforce). A top-level `mode =` key is rejected.

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

The same rules in the DSL surface (✅ shipped — `POLICY SUBJECT ACTION OBJECT`; `user =`
expands `~`; the block precedes the `[group.*]` tables as a top-level key):
```toml
user = "alice"
rules = '''
allow  @ssh-tools    @ro          ~/.ssh
allow  @aws-cli      read,write   ~/.aws
audit  *             read         @cloud-creds
deny   /tmp/sketchy  *            ~/.aws
'''
# …[group.*] tables follow, as above.
```

## Appendix B — compiled shapes (proposed; refine during impl)
```
CompiledPolicy { protected: [(FileId, ObjId)],         // → MAP_PROTECTED
                 rules:     [(ObjId, CompiledRule)],   // → MAP_RULES (+ MAP_RULE_COUNT)
                 pending:   [(PathBuf, ObjId)] }        // unresolved paths, re-tried on apply

CompiledRule  { subject: SubjectMatch, action_mask: u32 /*bitset*/, policy: u8 }
SubjectMatch  { exe: FileId, uid: u32, cgroup: u64, flags: u32 /*which fields are wildcard*/ }
```
Kernel maps: `MAP_PROTECTED: HashMap<FileId, ObjId>`,
`MAP_RULE_COUNT: HashMap<ObjId, u32>`, `MAP_RULES: HashMap<(ObjId,u32), CompiledRule>`,
`MAP_SETTINGS: Array<Settings{ daemon_pid, active_bank }>`, `MAP_EVENTS: RingBuf`.
