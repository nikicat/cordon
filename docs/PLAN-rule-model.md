# Implementation plan — the rule model

Concrete, reviewable plan for the architecture in [`DESIGN.md` §15](DESIGN.md). Replaces
the v1 owner model (`owners` / `owner_identities` / `subtrees` + the unenforced `rules`
table) with one flat rule model, compiled in userspace and enforced in-kernel.

> **M1 (rule core) is done and VM-validated**, along with the refinements that followed it —
> no global mode, subject specificity, leaf-path reconstruction — and the authoring
> ergonomics (compact DSL, `user =` header, conf.d fragments, `policy edit`, system/user
> tiers). What exists today is summarized in [`STATUS.md`](../STATUS.md) and specified in
> DESIGN §15; the M1 task breakdown has been retired now that it is code. What follows is
> what is left.

Guiding constraints (from §15):
- **Compile in userspace, flat in kernel.** Groups/nesting/precedence resolve at compile
  time; the eBPF program evaluates a pre-resolved per-object rule table.
- **Explicit apply, no autoreload.** Policy takes effect only on `cordon policy apply`.
- **Identity stays inode-based** across hooks (no `bpf_d_path`); subjects gain predicates
  over time, not a new matching mechanism.

The milestones are sequenced so each is shippable and VM-validated on its own.

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

## Carried-over notes (still live)
Loose ends left by shipped work, none of them a milestone of their own:
- **`MAX_RULES_PER_OBJ = 32`** — raise toward 64 if a verifier log demands it; `cordon policy
  check` errors when a compiled bucket exceeds it.
- **Per-object default deferred.** A protected object with no matching rule falls to the
  global default-deny (§15.6.3); a per-object default was considered and parked.
- **Group expansion is a lever, not a law.** Subject groups expand at compile time, so
  subject-group size × object-nesting depth multiplies bucket entries. If that ever binds,
  keep groups as a `(GroupId, exe)` membership map instead of expanding.
- **conf.d diagnostics don't carry the fragment name.** Parse/resolve errors name their
  fragment; compile-stage ones (e.g. pending-path warnings) carry only `line:col`. A source
  id on `Pos` would close it.
- **Tier precedence is flat.** *System is a floor* (a user tier may tighten, never loosen)
  isn't expressible in one first-match bucket, and only bites once user files are
  user-owned — so it lands with the home-migration below.
- **Home-migration.** User-tier files are root-owned under `/etc` today. The roadmap is
  `~user/.config/cordon/`, with cordon *cordoning* its own user-policy file — a protected
  object only an authorized editor may write. That self-protection is the future
  "edit without sudo".

## The policy surface
Authored TOML is specified in DESIGN §15.8 and shown by two regression-tested examples:
[`packaging/cordon.example.policy.toml`](../packaging/cordon.example.policy.toml) (verbose
`[[rule]]` tables) and
[`packaging/cordon.example.dsl.policy.toml`](../packaging/cordon.example.dsl.policy.toml)
(the compact one-rule-per-line DSL). The compiled shapes are
`crates/bpf-common/src/policy_maps.rs`.
