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
  binary swap. **It does not resist code injection** — under `LD_PRELOAD` the exe is
  genuinely unmodified, so its hash is correct and the predicate passes. That is M6's
  problem, not this one; do not read this bullet as covering it.
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
- **Done (2026-07-27):** `inode_link`, `inode_rename`, `inode_unlink`, `inode_rmdir` — the
  second-name escape, clobber, and destroy. Design + rationale in DESIGN §15.5.
- Left: `inode_mkdir` and `bprm_check_security` (the `execute` action).
- `listdir` ≈ "open dir for read" (coarse) — note the limitation; finer (`file_permission`)
  stays opt-in for cost.
- Verify `renameat2(RENAME_EXCHANGE)`: the hook has no `flags` argument, and the protected
  inode sits on the *destination* side. If the kernel does not call the hook a second time
  with the pair swapped, gate `new_dentry` when positive.

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

## Milestone 6 — Code identity as a subject predicate (the `exe`-identity fix)

### The gap

`exe` is `mm->exe_file`: set once at `execve`, never updated. That is a statement about *the
file that was exec'd*, not *the code that ends up running*, and any dynamic loading breaks
the equivalence. `LD_PRELOAD=evil.so ssh -V` runs attacker code with
`mm->exe_file == /usr/bin/ssh` and inherits every grant `ssh` has. **Every static `allow` is
therefore a confused-deputy grant.**

Preconditions are ordinary: `/usr/bin/ssh` is `0755`, not setuid, no file capabilities, so
`ld.so` is not in secure-execution mode and honours `LD_PRELOAD`. A one-shot scraper running
as the user can set an environment variable.

None of M2's predicates close it. `uid`/`gid`/`cgroup` are unchanged; `argv0` is still
`ssh`; `ancestor-exe` is still the shell. **IMA/fsverity exe-hash does not help either** —
the exe genuinely *is* ssh, unmodified, so its hash is correct. The injected code lives in a
file that is never the subject of any check. This is the trap: M2 lists exe-hash as
"resists binary swap", which is true and irrelevant, because nothing is swapped.

### Why it must be caught at load time, not decision time

At `file_open` you are inspecting state the attacker controls and has had time to launder:

- a constructor can patch what it wants and then `munmap`/`dlclose` itself
- `environ` lives in the process's own writable memory and can be scrubbed
- injection need not touch a file at all — `ptrace` of a forked child is permitted under
  Yama `scope=1`, and anonymous `PROT_EXEC` needs no file

There is no durable artifact to find. Walking the VMAs is also impractical (a maple tree on
modern kernels) and would still need a per-tool expectation set to interpret. So detection at
decision time is **structurally unsound**, not merely difficult.

### The mechanism

A sticky taint, recorded when code is acquired, read as one more predicate:

- **Set** at `mmap_file` (`PROT_EXEC` of a file outside the subject's code set),
  `file_mprotect` (anonymous memory turned executable), and `ptrace_access_check` (taints the
  *target*).
- **Sticky** for the life of the `mm`, so unloading launders nothing. Cleared by `execve`
  only — a genuinely new program image. (The attacker gains nothing by re-execing: that
  discards the injection too.)
- **Store** in `BPF_MAP_TYPE_TASK_STORAGE`, built for per-task LSM state; fork inherits.
- **Read** at `file_open` as a `SubjectFlags` bit, so a tainted process stops matching
  exe-based rules, falls through to the `*` catch-all, and is denied. Fail-safe by
  construction, no special-case code path, and it composes with copy-down and precedence
  unchanged.

The subject was never `exe`. It is **`exe AND untainted`**.

Ordering is what makes this work: `ld.so` must *map* a preloaded library before its
constructor can run, so the taint lands before any attacker code executes.

### Why this is not a per-tool profile

It looks like AppArmor's `m` permission and is not. §3 rejects per-tool profiles because
*unprofiled = unconfined*. Here a code set is a **precondition for a grant**, not a
confinement mechanism: an exe with no code set gets no grant and falls to the catch-all
deny. **Unprofiled = denied.** The failure mode that makes MAC profiles fragile cannot
arise, and sets are written only for the handful of exes that appear in `allow` rules — not
for the system.

### The code set is enumerated, not inferred

An earlier sketch used *provenance* — "taint if the mapped file was writable by the
adversary" (root-owned and not group/other-writable ⇒ trusted). It is cheap and it is too
weak: a **legitimate root-owned library** preloaded into `ssh` satisfies provenance and is
still an injection. Provenance answers "who wrote this file"; the grant needs "is this the
code that constitutes ssh". Different questions, and only the second one is what
`allow ssh read ~/.ssh` means.

So the set is enumerated per subject. Root-ownership still earns its keep, but only in a
narrow way: because the adversary cannot modify files under `/usr/lib`, **path identity is
sufficient and no hashes or signatures are needed**.

**Static derivation is off the table** — verified, not assumed (2026-07-27):

- `ldd /usr/bin/ssh` lists 17 libraries.
- At runtime ssh also loads `libnss_*.so` (dlopened by libc on every hostname lookup),
  krb5 plugins from `/usr/lib/krb5/plugins/{kdb,preauth,tls}/`, and OpenSSL providers from
  `/usr/lib/ossl-modules/`.
- **Which `libnss_*` is decided by `/etc/nsswitch.conf`** — runtime *configuration*, not the
  binary. This host's `hosts:` line alone pulls `mymachines`, `mdns4_minimal`, `resolve`,
  `files`, `myhostname`, `dns`, `wins`.

So the set is a property of the binary *plus machine configuration*, and cannot be read out
of the ELF. A hook that ran `ldd` would emit a set that breaks ssh the first time it resolves
a hostname, and break differently on different machines. **Learn it, don't derive it** —
which is M4's machinery and §15.10's audit→admit→enforce, applied to a second axis.

### Policy surface

The set is a property of the *subject*, not of a rule, so it hangs off the subject group —
the shape `blessing` already established. One token is hand-authored:

```toml
[group.subject.ssh-tools]
members = ["/usr/bin/ssh", "/usr/bin/ssh-add", "/usr/lib/gcr-ssh-agent"]
code = "learn"        # observe + journal, enforce nothing
# code = "strict"     # taint on any mapping outside the set
```

The entries themselves are **not policy** — they are facts about the machine, the same
category as the `(dev,ino)` resolutions cordon already performs invisibly at apply time.
They live in a generated, root-owned sidecar:

```
# /etc/cordon/code.d/ssh-tools.list
# generated by `cordon code promote` 2026-07-27 — do not hand-edit
# subject: @ssh-tools   observed over 14 days, 312 executions
@base
/usr/lib/libgssapi_krb5.so.2
/usr/lib/krb5/plugins/preauth/spake.so
/usr/lib/libnss_resolve.so.2
…
```

Groups keep it small. §15.7 makes groups symmetric across axes; code is simply a fourth one,
and nearly all bulk is shared (libc, libcrypto, libz appear under every subject), so a
`[group.code.base]` absorbs it. Per-subject content drops to the genuinely distinctive
handful: krb5 and NSS for ssh, gpgme for gopass. Expect ~40 lines of `@base` plus 5–10 per
subject — around 150 authored lines, against a compiled map of ~600 `(exe, lib)` pairs.
Compiled forms are not read by humans.

Verbs, matching the existing `policy`/`bless` surface: `cordon code show <subject>`,
`cordon code promote <subject>`, `cordon code check`.

### Flows

**Initial setup.** The code axis reuses the object axis's rhythm, so there is nothing new to
learn:

```sh
# objects first — today's flow, unchanged
sudo cordon policy edit          # @secrets at `audit`
… use the machine a week …
journalctl -u cordond            # see who actually touches what
sudo cordon policy edit          # admit the owners you saw
sudo cordon policy edit          # flip audit → deny

# ssh now holds a grant worth hijacking, so tighten the subject
sudo cordon policy edit          # [group.subject.ssh-tools]  code = "learn"
… use the machine a week …

cordon code show @ssh-tools
#   @ssh-tools — 31 libraries over 312 executions, 14 days
#     24 shared with @base
#      7 distinctive:  …/libgssapi_krb5.so.2, …/preauth/spake.so,
#                      …/libnss_resolve.so.2   ← dlopened; ldd would have missed it

sudo cordon code promote @ssh-tools
#   wrote /etc/cordon/code.d/ssh-tools.list (31 entries, 24 via @base)

sudo cordon policy edit          # code = "learn" → "strict"
```

No library path is ever typed by hand. `learn` is safe to leave on indefinitely — it
observes and journals only — so there is no pressure to rush to `strict`.

**System upgrade.** Usually nothing:

```sh
sudo pacman -Syu
#   (cordon) re-resolving code sets… 5 subjects, 0 drift
#   (cordon) policy applied
```

Paths are stable across an upgrade; only inodes change, and the pacman hook's
`cordon policy apply` re-resolves them. Empty diff, no review, no action.

When a package gains a dependency, the hook catches the common case *before* it bites by
comparing the new binary's `DT_NEEDED` against the recorded set. That check is incomplete (it
cannot see `dlopen`) but it is a strict subset, so anything it flags is real:

```
(cordon) WARNING @ssh-tools: /usr/bin/ssh gained a dependency that is not in its
         code set: /usr/lib/libfido2.so.1
         ssh will lose its grants until:  sudo cordon code promote @ssh-tools
```

When something slips past it — a newly `dlopen`ed module, exactly what static analysis
cannot predict — the failure is soft and self-diagnosing:

```
WARN  taint pid=8812 exe=/usr/bin/ssh lib=/usr/lib/libfido2.so.1 \
            subject=@ssh-tools reason=not-in-code-set
INFO  deny  pid=8812 user=nb exe=/usr/bin/ssh object=~/.ssh \
            path=~/.ssh/id_ed25519 action=read policy=default-deny tainted=1
```

**Taint revokes the grant; it does not break the program.** ssh still runs, and falls back to
a password. The journal names the exact library and recovery is one `promote`. That asymmetry
is what makes the design deployable: a false positive costs a password prompt, not a broken
tool.

**An attacker failing.**

```sh
LD_PRELOAD=/tmp/.x.so ssh -V     # scraper, running as you, one shot
```

```
mmap_file(exe=/usr/bin/ssh, lib=/tmp/.x.so, PROT_EXEC)
  → ∉ @ssh-tools code set → taint(task), sticky        ← before any attacker code runs
… constructor runs, opens ~/.ssh/id_ed25519 …
file_open(~/.ssh/id_ed25519)
  → object = ~/.ssh; exe matches @ssh-tools, but `untainted` fails
  → no rule matches → default-deny
```

| attempt | why it fails |
|---|---|
| `LD_PRELOAD=/usr/lib/libfoo.so` (**root-owned**) | passes provenance, but is not in *ssh's* set — the case that makes enumeration necessary |
| `dlclose` to hide the evidence | taint is sticky for the life of the `mm` |
| `ptrace` a forked ssh | `ptrace_access_check` taints the target |
| re-exec to clear the taint | `execve` clears it, but discards the injection too |
| `LD_AUDIT` instead of `LD_PRELOAD` | same `mmap_file` path; the mechanism does not care how the load was requested |

### Rejected alternatives

- **Glob the trust set** (`/usr/lib/*`) — three lines instead of 600, and exactly the
  provenance rule this milestone exists to replace. `LD_PRELOAD` of any system library passes.
- **Package granularity** (`code = ["openssh", "glibc", "krb5"]`, expanded via `pacman -Qlq`)
  — upgrade-stable and human-scale, but glibc ships ~50 libraries where ssh uses ~8, so all
  50 become loadable; and it couples cordon to a package manager.
- **`ldd`/`DT_NEEDED`** — static, blind to `dlopen`, and per-exe. See the nsswitch finding.
- **Detect `LD_PRELOAD` in the environment** at `bprm_check_security` — a bounded walk over
  the new stack, and defeated by `LD_AUDIT`, `/etc/ld.so.preload`, or `ptrace`, none of which
  touch the environment. Whack-a-mole that reads like a mitigation.
- **Force `AT_SECURE`** on gated binaries (`ld.so` ignores `LD_PRELOAD` for setuid/file-caps
  executables) — genuinely works, but means granting `/usr/bin/ssh` a capability it does not
  need, system-wide, for every user, to obtain a side effect.

### Honest limits

- **ROP** maps nothing and loads nothing — it chains fragments of already-mapped, already
  legitimate code — so no hook fires and the process stays untainted. The defences are
  compiler- and CPU-level (CFI, shadow stacks / Intel CET), not LSM-level.
- **A gadget already inside the subject's own code set** still works. 31 libraries is a far
  smaller search space than all of `/usr/lib`, but it is not zero. This is where IMA
  appraisal would compose usefully, rather than pretending to be a fix on its own.
- **Preloading a library already in the set** reorders symbol resolution, so interposition
  *between expected libraries* remains possible. Much narrower than arbitrary preload;
  accepted.
- The trust set needs tuning where tools legitimately load code from `$HOME` — nvim's
  compiled treesitter parsers under `~/.local/share/nvim` are the obvious first case.

### Implementation notes

- Hooks: `mmap_file`, `file_mprotect`, `ptrace_access_check`. All three are ordinary BPF LSM
  attach points; the same `clamped()` return discipline applies.
- Map: `ALLOWED_CODE: HashMap<(FileId exe, FileId lib), ()>` — one lookup per `PROT_EXEC`
  mapping. ~600 entries for a 15-subject policy.
- Taint: `BPF_MAP_TYPE_TASK_STORAGE`, one bit; cleared on `execve`, inherited on fork.
- `SubjectFlags` gains an `UNTAINTED` bit — §15.4 notes a fifth predicate bit extends
  matching and specificity for free.
- No new BTF offsets: the hooks hand over a `struct file *`, and the existing `file_f_inode`
  → `inode_i_ino`/`inode_i_sb` → `sb_s_dev` chain already yields a `FileId`.
- **Meanwhile, the deployment answer is `bless`:** a per-invocation cgroup grant has no
  standing exe rule to inject into, so preloading gains nothing. The lever is the ratio of
  static `allow` rules to blessings.

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
