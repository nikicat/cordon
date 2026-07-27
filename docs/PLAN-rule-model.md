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
- **`unsandboxed`** — enforcement point (3) of M6's invariant, and the answer for browsers.
  A privilege-separated app splits itself into a trusted process that touches the profile and
  untrusted ones that run web JS; the grant must attach only to the first. argv
  (`--type=renderer`, `-contentproc`) names the split but is **forgeable** — a compromised
  renderer rewrites `mm->arg_start..arg_end` with a memcpy — so match on the sandbox state
  itself, which is **one-way kernel state the task cannot shed**: `task->seccomp.mode != 0`
  and `cred->user_ns != &init_user_ns` (Chrome's layer-1 namespace sandbox). Two derefs,
  BTF-resolved like the existing `file → inode → sb` chain, one more `SubjectFlags` bit —
  §15.4 notes a fifth predicate bit extends matching and specificity for free. Strictly
  fail-safe: it only ever *narrows* an `exe` grant, so an attacker who declines to sandbox
  themselves still fails the `exe` check. **Measure which process opens the cookie DB first**
  — see M6 *Honest limits*.
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
- **Gate a positive `new_dentry` (security gap, do first).** `decide_reparent` classifies the
  source and `new_dentry.parent()`, never `new_dentry` itself — right for `inode_link` (its
  target is always negative), wrong for `inode_rename`, where rename-over destroys a positive
  target inode with no verdict of its own and dangles its `PROTECTED` entry. `mv anything
  secret` thus does what `rm secret` is refused. Run `find_object(new_dentry)` when
  `d_inode != NULL` and take that object's `write` verdict *before* the internal-shuffle
  short-circuit; add a rename-over case to the daemon self-test. This also settles
  `renameat2(RENAME_EXCHANGE)` — the protected inode sits on the *destination* side, the hook
  has no `flags` argument, and the second swapped call that would cover it is believed, not
  verified. Rationale and both exploit shapes in DESIGN §15.5.

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

## Milestone 6 — Fixed code as the precondition for a grant

> **The invariant.** A grant attaches only to a process that runs *the code it shipped with*.
> A process that executes foreign code **in its own address space** — a JIT, an interpreter
> running a script, a preloaded library — forfeits it. Not "is denied by a rule": has no
> subject identity worth granting to in the first place.

This is one rule with three enforcement points, and it is stated as an invariant rather than
a mechanism because the mechanism alone (the taint below) catches only one of the three.

### Why "in its own address space" is load-bearing

Taken as a property of a *program* the invariant is unsatisfiable, and browsers are the proof:
Chrome runs attacker JavaScript all day and must read its own cookie DB or it is not a
browser. Taken as a property of a *process* it is satisfiable, because well-built tools have
already done the separation:

| tool | runs foreign code | where | grant survives? |
|---|---|---|---|
| Chrome / Firefox | web JS, JIT | renderer / content process, sandboxed | **yes** — the browser/parent process holds the grant and runs no web JS |
| `ssh` | `ProxyCommand`, `LocalCommand` | `exec` → new process, new `exe` | **yes** — exec resets identity, the child holds no grant |
| `git` | hooks, credential helpers, pager | `exec` | **yes**, same reason |
| `python3 script.py` | the script | **same process** | **no** — no boundary exists, ever |
| `gdb`, `vim +python`, lua-linked daemons | embedded interpreter | **same process** | **no** — and no hook fires, see *Attestation* |

So `exec` and the process boundary are what make the invariant reachable. Anything that mixes
untrusted code into the granted process's own address space is out, permanently and by
construction — not a tuning problem, not a learning problem.

### The three enforcement points

| | catches | where | mechanism |
|---|---|---|---|
| **1. Attestation** | a program whose *purpose* is executing arbitrary code — `python`, `node`, `bash`, `deno` | `cordon policy check` | policy lint, no kernel code |
| **2. Taint** (this milestone's bulk) | a fixed-code program that *acquires* code at runtime — `LD_PRELOAD`, `dlopen`, anon RWX | `mmap_file` / `file_mprotect` / `ptrace_access_check` | sticky per-`mm` bit → `SubjectFlags` |
| **3. Sandbox state** | the untrusted half of a privilege-separated app — a Chrome renderer | `file_open` | `SubjectFlags` bit off one-way task state (M2) |

Only (2) needs new in-kernel machinery. (1) is a lint over the compiled policy. (3) is a
subject predicate that belongs to M2's axis, specified there and referenced here.

### The gap that (2) closes

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

### Attestation — enforcement point (1)

The taint structurally cannot catch an interpreter. `python3 evil.py` maps nothing
executable: the script is read as **data** and executed by the interpreter's own loop, so no
hook fires and the process is genuinely untainted. `exe` is `/usr/bin/python3`, unmodified,
and the code it runs is arbitrary. There is no runtime signal to find — the exclusion has to
be static.

It must be an **allowlist, not a blocklist.** Enumerating interpreters is unbounded and
§3 rejects exactly that shape (*unprofiled = unconfined*); the dangerous cases are not the
obvious ones but fixed ELF binaries with *embedded* interpreters — `gdb`, `vim +python`,
anything linking lua — which look like ordinary compiled tools and fire no hook. So invert
it: a subject appearing in an `allow` rule must **positively attest** fixed code, via the
same `code =` token the policy surface below already introduces. No attestation ⇒
`cordon policy check` warns that the rule is a confused-deputy grant. This scopes the vetting
to the handful of exes that actually hold grants — the same argument the code-set enumeration
makes — rather than to the system.

**Recorded consequence: the shipped example policy loses `allow /usr/bin/aws`.** The aws CLI
is Python, and M2's own audit signal records `~/.aws` being opened by `python3`, not `aws`.
Under this invariant that rule cannot be made honest, and the example policy should say so
rather than model a grant that grants nothing. Expect the same verdict for most npm- and
Electron-distributed tooling. **Static `allow` rules get rare**, and the residue routes
through `bless` — which is the lever this plan already names, arrived at deliberately instead
of by attrition.

**`bless` does not satisfy the invariant, and is not meant to.** A blessed `python` session
reads secrets. Blessing proves *human presence*, not code identity (DESIGN §16), so it is the
deliberate escape hatch from this rule. Naming it as such keeps the invariant honest instead
of quietly violated in the one place it is most often reached for.

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

- **Set** at `mmap_file` (`PROT_EXEC` of a file outside the subject's code set — **and of a
  NULL file**, since `security_mmap_file` is called with `file == NULL` for anonymous
  mappings and Linux does not enforce W^X, so a direct `mmap(PROT_EXEC|PROT_WRITE,
  MAP_ANONYMOUS)` never reaches `mprotect`), `file_mprotect` (existing memory turned
  executable), and `ptrace_access_check` (taints the *target*; `process_vm_writev` routes
  through `ptrace_may_access`, so it is covered by the same hook).
- **Sticky** for the life of the `mm`, so unloading launders nothing. Cleared by `execve`
  only — a genuinely new program image. (The attacker gains nothing by re-execing: that
  discards the injection too.)
- **Store** — open, and the one question that changes the mechanism rather than its notes.
  Stickiness above is stated per-`mm`; `BPF_MAP_TYPE_TASK_STORAGE` is per-*task*, and task-local
  storage is believed **not** to be copied on `clone` (which is why `security_task_alloc`
  exists) — **verify before relying on it**, the answer picks the map. If it does not
  inherit, two laundering paths open: a tainted process forks and the child starts clean, and
  — worse, because no hook closes it — thread A `dlopen`s the payload while thread B, created
  earlier, keeps its own untainted storage and does the read. `mm` is shared; task storage is
  not. Hooking `task_alloc` to copy the parent's bit closes fork and covers threads created
  *after* the taint, and nothing closes threads that already exist. Keying an LRU hash on
  `task->mm` implements the stated invariant directly, at the cost of no free-time hook to
  clean up on.
- **Read** at `file_open` as a `SubjectFlags` bit, so a tainted process stops matching
  exe-based rules and falls through to the object's catch-all. Fail-safe by construction, no
  special-case code path, and it composes with copy-down and precedence unchanged. Note the
  floor is the **catch-all, not denial**: on an object whose catch-all is `audit *` a tainted
  process still reads it and is merely logged. That is the intended composition — the
  catch-all is the floor for everyone — but "tainted ⇒ denied" holds only where the catch-all
  denies, so it is a policy-authoring trap to call out in the docs.

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
# code = "arbitrary"  # attested arbitrary-code executor — never eligible for a grant
#                     # (browsers, interpreters); `policy check` errors on an `allow`
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
| fork after tainting, read from the child | **only if the taint propagates** — task storage may not copy on `clone`; see *Store* |
| taint one thread, read from a sibling | **not closed by any hook** if the taint is per-task; the `mm` is shared and the storage is not |

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

- **A JIT self-taints, which is correct and is not the reason interpreters are excluded.**
  V8 turns anonymous memory executable on startup, so `node`/`deno`/JVM/Chrome trip
  `file_mprotect` on their own first JIT page, immediately, with no attacker present.
  `code = "strict"` is therefore structurally unusable for them — but they were already
  excluded by attestation for the prior and more basic reason that they execute arbitrary
  code with no injection at all. `python evil.py` involves no JIT and is equally
  disqualifying. Do not read the JIT taint as *the* interpreter answer; it is a correct
  second signal on a subject that never should have held a grant.
- **Browsers are where the JIT taint genuinely bites**, because unlike an interpreter a
  browser has a stable identity and a legitimate need for its own profile directory (the
  cookie DB is the single highest-value scraper target on a desktop). Enforcement point (3)
  is the answer: the grant attaches to the unsandboxed browser/parent process, and the
  JIT-running renderers are excluded by one-way sandbox state they cannot shed. The subject
  group is then `code = "arbitrary"` for the renderer side and the sandbox predicate carries
  the separation — **which process actually opens the cookie DB must be measured, not
  derived**; modern Chrome moved cookie handling into a sandboxed network-service utility
  process, which would put it on the wrong side of the predicate. Audit the profile directory
  and read the argv off the events before designing against a guess (§15.10, and the same
  discipline the overlayfs finding earned).
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
- Maps: `CODE_SETS: HashMap<FileId exe, mode>` probed **first**, then
  `ALLOWED_CODE: HashMap<(FileId exe, FileId lib), ()>` — ~600 entries for a 15-subject
  policy. The composite key alone cannot tell "this exe has no code set" from "this lib is
  not in it", so without the `CODE_SETS` probe the first library every process on the box maps
  is a miss and *every* process taints and pays the lookup. `CODE_SETS` also carries
  `learn` vs `strict`.
- Taint: one bit, cleared on `execve`. Map choice and fork/thread propagation are the open
  question in *The mechanism* above — settle that before writing the hooks, since it decides
  whether `task_alloc` is a fourth attach point.
- `SubjectFlags` gains an `UNTAINTED` bit — §15.4 notes a fifth predicate bit extends
  matching and specificity for free.
- No new BTF offsets: the hooks hand over a `struct file *`, and the existing `file_f_inode`
  → `inode_i_ino`/`inode_i_sb` → `sb_s_dev` chain already yields a `FileId`.
- **Meanwhile, the deployment answer is `bless`:** a per-invocation cgroup grant has no
  standing exe rule to inject into, so preloading gains nothing. The lever is the ratio of
  static `allow` rules to blessings.

### Task order

Attestation first — it is the cheapest of the three, needs no kernel code, and it is what
tells you which subjects the rest of the milestone is even for.

1. **`code =` on subject groups** — parse/resolve `arbitrary | learn | strict`, plus the
   absent case. Pure userspace.
2. **`cordon policy check` attestation lint** — error on an `allow` whose subject attests
   `arbitrary`; warn on one with no attestation at all. Ships independently of everything
   below and immediately makes the confused-deputy grants visible in an existing policy.
3. **Retire `allow /usr/bin/aws` from the example policies** and record why in-line, so the
   shipped examples stop modelling a grant that cannot be honest.
4. **Settle the taint's storage** (per-task + `task_alloc`, or an `mm`-keyed LRU) — verify
   `clone` semantics first; it decides the map and whether there is a fourth hook.
5. **`CODE_SETS` + `ALLOWED_CODE` seeding**, then the three taint hooks, then the
   `UNTAINTED` bit in `SubjectFlags`.
6. **Learning + `cordon code show|promote|check`** (M4 machinery on a second axis).

Enforcement point (3), the `unsandboxed` predicate, is sequenced under M2 and gated on the
cookie-DB measurement, not on any of the above.

## Carried-over notes (still live)
Loose ends left by shipped work, none of them a milestone of their own:
- **The self-test probe is a root-writable `/tmp` path (security bug, small fix).**
  `self_test` builds `$TMPDIR/cordon-selftest.<pid>` and now seeds a file inside it with
  `std::fs::write`, which is `O_WRONLY|O_CREAT|O_TRUNC` with no `O_NOFOLLOW` — and
  `create_dir_all` accepts a pre-existing directory of any owner. `cordond` is uid 0 and no
  unit sets `PrivateTmp=`, so a local user who pre-creates `/tmp/cordon-selftest.<N>/`
  (mode 0755, theirs) holding `src -> /etc/cordon/policy.toml` gets root to truncate the
  policy on the next start with that pid — after which the daemon fails to compile and the
  boundary is off entirely. Any root-owned file works; the pid guess is the only cost, and
  pids are sequential. `fs.protected_symlinks` does **not** cover this: `may_follow_link()`
  keys on the symlink's *immediate parent* being sticky and world-writable, and here that
  parent is the attacker's own plain directory, so the check returns before comparing uids.
  (Planting the top-level probe path itself as a symlink *is* blocked — that one sits
  directly in sticky `/tmp`.) The write also runs before `seed_policy`, so cordon is not yet
  enforcing on itself. Fix: put the probe under `/run/cordon/` (root-only, removes the shared
  namespace outright); if it must stay in `TMPDIR`, use `std::fs::create_dir` so a planted
  directory fails `EEXIST` and open the seed file `O_NOFOLLOW|O_EXCL` via
  `OpenOptionsExt::custom_flags`. `PrivateTmp=yes` on the unit is worth adding regardless, but
  as defence in depth — it misses the dev unit and any non-systemd start.
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
