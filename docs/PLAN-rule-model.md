# Implementation plan — the rule model

This is the concrete, reviewable plan for the architecture in
[`DESIGN.md` §15](DESIGN.md). It replaces the v1 owner model with one flat rule model,
compiled in userspace and enforced in the kernel. The v1 model consisted of `owners`,
`owner_identities` and `subtrees`, plus the `rules` table, which was never enforced.

> M1 (the rule core) is done and VM-validated. So are the refinements that followed it (no
> global mode, subject specificity, and leaf-path reconstruction) and the authoring
> ergonomics (the compact DSL, the `user =` header, conf.d fragments, `policy edit`, and the
> system and user tiers). [`STATUS.md`](../STATUS.md) summarizes what exists today, and
> DESIGN §15 specifies it. The M1 task breakdown was retired once it became code. What
> follows is what is left.

These guiding constraints come from §15:
- **Compile in userspace, keep the kernel flat.** Groups, nesting and precedence resolve at
  compile time. The eBPF program evaluates a pre-resolved rule table for each object.
- **Explicit apply, no autoreload.** A policy takes effect only on `cordon policy apply`.
- **Identity stays inode-based** across hooks, with no `bpf_d_path`. Subjects gain predicates
  over time, not a new matching mechanism.

The milestones are sequenced so that each one is shippable and VM-validated on its own.

## Order of work (set 2026-07-28)

The numbers identify milestones and do not set the schedule. This is the queue:

1. ~~**Known bugs**~~: done. The self-test probe ran in a world-writable `TMPDIR` and reused
   any directory it found. So a planted symlink let root be tricked into truncating the
   policy and switching the boundary off. The probe now lives in the root-only `/run/cordon`.
2. **Docs**: keep DESIGN, STATUS and the plans in step with what ships, because these files
   are the resume point.
3. ~~**Finish M3**~~: done. `inode_mkdir`, `bprm_check_security` and `RENAME_EXCHANGE` are
   verified. Every hook in the map from actions to hooks now fires, except `listdir`, which
   has no hook by design.
4. ~~**M5**~~: done. The links are pinned to bpffs, so enforcement no longer fails open when
   the daemon dies. A singleton `flock` guards the socket and the pins.
5. **M6** ← **here**. It closes the largest known hole and is the longest job. Start with its
   userspace-only tasks, attestation first (see *Task order*).

**M2 and M4 are not scheduled on their own.** M6 pulls in the parts it needs, so those parts
land as M6 tasks. M2's `unsandboxed` predicate is M6's enforcement point (3), and M4's
learning machinery is how code sets get built (M6 task 6). The rest of M2 and M4 is
opportunistic. Blessing's B3 and B4 are deferred behind all of this (see
[`PLAN-bless.md`](PLAN-bless.md)).

*Why this order:* soundness comes before ergonomics. M5 and M6 were the two ways the boundary
was unsound. It stopped enforcing when the daemon died, and `LD_PRELOAD` can hijack a grant.
M5 is closed and M6 is the one that remains. No ergonomic win is worth having on top of that
hole.

---

## Milestone 2 — Subject predicates beyond exe ← **not scheduled; M6 takes what it needs**
- Add `uid`, `gid` and `cgroup` matching to `SubjectMatch`, with kernel checks. The kernel
  helpers for these are cheap.
- **IMA or fsverity content identity.** It would match through `bpf_ima_inode_hash` or
  `bpf_ima_file_hash`, which needs `CONFIG_IMA` and an IMA policy. Userspace records the
  expected hashes. Content identity survives upgrades and resists a binary swap. It does not
  resist code injection. Under `LD_PRELOAD` the exe is genuinely unmodified, so its hash is
  correct and the predicate passes. That is M6's problem, not this one, so do not read this
  bullet as covering it.
- `argv0` (a bounded read of `mm->arg_start..arg_end`) and `ancestor-exe` (a bounded walk of
  the `task->real_parent` chain). Together they are the interpreter fix. Document how they
  can be forged, with a double fork or an argv rewrite.
- **`unsandboxed`.** This is enforcement point (3) of M6's invariant, and it is the answer
  for browsers. A privilege-separated app splits itself into a trusted process that touches
  the profile, and untrusted processes that run web JS. The grant must attach only to the
  trusted one. argv (`--type=renderer`, `-contentproc`) names the split, but it is forgeable.
  A compromised renderer can rewrite `mm->arg_start..arg_end` with a memcpy. So the predicate
  matches on the sandbox state itself, which is one-way kernel state that the task cannot
  shed. The tests are `task->seccomp.mode != 0` and `cred->user_ns != &init_user_ns`, the
  latter being Chrome's layer-1 namespace sandbox. That costs two dereferences, resolved
  through BTF like the existing chain from `file` to `inode` to `sb`, and one more
  `SubjectFlags` bit. §15.4 notes that a fifth predicate bit extends matching and
  specificity for free. The predicate is strictly fail-safe against an attacker, because it
  only ever narrows an `exe` grant. Someone who declines to sandbox themselves still fails
  the `exe` check.

  This was measured on 2026-07-27 (7.1.5-zen1-1-zen, Firefox 153.0, and Chrome
  150.0.7871.46 headless). The method was to find the processes holding the profile's
  databases and read `/proc/PID/{status,ns/user}` for each:

  | | holds the secrets | `Seccomp` | `ns/user` |
  |---|---|---|---|
  | firefox parent | `cookies.sqlite`, `key4.db`, `formhistory`, `places` | 0 | init |
  | firefox fork server (`-contentproc`) | — | 0 | init |
  | firefox content ×18 | — | 2 | one namespace each |
  | chrome browser | `Login Data`, `Web Data` | 0 | init |
  | chrome `network.mojom.NetworkService` | `Cookies` | 0 | init |
  | chrome `storage.mojom.StorageService` | — | 2 | sandboxed |
  | chrome renderers ×4 | — | 2 | sandboxed (shared) |
  | chrome gpu-process, zygote (`--no-zygote-sandbox`) | — | 0 | init |
  | chrome renderer zygotes | — | 0 | sandboxed |

  There are four conclusions, and only the first is the security property:

  1. **Every process that runs web JS is excluded, in both browsers, by each signal on its
     own.** That is what the predicate is for, and it holds.
  2. **The predicate selects a superset, not one process.** Chrome's GPU process and outer
     zygote are also unsandboxed. They run no web content, so this is not a failure. But do
     not write that the predicate identifies the process holding the grant, because it
     doesn't.
  3. **Require the conjunction, `Seccomp == 0 && ns/user == init`.** The signals are not
     redundant. Chrome's renderer zygotes are `Seccomp 0` in the sandboxed namespace, and
     only the AND excludes them.
  4. **Chrome's cookies work by luck.** The network service holds them, and on Linux that
     service runs with `--service-sandbox-type=none`. Chrome already sandboxes it on Windows
     and macOS. If `NetworkServiceSandbox` lands on Linux, this predicate stops Chrome from
     reading its own cookies. That false positive breaks the browser, which is a worse
     failure than the taint's, where the cost is a password prompt. The predicate needs a
     version check and a documented fallback before it ships enforcing. Re-measure a headful
     browser too, because the GPU row may differ.
- Extend the compiler and the TOML to author conjunctions of predicates (Appendix A shows the
  object form).

> *Audit signal:* the need for this milestone is targeted, not universal. In the first run,
> almost every opener was a compiled binary (helm, kubectl, gpg, gh, ssh, gopass), which is
> fine at plain `exe` granularity. Only shared runtimes needed more. They were `node` and
> `deno` on `~/.npmrc`, and `python` on `~/.aws` once that was exercised. So argv0 and
> ancestor matching matter for each directory that an interpreter fronts, not for the policy
> as a whole. Keep `exe`-only matching as the default, and opt into argv or ancestor matching
> where a directory's opener is an interpreter.

## Milestone 3 — Mutation + exec hooks ← **done**
- **Done (2026-07-27):** `inode_link`, `inode_rename`, `inode_unlink` and `inode_rmdir`. They
  cover the second-name escape, clobber and destroy. The design and its rationale are in
  DESIGN §15.5.
- **Done (2026-07-28): `inode_mkdir`.** `rmdir` was gated and `mkdir` was not. So a subject
  that could not remove a directory inside an object could still add one. The new dentry is
  negative, so `find_object` on it misses on the first step, and the verdict comes from the
  parent directory. That is the same shape as the clobber arm of `decide_reparent`. It is an
  ordinary create or write on the parent object, so `audit` still observes rather than
  blocks. This hook is not what closes `rm -rf ~/.ssh && mkdir ~/.ssh`. `inode_rmdir` closes
  that case by refusing the removal, because once the object's own directory is gone, there
  is no protected ancestor left for this hook to find.
- **Done (2026-07-28): `bprm_check_security`.** It implements the `execute` action. It is the
  first hook that needs a new BTF offset (`linux_binprm -> file`), because every other hook
  is handed a dentry that the existing offsets already cover. That offset is applied to the
  hook's trusted context pointer, so it must stay real under `maybe_poison_offsets`. The
  verifier range-checks trusted-pointer arithmetic against `.rodata` at load time, so
  poisoning the offset would turn the failure-path test into a load failure.
  - **`execute` is not implied by `read`.** The exec open is an ordinary `file_open`
    (`FMODE_EXEC | FMODE_READ`). So an object that denies reads already refuses to run its
    contents. This hook adds the converse, a file that is readable but not runnable.
  - Expressing that needs an explicit `deny`, not a narrower `allow`. Copy-down also puts the
    parent's rules into the child's bucket. So a child rule that does not match the action
    falls through to the parent's rules. The smoke scenario is built that way.
  - The self-test needs a second object for this hook. Under the deny-all probe rule,
    `file_open` refuses the exec open, and the verdict never reaches this hook. The probe
    would then pass with the hook detached. So the exec probe gets its own object, which
    allows `read` and denies everything else. Its file also needs the x bit, or
    `may_open(MAY_EXEC)` fails with `EACCES` first.
- **Done (2026-07-28): the `listdir` limitation is documented** (DESIGN §15.5), and it is
  sharper than "coarse". There is no hook for each `getdents`, so listing a directory is a
  `file_open` on it. `requested_action` derives only `read`, `write` and `create`. So nothing
  ever requests `listdir`. A rule that names `listdir` alone matches no request, and the open
  falls to default-deny. `allow @tools listdir @secrets` therefore denies the listing it
  appears to grant. It fails closed, so it is a usability trap rather than a hole, and the
  shipped example policies now carry a caution about it. Making `listdir` fire means tagging
  the request when the opened inode is a directory (`i_mode & S_IFMT`). That needs one more
  BTF offset, and it was deliberately not taken, because `read` covers the case correctly
  today.
  - Worth considering next is a `cordon policy check` warning on a rule whose action set
    names `listdir` without `read`. It is cheap and userspace-only, and it turns a silent
    surprise into a lint. It is not done here, because it is a change to CLI behaviour rather
    than an M3 hook.

**M3 is complete.** Every hook in the map from actions to hooks now fires, except `listdir`,
which is specified above as having no hook by design.
- `listdir` is roughly "open a directory for read", which is coarse. The limitation is noted.
  Finer mediation through `file_permission` stays opt-in, because of its cost.
- **Done: gate a positive `new_dentry`.** `decide_reparent` classified the source and
  `new_dentry.parent()`, but never `new_dentry` itself. So a rename over a protected inode
  destroyed it with no verdict, and left its `PROTECTED` entry dangling. `mv anything secret`
  did what `rm secret` is refused. `find_object` now runs on the destination dentry first and
  takes that object's `write` verdict. The daemon self-test and a `bpf-lsm-smoke.sh` scenario
  both cover it, and the smoke scenario also pins that atomic save still works. See DESIGN
  §15.5.
- **Done (2026-07-28): `renameat2(RENAME_EXCHANGE)` is verified.** An exchange re-parents both
  inodes and destroys neither, so the `write` floor of the destroy check does not cover it.
  When the protected side leaves its object, the unconditional escape refusal must catch it,
  and that requires the kernel to ask about that side. It does. `security_inode_rename` calls
  the hook a second time, with the pair swapped, when `RENAME_EXCHANGE` is set. The
  `rename_exchange` smoke scenario now measures this rather than assuming it. The case that
  matters is an object that allows write, with the unprotected name passed first. The first
  call then sees only an ordinary permitted clobber, and the swapped call is the only thing
  that keeps the secret from getting a name outside its object. The scenario first runs the
  syscall against two unprotected files, because an unavailable `renameat2` would otherwise
  read as a deny and pass for the wrong reason. An exchange wholly inside one object stays
  allowed, because it is an internal shuffle.

## Milestone 4 — Autolearn (the zones layer) ← **not scheduled; its machinery lands as M6 task 6**
- A separate `learned.db` (SQLite). The `zones` config says where learning may propose rules.
- `cordon learn [--for ZONE] [--ttl T]` opens a bounded window in which ring events become
  candidate rules. The candidates are generalized (from single files to subtrees), given a
  confidence (seen N times), and deduplicated. Each one records the rich subject (argv0,
  ancestor and hash).
- `cordon learn review` shows a diff of the proposals, and `promote` writes them into the text
  policy.
- Learned rules have lower precedence and never override a hand-written deny.

## Milestone 5 — Fail-safe pinning ← **done (2026-07-28), VM-validated**

Enforcement used to fail open. `attach()`'s `LsmLinkId` was discarded, so the links lived
inside `ebpf`, a local variable in `Backend::run`, and every hook detached when the daemon
exited. That made every other guarantee in this document depend on a process staying alive.

**What shipped: pin the links, and only the links.** A pinned link holds its program, and a
program holds its maps. So seven pinned links keep the programs and the seeded policy
enforcing with no process holding them. At startup the daemon attaches, runs the self-test,
seeds, pins, and then sweeps older generations. The previous generation keeps enforcing
until the new one is proven. So there is no instant with nothing attached, and an abort on a
bad policy leaves the boundary up. Each run pins into its own generation subdirectory of
`bpf_pin_dir`. `BPF_OBJ_PIN` fails with `EEXIST` on a path that is taken, so one shared
directory would force a gap between detaching and attaching. `PinDir::pin_links` in
`crates/daemon/src/backend/bpf_lsm/pin.rs` owns the layout and the order.

- **Adopting existing pins was specified here and deliberately dropped.** It buys nothing that
  the link pins don't already give. It costs three things. One is a mandatory cross-process
  writer lock. Another is an ABI or build-id check, so that an upgraded daemon doesn't drive
  the old kernel program. The third is a clash with the self-test, which writes bank 0 and
  `SETTINGS` before `Maps::seed` and so would briefly clobber a live adopted policy. A
  restarting daemon loads its own object with its own private maps, so the single-writer
  invariant in `seed.rs` is untouched.
- The old note "pin the policy maps only, because a pinned `BLESSED` means grants that never
  expire" was backwards, and it is retired. Under a pinned program, an unpinned `BLESSED` is
  still alive, and its stale grants persist anyway, only unreachably. Pinning no maps at all
  leaves `BLESSED` failing closed on restart, exactly as DESIGN §16 step 9 specifies.
- **The singleton guard shipped.** It is an exclusive `flock` on `<socket>.lock`, taken before
  the daemon touches the kernel or the socket. It is keyed on the socket rather than on the
  pin directory, so it also covers dev daemons in user mode. It also fixes a standing bug.
  `serve` unlinks any socket inode it finds without checking whether anyone is listening. So
  a second daemon used to steal the first one's live socket and leave the first one running
  but unreachable.
- **The fast-allow had to be narrowed in the same milestone.** For `settings.daemon_pid`,
  `live_bank` returns `None`, which is a total bypass of every object with no log line.
  Pinning makes that record outlive the process that wrote it, so a recycled pid would
  inherit the bypass. `Settings` gained `daemon_exe`, and the kernel now requires both. It
  needed no new BTF offset. `caller_exe()` takes no arguments, so `live_bank`'s signature and
  the five-register ceiling are unchanged. And `&&` short-circuits on the pid, so the hot path
  is unaffected.
- **Teardown is explicit and asynchronous.** `systemctl stop` deliberately leaves the pins.
  So a stop, a restart and a crash are all gapless, and killing the log drainer never disarms
  the box. `cordond --teardown` removes the pins, and it refuses while a daemon holds the
  lock. Unlinking a pin only drops the link's last reference, and the kernel detaches from a
  workqueue. So anything that needs to observe the boundary going down must poll.
- Two smoke scenarios cover this milestone. `pinned_survives_daemon_death` kills the daemon
  with SIGKILL and asserts that both the deny and the allow still stand. It then tears down
  and asserts that the read succeeds. The other is `singleton_refuses_a_second_daemon`.

---

## Milestone 6 — Fixed code as the precondition for a grant ← **the remaining must-have**

> **The invariant.** A grant attaches only to a process that runs *the code it shipped with*.
> A process that executes foreign code in its own address space forfeits the grant. That
> covers a JIT, an interpreter running a script, and a preloaded library. Such a process is
> not denied by a rule. It has no subject identity worth granting to in the first place.

This is one rule with three enforcement points. It is stated as an invariant rather than as a
mechanism, because the mechanism alone (the taint below) catches only one of the three.

### Why "in its own address space" is load-bearing

Taken as a property of a program, the invariant can't be satisfied, and browsers are the
proof. Chrome runs attacker JavaScript all day, and it must read its own cookie DB or it is
not a browser. Taken as a property of a process, the invariant can be satisfied, because
well-built tools have already done the separation:

| tool | runs foreign code | where | grant survives? |
|---|---|---|---|
| Chrome / Firefox | web JS, JIT | a sandboxed renderer or content process | yes, because the browser or parent process holds the grant and runs no web JS |
| `ssh` | `ProxyCommand`, `LocalCommand` | `exec` into a new process with a new `exe` | yes, because exec resets identity and the child holds no grant |
| `git` | hooks, credential helpers, pager | `exec` | yes, for the same reason |
| `python3 script.py` | the script | the same process | no, because no boundary ever exists |
| `gdb`, `vim +python`, lua-linked daemons | an embedded interpreter | the same process | no, and no hook fires (see *Attestation*) |

So `exec` and the process boundary are what make the invariant reachable. Anything that mixes
untrusted code into the granted process's own address space is out, permanently and by
construction. That is not a tuning problem, and it is not a learning problem.

### The three enforcement points

| | catches | where | mechanism |
|---|---|---|---|
| **1. Attestation** | a program whose purpose is executing arbitrary code, such as `python`, `node`, `bash` or `deno` | `cordon policy check` | a policy lint, with no kernel code |
| **2. Taint** (the bulk of this milestone) | a fixed-code program that acquires code at runtime, through `LD_PRELOAD`, `dlopen` or anonymous RWX memory | `mmap_file` / `file_mprotect` / `ptrace_access_check` | a sticky bit for each `mm`, read as a `SubjectFlags` bit |
| **3. Sandbox state** | the untrusted half of a privilege-separated app, such as a Chrome renderer | `file_open` | a `SubjectFlags` bit taken from one-way task state (M2) |

Only (2) needs new machinery in the kernel. (1) is a lint over the compiled policy. (3) is a
subject predicate that belongs to M2's axis. M2 specifies it, and this section refers to it.

### The gap that (2) closes

`exe` is `mm->exe_file`. It is set once at `execve` and never updated. So it describes the
file that was exec'd, not the code that ends up running, and any dynamic loading breaks the
equivalence. `LD_PRELOAD=evil.so ssh -V` runs attacker code with
`mm->exe_file == /usr/bin/ssh` and inherits every grant that `ssh` has. Every static `allow`
is therefore a confused-deputy grant.

The preconditions are ordinary. `/usr/bin/ssh` is `0755`, not setuid, and has no file
capabilities. So `ld.so` is not in secure-execution mode, and it honours `LD_PRELOAD`. A
one-shot scraper running as the user can set an environment variable.

None of M2's predicates close the gap. `uid`, `gid` and `cgroup` are unchanged. `argv0` is
still `ssh`, and `ancestor-exe` is still the shell. An IMA or fsverity hash of the exe does
not help either. The exe genuinely is ssh, unmodified, so its hash is correct. The injected
code lives in a file that is never the subject of any check. This is the trap. M2 lists the
exe hash as resisting a binary swap, which is true and irrelevant, because nothing is
swapped.

### Attestation — enforcement point (1)

The taint structurally cannot catch an interpreter. `python3 evil.py` maps nothing
executable. The interpreter reads the script as data and executes it in its own loop, so no
hook fires, and the process is genuinely untainted. `exe` is `/usr/bin/python3`, unmodified,
and the code it runs is arbitrary. There is no runtime signal to find, so the exclusion has
to be static.

It must be an allowlist, not a blocklist. Enumerating interpreters is an unbounded task, and
§3 rejects exactly that shape (*unprofiled means unconfined*). The dangerous cases are not
the obvious ones. They are fixed ELF binaries with embedded interpreters, such as `gdb`,
`vim +python` and anything that links lua. These look like ordinary compiled tools and fire
no hook. So the check is inverted. A subject that appears in an `allow` rule must positively
attest that it runs fixed code. It does so with the same `code =` token that the policy
surface below introduces. Without an attestation, `cordon policy check` warns that the rule
is a confused-deputy grant. This limits the vetting to the handful of exes that actually hold
grants, rather than the whole system. The code-set enumeration makes the same argument.

**A recorded consequence is that the shipped example policy loses `allow /usr/bin/aws`.** The
aws CLI is Python, and M2's own audit signal records `python3`, not `aws`, opening `~/.aws`.
Under this invariant that rule cannot be made honest. The example policy should say so,
rather than model a grant that grants nothing. Expect the same verdict for most tooling
distributed through npm or Electron. Static `allow` rules become rare, and the rest of the
access goes through `bless`. That is the lever this plan already names, now reached
deliberately instead of by attrition.

**`bless` does not satisfy the invariant, and is not meant to.** A blessed `python` session
reads secrets. Blessing proves human presence, not code identity (DESIGN §16), so it is the
deliberate escape hatch from this rule. Naming it as an escape hatch keeps the invariant
honest. Otherwise it would be quietly violated in the one place where people reach for it
most.

### Why it must be caught at load time, not decision time

At `file_open`, you are inspecting state that the attacker controls and has had time to
launder:

- A constructor can patch whatever it wants and then `munmap` or `dlclose` itself.
- `environ` lives in the process's own writable memory, and it can be scrubbed.
- Injection need not touch a file at all. `ptrace` of a forked child is permitted under Yama
  `scope=1`, and anonymous `PROT_EXEC` memory needs no file.

There is no durable artifact to find. Walking the VMAs is also impractical, because they are
a maple tree on modern kernels, and the result would still need an expected set for each tool
to interpret it. So detection at decision time is structurally unsound, and not merely
difficult.

### The mechanism

The mechanism is a sticky taint, recorded when code is acquired and read as one more
predicate:

- **Set.** The taint is set at three hooks. The first is `mmap_file`, on a `PROT_EXEC`
  mapping of a file outside the subject's code set. It is also set on a mapping with a NULL
  file. `security_mmap_file` is called with `file == NULL` for anonymous mappings, and Linux
  does not enforce W^X. So a direct `mmap(PROT_EXEC|PROT_WRITE, MAP_ANONYMOUS)` never reaches
  `mprotect`. The second is `file_mprotect`, when existing memory is made executable. The
  third is `ptrace_access_check`, which taints the target. `process_vm_writev` goes through
  `ptrace_may_access`, so the same hook covers it.
- **Sticky.** The taint lasts for the life of the `mm`, so unloading the code launders
  nothing. Only `execve` clears it, because that loads a genuinely new program image. The
  attacker gains nothing by re-execing, because that discards the injection too.
- **Store.** This is still open, and it is the one question that changes the mechanism rather
  than its notes. Stickiness above is stated per `mm`, but `BPF_MAP_TYPE_TASK_STORAGE` is per
  task. Task-local storage is believed not to be copied on `clone`, which is why
  `security_task_alloc` exists. Verify that before relying on it, because the answer picks
  the map. If the taint does not inherit, two laundering paths open. In the first, a tainted
  process forks and the child starts clean. The second is worse, because no hook closes it.
  Thread A `dlopen`s the payload, while thread B, created earlier, keeps its own untainted
  storage and does the read. The `mm` is shared, and task storage is not. Hooking
  `task_alloc` to copy the parent's bit closes the fork path and covers threads created after
  the taint. Nothing closes threads that already exist. An LRU hash keyed on `task->mm`
  implements the stated invariant directly. Its cost is that there is no hook at free time to
  clean up on.
- **Read.** `file_open` reads the taint as a `SubjectFlags` bit, so a tainted process stops
  matching exe-based rules and falls through to the object's catch-all. That is fail-safe by
  construction. It needs no special-case code path, and it composes with copy-down and
  precedence unchanged. Note that the floor is the catch-all, not denial. On an object whose
  catch-all is `audit *`, a tainted process still reads the object and is merely logged. That
  is the intended composition, because the catch-all is the floor for everyone. But "tainted
  means denied" holds only where the catch-all denies, so it is a trap for policy authors that
  the docs must call out.

The subject was never `exe`. It is `exe AND untainted`.

The order of events is what makes this work. `ld.so` must map a preloaded library before the
library's constructor can run, so the taint lands before any attacker code executes.

### Why this is not a per-tool profile

It looks like AppArmor's `m` permission, but it is not. §3 rejects per-tool profiles because
an unprofiled program is unconfined. Here a code set is a precondition for a grant, not a
confinement mechanism. An exe with no code set gets no grant and falls to the catch-all deny.
An unprofiled program is denied. So the failure that makes MAC profiles fragile cannot arise,
and code sets are written only for the handful of exes that appear in `allow` rules, not for
the whole system.

### The code set is enumerated, not inferred

An earlier sketch used provenance. It would taint a process if the mapped file was writable by
the adversary, and trust a file that is root-owned and not writable by group or other. That
rule is cheap, and it is too weak. A legitimate root-owned library preloaded into `ssh`
satisfies provenance and is still an injection. Provenance answers "who wrote this file", but
the grant needs to know "is this the code that makes up ssh". Those are different questions,
and only the second one is what `allow ssh read ~/.ssh` means.

So the set is enumerated for each subject. Root ownership still earns its keep, but only in a
narrow way. The adversary cannot modify files under `/usr/lib`, so path identity is enough,
and no hashes or signatures are needed.

**Static derivation is off the table.** This was verified on 2026-07-27, not assumed:

- `ldd /usr/bin/ssh` lists 17 libraries.
- At runtime ssh also loads `libnss_*.so` modules, which libc dlopens on every hostname
  lookup. It loads krb5 plugins from `/usr/lib/krb5/plugins/{kdb,preauth,tls}/` and OpenSSL
  providers from `/usr/lib/ossl-modules/` too.
- **`/etc/nsswitch.conf` decides which `libnss_*` modules load.** That is runtime
  configuration, not the binary. On this host, the `hosts:` line alone pulls in
  `mymachines`, `mdns4_minimal`, `resolve`, `files`, `myhostname`, `dns` and `wins`.

So the set is a property of the binary plus the machine's configuration, and it cannot be read
out of the ELF. A hook that ran `ldd` would emit a set that breaks ssh the first time ssh
resolves a hostname, and that breaks differently on different machines. The set must be
learned, not derived. That is M4's machinery and §15.10's audit, admit, enforce flow, applied
to a second axis.

### Policy surface

The code set is a property of the subject, not of a rule, so it hangs off the subject group.
That is the shape `blessing` already established. One token is written by hand:

```toml
[group.subject.ssh-tools]
members = ["/usr/bin/ssh", "/usr/bin/ssh-add", "/usr/lib/gcr-ssh-agent"]
code = "learn"        # observe and journal, enforce nothing
# code = "strict"     # taint on any mapping outside the set
# code = "arbitrary"  # attested arbitrary-code executor, never eligible for a grant
#                     # (browsers, interpreters); `policy check` errors on an `allow`
```

The entries themselves are not policy. They are facts about the machine, in the same category
as the `(dev,ino)` resolutions that cordon already performs silently at apply time. They live
in a generated, root-owned sidecar file:

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

Groups keep the set small. §15.7 makes groups symmetric across the axes, and code is simply a
fourth axis. Nearly all of the bulk is shared, because libc, libcrypto and libz appear under
every subject. So a `[group.code.base]` absorbs it. What is left for each subject is the
genuinely distinctive handful, such as krb5 and NSS for ssh, and gpgme for gopass. Expect
about 40 lines of `@base` plus 5 to 10 for each subject. That is around 150 authored lines,
against a compiled map of about 600 `(exe, lib)` pairs. Humans do not read the compiled forms.

The verbs match the existing `policy` and `bless` surface. They are
`cordon code show <subject>`, `cordon code promote <subject>` and `cordon code check`.

### Flows

**Initial setup.** The code axis reuses the rhythm of the object axis, so there is nothing new
to learn:

```sh
# objects first: today's flow, unchanged
sudo cordon policy edit          # @secrets at `audit`
… use the machine a week …
journalctl -u cordond            # see who actually touches what
sudo cordon policy edit          # admit the owners you saw
sudo cordon policy edit          # flip audit to deny

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

Nobody ever types a library path by hand. `learn` only observes and journals, so it is safe
to leave on indefinitely, and there is no pressure to rush to `strict`.

**System upgrade.** Usually an upgrade needs nothing:

```sh
sudo pacman -Syu
#   (cordon) re-resolving code sets… 5 subjects, 0 drift
#   (cordon) policy applied
```

Paths are stable across an upgrade, and only inodes change. The pacman hook runs
`cordon policy apply`, which re-resolves them. The diff is empty, so there is nothing to
review and nothing to do.

When a package gains a dependency, the hook catches the common case before it bites. It
compares the new binary's `DT_NEEDED` entries against the recorded set. That check is
incomplete, because it cannot see `dlopen`. But it checks a strict subset of what loads, so
anything it flags is real:

```
(cordon) WARNING @ssh-tools: /usr/bin/ssh gained a dependency that is not in its
         code set: /usr/lib/libfido2.so.1
         ssh will lose its grants until:  sudo cordon code promote @ssh-tools
```

Something can still slip past the check, such as a newly `dlopen`ed module, which is exactly
what static analysis cannot predict. Then the failure is soft and diagnoses itself:

```
WARN  taint pid=8812 exe=/usr/bin/ssh lib=/usr/lib/libfido2.so.1 \
            subject=@ssh-tools reason=not-in-code-set
INFO  deny  pid=8812 user=nb exe=/usr/bin/ssh object=~/.ssh \
            path=~/.ssh/id_ed25519 action=read policy=default-deny tainted=1
```

**Taint revokes the grant, and it does not break the program.** ssh still runs, and falls back
to a password. The journal names the exact library, and recovery takes one `promote`. That
asymmetry is what makes the design deployable. A false positive costs a password prompt, not
a broken tool.

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
| `LD_PRELOAD=/usr/lib/libfoo.so` (root-owned) | it passes provenance, but it is not in ssh's set, and this is the case that makes enumeration necessary |
| `dlclose` to hide the evidence | the taint is sticky for the life of the `mm` |
| `ptrace` a forked ssh | `ptrace_access_check` taints the target |
| re-exec to clear the taint | `execve` clears it, but it discards the injection too |
| `LD_AUDIT` instead of `LD_PRELOAD` | it takes the same `mmap_file` path, and the mechanism does not care how the load was requested |
| fork after tainting, read from the child | it fails only if the taint propagates, and task storage may not be copied on `clone` (see *Store*) |
| taint one thread, read from a sibling | no hook closes this if the taint is per task, because the `mm` is shared and the storage is not |

### Rejected alternatives

- **Glob the trust set** (`/usr/lib/*`). It takes three lines instead of 600, and it is
  exactly the provenance rule this milestone exists to replace. `LD_PRELOAD` of any system
  library passes it.
- **Package granularity** (`code = ["openssh", "glibc", "krb5"]`, expanded with
  `pacman -Qlq`). It is stable across upgrades and has a human scale. But glibc ships about
  50 libraries where ssh uses about 8, so all 50 become loadable. It also couples cordon to a
  package manager.
- **`ldd` or `DT_NEEDED`.** These are static, blind to `dlopen`, and only cover one exe. See
  the nsswitch finding.
- **Detect `LD_PRELOAD` in the environment** at `bprm_check_security`. That is a bounded walk
  over the new stack. `LD_AUDIT`, `/etc/ld.so.preload` and `ptrace` all defeat it, and none of
  them touch the environment. It is whack-a-mole that only reads like a mitigation.
- **Force `AT_SECURE`** on gated binaries, since `ld.so` ignores `LD_PRELOAD` for setuid and
  file-capability executables. It genuinely works. But it means granting `/usr/bin/ssh` a
  capability it does not need, system-wide and for every user, just to obtain a side effect.

### Honest limits

- **A JIT taints itself, which is correct, and it is not the reason interpreters are
  excluded.** V8 makes anonymous memory executable on startup. So `node`, `deno`, the JVM and
  Chrome trip `file_mprotect` on their own first JIT page, immediately, with no attacker
  present. `code = "strict"` is therefore structurally unusable for them. But attestation
  already excluded them, for a prior and more basic reason. They execute arbitrary code with
  no injection at all. `python evil.py` involves no JIT and is just as disqualifying. Do not
  read the JIT taint as the answer for interpreters. It is a correct second signal on a
  subject that should never have held a grant.
- **Browsers are where the JIT taint genuinely bites.** Unlike an interpreter, a browser has a
  stable identity and a legitimate need for its own profile directory. The cookie DB is the
  single most valuable scraper target on a desktop. Enforcement point (3) is the answer. The
  grant attaches to the unsandboxed side, and one-way sandbox state that the JIT-running
  renderers cannot shed excludes them. This was measured, not assumed, and the table under
  M2's `unsandboxed` bullet has the numbers. The guess it replaces was that Chrome's cookie DB
  had moved to a sandboxed network service, and would land on the wrong side of the
  predicate. It has indeed moved there. But on Linux that service runs unsandboxed, so it
  lands on the right side by luck rather than by design. That is the fragile part of the whole
  enforcement point, and it is specific to Chrome. Firefox's split is clean. Its parent holds
  every secret DB, and all 18 content processes run under seccomp in their own namespaces.
- **ROP** maps nothing and loads nothing. It chains fragments of code that is already mapped
  and already legitimate. So no hook fires, and the process stays untainted. The defences are
  at the compiler and CPU level (CFI, shadow stacks, Intel CET), not at the LSM level.
- **A gadget already inside the subject's own code set still works.** 31 libraries are a far
  smaller search space than all of `/usr/lib`, but the space is not empty. This is where IMA
  appraisal would compose usefully, rather than pretending to be a fix on its own.
- **Preloading a library that is already in the set** reorders symbol resolution. So
  interposition between expected libraries remains possible. That is much narrower than
  arbitrary preloading, and it is accepted.
- The trust set needs tuning where tools legitimately load code from `$HOME`. nvim's compiled
  treesitter parsers under `~/.local/share/nvim` are the obvious first case.

### Implementation notes

- Hooks: `mmap_file`, `file_mprotect` and `ptrace_access_check`. All three are ordinary BPF
  LSM attach points, and the same `clamped()` return discipline applies.
- Maps: `CODE_SETS: HashMap<FileId exe, mode>` is probed first, and then
  `ALLOWED_CODE: HashMap<(FileId exe, FileId lib), ()>`. The second map holds about 600
  entries for a policy with 15 subjects. The composite key alone cannot tell "this exe has no
  code set" from "this library is not in the set". So without the `CODE_SETS` probe, the
  first library that any process on the box maps would miss, and every process would taint
  and pay for the lookup. `CODE_SETS` also says whether the mode is `learn` or `strict`.
- Taint: one bit, cleared on `execve`. The choice of map and the propagation across fork and
  threads are the open question in *The mechanism* above. Settle that before writing the
  hooks, because it decides whether `task_alloc` is a fourth attach point.
- `SubjectFlags` gains an `UNTAINTED` bit. §15.4 notes that a fifth predicate bit extends
  matching and specificity for free.
- No new BTF offsets are needed. The hooks hand over a `struct file *`, and the existing chain
  from `file_f_inode` through `inode_i_ino` and `inode_i_sb` to `sb_s_dev` already yields a
  `FileId`.
- **In the meantime, the deployment answer is `bless`.** A per-invocation cgroup grant has no
  standing exe rule to inject into, so preloading gains nothing. The lever is the ratio of
  static `allow` rules to blessings.

### Task order

Attestation comes first. It is the cheapest of the three and needs no kernel code. It is also
what tells you which subjects the rest of the milestone is for.

1. **`code =` on subject groups.** Parse and resolve `arbitrary`, `learn` and `strict`, plus
   the case where the token is absent. This is pure userspace.
2. **The attestation lint in `cordon policy check`.** It errors on an `allow` whose subject
   attests `arbitrary`, and warns on one with no attestation at all. It ships independently of
   everything below, and it immediately makes the confused-deputy grants in an existing policy
   visible.
3. **Retire `allow /usr/bin/aws` from the example policies**, and record the reason inline,
   so the shipped examples stop modelling a grant that cannot be honest.
4. **Settle where the taint is stored**, either per task with a `task_alloc` hook or in an LRU
   keyed by `mm`. Verify the `clone` semantics first, because they decide the map and whether
   there is a fourth hook.
5. **Seed `CODE_SETS` and `ALLOWED_CODE`**, then add the three taint hooks, then the
   `UNTAINTED` bit in `SubjectFlags`.
6. **Learning, and `cordon code show|promote|check`.** This is M4's machinery on a second axis.

Enforcement point (3), the `unsandboxed` predicate, is sequenced under M2. It is gated on the
cookie-DB measurement, not on any of the tasks above.

## Carried-over notes (still live)
These are loose ends left by shipped work, and none of them is a milestone of its own:
- **`MAX_RULES_PER_OBJ = 32`.** Raise it toward 64 if a verifier log demands it.
  `cordon policy check` errors when a compiled bucket exceeds it.
- **A per-object default is deferred.** A protected object with no matching rule falls to the
  global default-deny (§15.6.3). A per-object default was considered and parked.
- **Group expansion is a lever, not a law.** Subject groups expand at compile time, so the
  number of bucket entries grows with the size of a subject group times the object nesting
  depth. If that ever binds, keep groups as a `(GroupId, exe)` membership map instead of
  expanding them.
- **conf.d diagnostics don't carry the fragment name.** Parse and resolve errors name their
  fragment. Compile-stage diagnostics, such as pending-path warnings, carry only `line:col`.
  A source id on `Pos` would close the gap.
- **Tier precedence is flat.** The rule that the system tier is a floor (a user tier may
  tighten it but never loosen it) can't be expressed in one first-match bucket. It only bites
  once user files are owned by their users, so it lands with the home migration below.
- **Home migration.** User-tier files are root-owned under `/etc` today. The roadmap moves
  them to `~user/.config/cordon/`, with cordon cordoning its own user-policy file. That file
  would be a protected object that only an authorized editor may write. That self-protection
  is the future "edit without sudo".
  - **M5 adds a precondition to it.** `compile_policy()` runs before the new generation loads.
    So the previous generation mediates it, and that generation does not fast-allow the new
    daemon, because the fast-allow checks pid and exe and the pid is new. A policy file that
    cordons itself must therefore carry an explicit rule that lets cordond's exe read it.
    Otherwise the next daemon cannot compile its own policy, and the box stays on the old
    policy until `cordond --teardown`. This is not a live problem, because the shipped
    examples protect no policy file. But do not discover it the hard way.

## The policy surface
DESIGN §15.8 specifies the authored TOML, and two regression-tested examples show it.
[`packaging/cordon.example.policy.toml`](../packaging/cordon.example.policy.toml) uses
verbose `[[rule]]` tables, and
[`packaging/cordon.example.dsl.policy.toml`](../packaging/cordon.example.dsl.policy.toml) uses
the compact one-rule-per-line DSL. The compiled shapes are in
`crates/bpf-common/src/policy_maps.rs`.
