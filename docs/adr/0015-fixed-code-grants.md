# 0015. Fixed code as the precondition for a grant

Status: Proposed. The remaining must-have; its tasks are M6 in [todo.md](../../todo.md).

## Context

`exe` is `mm->exe_file`. It is set once at `execve` and never updated. So it describes the
file that was exec'd, not the code that ends up running, and any dynamic loading breaks the
equivalence. `LD_PRELOAD=evil.so ssh -V` runs attacker code with
`mm->exe_file == /usr/bin/ssh` and inherits every grant that `ssh` has. Every static `allow`
is therefore a confused-deputy grant.

The preconditions are ordinary. `/usr/bin/ssh` is `0755`, not setuid, and has no file
capabilities. So `ld.so` is not in secure-execution mode, and it honours `LD_PRELOAD`. A
one-shot scraper running as the user can set an environment variable.

None of the planned subject predicates ([ADR 0006](0006-subject-predicates.md)) close the gap.
`uid`, `gid` and `cgroup` are unchanged. `argv0` is still `ssh`, and `ancestor-exe` is still
the shell. An IMA or fsverity hash of the exe does not help either. The exe genuinely is ssh,
unmodified, so its hash is correct. The injected code lives in a file that is never the subject
of any check. This is the trap. The exe hash resists a binary swap, which is true and
irrelevant, because nothing is swapped.

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

## Decision

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
| **2. Taint** (the bulk of the work) | a fixed-code program that acquires code at runtime, through `LD_PRELOAD`, `dlopen` or anonymous RWX memory | `mmap_file` / `file_mprotect` / `ptrace_access_check` | a sticky bit for each `mm`, read as a `SubjectFlags` bit |
| **3. Sandbox state** | the untrusted half of a privilege-separated app, such as a Chrome renderer | `file_open` | a `SubjectFlags` bit taken from one-way task state |

Only (2) needs new machinery in the kernel. (1) is a lint over the compiled policy. (3) is a
subject predicate on [ADR 0006](0006-subject-predicates.md)'s axis, specified under *Sandbox
state* below.

### Attestation — enforcement point (1)

The taint structurally cannot catch an interpreter. `python3 evil.py` maps nothing
executable. The interpreter reads the script as data and executes it in its own loop, so no
hook fires, and the process is genuinely untainted. `exe` is `/usr/bin/python3`, unmodified,
and the code it runs is arbitrary. There is no runtime signal to find, so the exclusion has
to be static.

It must be an allowlist, not a blocklist. Enumerating interpreters is an unbounded task, and
[ADR 0001](0001-object-centric-gating.md) rejects exactly that shape (*unprofiled means
unconfined*). The dangerous cases are not the obvious ones. They are fixed ELF binaries with
embedded interpreters, such as `gdb`, `vim +python` and anything that links lua. These look
like ordinary compiled tools and fire no hook. So the check is inverted. A subject that appears
in an `allow` rule must positively attest that it runs fixed code. It does so with the same
`code =` token that the policy surface below introduces. Without an attestation,
`cordon policy check` warns that the rule is a confused-deputy grant. This limits the vetting
to the handful of exes that actually hold grants, rather than the whole system. The code-set
enumeration makes the same argument.

**A recorded consequence is that the shipped example policy loses `allow /usr/bin/aws`.** The
aws CLI is Python, and the first audit run recorded `python3`, not `aws`, opening `~/.aws`.
Under this invariant that rule cannot be made honest. The example policy should say so,
rather than model a grant that grants nothing. Expect the same verdict for most tooling
distributed through npm or Electron. Static `allow` rules become rare, and the rest of the
access goes through `bless`. That is the lever *Implementation notes* names, now reached
deliberately instead of by attrition.

**`bless` does not satisfy the invariant, and is not meant to.** A blessed `python` session
reads secrets. Blessing proves human presence, not code identity ([ADR
0012](0012-blessing.md)), so it is the deliberate escape hatch from this rule. Naming it as an
escape hatch keeps the invariant honest. Otherwise it would be quietly violated in the one
place where people reach for it most.

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

It looks like AppArmor's `m` permission, but it is not. [ADR
0001](0001-object-centric-gating.md) rejects per-tool profiles because an unprofiled program is
unconfined. Here a code set is a precondition for a grant, not a confinement mechanism. An exe
with no code set gets no grant and falls to the catch-all deny. An unprofiled program is
denied. So the failure that makes MAC profiles fragile cannot arise, and code sets are written
only for the handful of exes that appear in `allow` rules, not for the whole system.

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
learned, not derived. That is the autolearn machinery ([ADR 0011](0011-autolearn.md)) and
[authoring flows](../authoring.md)'s audit, admit, enforce flow, applied to a second axis.

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

Groups keep the set small. [ADR 0009](0009-groups.md) makes groups symmetric across the axes,
and code is simply a fourth axis. Nearly all of the bulk is shared, because libc, libcrypto and
libz appear under every subject. So a `[group.code.base]` absorbs it. What is left for each
subject is the genuinely distinctive handful, such as krb5 and NSS for ssh, and gpgme for
gopass. Expect about 40 lines of `@base` plus 5 to 10 for each subject. That is around 150
authored lines, against a compiled map of about 600 `(exe, lib)` pairs. Humans do not read the
compiled forms.

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

### Sandbox state — enforcement point (3)

This is enforcement point (3) of the invariant, a new `unsandboxed` subject predicate, and it
is the answer for browsers. A privilege-separated app splits itself into a trusted process that
touches the profile, and untrusted processes that run web JS. The grant must attach only to the
trusted one. argv (`--type=renderer`, `-contentproc`) names the split, but it is forgeable. A
compromised renderer can rewrite `mm->arg_start..arg_end` with a memcpy. So the predicate
matches on the sandbox state itself, which is one-way kernel state that the task cannot shed.
The tests are `task->seccomp.mode != 0` and `cred->user_ns != &init_user_ns`, the latter being
Chrome's layer-1 namespace sandbox. That costs two dereferences, resolved through BTF like the
existing chain from `file` to `inode` to `sb`, and one more `SubjectFlags` bit, which extends
matching and specificity for free (see `SubjectFlags` in
`crates/bpf-common/src/policy_maps.rs`). The predicate is strictly fail-safe against an
attacker, because it only ever narrows an `exe` grant. Someone who declines to sandbox
themselves still fails the `exe` check.

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
## Alternatives rejected

- **Glob the trust set** (`/usr/lib/*`). It takes three lines instead of 600, and it is
  exactly the provenance rule this ADR exists to replace. `LD_PRELOAD` of any system
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

## Consequences

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
  *Sandbox state* has the numbers. The guess it replaces was that Chrome's cookie DB
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
  threads are the open question in *The mechanism* above. Settle that before writing the hooks,
  because it decides whether `task_alloc` is a fourth attach point.
- `SubjectFlags` gains an `UNTAINTED` bit. Its doc in `crates/bpf-common/src/policy_maps.rs`
  notes that a fifth bit extends matching and specificity for free.
- No new BTF offsets are needed. The hooks hand over a `struct file *`, and the existing chain
  from `file_f_inode` through `inode_i_ino` and `inode_i_sb` to `sb_s_dev` already yields a
  `FileId`.
- **In the meantime, the deployment answer is `bless`.** A per-invocation cgroup grant has no
  standing exe rule to inject into, so preloading gains nothing. The lever is the ratio of
  static `allow` rules to blessings.

