# STATUS

> This file is the resume point. It says what exists, what is left, and which facts cost real
> time to learn. It is deliberately not a changelog. Finished work is described in the present
> tense or not at all, and `git log` has the rest.

## Where things stand

The architecture is the flat rule model ([ADR 0005](docs/adr/0005-flat-rule-model.md)). A root-owned text policy of
`(who, where, action, policy)` rules is compiled in userspace and enforced in the kernel by
the `bpf-lsm` backend. M1, M3 and M5 are complete and VM-validated, and so are blessing stages
B1 and B2 ([ADR 0012](docs/adr/0012-blessing.md)). The `bpf-lsm-smoke.sh` suite is green on the CI-pinned v6.12 kernel.
The migration retired the earlier owner model, as *Pre-rule-model history* below describes.

Enforcement is now fail-safe. The LSM links are pinned to bpffs, so the boundary survives the
daemon crashing, being killed, or being restarted. M6 is the last must-have.

What is left is in [`todo.md`](todo.md).

## What's implemented

**The rule pipeline.** It runs in three stages. `parse` turns TOML into spans. It accepts both
the verbose `[[rule]]` surface and the compact one-rule-per-line DSL, and normalizes both to
one `ParsedRule`. `resolve` expands groups on all three axes, validates cycles and
references, and expands `~`. `compile` takes the cross product, applies copy-down object
precedence, and produces sorted, deduplicated per-object buckets with a size cap.
Diagnostics carry a source `Pos`. The compiled form is the contract in
`crates/bpf-common/src/policy_maps.rs`.

**Precedence.** Precedence goes by object depth first, then by subject specificity, then deny
over allow. There is no global mode. The per-rule `policy` is the only enforcement level, so
`audit` observes an object and `deny` enforces it, one object at a time. That is what makes
the audit, admit, enforce flow ([authoring flows](docs/authoring.md)) work object by object. "Off" means an empty policy or
`cordond --teardown`. Stopping the daemon leaves enforcement up (see *Fail-safe pinning*
below).

**In the kernel** (`crates/bpf`, `file_open`). The program walks the dentry chain up to the
deepest `PROTECTED` object and derives the action from `f_mode` and `f_flags`. It then scans
the packed `RULES` bucket for the first match, and denies by default when nothing matches.
Records carry the actual opened path, rebuilt from `d_name` up to the matched object
(`fill_comps` in `crates/bpf/src/kernel.rs`), because `bpf_d_path` is unavailable at
`file_open`.

**Sound directory objects** (`inode_link`, `inode_rename`, `inode_unlink`, `inode_rmdir`). A
directory protects its children by ancestry. So a second name for a protected inode, made by
a hardlink or by a rename out of the directory, gives it an ancestry that avoids the object.
The file would then be readable by everything, permanently and without a log line. The escape
case, where a protected inode takes a name outside its object, is refused unconditionally.
It gets no rule lookup and no blessing exemption. The clobber and destroy cases are ordinary
writes and take the subject's verdict, so `audit` objects keep working. A rename inside the
object short-circuits, and that is what keeps atomic save working inside a protected
directory. `inode_mkdir` joins these hooks and classifies by the parent directory, because a
dentry that is about to be created is negative and matches nothing itself. Every mutation
program shares `find_object`, so each one enters with a dentry rather than a `struct file`.
A rename over an existing name is a fourth case. It is classified by the destination dentry
rather than by its directory. Such a rename destroys the inode at the destination, and
`inode_rename` is the only hook the kernel fires for it. Without this case,
`mv anything secret` would do what `rm secret` is refused (`decide_reparent` in
`crates/bpf/src/main.rs`). See [ADR 0007](docs/adr/0007-action-hook-map.md).

**Volume control.** Tools re-open one config hundreds of times per run (helm opens
`~/.kube/config` 464 times). So an in-kernel LRU suppressor emits at most one event per key
per second and folds the rest into a `suppressed` count (`throttle` in
`crates/bpf/src/kernel.rs`). The key is `SuppressKey`, which holds `(exe, opened file,
action)`, so sibling files under one object surface separately. The daemon's `coalesce` then
folds each drain batch into one journal line per key.

**Atomic apply.** The three rule maps are banked, so a re-seed is never half-visible.
`Maps::seed` in `crates/daemon/src/backend/bpf_lsm/seed.rs` fills the inactive bank and flips
`Settings.active_bank`. There is a single writer by construction, because every map write goes
through the one `ControlMsg` channel to the backend thread that owns the `&mut Ebpf`.

**Fail-safe pinning.** The seven LSM links are pinned to bpffs, and nothing else is. A pinned
link holds its program, and a program holds its maps. So the boundary, including the seeded
policy, stays up with no process holding it. A restarting daemon adopts nothing. That keeps
the single-writer invariant, and it means an upgrade never drives the old kernel program.
`PinDir::pin_links` in `crates/daemon/src/backend/bpf_lsm/pin.rs` owns the handover order and
the generation directory made for each run. What the handover buys is that the previous
boundary stands until the replacement is proven, so a daemon that aborts on a bad policy
leaves enforcement up. Two consequences surprise people. `systemctl stop cordond` does not
stop enforcement. `cordond --teardown` does, and it refuses to run while a daemon runs. And
teardown is asynchronous (`PinDir::teardown`), so anything that must see the boundary down
has to poll.

**One daemon per socket** (`acquire_singleton` in `crates/daemon/src/main.rs`). Pinning
requires it, because two daemons would race over the pin paths. Removing a pin to place your
own would also detach a boundary that its owner still believes in. The socket requires it
too. `serve` unlinks any socket inode it finds, so without the lock a second daemon would
silently steal the first one's live socket.

**Policy tiers.** The effective policy is the system tier combined with the user tier. A
system fragment pulls in a user-tier file with `[[include]] user = … path = …`. The included
file is home-scoped, which means its objects must resolve under that user's `~`, and it may
not include anything itself. A policy path may be one file or a conf.d directory of fragments
merged in name order. Each fragment can expand `~` against its own `user =` header.

**CLI.** The commands are `policy check` (a lint that needs no daemon), `apply`, `show`,
`status`, and `policy edit`. `policy edit` is the sudoedit analog. It runs `$EDITOR` as the
invoking user, because a root editor on a same-uid box is an escalation ([threat model](docs/threat-model.md)). It then
validates the policy, and if the policy compiles, it applies and saves it in one step. Bare
`edit` opens your own tier, and `--system` and `--user NAME` open the others.

**Socket authorization** (`authorize` in `crates/daemon/src/ipc.rs`). `PolicyApply` and
`BlessApprove` require peer uid 0, as `SO_PEERCRED` reports it. Reads and `BlessRequest` are
open, because a request does nothing until it is approved. `BlessRevoke` is open at the
socket, and the backend checks ownership. The caller must be root or the uid that minted the
blessing. The match is exhaustive, so nobody can add a new verb without picking a side. The
socket mode is `0666`. The mode decides who can reach the daemon, and the table decides what
they may do.

**Blessing** (`cordon bless`). A blessing is one more `SubjectMatch` predicate, so a blessing
rule is an ordinary rule, and its scope is the rule's object column. `cordon bless` runs
unprivileged. It checks that the daemon runs as root, sends a request, and holds the
connection open. A helper spawned under `$CORDON_SUDO` reaches the daemon as uid 0, and that
is the entire proof of human presence. The daemon then creates a root-owned carrier cgroup
inside the requester's own user subtree, and passes back the carrier's `cgroup.procs`
descriptor over `SCM_RIGHTS`. The CLI forks, and the child joins the carrier in `pre_exec`. So
the target never runs unblessed, and the CLI never holds privilege. The environment, cwd, tty,
job control and session are inherited by construction.

## What's left

[`todo.md`](todo.md) holds every remaining step, in order. M6 is the last must-have
([ADR 0015](docs/adr/0015-fixed-code-grants.md)), and blessing's B3 and B4 wait behind it. The
rule is *soundness before ergonomics*. Until M6 ships, the deployment answer is `bless`: a
per-invocation grant has no standing exe rule to inject into.

## Settled, do not redo

- **Adopting existing pins on restart was specified, then dropped as unnecessary.** The M5
  text said "pin program + maps + link; adopt existing pins on startup". Pinning the links
  alone delivers the whole property, because a link holds its program and a program holds its
  maps. So adoption has nothing left to buy. What adoption costs is real. It needs a mandatory
  cross-process writer lock on the banked flip. It brings a stale-program-after-upgrade trap,
  which needs an ABI or build-id check plus a replace path as a fallback. And it conflicts
  directly with the startup self-test. The self-test writes bank 0 and `SETTINGS` before
  `Maps::seed`, so it would briefly clobber a live adopted policy. Replacing on start has none
  of these problems, and it is gap-free anyway, because the new generation attaches before
  the old one is swept.
- **"Pin the policy maps only, because a pinned `BLESSED` means grants that never expire" is
  backwards.** Under a pinned program, an unpinned `BLESSED` is still alive, because the
  program holds a reference to it. So its stale grants persist exactly the same and merely
  become unreachable, which is strictly worse than pinning it. The point is moot under the
  link-only design. That design pins no maps at all, so `BLESSED` keeps its fail-closed
  behaviour on restart exactly as [ADR 0014](docs/adr/0014-blessing-lifecycle.md) step 9 specifies. Do not "fix" this by pinning
  maps.
- **The daemon fast-allow tests both `daemon_pid` and `daemon_exe`, and it must stay that
  way.** `live_bank` returns `None` for the daemon's own pid, and that is a total bypass of
  every protected object with no log line. Pinning makes `SETTINGS` outlive the process that
  wrote it. So a pid-only test would hand that bypass to whatever process recycles the pid
  while the daemon is down. The exe half costs nothing on the hot path, because `&&`
  short-circuits on the pid. It needed no new BTF offset either, because `caller_exe()` takes
  no arguments and leaves `live_bank`'s signature (and the five-register ceiling) untouched.

- **Replacing `PathBuf` with `Box<Path>` for stored path fields was tried wholesale and
  reverted.** The premise was that the type would say "built once, never mutated". It doesn't
  say that. Anything holding `&mut self` can reassign a `Box<Path>` field just the same, so the
  change only removes in-place growth, which nothing was calling. What it adds is real. It
  needs `.into()` at every construction, `.to_path_buf()` at every owned read, and
  `.as_os_str()` because `Box<Path>` is not `AsRef<OsStr>`. It also adds a rule about fields
  versus transient values that everyone has to keep straight forever. If the intent needs
  recording, a doc line on the field costs nothing.

## Durable kernel facts

- **A pinned `bpf_link` keeps its whole apparatus alive.** The link holds a reference to its
  program, and the program holds references to its maps. So one pinned link per hook keeps
  the programs and the seeded policy resident with no process attached. This is why M5 pins
  links and nothing else.
- **Unlinking a pin detaches asynchronously.** This was measured on 2026-07-28 in the VM, and
  it will bite anyone who assumes otherwise. Removing the bpffs entry only drops the link's
  last reference. The kernel frees the link, and detaches the hooks, from a workqueue. So
  enforcement outlives the return of `cordond --teardown` by a beat. The first version of the
  smoke suite failed on exactly this, and its `rm -rf` of the workspace was refused because
  the boundary was still up. Poll for the effect, and never assume it is immediate.
- **`BPF_OBJ_PIN` refuses a path outside a bpffs with `EINVAL`.** So a `statfs`
  `BPF_FS_MAGIC` pre-check buys nothing but a nicer message. The kernel already makes it
  impossible to pin into a regular directory and silently keep working.
- **`/proc/self/exe` stops being resolvable once the binary is replaced.** This was measured
  on 2026-07-28. After a package upgrade renames a new file over a running daemon's
  executable, `readlink` gives `…/cordond (deleted)`, and `std::fs::canonicalize` fails with
  `ENOENT`. So `proc::file_id`, which canonicalizes before it consults the mount table,
  returns `None`. A `stat` through the magic link still reports the original inode, but cordon
  uses the path-based route. This is why `seed::daemon_exe` resolves once and memoizes the
  result (its doc has the full argument). Do not "simplify" it back into a lookup on every
  call.
- `bpf_d_path` is not allowed at `file_open`. So identity is the inode `(dev, inode)` pair,
  never a path, and the daemon resolves it at seed time.
- The daemon takes the device from the mount table (`/proc/self/mountinfo`). That device
  matches the kernel's `sb->s_dev` on overlayfs and btrfs, where `stat`'s `st_dev` does not.
- Loading an LSM program needs `CAP_BPF` and `CAP_MAC_ADMIN`, with `lockdown` off. An object
  built against one kernel runs on another, because BTF-resolved field offsets are injected
  at load time. rustc can't emit CO-RE relocations.
- On cgroup2 (kernfs), a directory's `st_ino` is the id that `bpf_get_current_cgroup_id()`
  returns. That is what lets the daemon key `BLESSED` by a carrier it just created.
- **logind is not needed to test carrier placement.** A session scope is a root-owned cgroup
  directory in the shape that systemd makes, and everything under test is kernel mechanics.
  Only the claim that polkit is then satisfied is host-only.
- **Overlayfs does not bypass the ancestor walk.** This was measured on 2026-07-27 on
  7.1.4-zen, against the live `deny` on `~/.npmrc`. An unprivileged `unshare -Urm` with an
  overlay over `$HOME`, read through the overlay, journaled
  `object=~/.config path=~/.config/dconf/user`. That is the real object and the real dentry
  chain. Overlayfs hands `security_file_open` the underlying dentry, so no `sb_mount` gating
  is needed. Do not re-derive this from first principles. The argument that `f_path` is the
  overlay path predicts the opposite, and it is wrong here.
- **Browsers really do separate the JS from the secrets.** This was measured on 2026-07-27 on
  7.1.5-zen1-1-zen, with Firefox 153.0 and headless Chrome 150.0.7871.46. Firefox is clean.
  The parent process holds `cookies.sqlite`, `key4.db`, `formhistory` and `places`, and no
  content process holds any of them. All 18 content processes run at `Seccomp 2`, each in its
  own namespace. Chrome splits the loot. `Login Data` and `Web Data` are in the browser
  process, and `Cookies` is in the network service. That service is on the right side of an
  `unsandboxed` test only because Linux runs it with `--service-sandbox-type=none`. It is
  sandboxed on Windows and macOS, so this can break. In both browsers, both signals exclude
  every process that runs web JS. Use the conjunction `Seccomp == 0 && ns/user == init`.
  Chrome's renderer zygotes are `Seccomp 0` in the sandboxed namespace, so either signal alone
  lets them through. The details and caveats are in [ADR 0015](docs/adr/0015-fixed-code-grants.md).
- **BPF passes at most five arguments in registers**, and it has no call stack for the rest.
  So a wider function must be `#[inline(always)]`, or it fails to link with "stack arguments
  are not supported". Inlining is more than a linkage workaround, too. Outlining `emit` added
  a fifth call frame, and the v6.12 verifier rejected the whole object with `E2BIG` and a
  storm of `mark_precise: frame4` lines. `consult` sits exactly at the five-argument ceiling.
- **`RENAME_EXCHANGE` fires `inode_rename` twice.** This was verified on 2026-07-28 in the VM,
  not reasoned from the source. `security_inode_rename` calls the hook once with the pair
  swapped, before the ordinary call. So both directions reach the escape check, and that is
  the only reason an exchange cannot walk a protected inode out of its object. It matters only
  where the object allows write. Otherwise the destroy or clobber check refuses first, and
  that hides whether the second call happened at all. The `rename_exchange` scenario is built
  around that case. Do not "simplify" it to a denying object, which would make it pass
  without testing anything.
- At the mutation hooks, the trusted context argument is a dentry, not a `file`. The verifier
  range-checks offsets applied to trusted pointers against `.rodata`. So the `dentry_d_*`
  offsets must stay real in `maybe_poison_offsets`, or the failure-path test aborts at load
  time instead of at the self-test.

## Pre-rule-model history (retired)

Phases 0 to 3 built an owner model. It had explicit rules plus TOFU creator-owns, a root-owned
SQLite store, and a privilege-agnostic core. It ran on two enforcement backends, and both were
VM-validated. One was a root `fanotify` `FAN_OPEN_PERM` backend (Phase 1). The other was an
in-kernel `bpf-lsm` backend that enforced `subtrees` and `owner_identities` (Phase 3). The
rule-model migration replaced all of it. Owners, TOFU and rules collapsed into one
`(who, where, action, policy)` model. The SQLite store and the `mock` and `fanotify` backends
were removed, and `bpf-lsm` is now the only backend. The detail lives in git history.
