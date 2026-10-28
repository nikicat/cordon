# Architecture

Where each piece of cordon lives, and what it does today. The decisions behind them are in
the [ADRs](adr/README.md), and what is left is in [todo.md](../todo.md).

**The rule pipeline** (`crates/core/src/policy`). `parse` turns TOML into a `ParsedPolicy`
that keeps source spans, accepting both the verbose `[[rule]]` surface and the compact
one-rule-per-line DSL. `resolve` expands groups on all three axes and expands `~`. `compile`
applies copy-down precedence ([ADR 0008](adr/0008-precedence.md)) and produces sorted,
size-capped per-object buckets. The compiled form is the contract in
`crates/bpf-common/src/policy_maps.rs`. There is no global mode: the per-rule `policy` is the
only enforcement level, so "off" is an empty policy or `cordond --teardown`.

**In the kernel** (`crates/bpf`, `file_open`). The program walks the dentry chain up to the
deepest `PROTECTED` object and derives the action from `f_mode` and `f_flags`. It then scans
the packed `RULES` bucket for the first match, and denies by default when nothing matches.
Records carry the actual opened path, rebuilt from `d_name` up to the matched object
(`fill_comps` in `crates/bpf/src/kernel.rs`), because `bpf_d_path` is unavailable at
`file_open`.

**Sound directory objects** (`inode_link`, `inode_rename`, `inode_unlink`, `inode_rmdir`,
`inode_mkdir`). A directory protects its children by ancestry, so a hardlink or a rename out
of it would give a secret an unguarded name. That escape is refused unconditionally. A
clobber, a destroy (including a rename over an existing protected name) and a `mkdir` are
ordinary writes and take the subject's verdict, so `audit` rules keep working. A rename
inside one object short-circuits, which keeps atomic save working. The cases are
[ADR 0007](adr/0007-action-hook-map.md)'s, and `decide_reparent` in
`crates/bpf/src/main.rs` implements them.

**Volume control.** Tools re-open one config hundreds of times per run (helm opens
`~/.kube/config` 464 times). So an in-kernel LRU suppressor emits at most one event per key per
second and folds the rest into a `suppressed` count (`throttle` in `crates/bpf/src/kernel.rs`).
The key is `SuppressKey`, which holds `(exe, opened file, action)`, so sibling files under one
object surface separately. The daemon's `coalesce` then folds each drain batch into one journal
line per key.

**Atomic apply** (`Maps::seed` in `crates/daemon/src/backend/bpf_lsm/seed.rs`). The rule maps
are banked, and an apply fills the inactive bank and flips one word.

**Fail-safe pinning** (`PinDir` in `crates/daemon/src/backend/bpf_lsm/pin.rs`,
[ADR 0002](adr/0002-bpf-lsm-boundary.md)). Only the LSM links are pinned, and they keep
the programs and the seeded policy enforcing with no process holding them. Two consequences
surprise people. `systemctl stop cordond` does not stop enforcement; `cordond --teardown`
does, and it refuses while a daemon runs. And teardown is asynchronous, so anything that must
see the boundary down has to poll.

**One daemon per socket** (`acquire_singleton` in `crates/daemon/src/main.rs`, which says why).

**Policy tiers.** The effective policy is the system tier combined with the user tier. A
system fragment pulls in a user-tier file with `[[include]] user = … path = …`. The included
file is home-scoped, which means its objects must resolve under that user's `~`, and it may
not include anything itself. A policy path may be one file or a conf.d directory of fragments
merged in name order. Each fragment can expand `~` against its own `user =` header.

**CLI.** `cordon policy check|apply|show|edit`, `cordon status` and `cordon bless`.
`policy check` is a lint that needs no daemon. `policy edit` is the sudoedit analog. It runs
`$EDITOR` as the invoking user, because a root editor on a same-uid box is an escalation
([threat model](threat-model.md)), then applies and saves the policy in one step if it
compiles. Bare `edit` opens your own tier, and `--system` and `--user NAME` open the others.

**Socket authorization** (`authorize` in `crates/daemon/src/ipc.rs`,
[ADR 0010](adr/0010-policy-storage.md)). The socket is `0666`, and `PolicyApply` and
`BlessApprove` need a root peer.

**Blessing** (`cordon bless`). A blessing is one more `SubjectMatch` predicate, so a blessing
rule is an ordinary rule, and its scope is the rule's object column. `cordon bless` runs
unprivileged. It checks that the daemon runs as root, sends a request, and holds the
connection open. A helper spawned under `$CORDON_SUDO` reaches the daemon as uid 0, and that
is the entire proof of human presence. The daemon then creates a root-owned carrier cgroup
inside the requester's own user subtree, and passes back the carrier's `cgroup.procs`
descriptor over `SCM_RIGHTS`. The CLI forks, and the child joins the carrier in `pre_exec`. So
the target never runs unblessed, and the CLI never holds privilege. The environment, cwd, tty,
job control and session are inherited by construction.
