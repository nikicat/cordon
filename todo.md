# To do

Everything that is left, in order. Each step is one commit, and each must pass
`packaging/test/run-bpf-lsm-vm.sh` before it counts as done. A finished step is deleted; the
others keep their numbers. The decisions behind the work are in [docs/adr](docs/adr/README.md).

## Cleanup

7. A fresh re-check over the touched files.
8. `cordon policy check` prints each diagnostic's file twice (`policy.toml:policy.toml: error…`):
   it prefixes the path, and the diagnostic already names its source.
9. The eBPF crate is outside the clippy gate, and clippy flags `crates/bpf/src/main.rs:121`
   (`ret < -4095 || ret > 0` is a manual range check). Lint it in `just`/CI and fix it.
10. Rustdoc's `-D warnings` run has 24 errors (private and unresolved intra-doc links), and CI
    does not run rustdoc. Fix them and add it to CI, or decide not to.

## M6: fixed code as the precondition for a grant

The last must-have; it closes the `LD_PRELOAD` hole. The design is
[ADR 0015](docs/adr/0015-fixed-code-grants.md). Until it ships, the deployment answer is `bless`.

11. `code =` on subject groups: parse and resolve `arbitrary`, `learn`, `strict` and absent.
    Userspace only.
12. The attestation lint in `cordon policy check`: error on an `allow` whose subject attests
    `arbitrary`, warn on one with no attestation. It ships on its own and makes the
    confused-deputy grants in a policy visible.
13. Retire `allow /usr/bin/aws` from the example policies (the CLI is Python), with the reason
    inline.
14. Settle where the taint is stored: per task with a `task_alloc` hook, or an LRU keyed by
    `mm`. Verify the `clone` semantics of task storage first; they decide the map and whether
    there is a fourth hook.
15. Seed `CODE_SETS` and `ALLOWED_CODE`, add the `mmap_file`, `file_mprotect` and
    `ptrace_access_check` taint hooks, then the `UNTAINTED` bit in `SubjectFlags`.
16. Learning, and `cordon code show|promote|check`, on the autolearn machinery
    ([ADR 0011](docs/adr/0011-autolearn.md)).
17. The `unsandboxed` predicate (enforcement point 3). Before it ships enforcing it needs a
    Chrome version check and a fallback, because Chrome's cookies are on the right side only
    while Linux runs its network service unsandboxed. Re-measure a headful browser too.

## Loose ends

18. `cordon policy check` should warn on a rule whose actions name `listdir` without `read`:
    such a rule denies the listing it appears to grant ([ADR
    0007](docs/adr/0007-action-hook-map.md)).
20. Detect cgroup v1 and hybrid setups and refuse with a clear diagnostic; only the unified
    hierarchy is supported.
21. VM coverage of the systemd packaging. The smoke runs under virtme-ng's init, so nothing
    tests `cordond.service` (`DefaultDependencies=no`, `Before=basic.target`,
    `RequiresMountsFor=/sys/fs/bpf`, `Delegate=yes`) or `just install-service`. It needs a
    guest booted by systemd.

## Deferred until the core is sound

22. B3: PAM in the daemon replaces the uid-0 mint gate ([ADR
    0013](docs/adr/0013-bless-authentication.md)). A non-sudoer can then bless their own tools,
    and every mint authenticates, which retires the sudo grace window. B2 already ships the
    `SCM_RIGHTS` hand-off, so this only swaps what proves a human is present. Open: whether
    some users may bless with less than a full PAM conversation (`pam_u2f` only, or a group).
23. B4: blessing ergonomics. A richer `bless list`, a structured journal, `revoke` polish, a
    blessed-shell marker derived from cgroup membership (never the environment), an optional
    `--path P` that narrows one invocation, and an optional `pam_u2f` touch on every mint.
24. B4: an opt-in "uncordoned" blessing class, so a class's scope stops drifting against
    `@secrets`. The cheap form allows `*` in the object column of allow rules only and fans
    them out to every protected object. Open: what a bare `*` means in a user-tier fragment.
    A blanket class is a skeleton key, so it must stay a second, opt-in class.
25. Home migration: move user-tier files to `~user/.config/cordon/`, cordoned so only an
    authorized editor writes them. It brings two things with it. The system tier must become
    a floor that a user tier can tighten but not loosen, which one first-match bucket cannot
    express. And the policy must let cordond's exe read the file, because the previous
    generation mediates the next daemon's compile and does not fast-allow its new pid.

## Opportunistic

Taken when a real policy needs them ([ADR 0006](docs/adr/0006-subject-predicates.md),
[ADR 0011](docs/adr/0011-autolearn.md)).

26. `uid`, `gid` and `cgroup` subject predicates.
27. IMA or fsverity content identity (`bpf_ima_inode_hash`). It resists a binary swap, not
    code injection.
28. `argv0` and `ancestor-exe`, for the directories an interpreter fronts (`node` and `deno`
    on `~/.npmrc`, `python` on `~/.aws`). Document how a double fork or an argv rewrite
    forges them.
29. Authoring conjunctions of predicates in the TOML and the compiler.
30. Autolearn for objects: `learned.db`, `cordon learn`, `review` and `promote`.

Parked, with no step until something forces it:
- `MAX_RULES_PER_OBJ = 32`. Raise it toward 64 if a verifier log demands it; `policy check`
  already errors on an oversized bucket.
- A per-object default, instead of falling to the global default-deny ([ADR
  0008](docs/adr/0008-precedence.md)).
- Subject groups expand at compile time, so buckets grow with group size times nesting depth.
  If that binds, keep a `(GroupId, exe)` membership map instead.
