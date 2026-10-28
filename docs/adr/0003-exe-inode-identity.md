# ADR 0003: The exe inode is the caller identity

Status: Accepted

## Context

A rule names its subject, so the kernel needs an identity for the caller that the caller
cannot forge. Ancestry, argv and paths are all candidates, and they are not equally strong.

## Decision

In the in-kernel backend, the caller's identity is its exe `(dev,inode)`, read straight from
`task->mm->exe_file`. That is race-free and needs no `/proc` readlink. The other predicates
of [ADR 0006](0006-subject-predicates.md) add to it.

### Caller vs. ancestry forgeability

Treat the immediate caller and the ancestry chain as different security objects:
- **The immediate caller is strong and race-free.** It is suspended in the kernel while it
  waits for our verdict, so it cannot exit or exec under us. On Linux, the exe path is
  kernel truth, and it is race-free while the caller is blocked. On macOS, the per-event
  `audit_token` yields a *cryptographic* code identity (`cdhash`, `team_id`, `signing_id`,
  validated with `SecCodeCheckValidity`). That is strictly stronger than a path, and it is the
  real win of ES.
- **Ancestry is best-effort, and it faces two distinct attacks:**
  - **Removal.** A double fork reparents the process to init and erases the chain on Linux.
    macOS resists this, because `original_ppid` and the *responsible* audit token survive
    reparenting.
  - **Construction.** The attacker runs `fork(scraper); exec(real trusted binary)` in the
    parent. That builds a *genuine* ancestry whose ancestor really is the trusted tool. It
    defeats ancestry on both platforms. Stricter identity does not fix it, whether that is
    `path+inode`, `signature` or macOS code signing, because the binary is authentic and is
    attested truthfully. Only a liveness window bounds it, where the trusted ancestor must be
    alive at access time. The launcher can also influence macOS's "responsible process"
    attribution (through the `posix_spawn` disclaim attributes), so that is not unforgeable
    either.
- **The interpreter problem persists on macOS.** A script tool surfaces as `/usr/bin/python3`,
  which is an Apple *platform binary*. So the strong code identity belongs to the interpreter,
  not the tool. That pushes you back onto the weaker link of ancestry or the responsible pid,
  as on Linux.
- **Conclusion.** Ancestry raises the cost and is never a boundary. The construction attacker
  belongs to the targeted reverse-engineering class that [threat model](../threat-model.md)
concedes. The object-centric deny is the boundary.

## Consequences

**Lineage lives in the backend.** The backend already runs in the kernel, so ancestry hardening
is folded in rather than built as a separate proc-connector subsystem. A live walk of
`task->real_parent` gives the same best-effort chain for free at decision time. Lineage that
lasts past a process's exit only needs `sched_process_{fork,exec}` tracepoints that fill a BPF
map from `(pid, starttime)` to the parent, within this backend. The ceiling is unchanged. A
real `exec` of a trusted binary (the construction attack, above) is still recorded faithfully,
so ancestry stays best-effort and is never the boundary.
