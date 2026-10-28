# ADR 0006: The subject is a predicate set

Status: Accepted

## Context

Shebang tools exec as their interpreter (`python3`, not `aws`), and helpers and installers
read configs they didn't create, so the exe alone is too coarse a subject.

## Decision

`who` is a conjunction of predicates that are cheap to check, ANDed together:
- `exe` is the path or inode, and it is cheap.
- `uid` and `gid` are cheap (`bpf_get_current_uid_gid`).
- `cgroup` or unit is cheap (`bpf_get_current_cgroup_id`), and it names a systemd service.
- `exe-hash` is the content identity, which IMA or fsverity measures in the kernel. It is
  *not* hashed in BPF. It survives upgrades and resists a binary swap.
- `argv0` and `ancestor-exe` cost more. They are the only real fix for the interpreter
  problem. `~/.aws` is opened by `python3`, not by `aws`. So the rule must match "python3
  whose argv0 or ancestor is aws", and not every python.

## Consequences

Only `exe`, and the `blessing` predicate of [ADR 0012](0012-blessing.md), ship today. `uid`,
`cgroup`, the hash, argv0 and ancestor are later milestones (PLAN-rule-model M2). No rule
grammar fixes the granularity of identity. This axis is where the security
actually lives.
