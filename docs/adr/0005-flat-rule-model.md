# ADR 0005: The flat rule model, compiled in userspace

Status: Accepted

## Context

The first design had owners, explicit rules and trust-on-first-use claims, and its kernel
backend enforced only part of them.

The owner entity reduces to allow rules. `owner_match` means the same as "an allow rule
exists for this caller exe and this subtree." Owner groups bought grouping, deduplication and
naming. But a general group mechanism ([ADR 0009](0009-groups.md)) gives that on all axes,
symmetrically, so a
dedicated owner table was incidental complexity. Collapsing it also closed a real gap. The
owner model's bpf-lsm backend enforced only `subtrees` and `owner_identities`, and not the
`rules` table. So `cordon add` allow and deny rules and TOFU were silently not enforced in the
kernel. Now there is one model, enforced uniformly.

## Decision

The flat rule model is cordon's architecture, and it shipped in M1. A rule is
`(who, where, action, policy)`, in the lineage of SELinux and AppArmor. The kernel enforces
it uniformly. The status of each milestone is in

### The rule

A rule is `(who, where, action, policy)`:
- **who** is the subject. It is a *conjunction of predicates*, not just an exe ([ADR 0006](0006-subject-predicates.md)).
- **where** is the object. It is a file, a directory, or a recursive subtree. The kernel
  matches it with the walk over dentry ancestors, and the most specific object wins.
- **action** is one of `read | write | create | execute | listdir | unlink | mkdir | rmdir |
  rename | link`, and the list can grow. Each action maps to an LSM hook ([ADR
0007](0007-action-hook-map.md)).
- **policy** is one of `allow | deny | audit | silence`. The four are the product of
  `{allow,deny}` and `{log,silent}`. `allow` allows silently, `audit` allows and logs, `deny`
  denies and logs, and `silence` denies silently.

### The compile principle (load-bearing)

**Userspace resolves groups, nesting, defaults and precedence entirely at compile time, and
the kernel evaluates a flat decision table that is already resolved.** cordond parses the text
policy, expands the groups, and resolves paths to `(dev,ino)`. It then flattens the result to
a rule table for each object and loads the BPF maps. This works like SELinux's `checkpolicy`,
with an expressive source and a simple, fast binary form. The eBPF program never sees a group
or a nested reference. So it stays small and friendly to the verifier, however expressive the
authoring gets.

## Consequences

Milestone status is in [`PLAN-rule-model.md`](../PLAN-rule-model.md). Every later decision
about the policy is a decision about one axis of this rule: the subject ([ADR
0006](0006-subject-predicates.md)), the action ([ADR 0007](0007-action-hook-map.md)),
precedence ([ADR 0008](0008-precedence.md)), groups ([ADR 0009](0009-groups.md)) and storage
([ADR 0010](0010-policy-storage.md)).
