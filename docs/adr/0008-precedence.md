# ADR 0008: Precedence, and no global mode

Status: Accepted

## Context

Groups and copy-down put several rules on one object, so the kernel needs one answer for
which rule wins, and the answer must not depend on source order.

## Decision

The kernel takes the first matching rule in the bucket of the most specific protected object.
The compiler sorts each bucket in advance, so that the first match is also the most specific
one:
1. The most specific **where** wins, by object depth. An exact file beats a deeper subtree,
   and a deeper subtree beats an ancestor.
2. The most specific **who** wins. A concrete subject (an `exe`, and later more predicates)
   beats `who="*"`, so a specific `allow` or `deny` overrides a broad catch-all on the same
   object.
3. **Deny beats allow.** That is fail-safe, but it is only the tie-break among rules whose
   object and subject are *equally* specific. `allow X` against `deny X` gives deny, and
   `allow *` against `deny *` gives deny.

A protected object with no matching rule is denied by default. The denial is logged with a
distinct `default-deny` cause, so it reads apart from an explicit `deny`. An object is
"protected" when it appears in some rule or lies under one. Everything else is allowed without
mediation, because you cannot default-deny the whole file system.

## Consequences

**There is no global mode, because the per-rule `policy` *is* the enforcement level.** `audit`
allows and logs, so it *observes* an object. `deny` blocks and logs, so it *enforces* the
object. So the choice between observing and enforcing is made per object, by editing that
object's catch-all rule, and there is no system-wide switch. This deliberately drops SELinux's
`enforce|permissive|off`. cordon's user is the admin of their *own* policy, iterating live on
one box, not an admin staging policy for a fleet. So a global "permissive" preview followed by
an "enforce" cutover is just the progression from audit to deny ([authoring
flows](../authoring.md)). "Off" is an empty policy, or `cordond --teardown`. Stopping the
daemon leaves the pinned boundary enforcing ([ADR 0002](0002-bpf-lsm-boundary.md)). The kernel
blocks if and only if the matched rule's policy denies (`Policy::denies` in
`crates/bpf-common/src/policy_maps.rs`).
