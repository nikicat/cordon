# Architecture decisions

Each record states one decision: its context, the decision, and its consequences. The code
cites them as `ADR NNNN`.

| ADR | Decision |
|---|---|
| [0001](0001-object-centric-gating.md) | Object-centric gating |
| [0002](0002-bpf-lsm-boundary.md) | BPF-LSM is the boundary, and it outlives the daemon |
| [0003](0003-exe-inode-identity.md) | The exe inode is the caller identity |
| [0004](0004-no-encryption.md) | No encryption |
| [0005](0005-flat-rule-model.md) | The flat rule model, compiled in userspace |
| [0006](0006-subject-predicates.md) | The subject is a predicate set |
| [0007](0007-action-hook-map.md) | Actions map to LSM hooks, and escapes are refused |
| [0008](0008-precedence.md) | Precedence, and no global mode |
| [0009](0009-groups.md) | Groups |
| [0010](0010-policy-storage.md) | Policy storage, editing and socket authorization |
| [0011](0011-autolearn.md) | Autolearn |
| [0012](0012-blessing.md) | Blessing is a carrier-cgroup subject predicate |
| [0013](0013-bless-authentication.md) | Bless authenticates by client-side elevation |
| [0014](0014-blessing-lifecycle.md) | The blessing lifecycle |
| [0015](0015-fixed-code-grants.md) | Fixed code as the precondition for a grant (proposed) |

Reference material that is not a decision: the [threat model](../threat-model.md),
[limitations](../limitations.md), [testing](../testing.md), [authoring flows](../authoring.md)
and [prior art](../prior-art.md). What exists is in [STATUS](../../STATUS.md), and what is left
in [todo.md](../../todo.md).
