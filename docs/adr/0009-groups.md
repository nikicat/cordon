# ADR 0009: Groups

Status: Accepted

## Context

The owner model's owner groups bought grouping, deduplication and naming, but only on the
subject axis.

## Decision

Groups are named and can nest. They work the same way on all three axes (subject, object and
action), and cycles are checked at load time. The old "owner" becomes one ordinary *subject
group*. An example in TOML:
```toml
[group.subject.ssh-tools]
members = ["/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/git"]
[group.object.cloud-creds]
members = ["~/.aws", "~/.config/gcloud", "~/.config/gh"]
[group.action.ro]
members = ["read", "listdir"]

[[rule]]
who = "@ssh-tools"
where = "~/.ssh"
action = "@ro"
policy = "allow"

[[rule]]
who = "*"
where = "@cloud-creds"
action = ["read", "write"]
policy = "audit"
```

## Consequences

Groups resolve entirely at compile time ([ADR 0005](0005-flat-rule-model.md)), so the kernel
never sees one. A blessing class is also declared as a subject group ([ADR
0012](0012-blessing.md)).
