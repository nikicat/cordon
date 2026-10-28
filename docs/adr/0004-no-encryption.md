# ADR 0004: No encryption

Status: Accepted

## Context

"Keys" came up early, as if protecting secrets meant encrypting them.

## Decision

**No.** The gater denies the live scraper's `open()`, so plaintext in place is fine.
Encryption only protects reads that the gater *doesn't* mediate:

| Un-gated read | In scope? | Already covered by |
|---|---|---|
| stolen / offline disk | no, because it is physical | FileVault / LUKS |
| pre-daemon boot window | no (a scraper is interactive and runs after login) | — |
| gater bug / bypass | defense in depth only | — |

So encryption adds almost nothing in scope, and it drags in keys, a broker and a shim. It is
deferred. "Keys" only exist if we encrypt later. There would be a master key that the broker
holds in RAM and that is unlocked once per session.

## Consequences

Relocating and encrypting the files would need a key, a resident broker to hold it, and a
transparency layer (`fuse-t`, or seccomp `ADDFD` under `cordon run`), so it is all three or
none. That bundle stays an optional later addition.

Orthogonally, capability brokering serves tools that have a credential-helper seam (git, AWS
`credential_process`, docker, kube). The broker hands back short-lived credentials. It works
one tool at a time.
