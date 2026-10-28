# ADR 0001: Object-centric gating

Status: Accepted

## Context

Make secret-bearing config directories readable only by the tool that owns them. The owning
tool notices nothing, because it reads its config at the normal path, unmodified. Everything
else running as the same user sees the directories as denied or empty.

The adversary is a same-uid, one-shot scraper ([threat model](../threat-model.md)). Stock
MAC does nothing about it, because confinement is a property of the program and a scraper is
a program without a profile ([prior art](../prior-art.md)).

## Decision

1. **Unix DAC can't separate two processes with the same UID.** So we add an object-centric
   authorizer. It protects the resource, denies all subjects by default, and allows only the
   owning identity.
2. **Enforcement lives outside the confined process.** So it is a privileged daemon, not an
   in-process `LD_PRELOAD` trick.
3. **Object-centric beats subject-centric.** One rule over the resource covers all subjects,
   including unknown future scrapers. AppArmor and SELinux instead need a profile for each
   tool, and a tool without a profile is unconfined.
4. **The gater alone meets the threat model, with no crypto and no relocation.** Files stay
   plaintext in place, and the gater denies `open()` to anyone but the owner. Because nothing
   is moved or encrypted, transparency is automatic. Encryption, a broker and a shim are an
   optional later bundle ([ADR 0004](0004-no-encryption.md)), and not built.

## Consequences

Every subject is denied by default on a protected object, so the work moves to admitting the
legitimate tools ([authoring flows](../authoring.md)). How a subject is identified is the
hard part, and [ADR 0006](0006-subject-predicates.md) owns it.
