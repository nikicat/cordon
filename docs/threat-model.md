# Threat model

Who cordon defends against, and what it concedes. [ADR 0001](adr/0001-object-centric-gating.md)
is the design that follows from it.

**In scope (defeat these).** One-shot scrapers, which run once, scan paths, exfiltrate and
exit, with the same UID as you. They come in rungs: hardcoded path lists, directory walkers and
content greppers, and `environ` readers that follow path-like values.

**Out of scope (conceded).** Root is out of scope. So is a resident or persistent attacker,
who can ptrace, wait for unlocks, replace binaries, kill the daemon, or double-fork to launder
ancestry. Targeted reverse-engineering of this setup is out of scope too. We raise the cost
and bound the blast radius, and no more.

The simplification that makes this possible is that we never confine the adversary. We
protect the *resource* and serve the *owner*, and the scraper finds nothing.
