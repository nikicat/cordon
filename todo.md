# To do

Refactors and fixes found by the code-smell surveys. Each step is one commit, and each
must pass `packaging/test/run-bpf-lsm-vm.sh` before it counts as done.

4. Split docs/DESIGN.md into ADRs under docs/adr/, one decision each (context, decision,
   consequences, status). It goes before the doc steps, because the code cites
   `DESIGN §N` about 140 times and those citations move to ADR numbers.
   - Live decisions, roughly one ADR each: object-centric gating (§1, §3); BPF-LSM as the
     boundary and the pinned links that outlive the daemon (§4); the exe inode as the
     caller identity (§8); no encryption (§7); the flat rule model and its compile
     principle (§15.1–15.3); the subject predicate set (§15.4); the action-to-hook map and
     escape-deny (§15.5); precedence (§15.6); groups (§15.7); policy storage and
     `policy edit` (§15.8); autolearn zones (§15.9); blessing as a carrier-cgroup subject
     predicate and its membership boundary (§16.3–16.4); bless authentication by
     client-side elevation (§16.5); the blessing lifecycle (§16.6).
   - Not decisions, so not ADRs: the threat model (§2), limitations (§10, §16.7), the
     testing strategy (§11) and prior art (§13) become their own reference docs; the
     phased plan (§12) and open decisions (§14) go, since STATUS.md and the plans own
     them.
   - The owner model, TOFU, interactive mode and the fanotify backend (§5, §6, §8.2, §12)
     no longer exist in the code. Proposed: drop them rather than keep superseded ADRs,
     since git history holds the text and the live ADRs keep the rationale that survived.
5. Code docs: false claims, long comments, duplicated facts and garbled sentences.
   - match_rule stays fail-closed; only its doc changes.
   - bpf main.rs: "all unsafe lives in kernel.rs" and "fails open" are false.
   - Bank::masked's doc is wrong about what a garbage bank finds.
6. Markdown:
   - Fix the false claims.
   - Replace README's example.
   - Add the SANTA banner.
   - Consolidate the duplicated facts.
   - Delete docs/PLAN-unsmell.md.
7. A fresh re-check over the touched files.
8. `cordon policy check` prints each diagnostic's file twice (`policy.toml:policy.toml: error…`):
   it prefixes the path, and the diagnostic already names its source.
