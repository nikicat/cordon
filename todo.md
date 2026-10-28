# To do

Refactors and fixes found by the code-smell surveys. Each step is one commit, and each
must pass `packaging/test/run-bpf-lsm-vm.sh` before it counts as done.

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
9. The eBPF crate is outside the clippy gate, and clippy flags `crates/bpf/src/main.rs:121`
   (`ret < -4095 || ret > 0` is a manual range check). Lint it in `just`/CI and fix it.
