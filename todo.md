# To do

Refactors and fixes found by the code-smell surveys. Each step is one commit, and each
must pass `packaging/test/run-bpf-lsm-vm.sh` before it counts as done.

1. The daemon attaches every program, and HOOKS goes away.
2. Small derivations and duplication:
   - seed_object.
   - SubjectMatch ..ANY.
   - BankedObj::rule_slot.
   - A NUM_BANKS assert.
   - config_dir.
   - Proto framing.
   - Coalesced::log.
   - Merge ObjectName and OpenedPath.
   - euid returns Uid.
   - CLI: an exit helper and one match.
   - Client::load_policy.
   - The enforcement_note enum.
   - Settings identity.
   - Blessing methods and CarrierDir.
   - The mint rollback.
   - gc uses extract_if.
   - Smoke helpers.
   - Events: one constant for the settings map's index 0, which the daemon and the kernel
     each spell; a named `Suppressed::NONE`; Coalesced holds the first DecisionEvent
     instead of copying its fields; the comps/depth/trunc decode rule moves beside its type
     in bpf-common; one name each for the kernel's suppression and the daemon's coalescing
     (now "suppress", "throttle" and "fold").
   - btf: a ByteOrder enum instead of `le: bool`, and a TypeId newtype instead of the
     u32/usize mix.
   - edit.rs: parse SUDO_UID once, and give the note repeated across three comments one
     owner.
3. PolicyRoot everywhere. It fixes a bug: `cordon policy edit local.conf` saves
   `conf.d/local.conf`, which the daemon applies live, but fragment_paths reads only
   `*.toml`, so the fragment is dropped at the next restart. The `toml` extension is
   spelled in edit.rs and in core.
   - edit.rs types name their cases: EditFile.scaffold, EditorAs::Current and
     EditTarget::System(None) become variants that say what they are.
4. PeerCred, the events receiver and the Runtime split.
5. Policy types at parse: the GroupDef enum and the expand leaf type.
6. Code docs: false claims, long comments, duplicated facts and garbled sentences.
   - match_rule stays fail-closed; only its doc changes.
   - bpf main.rs: "all unsafe lives in kernel.rs" and "fails open" are false.
   - Bank::masked's doc is wrong about what a garbage bank finds.
7. Markdown:
   - Fix the false claims.
   - Replace README's example.
   - Add the SANTA banner.
   - Consolidate the duplicated facts.
   - Delete docs/PLAN-unsmell.md.
8. A fresh re-check over the touched files.
