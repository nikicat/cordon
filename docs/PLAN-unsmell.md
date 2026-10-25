# Implementation plan: whole-repo smell cleanup

This plan sequences the cleanup that the 2026-10-26 whole-repo `/unsmell` survey found. Each
numbered step is one commit. Every step leaves `just test` and the VM smoke
(`packaging/test/run-bpf-lsm-vm.sh`) green, and every step except step 0 is a pure refactor
unless it says otherwise. Steps are ordered so that later ones build on the types earlier
ones introduce, and so that the doc pass runs last, over code that has stopped moving.

> **Status:** step 0 is in the working tree, unstaged. The rest is not started.

## 0. Bug fixes and false doc claims (done, unstaged)

Behaviour changes, each with a pinning test:
- `policy edit` on a conf.d refused only an *empty* directory as "no siblings". Any other
  load error (an unreadable fragment or include) used to drop every sibling from the
  candidate, so the apply replaced the live policy with the edited fragment alone.
- `policy edit` treated every apply failure as "daemon down, saved". Now only a missing
  socket or a refused connection does; a daemon that errors or dies mid-request fails.
- `cordon` exits non-zero on a stray mid-handshake reply.
- `normalize("/../a")` is `/a`, not `/../a`.
- A `Nonce` decoded off the socket is validated like one parsed from argv.
- The smoke suite's user-tier and edit scenarios wrote a config without `bpf_pin_dir`, so
  their teardown targeted the real `/sys/fs/bpf/cordon`. All configs now go through
  `write_config`.

Refactors and docs: `Uid::ROOT` replaces three local root constants and the `Uid(0)`
literals; four doc blocks that rustdoc attached to the wrong item are moved; about fifteen
stale or false doc claims are corrected.

## 1. Delete dead code

- `Config.zones`, `default_zones` and `paths::claimable_subtree`. Their only user was the
  M4 autolearn, which does not exist.
- `MAP_SUPPRESS` (the daemon never opens the map), `DecisionEvent.obj` (never read; it
  names the same object as `.object`), and `PathComp`'s unused `Deref`/`DerefMut`.
- `DecisionEvent.decision` and the `Decision` type: it always equals `policy.denies()`, so
  a record could claim `audit` with a `deny` policy. The daemon branches on the policy.
- `parse::Include.pos` (`#[allow(dead_code)]`, "for future diagnostics").
- The `[macos]`/`[windows]` justfile recipes and `build-bpf-daemon`.
- `BackendKind` keeps its one variant, because the config key is user-facing, but
  `Backend::name` goes: the daemon logs `BackendKind`.

The `DecisionEvent` changes alter the ring record layout. Both sides build from the same
commit, so nothing needs compatibility.

## 2. Shared core types

One commit each, in this order:
1. **`ClassRegistry`** (core policy): the dense `ClassName ↔ ClassId` map, built by compile,
   with `id(&ClassName)`, `name(ClassId)` and the "first assignable id is `UNBLESSED + 1`"
   rule. It replaces the `Vec<(ClassName, ClassId)>` on `CompiledPolicy` and the four
   `BTreeMap<ClassName, ClassId>` signatures in the daemon.
2. **One passwd reader**: `crate::passwd` parses each entry once into a named
   `PasswdEntry`, and gains a lookup by name. `policy::home_in_passwd` and the CLI's
   `sys::user_identity` both go through it.
3. **Located errors**: one `Pos`-owned constructor builds the `line:col: msg` text that is
   formatted four ways today, and a fragment's error keeps its position in
   `Diagnostic.pos` instead of only in the message.
4. **`Error::context`**: one helper replaces about 30 hand-written
   `.map_err(|e| Error::msg(format!("<verb> {path}: {e}")))` sites, and
   `Response::into_result` plus `read_reply` replace the three ways the CLI turns a daemon
   error into an `Error`.

## 3. Missing receivers

One commit per crate area. Each turns context that every sibling function takes as a
parameter into a struct the caller builds once:
- core policy: `Resolver { lines, groups, home }` in resolve.rs, which also owns the axis
  name as an `Axis` enum, and `Compiler { resolve_fileid, classes, diagnostics }` in
  compile.rs, whose `compile` then reads as its four steps.
- core proto and daemon ipc: a `Conn` that reads peer credentials once and sends and
  receives framed messages and descriptors. The daemon's per-connection state
  (`peer_uid`, `stream`, `writer`) moves onto it, and `dispatch` stops having an
  `unreachable!` arm.
- daemon bpf_lsm: `Maps<'a>(&'a mut Ebpf)` with the eleven seed helpers as methods, used by
  `Blessings`; a `PinDir` type for the four pin functions.
- cli: a `Client` that loads the config once (today: three times) and owns the socket, the
  policy path and the request round trip; a `PolicyRoot { File, ConfD }` in core for the
  five edit functions that branch on `is_dir()`.

## 4. Behaviour changes

1. **`MAX_OBJECTS` diagnostic**: compile reports a policy with too many objects as an
   error, as it already does for `MAX_RULES_PER_OBJ`. Today only seeding catches it, at
   load time.
2. **`tempfile` crate**: it replaces the hand-built edit temp dir and the hand-rolled
   atomic write. The atomic write gains the missing fsync of the parent directory after
   the rename. The ~16 test temp dirs move to it too, so a panicking test cleans up.
3. **Dev unit as a drop-in**: `just install-service` installs the packaged
   `cordond.service` plus a `cordond.service.d/dev.conf` that overrides only `ExecStart=`
   and `Environment=`. The generated unit has already lost `RequiresMountsFor=`,
   `DefaultDependencies=no` and `Before=basic.target`.
4. **Machine-checkable outcomes for the smoke suite**: the suite matches about fifteen
   message strings that the Rust code writes. Each matched string is either replaced by a
   distinct exit code or `--json` field, or marked at its Rust site as matched by the
   suite. The step starts with the inventory and a per-string choice.

## 5. Smoke-suite helpers

`bpf-lsm-smoke.sh` gets a `rule` emitter for the ~45 hand-written `[[rule]]` heredocs, a
`run_scenario` driver for the shared setup and teardown, `wait_until` for the eleven
sleep loops, a cleanup stack that an early return cannot skip (it fixes the `$TMP` leak in
the rename-exchange scenario), and `expect_log` beside `expect_allow`/`expect_deny`. The
156-line stale scenario catalog in the header is cut to a short file header.

## 6. Doc pass

Two commits:
1. **One owner per fact.** Each fact that is restated in three to nine places (no
   `bpf_d_path` at `file_open`, the bank flip, `CarrierProcs` as the grant, teardown being
   explicit, the bless handshake, ClassIds being renumbered, and so on) is kept on the item
   that decides it, and the other sites point there. History and milestone notes leave the
   code.
2. **House style.** Every flagged doc is rewritten as plain, verb-first Google-style
   reference text, with "Errors when…" for the error contract. Entity docs state the item's
   place in the system instead of listing its fields.

## Out of scope

- Rustdoc's `-D warnings` run has 33 pre-existing errors (private and unresolved intra-doc
  links). CI does not run rustdoc. The doc pass will not add any; fixing them is a separate
  decision.
