# Implementation plan: whole-repo smell cleanup

This plan sequences the cleanup that the 2026-10-26 whole-repo `/unsmell` survey found. Each
numbered step is one commit. Every step leaves `just test` and the VM smoke
(`packaging/test/run-bpf-lsm-vm.sh`) green, and every step except step 0 is a pure refactor
unless it says otherwise. Steps are ordered so that later ones build on the types earlier
ones introduce, and so that the doc pass runs last, over code that has stopped moving.

> **Status:** steps 0 through 3.2 are committed. Steps 3.3 (`Maps`, `PinDir`) and 3.4
> (`Client`, `PolicyRoot`) are in the working tree, unstaged.

## 0. Bug fixes and false doc claims (done)

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

## 1. Delete dead code (done)

- `MAP_SUPPRESS` (the daemon never opens the map), `DecisionEvent.obj` (never read; it
  names the same object as `.object`), and `PathComp`'s unused `Deref`/`DerefMut`.
- `DecisionEvent.decision` and the `Decision` type: it always equals `policy.denies()`, so
  a record could claim `audit` with a `deny` policy. The daemon branches on the policy.
- `parse::Include.pos` (`#[allow(dead_code)]`, "for future diagnostics").
- The `build-bpf-daemon` justfile recipe, a one-line alias for `cargo build -p cordon-daemon`.
- `BackendKind` keeps its one variant, because the config key is user-facing, but
  `Backend::name` goes: the daemon logs `BackendKind`.

The `DecisionEvent` changes alter the ring record layout. Both sides build from the same
commit, so nothing needs compatibility.

Kept after a closer look, though the survey flagged them:
- `Config.zones` and `paths::claimable_subtree` are the autolearn scope, and M6 task 6
  pulls autolearn in. The config also rejects unknown keys, so removing `zones` would
  break any config that sets it.
- The `[macos]`/`[windows]` `build` recipe is what lets `just build` compile the workspace
  off Linux.

## 2. Shared core types

One commit each, in this order:
1. **`ClassRegistry`** (done; core policy): the dense `ClassName ↔ ClassId` map, built by compile,
   with `id(&ClassName)`, `name(ClassId)` and the "first assignable id is `UNBLESSED + 1`"
   rule. It replaces the `Vec<(ClassName, ClassId)>` on `CompiledPolicy` and the four
   `BTreeMap<ClassName, ClassId>` signatures in the daemon.
2. **One passwd reader** (done): `crate::passwd` parses each line once into an
   `Entry` and gains `home_of`, which `policy::home_for` calls in place of its own parser.
   The CLI's `sys::user_identity` stays separate on purpose: it asks NSS (`getpwuid`), so
   `policy edit` also works for an LDAP or other non-file account.
3. **Located errors** (done): `Error::at(pos, msg)` builds every positioned
   error as an `Error::Located`, and `Diagnostic` carries a `Loc` (fragment name and
   position) in place of a bare `pos`. Output changes: a fragment's error renders as
   `file:line:col: error: msg` instead of `error: file: line:col: msg`, and a compile
   warning about a rule now names the rule's fragment.
4. **`Context`** (done): a `Context` extension trait in core replaces all 64
   hand-written `.map_err(|e| Error::msg(format!("<what>: {e}")))` sites, with identical
   error text. `Response::into_result` replaces the CLI's two ways of turning a daemon
   `Error` reply into an error (`daemon:` and `daemon error:` prefixes; now `daemon:`).
   `read_reply` was dropped: its two callers read different frame shapes (with and without
   a descriptor), so a shared helper would only move the one-line `None` check.

## 3. Missing receivers

One commit per crate area. Each turns context that every sibling function takes as a
parameter into a struct the caller builds once:
- core policy (done): `Resolver { parsed, home }` in resolve.rs, with the axis
  name as an `Axis` enum that also picks the group namespace, and
  `Compiler { resolve_fileid, classes, diagnostics }` in compile.rs, whose `compile` now
  reads as its three steps (objects, own rules, buckets).
- core proto and daemon ipc (done): a `Conn` that reads peer credentials once
  and sends and receives framed messages and descriptors; the framing functions are
  private to it. The daemon's per-connection state (`peer_uid`, `stream`, `writer`) moves
  onto it, and `dispatch` becomes `handle`, which replies itself, so `BlessRequest` is an
  ordinary arm instead of an `unreachable!`. `recv_with_fd` refuses to run behind a
  buffered `recv`, which would lose the descriptor.
- daemon bpf_lsm (done, unstaged): `Maps<'a>(&'a mut Ebpf)` with the seed helpers as
  methods, used by `Blessings`, the event loop and the self-test. Typed `hash`/`array`
  accessors replace the ten copies of the `try_from(map_mut(…))` lookup, and one
  `remove_where` replaces `clear_bank`'s two copies of the key sweep. A `PinDir` type
  holds the four pin functions.
- cli (done, unstaged): a `Client` that loads the config at most once (it was loaded up to
  three times), on first use, so a command given `--socket` and a file still never reads
  it. It owns the socket choice, the policy path, the request-and-render tail and the
  enforcement note. `PolicyRoot { File, ConfD }` in core classifies the policy path once;
  the four edit functions that branched on `is_dir()` match on it, and their tests no
  longer need real directories.

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
