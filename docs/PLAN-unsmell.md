# Implementation plan: whole-repo smell cleanup

This plan sequences the cleanup that the 2026-10-26 whole-repo `/unsmell` survey found. Each
numbered step is one commit. Every step leaves `just test` and the VM smoke
(`packaging/test/run-bpf-lsm-vm.sh`) green, and every step except step 0 is a pure refactor
unless it says otherwise. Steps are ordered so that later ones build on the types earlier
ones introduce, and so that the doc pass runs last, over code that has stopped moving.

> **Status:** steps 0 through 6.1 are committed. Step 6.2 (house style) is in the working
> tree, unstaged.

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
- daemon bpf_lsm (done): `Maps<'a>(&'a mut Ebpf)` with the seed helpers as
  methods, used by `Blessings`, the event loop and the self-test. Typed `hash`/`array`
  accessors replace the ten copies of the `try_from(map_mut(…))` lookup, and one
  `remove_where` replaces `clear_bank`'s two copies of the key sweep. A `PinDir` type
  holds the four pin functions.
- cli (done): a `Client` that loads the config at most once (it was loaded up to
  three times), on first use, so a command given `--socket` and a file still never reads
  it. It owns the socket choice, the policy path, the request-and-render tail and the
  enforcement note. `PolicyRoot { File, ConfD }` in core classifies the policy path once;
  the four edit functions that branched on `is_dir()` match on it, and their tests no
  longer need real directories.

## 4. Behaviour changes

1. **`MAX_OBJECTS` diagnostic** (done): compile reports a policy with too many
   objects as an error, as it already does for `MAX_RULES_PER_OBJ`, so `policy check`
   catches it. The seed-time check stays as a guard on the slot arithmetic.
2. **`tempfile` crate** (done): it replaces the hand-built edit temp dir and the
   hand-rolled atomic write, which gains the missing fsync of the parent directory after
   the rename. The 16 test temp dirs and files move to it too, so a panicking test cleans
   up. The daemon also drops nix's `socket` feature, unused since `Conn` moved to core.
3. **Dev unit as a drop-in** (done; only dry-run, see STATUS.md): `just install-service` installs the
   packaged `cordond.service` plus a `cordond.service.d/dev.conf` that overrides only
   `ExecStart=` and `Environment=`, so the dev unit regains `RequiresMountsFor=`,
   `DefaultDependencies=no` and `Before=basic.target`. Every privileged step runs under
   one `sudo` (it was three).
4. **Machine-checkable outcomes for the smoke suite** (done): the suite matched
   27 distinct strings the Rust code writes. Now:
   - `bless list`, `bless revoke` and `policy show` are read through `--json`, which also
     removes the pid-collision hazard of matching ids in the rendered list.
   - `cordond --log-format json` writes one JSON object per line. The suite starts the
     daemon with it and checks the decision records by field (`.user`, `.path`,
     `.policy`, …) through jq, instead of regexes over the rendered line.
   - The records a tool waits for carry an `event` field: `ready`, `backend_failed`,
     `self_test_failed`, `carrier_not_adopted`, `already_running` and `teardown` (with
     `generations`, 0 when nothing was pinned). Teardown keeps exit 0 either way, so it
     stays safe to run blind.
   - Left as text: the three refusal reasons (`requires root`, `not root`), which need an
     error kind on the wire and distinct CLI exit codes. That is a protocol change, not
     taken here.

## 5. Smoke-suite helpers (done)

`bpf-lsm-smoke.sh` gains:
- `rule WHO WHERE ACTION POLICY`, which renders a `[[rule]]` table (space-separated values
  become a TOML array) and replaces all 47 hand-written rule blocks;
- `run_scenario`, which drives every scenario and always stops its daemon afterwards, so
  the 51 per-exit `daemon_stop` calls are gone and an early return can no longer leak
  `$TMP` or a pinned boundary;
- `on_cleanup`, a stack of commands a scenario queues as it sets things up (the synthetic
  passwd users, the fake sudo, the placement and reconcile cgroup trees, the `/root`
  vault). They used to be repeated, or skipped, at each exit;
- `wait_until TRIES CMD…` for the poll loops, and `expect_log` for the positive log checks.

The 156-line scenario catalog in the header moved onto the scenario functions it
described, and its numbering, stale since four scenarios were added unnumbered, is gone.

## 6. Doc pass

Two commits:
1. **One owner per fact** (done). A survey of the current tree found 92 facts
   restated at about 560 sites and 110 history or milestone notes in code. Each fact is
   now stated on the item that decides it, and the other sites point there or are gone;
   regression notes stay as present-tense statements of what they guard. The pass also
   fixed about 25 statements that contradicted the code (the suppressor key, "off is a
   stopped daemon", a `BlessMint` verb and two `policy check` lints that don't exist, the
   pinning of maps, `/dev/urandom` for the nonce, and others). It adds no rustdoc
   error: the `--document-private-items` run has 30, all pre-existing.
2. **House style** (done, unstaged). Every doc and comment, in the crates, the smoke suite,
   the example configs and the markdown docs, is rewritten as plain, verb-first reference
   text, with "Errors when…" for the error contract. Entity docs state the item's place in
   the system instead of listing its fields, tautologies are deleted, and mechanism moved
   into `//` comments beside the code. About 10 more docs that contradicted the code were
   fixed on the way. Refactor candidates the rewrite surfaced (functions whose docs cannot
   be short because they do several things) are listed below, not done.

## Refactor candidates from the doc pass

Left as code; each makes its doc long or awkward:
- `Ctx::serve_bless_request` issues the nonce, waits for approval, mints and sends the
  descriptor in one function.
- `events::apply`, `Resolver::expand` and `Compiler`'s steps return results through a
  parameter or side channel (`reply`, the `leaf` callback, `self.diagnostics`).
- `Maps::seed` also rewrites the daemon's fast-allow identity on every flip.
- `Session::open` (edit) does four jobs; `editor_identity` and `invoker_uid` both parse
  `SUDO_UID` with the same message.
- `decide_reparent` (eBPF) answers three questions, within the verifier's limits.
- `OneOrMany::classified` is `tokens().to_vec()` under a misleading name.
- `UserName::from_str` accepts the empty string; the doc now says so.
- Smoke suite: `cgroup2_ready` has three unrelated effects; `edit_env_setup` returns its
  results through five globals.

## Out of scope

- Rustdoc's `-D warnings` run has 24 pre-existing errors (private and unresolved intra-doc
  links). CI does not run rustdoc. The doc pass will not add any; fixing them is a separate
  decision.
