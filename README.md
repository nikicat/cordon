# cordon

Make secret config directories readable **only by the tool that owns them** —
transparently to that tool, invisibly to everything else running as your user.

`~/.aws`, `~/.config/gcloud`, `~/.ssh`, `~/.config/gh`, `~/.netrc`, `~/.npmrc`,
`~/.docker/config.json`, … all sit there readable by any process running as you.
A script you accidentally `curl | sh` can scoop the lot. `cordon` cordons those
directories off: the owning tool sees its config unchanged; an unauthorized reader
gets `ENOENT`/`EACCES` (and, with the vault, only ciphertext at rest).

- **Threat model and full design:** [`docs/DESIGN.md`](docs/DESIGN.md)
- **Current state / where to resume:** [`STATUS.md`](STATUS.md)

> Working name. See the naming note in `DESIGN.md` — deliberately *not* in the
> `gate`/`Gatekeeper` namespace.

Status: the flat **rule model** ([`DESIGN.md` §15](docs/DESIGN.md)) — a root-owned
text policy of `(who, where, action, policy)` rules, compiled in userspace and
enforced **in-kernel** by the `bpf-lsm` backend — is the architecture. M1 (TOML
parser → copy-down compiler → flat BPF maps → in-kernel `file_open` verdicts for
read/write/create, with the per-rule `allow`/`audit`/`deny`/`silence` policy as the only
enforcement level — no global mode — and `cordon policy check`/`apply`/`edit`/`show`) is
implemented and validated end-to-end in a virtme-ng VM. The
earlier owner model (`fanotify`/`mock` backends, SQLite store, `adopt`/TOFU) has been
retired in favor of the one model. See [`STATUS.md`](STATUS.md).

## Build & try

```sh
cargo test                 # unprivileged: the policy parser + copy-down compiler

# Lint a policy file locally — no daemon, no root (great for CI):
cargo build -p cordon-cli
./target/debug/cordon policy check packaging/cordon.example.policy.toml
```

The **real boundary** is the in-kernel `bpf-lsm` backend (root, `CAP_BPF` +
`CAP_MAC_ADMIN`, a kernel with `CONFIG_BPF_LSM=y` and `bpf` in the LSM list). The full
end-to-end suite — allow/deny, per-action, groups, copy-down precedence, audit→deny,
silence, and runtime `policy apply` — runs in a virtme-ng VM with no host root (just
`/dev/kvm`):

```sh
packaging/test/run-bpf-lsm-vm.sh
```

**This VM run is the definition of done:** validate *every* change with it before considering
the change complete — including userspace-only ones (compiler, CLI, daemon) — since it's the
only tier that exercises the real kernel boundary end-to-end. `cargo test` is necessary but
not sufficient. It defaults to the CI-pinned kernel, so a green local run matches CI. (See
[`DESIGN.md` §11](docs/DESIGN.md).)

The authoritative policy is root-owned text — either the verbose `[[rule]]` form (see
[`packaging/cordon.example.policy.toml`](packaging/cordon.example.policy.toml)) or the
compact one-rule-per-line DSL
([`packaging/cordon.example.dsl.policy.toml`](packaging/cordon.example.dsl.policy.toml)),
which compile identically. It can be a single file (`/etc/cordon/policy.toml`) or a
`/etc/cordon/conf.d/` directory of fragments merged in name order, each able to expand
`~` against a `user = "name"` header. `cordon policy apply` compiles it and atomically
re-seeds the in-kernel maps.

To edit it safely, `sudo cordon policy edit` is the **sudoedit analog**: it runs your
`$EDITOR` as *you* (never root — a root editor on a same-uid box is an escalation), then
validates and, if it compiles, applies *and* saves in one step (rejecting a broken policy
visudo-style instead of persisting it).

