# cordon

Make secret config directories readable **only by the tool that owns them** —
transparently to that tool, invisibly to everything else running as your user.

`~/.aws`, `~/.config/gcloud`, `~/.ssh`, `~/.config/gh`, `~/.netrc`, `~/.npmrc`,
`~/.docker/config.json`, … all sit there readable by any process running as you.
A script you accidentally `curl | sh` can scoop the lot. `cordon` cordons those
directories off: the owning tool sees its config unchanged; an unblessed reader
gets `ENOENT`/`EACCES` (and, with the vault, only ciphertext at rest).

- **Threat model and full design:** [`docs/DESIGN.md`](docs/DESIGN.md)
- **Current state / where to resume:** [`STATUS.md`](STATUS.md)

> Working name. See the naming note in `DESIGN.md` — deliberately *not* in the
> `gate`/`Gatekeeper` namespace.

Status: **Phase 3 in progress** — the in-kernel **`bpf-lsm`** backend (the real
Linux boundary) denies non-owner opens of owned subtrees, validated end-to-end in a
virtme-ng VM in CI. Phases 0–1 (policy core, SQLite store, `cordond` daemon,
`cordon` CLI, TOFU creator-owns, enforce/audit) are done. The Linux **`fanotify`**
backend is a **dev/test backend, NOT a security boundary** (it fails open and is
path-bypassable). See [`STATUS.md`](STATUS.md).

## Build & try (dev, user-mode, mock backend)

```sh
cargo test                 # unprivileged: decision flow + IPC e2e
cargo build

# a throwaway config (mock backend = not a boundary; for logic only)
cat > /tmp/cordon.toml <<EOF
backend = "mock"
socket = "/tmp/cordon.sock"
store  = "/tmp/cordon.db"
zones  = ["${HOME}", "${HOME}/.config"]
EOF
export CORDON_CONFIG=/tmp/cordon.toml
./target/debug/cordond &

# a tool that creates its own config becomes its owner (TOFU)...
./target/debug/cordon submit --path "$HOME/.config/mytool/secret" --exe /usr/bin/mytool --op create
# ...reads it back fine...
./target/debug/cordon submit --path "$HOME/.config/mytool/secret" --exe /usr/bin/mytool --op read
# ...but a scraper is denied (exit 13):
./target/debug/cordon submit --path "$HOME/.config/mytool/secret" --exe /tmp/scraper --op read
./target/debug/cordon status
```

For the **real** boundary (root **`bpf-lsm`**, in-kernel), see
`packaging/cordon.example.toml` and `packaging/test/run-bpf-lsm-vm.sh` (runs it in a
VM, no host root). The root `fanotify` backend (`run-in-vm.sh`) is dev/test only —
not a security boundary.

