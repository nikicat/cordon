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

Status: **Phase 0 built** — policy core, SQLite store, `cordond` daemon, and
`cordon` CLI, all unprivileged with a `mock` backend (logic/CI only — *not* a
security boundary yet; that's the root `fanotify` backend in Phase 1). See
[`STATUS.md`](STATUS.md).

## Build & try (dev, user-mode)

```sh
cargo test                 # 18 tests: decision flow + IPC e2e
cargo build

# run the dev daemon (mock backend) against a throwaway $HOME
export CORDON_SOCK=/tmp/cordon.sock CORDON_STORE=/tmp/cordon.db
export CORDON_ZONES="$HOME:$HOME/.config"
./target/debug/cordond &

# a tool that creates its own config becomes its owner (TOFU)...
./target/debug/cordon submit --path "$HOME/.config/mytool/secret" --exe /usr/bin/mytool --op create
# ...reads it back fine...
./target/debug/cordon submit --path "$HOME/.config/mytool/secret" --exe /usr/bin/mytool --op read
# ...but a scraper is denied (exit 13):
./target/debug/cordon submit --path "$HOME/.config/mytool/secret" --exe /tmp/scraper --op read
./target/debug/cordon owners
```

