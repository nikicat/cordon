# cordon

**Object-first file access control for Linux.** Make `~/.ssh`, `~/.aws`, `~/.config/gcloud`
and the rest of your secrets readable **only by the tools that own them** — transparently to
those tools, invisibly to everything else running as your user. Enforced in the kernel with
eBPF (BPF-LSM), written in Rust.

[![ci](https://github.com/nikicat/cordon/actions/workflows/ci.yml/badge.svg)](https://github.com/nikicat/cordon/actions/workflows/ci.yml)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![status: early development](https://img.shields.io/badge/status-early%20development-orange)

> **Not production-ready.** The kernel boundary works and is validated end-to-end against a
> pinned kernel in CI, but this is active development: the policy format, CLI and on-disk
> layout change without notice, and the largest known hole is still open by design (see
> [Known limitations](#known-limitations)). Try it on a machine you can afford to lock
> yourself out of. Issues and design feedback are welcome.

## The problem

Every credential on a Linux box is one `open()` away from any process running as you:

```
~/.ssh/id_ed25519    ~/.aws/credentials   ~/.config/gcloud/   ~/.kube/config
~/.netrc             ~/.npmrc             ~/.docker/config.json
~/.config/gh/hosts.yml   ~/.gnupg/        .env
```

Unix permissions separate *users*, not *programs*. A `curl … | sh`, an npm `postinstall`
hook, a compromised editor extension, an infostealer — all run at your uid and can scoop the
lot in one pass. AppArmor and SELinux do essentially nothing here by default, and not by
oversight: confinement is a property of the *program*, and an unknown program is unconfined.
A scraper is definitionally an unknown program.
([The long version, with what each incumbent actually does.](docs/DESIGN.md#31-what-the-incumbents-actually-do-to-a-scraper))

## What cordon does

Turn the model around: protect the **object**, deny every subject by default, allow only the
tools that legitimately own it.

```toml
# /etc/cordon/policy.toml — root-owned, compiled and pushed into the kernel
user = "alice"                                          # whose ~ these paths mean

rules = '''
allow    @ssh-tools     read,write   ~/.ssh             # ssh/scp/sftp: unchanged
allow    /usr/bin/aws   read,write   ~/.aws             # the aws CLI: unchanged
audit    *              read         @cloud-creds       # everyone else: allowed, but logged
'''

[group.subject.ssh-tools]
members = ["/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/sftp"]

[group.object.cloud-creds]
members = ["~/.aws", "~/.config/gcloud", "~/.config/gh"]
```

`ssh` reads its key exactly as before. Anything else opening `~/.ssh` gets `EPERM` and a
journal line naming the exe, the path and the action — with no cooperation from the program
being denied, no `LD_PRELOAD` shim, and no change to where your files live.

The intended flow is **audit → look → deny**: start with `audit` on a directory, see who
actually touches it, then flip that one directory to `deny`. There is no global on/off
switch and no interactive prompt — `allow`/`audit`/`deny`/`silence` is a per-rule choice, so
you tighten one object at a time instead of arming the whole box at once.

Check a policy without root, a daemon, or any risk:

```sh
cargo build -p cordon-cli
./target/debug/cordon policy check packaging/cordon.example.policy.toml
```

## How it works

```
policy.toml ──parse──> resolve groups ──compile──> flat per-object rule table
                                                            │ seed (atomic, banked maps)
                                                            ▼
   open()/rename()/exec() ────> BPF-LSM programs ────> allow | EPERM  (+ ring-buffer event)
                                                            │
                                                     cordond ──> journal
```

- **Root-owned text policy, compiled in userspace.** Groups, nesting and precedence resolve
  at compile time into a flat rule table per protected object; the kernel side does a
  first-match scan and nothing else. Precedence is object depth → subject specificity →
  deny > allow, so a rule on `~/.aws/.danger-token` beats one on `~/.aws`.
- **Enforced in-kernel**, in a BPF-LSM program written in Rust with
  [aya](https://github.com/aya-rs/aya): `file_open` for read/write/create,
  `inode_link`/`inode_rename`/`inode_unlink`/`inode_rmdir`/`inode_mkdir` so a secret can't be
  hardlinked or renamed out of its protected directory and read from an unguarded path, and
  `bprm_check_security` for exec.
- **Fail-safe.** The LSM links are pinned to bpffs, so the boundary survives the daemon
  crashing, being killed or being restarted — with no gap. See
  [below](#enforcement-outlives-the-daemon).
- **Atomic reloads.** The rule maps are banked; a re-seed fills the inactive bank and flips
  one word, so policy is never half-applied.
- **Quiet by construction.** Tools re-open one config hundreds of times per run (helm: 464×
  `~/.kube/config`), so an in-kernel LRU suppressor emits at most one event per
  `(exe, opened file, action)` per second and folds the rest into a count.

Full design, threat model and rationale: [`docs/DESIGN.md`](docs/DESIGN.md).

## Blessing — `sudo` for file reads

Static rules name *known* exes. For the tools you reach for interactively over secrets —
`cat`, `rg`, a shell — no static subject works: `allow /usr/bin/cat` admits every `cat`,
including the one a scraper runs. `cordon bless` grants a **specific invocation** (and its
descendants) a runtime pass, per a class you declare in policy:

```toml
# added to the policy above
rules = '''
allow  @blessed-ro  read  @cloud-creds
'''

[group.subject.blessed-ro]
blessing = "ro"                       # a subject group matched by blessing class, not by exe
```

```sh
cordon bless --class ro -- aws s3 ls   # this aws may read the cloud creds, nothing else
cordon bless --class ro                # …or a blessed shell
cordon bless list                      # live blessings: id, class, age, pids
cordon bless revoke 3                  # kill that blessed tree now
```

No `sudo` prefix — `cordon bless` runs as you and prompts for authentication partway through
(via `sudo` by default; `$CORDON_SUDO` picks another tool), because **a human at the keyboard**
is the one thing a one-shot scraper can't produce. The blessed command stays an ordinary child
of your shell, so environment, tty, job control and desktop session survive; GUI apps and
`run0`/`pkexec` work inside a blessed shell. The grant rides a per-invocation root-owned
cgroup, so it evaporates when the command exits, is scoped to whatever objects its rules name,
and every blessed access is journaled with its class.
([`DESIGN.md` §16](docs/DESIGN.md#16-blessing--runtime-authenticated-access-grants))

> **Sudoers note.** sudo caches authentication (~15 min), so a second `bless` in that window
> won't prompt. To require a human for *every* grant:
> `Defaults!/usr/bin/cordon timestamp_timeout=0`

## Enforcement outlives the daemon

The LSM programs are attached by `bpf_link`s **pinned to bpffs**, so the boundary does not
depend on `cordond` staying alive: kill it, crash it, restart it, and every verdict keeps
being enforced with no gap. The daemon is still what journals decisions and applies policy
changes — but its absence costs you the *log*, never the *boundary*. The corollary surprises
people, so plainly:

> **`systemctl stop cordond` does not stop enforcement.**

Turning the boundary off is a deliberate, separate act:

```sh
sudo systemctl stop cordond     # stops the daemon; the box is STILL enforcing
sudo cordond --teardown         # removes the pins — THIS is what turns it off
```

`--teardown` refuses while a daemon is running (stop it first) and needs no socket, so it
works when the daemon is dead — which is exactly when you need it. It takes effect a moment
after it returns: unlinking a pin drops the link's last reference and the kernel detaches on a
workqueue. If `cordon status` can't reach the daemon it reports whether the pins are still in
place, so "connection refused" is never mistaken for "not enforcing".

## Requirements

| | |
|---|---|
| Kernel | `CONFIG_BPF_LSM=y` **and** `bpf` in the active LSM list (`lsm=…,bpf` on the cmdline). ≥ 5.7 in principle; CI pins **v6.12**, which is what's actually tested. |
| Privileges | root with `CAP_BPF` + `CAP_MAC_ADMIN` (the packaged unit runs as root) |
| Build | stable Rust for the workspace, plus a pinned nightly + [`bpf-linker`](https://github.com/aya-rs/bpf-linker) for the eBPF object, and [`just`](https://just.systems) |
| VM tests | `/dev/kvm`, `qemu`, [`virtme-ng`](https://github.com/arighi/virtme-ng) — no host root needed |

```sh
# `bpf` in the active list is the whole check — it implies CONFIG_BPF_LSM=y.
grep bpf /sys/kernel/security/lsm || echo 'add lsm=…,bpf to the kernel cmdline and reboot'
```

If adding it doesn't take, the kernel was built without `CONFIG_BPF_LSM=y` (check
`/proc/config.gz` or `/boot/config-$(uname -r)`) and needs a different one.

`bpf-lsm` is **additive** to whatever LSM you already run: it can only further restrict,
never loosen. A SELinux or AppArmor denial still denies.

## Try it

**Without touching your machine** — the full end-to-end suite (allow/deny, per-action rules,
groups, copy-down precedence, audit→deny, silence, blessing, runtime `policy apply`) runs in a
virtme-ng VM on a pinned kernel, using your host userspace read-only, with no host root:

```sh
cargo install bpf-linker just
packaging/test/run-bpf-lsm-vm.sh                          # pinned kernel v6.12 — same as CI
CORDON_VM_KERNEL=host packaging/test/run-bpf-lsm-vm.sh    # host kernel, fast iteration
```

**On a real box** (after the requirements check above):

```sh
just build                                # workspace + the eBPF object
sudo install -Dm755 target/debug/cordond  /usr/bin/cordond
sudo install -Dm755 target/debug/cordon   /usr/bin/cordon
sudo install -Dm644 target/bpf/cordon.bpf.o /usr/lib/cordon/cordon.bpf.o
sudo install -Dm644 packaging/cordon.example.toml /etc/cordon/config.toml
sudo install -Dm644 packaging/systemd/cordond.service /etc/systemd/system/cordond.service
sudo cordon policy edit --system          # author the policy — start with `audit` rules
sudo systemctl enable --now cordond
cordon status                             # what's loaded, and whether the boundary is up
journalctl -u cordond -f -o cat           # watch decisions
```

`cordon policy edit` is the **sudoedit analog**: it runs your `$EDITOR` as *you* (never root —
a root editor on a same-uid box is an escalation), then validates and, if it compiles, applies
*and* saves in one step, rejecting a broken policy visudo-style instead of persisting it.
Bare `edit` opens your own user tier, `--system` the system policy, `--user bob` someone
else's. Writing policy is root-only (gated on the peer's kernel-attested uid); reading —
`cordon status`, `cordon policy show`, `cordon bless list` — needs no privilege.

Policy may be one file (`/etc/cordon/policy.toml`) or a `/etc/cordon/conf.d/` directory of
fragments merged in name order, each with its own `user =` header. Both the verbose
[`[[rule]]` form](packaging/cordon.example.policy.toml) and the compact
[one-rule-per-line DSL](packaging/cordon.example.dsl.policy.toml) compile identically and can
be mixed in one file.

## Status

Milestones M1 (rule core), M3 (mutation + exec hooks) and M5 (fail-safe pinning) are
implemented and VM-validated, along with blessing B1+B2. **M6 — the code-identity fix — is
the last must-have** before this is worth trusting.

- [`STATUS.md`](STATUS.md) — what exists, what's left, and the facts that cost real time to
  learn
- [`docs/PLAN-rule-model.md`](docs/PLAN-rule-model.md) — the remaining milestone
- [`docs/PLAN-bless.md`](docs/PLAN-bless.md) — blessing roadmap (PAM auth, scope classes)

## Known limitations

Stated plainly, because a security tool that oversells itself is worse than none.

- **`LD_PRELOAD` and interpreted subjects break `exe` identity.** `LD_PRELOAD=evil.so ssh -V`
  runs attacker code with `ssh`'s identity and inherits its grants, and a script surfaces as
  its interpreter (`python3`, not `aws`) — so today **every static `allow` is a potential
  confused-deputy grant**. That's what M6 closes, with a sticky load-time taint; until it
  ships, `bless` (which proves human presence rather than code identity) is the honest answer
  for anything sensitive.
- **Root is out of scope**, as is a resident attacker: ptrace, waiting for unlocks, replacing
  binaries. The design targets one-shot same-uid scrapers and bounds blast radius; it does not
  claim to beat a persistent adversary already running as you.
- **Gating ≠ containing.** cordon stops the read; it does nothing about what an authorized
  tool does with data it legitimately read.
- **Ancestry is best-effort.** Double-fork launders the parent chain; argv is untrusted.
- **No hardened boundary at all** on kernels without BPF-LSM, or with `bpf` absent from the
  LSM list.
- **First-access friction.** A tool with no matching rule is default-denied; granting access
  means editing the root-owned policy and re-applying. There is no interactive per-open prompt
  — a deliberate rejection of the consent-fatigue failure mode that killed the HIPS category.

Longer list with the reasoning: [`DESIGN.md` §10](docs/DESIGN.md#10-honest-limitations).

## How it compares

| | Protects secrets from same-uid programs | Default for an unknown program |
|---|---|---|
| **cordon** | yes — per-object rules, default-deny | denied |
| AppArmor / SELinux (stock desktop) | no — the object isn't the unit of policy | unconfined |
| Flatpak / snap | yes, but only for apps that ship as one | unconfined (a scraper isn't a Flatpak) |
| macOS TCC | yes — the closest existing model | prompted (consent fatigue is its failure mode) |
| Windows Controlled Folder Access | writes only — built against ransomware, not theft | blocked for writes |
| EDR (CrowdStrike, Defender…) | detects after the read, races exfiltration | flagged, not bounded |

Android proves the enforcement works (per-app uid + domain), TCC proves the model is usable,
Windows ships the two halves separately and never joins them — and none of it exists for
Linux desktop. Detailed prior-art survey, including Santa, KubeArmor, Tetragon and bpflock, in
[`DESIGN.md` §13](docs/DESIGN.md#13-related-work--prior-art) and
[`docs/SANTA.md`](docs/SANTA.md).

## Contributing

Pre-1.0 and moving fast — please open an issue to discuss before a large PR. Two gates:

```sh
just test                          # fmt + clippy -D warnings + cargo test
packaging/test/run-bpf-lsm-vm.sh   # the VM smoke — the definition of done
```

The VM run is required for **every** change, including userspace-only ones: it's the only
tier that exercises the real kernel boundary end-to-end, and a compiler or IPC change can
break seeding without failing a single unit test. It defaults to the CI-pinned kernel, so a
green local run matches CI.

## Security

This is unaudited software under active development with a known open hole (above), so please
don't rely on it to protect anything you can't afford to lose. If you find a vulnerability —
especially a bypass of the kernel boundary — report it privately via
[GitHub security advisories](https://github.com/nikicat/cordon/security/advisories/new)
rather than a public issue.

## License

[Apache-2.0](LICENSE).

> *Working name — deliberately outside the `gate`/`Gatekeeper` namespace. It's object-centric:
> you cordon off the secret directories.*
