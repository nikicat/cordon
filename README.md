# cordon

Object-first file access control for Linux. cordon makes `~/.ssh`, `~/.aws`,
`~/.config/gcloud` and the rest of your secrets readable only by the tools that own them.
Those tools notice no difference, and everything else running as your user is refused.
Enforcement happens in the kernel with eBPF (BPF-LSM), and cordon is written in Rust.

[![ci](https://github.com/nikicat/cordon/actions/workflows/ci.yml/badge.svg)](https://github.com/nikicat/cordon/actions/workflows/ci.yml)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![status: early development](https://img.shields.io/badge/status-early%20development-orange)

> cordon is not production-ready. The kernel boundary works, and CI validates it end to end
> against a pinned kernel. But this is active development. The policy format, the CLI and the
> on-disk layout change without notice, and the largest known hole is still open by design
> (see [Known limitations](#known-limitations)). Try it on a machine you can afford to lock
> yourself out of. Issues and design feedback are welcome.

## The problem

Every credential on a Linux box is one `open()` away from any process running as you:

```
~/.ssh/id_ed25519    ~/.aws/credentials   ~/.config/gcloud/   ~/.kube/config
~/.netrc             ~/.npmrc             ~/.docker/config.json
~/.config/gh/hosts.yml   ~/.gnupg/        .env
```

Unix permissions separate users, not programs. A `curl … | sh`, an npm `postinstall` hook, a
compromised editor extension and an infostealer all run at your uid, and any of them can scoop
the lot in one pass. AppArmor and SELinux do essentially nothing here by default, and not by
oversight. Confinement is a property of the program, and an unknown program is unconfined. A
scraper is by definition an unknown program.
([The long version, with what each incumbent actually does.](docs/DESIGN.md#31-what-the-incumbents-actually-do-to-a-scraper))

## What cordon does

cordon turns the model around. It protects the object, denies every subject by default, and
allows only the tools that legitimately own the object.

```toml
# /etc/cordon/policy.toml — root-owned, compiled and pushed into the kernel
user = "alice"                                          # the user whose ~ these paths use

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

`ssh` reads its key exactly as before. Anything else that opens `~/.ssh` gets `EPERM`, and the
journal gets a line naming the exe, the path and the action. None of this needs cooperation
from the denied program, an `LD_PRELOAD` shim, or a change to where your files live.

The intended flow is audit, look, then deny. You start with `audit` on a directory, see who
actually touches it, and then flip that one directory to `deny`. There is no global on/off
switch and no interactive prompt. Each rule picks its own verdict (`allow`, `audit`, `deny` or
`silence`), so you tighten one object at a time instead of arming the whole box at once.

Check a policy without root, without a daemon, and without any risk:

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
  at compile time into a flat rule table for each protected object. The kernel side does a
  first-match scan and nothing else. Precedence goes by object depth first, then by subject
  specificity, then deny over allow. So a rule on `~/.aws/.danger-token` beats one on
  `~/.aws`.
- **Enforced in the kernel.** The BPF-LSM program is written in Rust with
  [aya](https://github.com/aya-rs/aya). It hooks `file_open` for read, write and create, and
  `bprm_check_security` for exec. It also hooks `inode_link`, `inode_rename`, `inode_unlink`,
  `inode_rmdir` and `inode_mkdir`, so a secret can't be hardlinked or renamed out of its
  protected directory and then read from an unguarded path.
- **Fail-safe.** The LSM links are pinned to bpffs, so the boundary survives the daemon
  crashing, being killed or being restarted, with no gap. See
  [below](#enforcement-outlives-the-daemon).
- **Atomic reloads.** The rule maps are banked. A re-seed fills the inactive bank and then
  flips one word, so a policy is never half-applied.
- **Quiet by construction.** Tools re-open one config hundreds of times per run (helm opens
  `~/.kube/config` 464 times). So an in-kernel LRU suppressor emits at most one event per
  second for each `(exe, opened file, action)`, and folds the rest into a count.

The full design, threat model and rationale are in [`docs/DESIGN.md`](docs/DESIGN.md).

## Blessing — `sudo` for file reads

Static rules name known exes. No static subject works for the tools you reach for
interactively over secrets, such as `cat`, `rg` or a shell. `allow /usr/bin/cat` admits every
`cat`, including the one a scraper runs. `cordon bless` instead grants one specific invocation,
and its descendants, a runtime pass. The pass belongs to a class that you declare in the
policy:

```toml
# added to the policy above
rules = '''
allow  @blessed-ro  read  @cloud-creds
'''

[group.subject.blessed-ro]
blessing = "ro"                       # a subject group matched by blessing class, not by exe
```

```sh
cordon bless --class ro -- aws s3 ls   # this aws may read the cloud creds and nothing else
cordon bless --class ro                # or open a blessed shell
cordon bless list                      # live blessings: id, class, age, pids
cordon bless revoke 3                  # kill that blessed tree now
```

You don't prefix it with `sudo`. `cordon bless` runs as you and prompts for authentication
partway through. It uses `sudo` for that by default, and `$CORDON_SUDO` picks another tool.
The prompt is there because a human at the keyboard is the one thing a one-shot scraper can't
produce. The blessed command stays an ordinary child of your shell, so its environment, tty,
job control and desktop session survive. GUI apps, `run0` and `pkexec` work inside a blessed
shell. The grant rides on a root-owned cgroup made for that one invocation. So the grant
evaporates when the command exits, it reaches only the objects its rules name, and every
blessed access is journaled with its class.
([`DESIGN.md` §16](docs/DESIGN.md#16-blessing--runtime-authenticated-access-grants))

> Sudoers note. sudo caches authentication for about 15 minutes, so a second `bless` in that
> window won't prompt. To require a human for every grant, add this line:
> `Defaults!/usr/bin/cordon timestamp_timeout=0`

## Enforcement outlives the daemon

The LSM programs are attached by `bpf_link`s that are pinned to bpffs. So the boundary does not
depend on `cordond` staying alive. You can kill it, crash it or restart it, and every verdict
keeps being enforced with no gap. The daemon still journals decisions and applies policy
changes. Its absence costs you the log, never the boundary. That corollary surprises people,
so here it is plainly:

> `systemctl stop cordond` does not stop enforcement.

Turning the boundary off is a deliberate, separate act:

```sh
sudo systemctl stop cordond     # stops the daemon, but the box is still enforcing
sudo cordond --teardown         # removes the pins, which is what turns enforcement off
```

`--teardown` refuses to run while a daemon is running, so stop the daemon first. It needs no
socket, so it works when the daemon is dead, which is exactly when you need it. It takes
effect a moment after it returns, because unlinking a pin drops the link's last reference and
the kernel then detaches the program on a workqueue. If `cordon status` can't reach the daemon,
it reports whether the pins are still in place. That way "connection refused" is never
mistaken for "not enforcing".

## Requirements

| | |
|---|---|
| Kernel | `CONFIG_BPF_LSM=y`, and `bpf` in the active LSM list (`lsm=…,bpf` on the kernel command line). Kernel 5.7 or later should work in principle, but CI pins v6.12, and that is the version actually tested. |
| Privileges | root with `CAP_BPF` and `CAP_MAC_ADMIN` (the packaged unit runs as root) |
| Build | stable Rust for the workspace, a pinned nightly and [`bpf-linker`](https://github.com/aya-rs/bpf-linker) for the eBPF object, and [`just`](https://just.systems) |
| VM tests | `/dev/kvm`, `qemu` and [`virtme-ng`](https://github.com/arighi/virtme-ng). No host root is needed. |

```sh
# `bpf` in the active list is the whole check, because it implies CONFIG_BPF_LSM=y.
grep bpf /sys/kernel/security/lsm || echo 'add lsm=…,bpf to the kernel cmdline and reboot'
```

If adding it doesn't take effect, the kernel was built without `CONFIG_BPF_LSM=y` (check
`/proc/config.gz` or `/boot/config-$(uname -r)`), and you need a different kernel.

`bpf-lsm` adds to whatever LSM you already run. It can only restrict further and never
loosens anything, so a SELinux or AppArmor denial still denies.

## Try it

To try it without touching your machine, run the full end-to-end suite in a virtme-ng VM on a
pinned kernel. The suite covers allow and deny, per-action rules, groups, copy-down
precedence, audit to deny, silence, blessing and runtime `policy apply`. It uses your host
userspace read-only and needs no host root:

```sh
cargo install bpf-linker just
packaging/test/run-bpf-lsm-vm.sh                          # pinned kernel v6.12, the same as CI
CORDON_VM_KERNEL=host packaging/test/run-bpf-lsm-vm.sh    # host kernel, for fast iteration
```

To run it on a real box, pass the requirements check above first:

```sh
just build                                # workspace + the eBPF object
sudo install -Dm755 target/debug/cordond  /usr/bin/cordond
sudo install -Dm755 target/debug/cordon   /usr/bin/cordon
sudo install -Dm644 target/bpf/cordon.bpf.o /usr/lib/cordon/cordon.bpf.o
sudo install -Dm644 packaging/cordon.example.toml /etc/cordon/config.toml
sudo install -Dm644 packaging/systemd/cordond.service /etc/systemd/system/cordond.service
sudo cordon policy edit --system          # author the policy, starting with `audit` rules
sudo systemctl enable --now cordond
cordon status                             # what's loaded, and whether the boundary is up
journalctl -u cordond -f -o cat           # watch decisions
```

`cordon policy edit` works like sudoedit. It runs your `$EDITOR` as you and never as root,
because a root editor on a same-uid box is an escalation. It then validates the policy, and if
the policy compiles, it applies and saves it in one step. Like visudo, it rejects a broken
policy instead of saving it. Bare `edit` opens your own user tier, `--system` opens the system
policy, and `--user bob` opens someone else's. Writing policy is root-only, and the check uses
the peer's uid as the kernel attests it. Reading needs no privilege. That covers
`cordon status`, `cordon policy show` and `cordon bless list`.

A policy may be one file (`/etc/cordon/policy.toml`) or a `/etc/cordon/conf.d/` directory of
fragments. The fragments are merged in name order, and each has its own `user =` header. The
verbose [`[[rule]]` form](packaging/cordon.example.policy.toml) and the compact
[one-rule-per-line DSL](packaging/cordon.example.dsl.policy.toml) compile identically and can
be mixed in one file.

## Status

Milestones M1 (rule core), M3 (mutation and exec hooks) and M5 (fail-safe pinning) are
implemented and VM-validated, and so are blessing stages B1 and B2. M6, the code-identity fix,
is the last must-have before cordon is worth trusting.

- [`STATUS.md`](STATUS.md): what exists, what's left, and the facts that cost real time to
  learn
- [`docs/PLAN-rule-model.md`](docs/PLAN-rule-model.md): the remaining milestone
- [`docs/PLAN-bless.md`](docs/PLAN-bless.md): the blessing roadmap (PAM auth, scope classes)

## Known limitations

These are stated plainly, because a security tool that oversells itself is worse than none.

- **`LD_PRELOAD` and interpreted subjects break `exe` identity.** `LD_PRELOAD=evil.so ssh -V`
  runs attacker code with `ssh`'s identity and inherits its grants. A script surfaces as its
  interpreter (`python3`, not `aws`). So today every static `allow` is a potential
  confused-deputy grant. M6 closes this hole with a sticky load-time taint. Until it ships,
  `bless` is the honest answer for anything sensitive, because it proves human presence rather
  than code identity.
- **Root is out of scope.** So is a resident attacker who uses ptrace, waits for unlocks or
  replaces binaries. The design targets one-shot same-uid scrapers and bounds the blast radius.
  It does not claim to beat a persistent adversary already running as you.
- **Gating is not containing.** cordon stops the read. It does nothing about what an
  authorized tool does with data it legitimately read.
- **Ancestry is best-effort.** A double fork launders the parent chain, and argv is untrusted.
- **No hardened boundary at all** exists on kernels without BPF-LSM, or when `bpf` is absent
  from the LSM list.
- **First-access friction.** A tool with no matching rule is denied by default. Granting it
  access means editing the root-owned policy and re-applying it. There is no interactive
  per-open prompt. That is a deliberate rejection of consent fatigue, the failure mode that
  killed the HIPS category.

A longer list with the reasoning is in [`DESIGN.md` §10](docs/DESIGN.md#10-honest-limitations).

## How it compares

| | Protects secrets from same-uid programs | Default for an unknown program |
|---|---|---|
| cordon | yes, with per-object rules and default deny | denied |
| AppArmor / SELinux (stock desktop) | no, because the object isn't the unit of policy | unconfined |
| Flatpak / snap | yes, but only for apps that ship as one | unconfined (a scraper isn't a Flatpak) |
| macOS TCC | yes, and it is the closest existing model | prompted (consent fatigue is its failure mode) |
| Windows Controlled Folder Access | writes only, because it was built against ransomware, not theft | blocked for writes |
| EDR (CrowdStrike, Defender…) | detects after the read, and races the exfiltration | flagged, not bounded |

Android proves that the enforcement works (a per-app uid plus a domain), and TCC proves that
the model is usable. Windows ships the two halves separately and never joins them. None of it
exists for the Linux desktop. A detailed prior-art survey, including Santa, KubeArmor,
Tetragon and bpflock, is in [`DESIGN.md` §13](docs/DESIGN.md#13-related-work--prior-art) and
[`docs/SANTA.md`](docs/SANTA.md).

## Contributing

cordon is pre-1.0 and moving fast, so please open an issue to discuss a large PR before you
send it. There are two gates:

```sh
just test                          # fmt + clippy -D warnings + cargo test
packaging/test/run-bpf-lsm-vm.sh   # the VM smoke test, which is the definition of done
```

The VM run is required for every change, including userspace-only ones. It is the only tier
that exercises the real kernel boundary end to end, and a compiler or IPC change can break
seeding without failing a single unit test. It defaults to the CI-pinned kernel, so a green
local run matches CI.

## Security

This is unaudited software under active development with a known open hole (see above). So
please don't rely on it to protect anything you can't afford to lose. If you find a
vulnerability, and especially a bypass of the kernel boundary, report it privately through
[GitHub security advisories](https://github.com/nikicat/cordon/security/advisories/new)
rather than in a public issue.

## License

[Apache-2.0](LICENSE).

> cordon is a working name, chosen deliberately outside the `gate`/`Gatekeeper` namespace. The
> name is object-centric, because you cordon off the secret directories.
