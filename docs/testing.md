# Testing

How a change is validated.

> **Definition of done: every change is validated in a VM locally before it is complete.**
> Run `packaging/test/run-bpf-lsm-vm.sh`, which defaults to the CI-pinned kernel (currently
> `v6.12`), and confirm that all `bpf-lsm-smoke.sh` scenarios pass. This holds for
> userspace-only changes too, such as the policy compiler, the CLI or the daemon's control
> plane. The VM is the one tier that exercises the real kernel boundary end to end, and a
> userspace change can still break seeding, the IPC apply path, or a policy shape.
> `cargo test` (the unprivileged tier) is necessary but not sufficient. When a change adds or alters
> enforcement behavior, add or extend a scenario so that the suite still covers it. The same
> harness and the same pinned kernel run locally and in CI, so a green local VM run is the
> gate, not a courtesy.

The kernel-backed smoke test (`bpf-lsm-smoke.sh`) drives the rule model end to end against a
policy file. Its subjects are exes with distinct inodes (copies of `bash`, so each is its own
subject) that read and write secrets under a protected subtree. It covers:
- an owner exe that is allowed to read its secret, and a scraper with no matching rule that
  is denied by default (`EPERM`) and reported on the ring buffer with the object inode and the
  action;
- per-action rules (read allowed and write denied by default on the same object), subject and
  object groups, and ties where deny beats allow. It also covers copy-down precedence, where
  a subtree allow is combined with a file-specific deny for one subject and the sibling file
  stays readable. Then there is audit to deny, which observes with a catch-all and then
  enforces by flipping that one rule, with no global mode. Finally it covers silence (denied
  but not logged), runtime `policy apply`, and event coalescing.

The suite asserts that the right subject reads, that the wrong one is denied in the kernel,
that precedence resolves as [ADR 0008](adr/0008-precedence.md) says, and that a tight loop of
opens collapses to a few records. All of this runs on a real kernel. The unprivileged
`cargo test` tier covers the parser and the copy-down compiler.

## Test tiers (by privilege)
- **Unprivileged, with no kernel backend.** `cargo test` covers the policy parser, the
  copy-down compiler and the IPC types. With `--all-features` it also builds and unit-tests
  the `bpf-lsm` control plane, including event coalescing. It is CI-friendly and needs no
  root, and it covers everything except the in-kernel hook itself.
- **The `bpf-lsm` boundary in a VM, without host root, through virtme-ng.** Loading the LSM
  program needs `CAP_BPF` and `CAP_MAC_ADMIN`, plus `bpf` in the active LSM list. A virtme-ng
  VM (`packaging/test/run-bpf-lsm-vm.sh`) provides both. It boots a pinned upstream kernel
  (Ubuntu mainline, for example `v6.12`) with `lsm=…,bpf` and runs as root in the guest. It
  needs only `/dev/kvm` (group `kvm`) and no host root. The VM runs qemu directly, with no
  container, and virtme-ng reuses the host userspace. So there is no rootfs to build and no
  glibc mismatch. The same harness and kernel run locally and in CI, so the kernel never
  diverges. The pinned version is the default, and `CORDON_VM_KERNEL=host` selects the host
  kernel for fast local iteration.
- **Why not libkrun or krunvm.** They were evaluated and dropped. Getting `krunvm` onto a CI
  runner means nesting it inside a container. That stacks two user namespaces
  (`buildah unshare`) under the libkrun VMM, and the stack fails differently in each
  environment (`gid_map: operation not permitted` locally, and `memfd_create: EINVAL` on
  GitHub). So it is not reproducible. virtme-ng collapses the stack to a single dependency on
  `/dev/kvm`.
- `bpf-lsm-smoke.sh` proves the rule model end to end through a real kernel. It covers allow
  and deny, per-action rules, subject and object groups, copy-down precedence, audit to deny,
  silence, runtime `policy apply` and event coalescing. It is green in the virtme-ng VM, on
  both the host kernel and the pinned `v6.12`, booted with `lsm=…,bpf`.

## A probe must not build its own premise

B2's derisk spike made a cgroup under `session-3.scope` with `mkdir`, confirmed that logind
saw the session, and concluded that blessing could place carriers there. It never asked where
the user's processes actually are: under the delegated `user@UID.service`, with no session
scope above them. A probe that builds its own world proves only that the world is
self-consistent. The `bless_placement` and `bless_reconcile_ownership` smoke scenarios now
cover the placement rule against where processes really run.
