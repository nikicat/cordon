#!/usr/bin/env bash
# Runs the bpf-lsm smoke suite in a virtme-ng VM with `bpf` appended to the active LSM
# list. That is the only way to exercise the BPF-LSM boundary without rebooting the host,
# whose kernel usually omits `bpf` from `lsm=`. Needs only /dev/kvm, virtme-ng and qemu,
# The eBPF toolchain (the nightly and bpf-linker) is fetched by `just build-ebpf`.
#
#   packaging/test/run-bpf-lsm-vm.sh                          # pinned kernel v6.12 (== CI)
#   CORDON_VM_KERNEL=host packaging/test/run-bpf-lsm-vm.sh    # host kernel (fast iteration)
#   CORDON_VM_KERNEL=v6.6 packaging/test/run-bpf-lsm-vm.sh    # another pinned kernel
#
# The default is the CI-pinned kernel, not the host's. The host verifier is laxer and can
# pass an object that the v6.12 verifier rejects (see `clamped` in crates/bpf/src/main.rs).
# So local runs match CI by default, and the host kernel is an explicit opt-in.
#
# The host userspace and the host-built binaries are exposed read-only in the guest, so
# there is no rootfs to build.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

# Build the daemon (with its default bpf-lsm backend), the `cordon` CLI and the eBPF
# object on the host. All three reach the guest read-only.
cargo build -p cordon-daemon
cargo build -p cordon-cli
just build-ebpf

# Activate `bpf` in the LSM list (override with CORDON_VM_LSM). The list is kept minimal.
# `lockdown` in a restrictive mode blocks BPF_PROG_LOAD with EPERM, so it is left out, and
# `capability` is the base every kernel needs.
LSM="${CORDON_VM_LSM:-capability,bpf}"

# Default to the CI-pinned kernel. `host` selects the running kernel for fast iteration.
KERNEL="${CORDON_VM_KERNEL:-v6.12}"
if [ "$KERNEL" = host ]; then
    exec vng --run -a "lsm=$LSM" -- bash packaging/test/bpf-lsm-smoke.sh
else
    exec vng --run "$KERNEL" -a "lsm=$LSM" -- bash packaging/test/bpf-lsm-smoke.sh
fi
