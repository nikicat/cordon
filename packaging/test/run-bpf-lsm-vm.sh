#!/usr/bin/env bash
# Run the bpf-lsm smoke in a virtme-ng VM with `bpf` appended to the active LSM
# list — the only way to exercise the BPF-LSM boundary without rebooting the host
# (the host kernel usually omits `bpf` from `lsm=`). Needs only /dev/kvm + virtme-ng
# + qemu, plus the eBPF toolchain to build the object (nightly + bpf-linker).
#
#   packaging/test/run-bpf-lsm-vm.sh                          # host kernel (local dev)
#   CORDON_VM_KERNEL=v6.12 packaging/test/run-bpf-lsm-vm.sh   # pinned kernel (CI)
#
# The host userspace + host-built binaries are exposed read-only in the guest, so
# there is no rootfs to build.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

# Build the feature daemon + the eBPF object on the host (both reach the guest
# read-only). The rule-model smoke drives the kernel via a compiled policy file, not
# the `cordon` CLI, so the CLI isn't needed here.
cargo build -p cordon-daemon --features bpf-lsm
just build-ebpf

# Activate `bpf` in the LSM list (override via CORDON_VM_LSM). Kept minimal —
# `lockdown` in a restrictive mode blocks BPF_PROG_LOAD (EPERM), so it's excluded;
# `capability` is the base every kernel needs.
LSM="${CORDON_VM_LSM:-capability,bpf}"

if [ -n "${CORDON_VM_KERNEL:-}" ]; then
    exec vng --run "$CORDON_VM_KERNEL" -a "lsm=$LSM" -- bash packaging/test/bpf-lsm-smoke.sh
else
    exec vng --run -a "lsm=$LSM" -- bash packaging/test/bpf-lsm-smoke.sh
fi
