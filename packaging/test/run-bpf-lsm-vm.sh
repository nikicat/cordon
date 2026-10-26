#!/usr/bin/env bash
# Run the bpf-lsm smoke in a virtme-ng VM with `bpf` appended to the active LSM
# list — the only way to exercise the BPF-LSM boundary without rebooting the host
# (the host kernel usually omits `bpf` from `lsm=`). Needs only /dev/kvm + virtme-ng
# + qemu, plus the eBPF toolchain to build the object (nightly + bpf-linker).
#
#   packaging/test/run-bpf-lsm-vm.sh                          # pinned kernel v6.12 (== CI)
#   CORDON_VM_KERNEL=host packaging/test/run-bpf-lsm-vm.sh    # host kernel (fast iteration)
#   CORDON_VM_KERNEL=v6.6 packaging/test/run-bpf-lsm-vm.sh    # another pinned kernel
#
# Default = the CI-pinned kernel, NOT the host: the host verifier is laxer and can pass
# an object the v6.12 verifier rejects (see `clamped` in crates/bpf/src/main.rs). So local
# runs match CI by default; opt into the host kernel explicitly for fast iteration.
#
# The host userspace + host-built binaries are exposed read-only in the guest, so
# there is no rootfs to build.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

# Build the daemon (bpf-lsm backend on by default) + the `cordon` CLI (for the policy
# apply/show scenario) + the eBPF object on the host (all reach the guest read-only).
cargo build -p cordon-daemon
cargo build -p cordon-cli
just build-ebpf

# Activate `bpf` in the LSM list (override via CORDON_VM_LSM). Kept minimal —
# `lockdown` in a restrictive mode blocks BPF_PROG_LOAD (EPERM), so it's excluded;
# `capability` is the base every kernel needs.
LSM="${CORDON_VM_LSM:-capability,bpf}"

# Default to the CI-pinned kernel; `host` selects the running kernel for fast iteration.
KERNEL="${CORDON_VM_KERNEL:-v6.12}"
if [ "$KERNEL" = host ]; then
    exec vng --run -a "lsm=$LSM" -- bash packaging/test/bpf-lsm-smoke.sh
else
    exec vng --run "$KERNEL" -a "lsm=$LSM" -- bash packaging/test/bpf-lsm-smoke.sh
fi
