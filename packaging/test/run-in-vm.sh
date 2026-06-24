#!/usr/bin/env bash
# Run the Phase 1 fanotify smoke test in a virtme-ng VM — a nested kernel, as
# guest-root, with NO host root. Needs only /dev/kvm (group `kvm`) + virtme-ng +
# qemu. The VM runs DIRECTLY on the host (no container / userns nesting), so it
# behaves identically locally and in CI.
#
#   packaging/test/run-in-vm.sh                          # host kernel (fast, local dev)
#   CORDON_VM_KERNEL=v6.12 packaging/test/run-in-vm.sh   # pinned upstream kernel (reproducible / CI)
#
# A pinned kernel (e.g. v6.12) is fetched from the Ubuntu mainline repo by
# virtme-ng (needs `dpkg` to unpack — present on Ubuntu/CI). The host userspace
# (and the host-built cordon binaries) are exposed read-only via virtme-ng, so
# there is no rootfs to build and no glibc mismatch.
#
# Why not libkrun/krunvm: booting libkrun *inside a container* (the only way to
# get krunvm onto a CI runner without packaging it for the distro) fails with
# environment-specific userns (gid_map) / memfd_create errors that diverge
# between local and GitHub runners. virtme-ng runs qemu directly — robust and
# reproducible.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cargo build --manifest-path "$ROOT_DIR/Cargo.toml"
cd "$ROOT_DIR"

if [ -n "${CORDON_VM_KERNEL:-}" ]; then
    exec vng --run "$CORDON_VM_KERNEL" -- bash packaging/test/phase1-fanotify-smoke.sh
else
    exec vng --run -- bash packaging/test/phase1-fanotify-smoke.sh
fi
