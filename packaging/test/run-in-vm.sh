#!/usr/bin/env bash
# Run the Phase 1 fanotify smoke test in a libkrun microVM — a FIXED kernel
# (libkrunfw's bundled kernel, verified to enable FANOTIFY_ACCESS_PERMISSIONS),
# as guest-root, with NO host root. Needs only /dev/kvm (group `kvm`) plus
# krunvm + buildah. Same path works locally and in CI, so "works on my kernel"
# never diverges from "works on the CI kernel".
#
#   packaging/test/run-in-vm.sh
#
# The base image only provides userspace (bash, cat, coreutils) + a matching
# glibc for the host-built binaries. Default is archlinux to match an Arch host's
# rolling glibc; override with CORDON_VM_IMAGE for other hosts (or build static
# musl binaries to decouple entirely).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${CORDON_VM_IMAGE:-docker.io/library/archlinux:latest}"
NAME="${CORDON_VM_NAME:-cordon-fanotify-test}"

if [ -z "${_CORDON_VM_INNER:-}" ]; then
    # Host side: build, ensure the base image (buildah shares storage with krunvm;
    # no podman needed), then re-enter under buildah unshare (krunvm requires a
    # rootless user-namespace session).
    cargo build --manifest-path "$ROOT_DIR/Cargo.toml"
    buildah pull --policy missing "$IMAGE"
    exec buildah unshare env _CORDON_VM_INNER=1 \
        ROOT_DIR="$ROOT_DIR" IMAGE="$IMAGE" NAME="$NAME" bash "$0"
fi

# Inside buildah unshare: drive the microVM.
krunvm delete "$NAME" >/dev/null 2>&1 || true
krunvm create "$IMAGE" --name "$NAME" --volume "$ROOT_DIR:/src" >/dev/null
set +e
krunvm start "$NAME" -- bash /src/packaging/test/phase1-fanotify-smoke.sh
rc=$?
set -e
krunvm delete "$NAME" >/dev/null 2>&1 || true
exit "$rc"
