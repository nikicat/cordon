#!/usr/bin/env bash
# Phase 3 smoke — the bpf-lsm boundary. Needs guest-root and a kernel with
# CONFIG_BPF_LSM=y *and* `bpf` in the active LSM list (boot `lsm=…,bpf`). The host's
# running kernel usually omits `bpf`, so run this under virtme-ng via
# packaging/test/run-bpf-lsm-vm.sh, which appends the LSM cmdline.
#
# The verdict is returned in-kernel by the eBPF `file_open` hook. Thanks to
# map-sync-on-adopt the daemon pushes ownership into the BPF maps at runtime, so we
# adopt against the *running* daemon (no restart) and just wait for the sync.
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (bpf-lsm needs CAP_BPF + CAP_MAC_ADMIN)" >&2
    exit 1
fi
if ! grep -qw bpf /sys/kernel/security/lsm; then
    echo "error: 'bpf' not in active LSM list ($(cat /sys/kernel/security/lsm))." >&2
    echo "       boot with lsm=…,bpf (the hook loads but never mediates otherwise)." >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CORDOND="$ROOT_DIR/target/debug/cordond"
CORDON="$ROOT_DIR/target/debug/cordon"
OBJ="$ROOT_DIR/target/bpf/cordon.bpf.o"
[ -x "$CORDOND" ] || { echo "missing $CORDOND — cargo build -p cordon-daemon --features bpf-lsm" >&2; exit 1; }
[ -e "$OBJ" ]    || { echo "missing $OBJ — just build-ebpf" >&2; exit 1; }

# Default /tmp is fine even though virtme-ng makes it an overlayfs: the daemon
# resolves a path's device from the mount table (proc::file_id), not stat(2)'s
# st_dev, so the daemon and the kernel's inode->i_sb->s_dev agree on overlayfs and
# btrfs too. Exercising the overlay here is the stronger test.
TMP="$(mktemp -d)"
HOME_DIR="$TMP/home"
SECRET="$HOME_DIR/.config/mytool/secret"
mkdir -p "$(dirname "$SECRET")"
echo "TOPSECRET" > "$SECRET"

# Two distinct executables → two distinct exe identities (copies of `cat`).
OWNER="$TMP/owner-tool"
SCRAPER="$TMP/scraper-tool"
cp "$(command -v cat)" "$OWNER"
cp "$(command -v cat)" "$SCRAPER"

SOCK="$TMP/cordon.sock"
LOG="$TMP/daemon.log"
cat > "$TMP/config.toml" <<EOF
backend = "bpf-lsm"
socket = "$SOCK"
store = "$TMP/store.db"
bpf_object = "$OBJ"
zones = ["$HOME_DIR", "$HOME_DIR/.config"]
EOF
export CORDON_CONFIG="$TMP/config.toml"

RUST_LOG="${RUST_LOG:-info}" "$CORDOND" >"$LOG" 2>&1 &
DPID=$!
cleanup() { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "error: daemon did not start" >&2; sed 's/^/  daemon| /' "$LOG"; exit 1; }

# Wait for the backend thread to settle — it attaches concurrently with the IPC
# socket coming up, so the socket existing doesn't mean the program loaded yet.
# Either it attaches (make-or-break: verifier accepted it) or it logs a fatal error.
attached=0
for _ in $(seq 1 50); do
    grep -q "active on the file_open hook" "$LOG" && { attached=1; break; }
    grep -q "backend exited with error" "$LOG" && break
    sleep 0.1
done
if [ "$attached" -ne 1 ]; then
    echo "FAIL: eBPF program did not attach (verifier/load error):" >&2
    sed 's/^/  daemon| /' "$LOG" >&2
    exit 1
fi

# adopt against the running daemon → bumps the policy clock → backend re-syncs the
# BPF maps within one poll interval.
"$CORDON" adopt "$HOME_DIR/.config/mytool" --as "$OWNER"

# Wait for the in-kernel maps to reflect the adopt (scraper starts getting EPERM).
synced=0
for _ in $(seq 1 30); do
    if ! "$SCRAPER" "$SECRET" >/dev/null 2>&1; then synced=1; break; fi
    sleep 0.1
done

fail=0
echo "--- owner reads its own secret (expect ALLOW) ---"
if out="$("$OWNER" "$SECRET" 2>&1)"; then
    echo "  OK: owner read: $out"
else
    echo "  FAIL: owner denied: $out"; fail=1
fi
echo "--- scraper reads the same secret (expect DENY / EPERM) ---"
if out="$("$SCRAPER" "$SECRET" 2>&1)"; then
    echo "  FAIL: scraper read succeeded: $out"; fail=1
else
    echo "  OK: scraper denied: $out"
fi
[ "$synced" -eq 1 ] || echo "  note: maps never synced within timeout (scraper stayed allowed)"

if [ "$fail" -eq 0 ]; then
    echo "PASS: bpf-lsm enforced owner-allow + scraper-deny (in-kernel)"
else
    echo "FAILED" >&2
    sed 's/^/  daemon| /' "$LOG" >&2
fi
exit "$fail"
