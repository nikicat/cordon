#!/usr/bin/env bash
# Phase 1 smoke test — the real fanotify boundary. Needs init-namespace ROOT
# (FAN_OPEN_PERM requires CAP_SYS_ADMIN). The hermetic `cargo test` suite can't
# cover this, so this is the proof that the root backend actually denies a
# non-owner's open. Run it three ways:
#
#   sudo packaging/test/phase1-fanotify-smoke.sh          # local, with root
#   packaging/test/run-in-vm.sh                           # local, NO host root (virtme-ng)
#   (CI) sudo packaging/test/phase1-fanotify-smoke.sh     # GHA runner = disposable root VM
#
# It marks the *filesystem* backing a throwaway $HOME (fs marks give recursive
# coverage), then checks two ownership paths — both must deny a non-owner (EPERM):
#   A) adopt: claim a pre-existing secret dir for one exe identity.
#   B) TOFU:  a tool that *creates* its config auto-claims it (no adopt).
#
# NOTE: a filesystem mark routes *all* opens on that fs through the daemon while
# it runs. Keep $TMPDIR on scratch/tmpfs, not a precious fs, if you care about
# the transient overhead.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (fanotify needs CAP_SYS_ADMIN)" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CORDOND="$ROOT_DIR/target/debug/cordond"
CORDON="$ROOT_DIR/target/debug/cordon"
for bin in "$CORDOND" "$CORDON"; do
    [ -x "$bin" ] || { echo "error: $bin missing — run 'cargo build' first" >&2; exit 1; }
done

TMP="$(mktemp -d)"
HOME_DIR="$TMP/home"
SECRET="$HOME_DIR/.config/mytool/secret"
mkdir -p "$(dirname "$SECRET")"
echo "TOPSECRET" > "$SECRET"

# Two distinct executables → two distinct /proc/<pid>/exe identities. Copies of
# `cat` so each just prints the file it is handed.
OWNER="$TMP/owner-tool"
SCRAPER="$TMP/scraper-tool"
cp "$(command -v cat)" "$OWNER"
cp "$(command -v cat)" "$SCRAPER"

export CORDON_SOCK="$TMP/cordon.sock"
export CORDON_STORE="$TMP/store.db"
export CORDON_ZONES="$HOME_DIR:$HOME_DIR/.config"

DPID=""
cleanup() { [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

RUST_LOG="${RUST_LOG:-info}" "$CORDOND" --backend fanotify &
DPID=$!

for _ in $(seq 1 40); do [ -S "$CORDON_SOCK" ] && break; sleep 0.1; done
[ -S "$CORDON_SOCK" ] || { echo "error: cordond did not start" >&2; exit 1; }

# --- A) adopt: claim a pre-existing subtree. On the already-marked fs, so it is
# enforced immediately.
"$CORDON" adopt "$HOME_DIR/.config/mytool" --as "$OWNER"

fail=0

echo "=== A) adopt-based ownership ==="
echo "--- owner reads its own secret (expect ALLOW) ---"
if out="$("$OWNER" "$SECRET" 2>&1)"; then
    echo "  OK: owner read succeeded: $out"
else
    echo "  FAIL: owner was denied: $out"; fail=1
fi

echo "--- scraper reads the same secret (expect DENY / EPERM) ---"
if out="$("$SCRAPER" "$SECRET" 2>&1)"; then
    echo "  FAIL: scraper read succeeded: $out"; fail=1
else
    echo "  OK: scraper denied: $out"
fi

echo "=== B) TOFU-on-create (no adopt) ==="
# Copied `bash` whose `>` redirect opens with O_CREAT — the create signal the
# backend reads from /proc/<pid>/syscall to auto-claim ownership. A second copy
# is the scraper (distinct exe path = distinct identity).
TOFU_OWNER="$TMP/tofu-tool"
TOFU_SCRAPER="$TMP/tofu-scraper"
cp "$(command -v bash)" "$TOFU_OWNER"
cp "$(command -v bash)" "$TOFU_SCRAPER"
TSECRET="$HOME_DIR/.config/tofutool/secret"
mkdir -p "$(dirname "$TSECRET")"

echo "--- tool creates its config under a zone (expect ALLOW + auto-claim) ---"
if "$TOFU_OWNER" -c "echo TOFUSECRET > '$TSECRET'" 2>/dev/null; then
    echo "  OK: create allowed"
else
    echo "  FAIL: create was denied"; fail=1
fi

echo "--- same tool reads it back, never adopted (expect ALLOW via TOFU) ---"
if out="$("$TOFU_OWNER" -c "cat < '$TSECRET'" 2>&1)"; then
    echo "  OK: owner read after TOFU: $out"
else
    echo "  FAIL: owner denied after TOFU: $out"; fail=1
fi

echo "--- scraper reads the TOFU-claimed secret (expect DENY / EPERM) ---"
if out="$("$TOFU_SCRAPER" -c "cat < '$TSECRET'" 2>&1)"; then
    echo "  FAIL: scraper read succeeded: $out"; fail=1
else
    echo "  OK: scraper denied: $out"
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: fanotify enforced owner-allow + scraper-deny for both adopt and TOFU"
else
    echo "FAILED" >&2
fi
exit "$fail"
