#!/usr/bin/env bash
# Phase 3 e2e — the bpf-lsm boundary. Three scenarios in a single VM boot:
#
#   1. enforce       — owner reads its secret (ALLOW), a scraper is denied in-kernel
#                      (DENY/EPERM). The happy path.
#   2. self-test neg — start with deliberately *wrong* field offsets; the program
#                      attaches but mediates nothing. The daemon's self-test MUST turn
#                      that silent no-op into a loud abort, never a "running" boundary
#                      that protects nothing. (Guards the offset-injection design —
#                      "a kernel mismatch must not go silent".)
#   3. audit         — a non-owner open is ALLOWED but logged as a would-deny, so the
#                      blast radius of an ownership decision can be previewed.
#
# Needs guest-root and a kernel with CONFIG_BPF_LSM=y *and* `bpf` in the active LSM
# list (boot `lsm=…,bpf`). The host's running kernel usually omits `bpf`, so run this
# under virtme-ng via packaging/test/run-bpf-lsm-vm.sh, which appends the LSM cmdline.
#
# The verdict is returned in-kernel by the eBPF `file_open` hook. Thanks to
# map-sync-on-adopt the daemon pushes ownership into the BPF maps at runtime, so we
# adopt against the *running* daemon (no restart) and wait for the sync.
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
[ -x "$CORDON" ]  || { echo "missing $CORDON — cargo build -p cordon-cli" >&2; exit 1; }
[ -e "$OBJ" ]     || { echo "missing $OBJ — just build-ebpf" >&2; exit 1; }

# --- shared per-scenario state + helpers -----------------------------------
# Each scenario gets a fresh workspace + daemon. Globals are reset by `ws_new`.
TMP="" HOME_DIR="" SECRET="" OWNER="" SCRAPER="" SOCK="" LOG="" DPID=""

# Build a throwaway home + two distinct exes (copies of `cat` → two distinct exe
# identities) and a config for the requested mode. Default /tmp is fine even though
# virtme-ng makes it an overlayfs: the daemon resolves a path's device from the mount
# table (proc::file_id), not stat(2)'s st_dev, so it agrees with the kernel's
# inode->i_sb->s_dev on overlayfs/btrfs. Exercising the overlay here is the stronger
# test.
ws_new() { # $1 = enforce|audit
    TMP="$(mktemp -d)"
    HOME_DIR="$TMP/home"
    SECRET="$HOME_DIR/.config/mytool/secret"
    mkdir -p "$(dirname "$SECRET")"
    echo "TOPSECRET" > "$SECRET"
    OWNER="$TMP/owner-tool"; SCRAPER="$TMP/scraper-tool"
    cp "$(command -v cat)" "$OWNER"; cp "$(command -v cat)" "$SCRAPER"
    SOCK="$TMP/cordon.sock"; LOG="$TMP/daemon.log"
    cat > "$TMP/config.toml" <<EOF
backend = "bpf-lsm"
mode = "$1"
socket = "$SOCK"
store = "$TMP/store.db"
bpf_object = "$OBJ"
zones = ["$HOME_DIR", "$HOME_DIR/.config"]
EOF
    # Both the daemon and the `cordon` CLI (adopt) resolve the socket from here.
    export CORDON_CONFIG="$TMP/config.toml"
}

# Start cordond in the background with extra KEY=VAL env (e.g. a test hook), waiting
# for the IPC socket. The socket comes up independently of the backend attaching, so
# callers still gate on the log via `wait_active`.
daemon_start() {
    RUST_LOG="${RUST_LOG:-info}" env "$@" "$CORDOND" >"$LOG" 2>&1 &
    DPID=$!
    for _ in $(seq 1 50); do
        [ -S "$SOCK" ] && break
        kill -0 "$DPID" 2>/dev/null || break
        sleep 0.1
    done
}

daemon_stop() {
    [ -n "$DPID" ] && { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
    DPID=""
    [ -n "$TMP" ] && rm -rf "$TMP"
}

# 0 once the program is attached + self-tested ("active …"); 1 on a fatal backend
# error / dead process / timeout. The backend attaches concurrently with the socket,
# so the socket existing doesn't mean the program loaded yet.
wait_active() {
    for _ in $(seq 1 80); do
        grep -q "active on the file_open hook" "$LOG" && return 0
        grep -qiE "backend exited with error|self-test FAILED" "$LOG" && return 1
        kill -0 "$DPID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

# --- scenario 1: enforce ----------------------------------------------------
scenario_enforce() {
    echo "### scenario: enforce (owner ALLOW + scraper DENY, in-kernel)"
    ws_new enforce
    daemon_start
    if ! wait_active; then
        echo "  FAIL: daemon did not attach"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1
    fi
    # adopt against the running daemon → bumps the policy clock → backend re-syncs the
    # BPF maps within a poll interval. Then wait for the sync (scraper starts EPERM-ing).
    "$CORDON" adopt "$HOME_DIR/.config/mytool" --as "$OWNER" >/dev/null
    for _ in $(seq 1 30); do "$SCRAPER" "$SECRET" >/dev/null 2>&1 || break; sleep 0.1; done

    local fail=0
    if out="$("$OWNER" "$SECRET" 2>&1)"; then echo "  OK: owner read: $out"; else echo "  FAIL: owner denied: $out"; fail=1; fi
    if out="$("$SCRAPER" "$SECRET" 2>&1)"; then echo "  FAIL: scraper read succeeded: $out"; fail=1; else echo "  OK: scraper denied: $out"; fi
    daemon_stop
    return $fail
}

# --- scenario 2: self-test negative (poisoned offsets must abort) ------------
scenario_selftest_negative() {
    echo "### scenario: self-test negative (wrong offsets MUST abort, not silently allow)"
    ws_new enforce
    daemon_start CORDON_SELFTEST_POISON_OFFSETS=1

    local fail=0
    if wait_active; then
        echo "  FAIL: daemon went 'active' with poisoned offsets — the self-test did NOT catch the silent no-op"
        fail=1
    elif grep -q "self-test FAILED" "$LOG"; then
        echo "  OK: daemon aborted (self-test caught the no-op: a protected open was allowed)"
    else
        echo "  FAIL: backend stopped, but not via the self-test guard:"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop
    return $fail
}

# --- scenario 3: audit (non-owner allowed, but logged as would-deny) ---------
scenario_audit() {
    echo "### scenario: audit (non-owner ALLOWED but logged as would-deny)"
    ws_new audit
    daemon_start
    if ! wait_active; then
        echo "  FAIL: daemon did not attach"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1
    fi
    "$CORDON" adopt "$HOME_DIR/.config/mytool" --as "$OWNER" >/dev/null

    # In audit the scraper is never denied, so we can't poll for EPERM. Instead drive
    # scraper reads until the daemon logs the would-deny (which only happens once the
    # adopt has re-synced into the kernel maps) — that doubles as the sync wait.
    local synced=0
    for _ in $(seq 1 50); do
        "$SCRAPER" "$SECRET" >/dev/null 2>&1
        grep -q "would deny (audit mode)" "$LOG" && { synced=1; break; }
        sleep 0.1
    done

    local fail=0
    if out="$("$SCRAPER" "$SECRET" 2>&1)"; then echo "  OK: scraper allowed (audit): $out"; else echo "  FAIL: scraper denied in audit mode: $out"; fail=1; fi
    if out="$("$OWNER" "$SECRET" 2>&1)"; then echo "  OK: owner allowed (audit): $out"; else echo "  FAIL: owner denied in audit mode: $out"; fail=1; fi
    if [ "$synced" -eq 1 ]; then echo "  OK: would-deny logged (audit observed the non-owner open)"; else echo "  FAIL: no would-deny logged within timeout"; sed 's/^/  daemon| /' "$LOG"; fail=1; fi
    daemon_stop
    return $fail
}

# --- run all scenarios; fail the suite if any fails -------------------------
rc=0
scenario_enforce          || rc=1
scenario_selftest_negative || rc=1
scenario_audit            || rc=1

echo
if [ "$rc" -eq 0 ]; then
    echo "PASS: bpf-lsm e2e — enforce + self-test-negative + audit all green (in-kernel)"
else
    echo "FAILED: one or more bpf-lsm scenarios failed" >&2
fi
exit "$rc"
