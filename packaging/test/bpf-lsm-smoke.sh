#!/usr/bin/env bash
# Phase 3 e2e — the bpf-lsm boundary. A suite of scenarios in a single VM boot:
#
#   1. enforce        — owner reads its secret (ALLOW); a scraper is denied in-kernel
#                       (DENY/EPERM); the denial is reported on the learn path with the
#                       owning subtree's inode identity.
#   2. self-test neg  — start with deliberately *wrong* field offsets; the program
#                       attaches but mediates nothing. The daemon's self-test MUST turn
#                       that silent no-op into a loud abort, never a "running" boundary
#                       that protects nothing. (Guards the offset-injection design —
#                       "a kernel mismatch must not go silent".)
#   3. audit          — a non-owner open is ALLOWED but logged as a would-deny.
#   4. nested         — most-specific subtree wins: an inner subtree owned by B governs
#                       its files even against the owner A of the enclosing subtree.
#   5. multi-identity — a second identity (`claim --add`) of the same owner is allowed.
#   6. disown         — dropping ownership re-syncs into the kernel; protection lifts.
#   7. learn enrich   — a *live* denied caller's exe is enriched from /proc into the log
#                       (the inode-validated path resolution), not just dev/ino.
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

# A throwaway exe with a distinct inode identity (a copy of `cat`). Echoes its path.
mk_exe() { local p="$TMP/$1"; cp "$(command -v cat)" "$p"; echo "$p"; }

# Build a throwaway home + the base fixtures (a secret, an owner exe, a scraper exe)
# and a config for the requested mode. Default /tmp is fine even though virtme-ng
# makes it an overlayfs: the daemon resolves a path's device from the mount table
# (proc::file_id), not stat(2)'s st_dev, so it agrees with the kernel's
# inode->i_sb->s_dev on overlayfs/btrfs. Exercising the overlay here is the stronger
# test.
ws_new() { # $1 = enforce|audit
    TMP="$(mktemp -d)"
    HOME_DIR="$TMP/home"
    SECRET="$HOME_DIR/.config/mytool/secret"
    mkdir -p "$(dirname "$SECRET")"
    echo "TOPSECRET" > "$SECRET"
    OWNER="$(mk_exe owner-tool)"; SCRAPER="$(mk_exe scraper-tool)"
    SOCK="$TMP/cordon.sock"; LOG="$TMP/daemon.log"
    cat > "$TMP/config.toml" <<EOF
backend = "bpf-lsm"
mode = "$1"
socket = "$SOCK"
store = "$TMP/store.db"
bpf_object = "$OBJ"
zones = ["$HOME_DIR", "$HOME_DIR/.config"]
EOF
    # Both the daemon and the `cordon` CLI resolve the socket from here.
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

# Poll until `$1 $2` (exe, file) is DENIED — the in-kernel maps have caught up with an
# adopt. 0 on deny, 1 on timeout. (Only meaningful in enforce mode.)
wait_denied() {
    for _ in $(seq 1 50); do "$1" "$2" >/dev/null 2>&1 || return 0; sleep 0.1; done
    return 1
}

# Assertions: read the file as the exe and check it matches the expectation. Each
# prints OK/FAIL and returns non-zero on a mismatch so the caller can OR into `fail`.
expect_allow() { # $1 label  $2 exe  $3 file
    if "$2" "$3" >/dev/null 2>&1; then echo "  OK: $1 (allowed)"; else echo "  FAIL: $1 — denied, expected ALLOW"; return 1; fi
}
expect_deny() { # $1 label  $2 exe  $3 file
    if "$2" "$3" >/dev/null 2>&1; then echo "  FAIL: $1 — allowed, expected DENY"; return 1; else echo "  OK: $1 (denied)"; fi
}

# grep the daemon log with ANSI styling stripped — tracing colorizes the `key=value`
# separators, so a field value isn't literally adjacent to its key on disk.
log_has() { sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -qE "$1"; }

adopt()      { "$CORDON" adopt "$1" --as "$2" >/dev/null; }      # $1 subtree  $2 exe
claim_add()  { "$CORDON" claim "$1" --add "$2" >/dev/null; }     # $1 subtree  $2 exe
disown()     { "$CORDON" disown "$1" >/dev/null; }               # $1 subtree

# --- scenario 1: enforce + learn path --------------------------------------
scenario_enforce() {
    echo "### scenario: enforce (owner ALLOW + scraper DENY + learn-path report)"
    ws_new enforce
    daemon_start
    if ! wait_active; then echo "  FAIL: daemon did not attach"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1; fi
    adopt "$HOME_DIR/.config/mytool" "$OWNER"
    wait_denied "$SCRAPER" "$SECRET" || { echo "  FAIL: adopt never synced into the kernel maps"; daemon_stop; return 1; }

    local fail=0
    expect_allow "owner reads its secret" "$OWNER" "$SECRET"   || fail=1
    expect_deny  "scraper reads the secret" "$SCRAPER" "$SECRET" || fail=1
    # Learn path: the denial reached the ring buffer and was logged with the owning
    # subtree's inode identity (no d_path at this hook, so identity is dev/ino). The
    # drain is async, so poll.
    local logged=0
    for _ in $(seq 1 30); do
        log_has 'deny .*subtree=dev=[0-9]+ ino=[0-9]+.*owner=' && { logged=1; break; }
        sleep 0.1
    done
    if [ "$logged" -eq 1 ]; then
        echo "  OK: denial reported on the learn path (subtree inode + owner)"
    else
        echo "  FAIL: no learn-path deny record with a subtree identity"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
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
    if ! wait_active; then echo "  FAIL: daemon did not attach"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1; fi
    adopt "$HOME_DIR/.config/mytool" "$OWNER"

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
    expect_allow "scraper reads in audit" "$SCRAPER" "$SECRET" || fail=1
    expect_allow "owner reads in audit"   "$OWNER" "$SECRET"   || fail=1
    if [ "$synced" -eq 1 ]; then echo "  OK: would-deny logged (audit observed the non-owner open)"; else echo "  FAIL: no would-deny logged within timeout"; sed 's/^/  daemon| /' "$LOG"; fail=1; fi
    daemon_stop
    return $fail
}

# --- scenario 4: nested subtrees (most-specific owner wins) ------------------
scenario_nested() {
    echo "### scenario: nested subtrees (deepest match wins)"
    ws_new enforce
    # An inner subtree under mytool, with its own secret and its own owner exe.
    local inner="$HOME_DIR/.config/mytool/inner"
    local inner_secret="$inner/secret"
    mkdir -p "$inner"; echo "INNERSECRET" > "$inner_secret"
    local owner_b; owner_b="$(mk_exe owner-b)"

    daemon_start
    if ! wait_active; then echo "  FAIL: daemon did not attach"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1; fi
    adopt "$HOME_DIR/.config/mytool" "$OWNER"     # outer → owner A
    adopt "$inner" "$owner_b"                      # inner → owner B (carve-out)
    wait_denied "$SCRAPER" "$inner_secret" || { echo "  FAIL: adopts never synced"; daemon_stop; return 1; }

    local fail=0
    expect_allow "owner A reads outer secret" "$OWNER"   "$SECRET"       || fail=1
    expect_deny  "owner B reads outer secret" "$owner_b" "$SECRET"       || fail=1
    expect_allow "owner B reads inner secret" "$owner_b" "$inner_secret" || fail=1
    # The crux: A owns the *enclosing* subtree but the inner one is more specific, so
    # A is governed by B's ownership there → denied. Proves the deepest ancestor wins.
    expect_deny  "owner A reads inner secret" "$OWNER"   "$inner_secret" || fail=1
    daemon_stop
    return $fail
}

# --- scenario 5: multiple identities for one owner --------------------------
scenario_multi_identity() {
    echo "### scenario: multiple identities (claim --add) for one owner"
    ws_new enforce
    local owner_b; owner_b="$(mk_exe owner-b)"

    daemon_start
    if ! wait_active; then echo "  FAIL: daemon did not attach"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1; fi
    adopt "$HOME_DIR/.config/mytool" "$OWNER"
    claim_add "$HOME_DIR/.config/mytool" "$owner_b"   # second identity of the same owner
    wait_denied "$SCRAPER" "$SECRET" || { echo "  FAIL: adopt never synced"; daemon_stop; return 1; }

    local fail=0
    expect_allow "first identity reads"  "$OWNER"   "$SECRET" || fail=1
    expect_allow "second identity reads" "$owner_b" "$SECRET" || fail=1
    expect_deny  "scraper reads"         "$SCRAPER" "$SECRET" || fail=1
    daemon_stop
    return $fail
}

# --- scenario 6: disown re-syncs (protection lifts in-kernel) ----------------
scenario_disown() {
    echo "### scenario: disown re-syncs (protection lifts)"
    ws_new enforce
    daemon_start
    if ! wait_active; then echo "  FAIL: daemon did not attach"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1; fi
    adopt "$HOME_DIR/.config/mytool" "$OWNER"
    wait_denied "$SCRAPER" "$SECRET" || { echo "  FAIL: adopt never synced"; daemon_stop; return 1; }

    local fail=0
    expect_deny "scraper denied while owned" "$SCRAPER" "$SECRET" || fail=1
    disown "$HOME_DIR/.config/mytool"
    # The clear-then-insert re-sync must reach the kernel: the scraper goes back to
    # ALLOW within a poll interval.
    if for _ in $(seq 1 50); do "$SCRAPER" "$SECRET" >/dev/null 2>&1 && break; sleep 0.1; done; "$SCRAPER" "$SECRET" >/dev/null 2>&1; then
        echo "  OK: scraper allowed after disown (re-sync lifted protection)"
    else
        echo "  FAIL: scraper still denied after disown (re-sync did not reach the kernel)"; fail=1
    fi
    daemon_stop
    return $fail
}

# --- scenario 7: learn-path exe enrichment (live caller) --------------------
# A short-lived denied caller (the scraper) usually exits before the async ring drain,
# so its exe falls back to dev/ino. Here we deny a *live* caller (python sleeps after
# the denied open) so /proc/<pid>/exe still resolves and — its inode matching the
# event — the daemon enriches the log with the real exe path.
scenario_learn_enrich() {
    echo "### scenario: learn-path exe enrichment (live denied caller)"
    if ! command -v python3 >/dev/null; then echo "  SKIP: python3 unavailable"; return 0; fi
    ws_new enforce
    daemon_start
    if ! wait_active; then echo "  FAIL: daemon did not attach"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1; fi
    adopt "$HOME_DIR/.config/mytool" "$OWNER"
    wait_denied "$SCRAPER" "$SECRET" || { echo "  FAIL: adopt never synced"; daemon_stop; return 1; }

    # Open (denied), then stay alive so the drainer can read /proc/<pid>/exe.
    python3 -c "
import time
try: open('$SECRET')
except OSError: pass
time.sleep(5)" &
    local pypid=$!

    local fail=1
    for _ in $(seq 1 40); do
        # A deny record whose exe was enriched to a real path (the fallback is the
        # space-containing 'exe=dev=… ino=…', which won't match).
        if log_has 'deny .*exe=[^ ]*python'; then fail=0; break; fi
        sleep 0.1
    done
    if [ "$fail" -eq 0 ]; then
        echo "  OK: live caller's exe enriched from /proc into the deny record"
    else
        echo "  FAIL: deny record was not enriched with the live caller's exe path"; grep -E 'deny' "$LOG" | sed 's/^/  daemon| /'
    fi
    kill "$pypid" 2>/dev/null; wait "$pypid" 2>/dev/null
    daemon_stop
    return $fail
}

# --- run all scenarios; fail the suite if any fails -------------------------
rc=0
scenario_enforce            || rc=1
scenario_selftest_negative  || rc=1
scenario_audit              || rc=1
scenario_nested             || rc=1
scenario_multi_identity     || rc=1
scenario_disown             || rc=1
scenario_learn_enrich       || rc=1

echo
if [ "$rc" -eq 0 ]; then
    echo "PASS: bpf-lsm e2e — all scenarios green (in-kernel)"
else
    echo "FAILED: one or more bpf-lsm scenarios failed" >&2
fi
exit "$rc"
