#!/usr/bin/env bash
# M1 e2e — the bpf-lsm boundary under the flat rule model (DESIGN §15). A suite of
# scenarios in a single VM boot. Unlike the old owner-model smoke, there is no runtime
# adopt/claim: the daemon **compiles a text policy file** and seeds the maps at startup,
# so once it logs "active …" enforcement is already live (no sync to wait for).
#
#   1. allow+deny     — a rule allows the owner exe to read its secret (ALLOW); a
#                       scraper has no matching rule → default-deny (EPERM), reported on
#                       the ring buffer with the object's inode + the requested action.
#   2. self-test neg  — start with deliberately *wrong* field offsets; the program
#                       attaches but mediates nothing. The daemon's self-test MUST turn
#                       that silent no-op into a loud abort, never a "running" boundary.
#   3. per-action     — a read-only allow does NOT cover a write: the owner reads
#                       (ALLOW) but writing the same object is default-denied. Proves
#                       f_mode/f_flags → read/write are distinguished.
#   4. subject group  — `@tools = [a, b]`; both allowed, a third exe denied.
#   5. object group   — one rule over `@creds = [v1, v2]` governs both dirs.
#   6. deny > allow   — `allow * read` + `deny scraper read` on one object: the scraper
#                       loses the tie (fail-safe), everyone else still reads.
#   7. copy-down      — `allow {a,b} read DIR` + `deny b read DIR/secret`: a reads the
#                       secret (inherited allow), b is denied *that file* but still reads
#                       a sibling under DIR (inheritance survives the carve-out). The
#                       per-subject sub-object exception a "deepest bucket only" model
#                       can't express.
#   8. audit → deny   — there is no global mode (§15.6): a `who="*" … audit` catch-all
#                       *observes* (allow + log); flipping that one rule to `deny`
#                       *enforces* (block + log) — the per-object observe→enforce
#                       progression that replaces SELinux's global permissive→enforce.
#   9. silence        — a `silence` policy denies (EPERM) *without* a log record (vs a
#                       `deny`, which logs).
#  10. apply + show    — `cordon policy apply` re-seeds the live maps at runtime via the
#                       atomic double-buffer swap (a previously-unprotected dir becomes
#                       protected with no restart), and `policy show` reflects it.
#  11. coalescing      — a tight loop of identical denied opens collapses to a handful of
#                       ring records (the in-kernel 1s suppressor), and the folded
#                       `suppressed` count is carried into a record so volume stays
#                       visible (M1 §1g).
#
# Needs guest-root and a kernel with CONFIG_BPF_LSM=y *and* `bpf` in the active LSM
# list (boot `lsm=…,bpf`). Run under virtme-ng via packaging/test/run-bpf-lsm-vm.sh.
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
TMP="" VAULT="" SECRET="" OWNER="" OWNER_B="" SCRAPER="" SOCK="" LOG="" DPID=""

# A throwaway exe with a distinct inode identity — a copy of `bash`, so we can drive
# both reads (`exec 3<f`) and writes (`exec 3>f`) *as that subject*. Echoes its path.
mk_exe() { local p="$TMP/$1"; cp "$(command -v bash)" "$p"; echo "$p"; }

# Open FILE as the subject EXE, for read / write. A denied open makes the redirection
# (hence the exe) fail → non-zero. The process image is the exe copy, so the kernel
# sees *its* inode as the caller.
read_as()  { "$1" -c 'exec 3<"$1"' bash "$2" 2>/dev/null; }   # $1 exe  $2 file
write_as() { "$1" -c 'exec 3>"$1"' bash "$2" 2>/dev/null; }   # opens O_WRONLY|O_CREAT|O_TRUNC

# Fresh workspace: a vault with a secret + a sibling, and three distinct exes.
ws_new() {
    TMP="$(mktemp -d)"
    VAULT="$TMP/vault"
    SECRET="$VAULT/secret"
    mkdir -p "$VAULT"
    echo "TOPSECRET" > "$SECRET"
    echo "SIBLING"   > "$VAULT/other"
    OWNER="$(mk_exe owner)"; OWNER_B="$(mk_exe owner-b)"; SCRAPER="$(mk_exe scraper)"
    SOCK="$TMP/cordon.sock"; LOG="$TMP/daemon.log"
}

# Write the policy (rules on stdin) + a matching config, then point the daemon at it.
# Absolute paths only, so no `~` ambiguity. There is no global mode — the per-rule
# `policy` is the only enforcement level (DESIGN §15.6). `zones = []` keeps the
# (rule-model-irrelevant) first-run zone seed empty.
write_policy() { # rules on stdin
    cat > "$TMP/policy.toml"
    cat > "$TMP/config.toml" <<EOF
backend = "bpf-lsm"
socket = "$SOCK"
bpf_object = "$OBJ"
policy = "$TMP/policy.toml"
EOF
    export CORDON_CONFIG="$TMP/config.toml"
}

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

# 0 once the program is attached, self-tested, AND the policy is seeded ("active …",
# which the daemon logs only after seeding); 1 on a fatal backend error / timeout.
wait_active() {
    for _ in $(seq 1 80); do
        grep -q "active on the file_open hook" "$LOG" && return 0
        grep -qiE "backend exited with error|self-test FAILED|has errors" "$LOG" && return 1
        kill -0 "$DPID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

# grep the daemon log with ANSI styling stripped (tracing colorizes key=value).
log_has() { sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -qE "$1"; }
# count matching daemon-log lines (ANSI stripped) — for the coalescing assertion.
log_count() { sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -cE "$1"; }

# Poll for a log line that the async ring drain produces (e.g. a deny record).
wait_log() { for _ in $(seq 1 30); do log_has "$1" && return 0; sleep 0.1; done; return 1; }

expect_allow() { local l="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  OK: $l (allowed)"; else echo "  FAIL: $l — denied, expected ALLOW"; return 1; fi; }
expect_deny()  { local l="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL: $l — allowed, expected DENY"; return 1; else echo "  OK: $l (denied)"; fi; }

started() { # gate on the daemon being active; dumps the log + fails on timeout
    if ! wait_active; then echo "  FAIL: daemon did not become active"; sed 's/^/  daemon| /' "$LOG"; daemon_stop; return 1; fi
}

# --- scenario 1: allow + default-deny + decision record ----------------------
scenario_enforce() {
    echo "### scenario: allow + default-deny (owner ALLOW + scraper default-DENY + record)"
    ws_new
    write_policy <<EOF
[[rule]]
who = "$OWNER"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads its secret"  read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper reads the secret" read_as "$SCRAPER" "$SECRET" || fail=1
    if wait_log 'deny pid=[0-9]+ exe=.* object=.*vault action=read policy=default-deny'; then
        echo "  OK: denial reported on the ring buffer (object path + action, default-deny cause)"
    else
        echo "  FAIL: no deny record with an object identity + action"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop; return $fail
}

# --- scenario 2: self-test negative (poisoned offsets must abort) ------------
scenario_selftest_negative() {
    echo "### scenario: self-test negative (wrong offsets MUST abort, not silently allow)"
    ws_new
    write_policy <<EOF
[[rule]]
who = "$OWNER"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    daemon_start CORDON_SELFTEST_POISON_OFFSETS=1
    local fail=0
    if wait_active; then
        echo "  FAIL: daemon went 'active' with poisoned offsets — self-test missed the no-op"; fail=1
    elif grep -q "self-test FAILED" "$LOG"; then
        echo "  OK: daemon aborted (self-test caught the no-op: a protected open was allowed)"
    else
        echo "  FAIL: backend stopped, but not via the self-test guard:"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop; return $fail
}

# --- scenario 3: per-action (read-allow does not grant write) ----------------
scenario_per_action() {
    echo "### scenario: per-action (read allowed, write default-denied on the same object)"
    ws_new
    write_policy <<EOF
[[rule]]
who = "$OWNER"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads (action=read covered)"        read_as  "$OWNER" "$SECRET" || fail=1
    expect_deny  "owner writes (action=write not covered)"  write_as "$OWNER" "$SECRET" || fail=1
    daemon_stop; return $fail
}

# --- scenario 4: subject group ----------------------------------------------
scenario_subject_group() {
    echo "### scenario: subject group (@tools allowed, third exe denied)"
    ws_new
    write_policy <<EOF
[group.subject.tools]
members = ["$OWNER", "$OWNER_B"]
[[rule]]
who = "@tools"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "first member reads"  read_as "$OWNER"   "$SECRET" || fail=1
    expect_allow "second member reads" read_as "$OWNER_B" "$SECRET" || fail=1
    expect_deny  "non-member reads"    read_as "$SCRAPER" "$SECRET" || fail=1
    daemon_stop; return $fail
}

# --- scenario 5: object group ------------------------------------------------
scenario_object_group() {
    echo "### scenario: object group (one rule governs @creds = two dirs)"
    ws_new
    local vault2="$TMP/vault2"; mkdir -p "$vault2"; echo S2 > "$vault2/secret"
    write_policy <<EOF
[group.object.creds]
members = ["$VAULT", "$vault2"]
[[rule]]
who = "$OWNER"
where = "@creds"
action = "read"
policy = "allow"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads dir 1"   read_as "$OWNER"   "$SECRET"        || fail=1
    expect_allow "owner reads dir 2"   read_as "$OWNER"   "$vault2/secret" || fail=1
    expect_deny  "scraper denied dir 1" read_as "$SCRAPER" "$SECRET"        || fail=1
    expect_deny  "scraper denied dir 2" read_as "$SCRAPER" "$vault2/secret" || fail=1
    daemon_stop; return $fail
}

# --- scenario 6: deny beats allow at the same specificity --------------------
scenario_deny_wins() {
    echo "### scenario: deny > allow (scraper loses the tie, others still read)"
    ws_new
    write_policy <<EOF
[[rule]]
who = "*"
where = "$VAULT"
action = "read"
policy = "allow"
[[rule]]
who = "$SCRAPER"
where = "$VAULT"
action = "read"
policy = "deny"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads (matched by *)" read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper denied (deny wins)" read_as "$SCRAPER" "$SECRET" || fail=1
    daemon_stop; return $fail
}

# --- scenario 7: copy-down (per-subject sub-object exception) ----------------
scenario_copydown() {
    echo "### scenario: copy-down (subtree allow + a file-specific deny for one subject)"
    ws_new
    write_policy <<EOF
[[rule]]
who = ["$OWNER", "$OWNER_B"]
where = "$VAULT"
action = "read"
policy = "allow"
[[rule]]
who = "$OWNER_B"
where = "$SECRET"
action = "read"
policy = "deny"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "A reads the carved-out file (inherited allow)" read_as "$OWNER"   "$SECRET"       || fail=1
    expect_deny  "B denied the carved-out file (more-specific)"  read_as "$OWNER_B" "$SECRET"       || fail=1
    expect_allow "B still reads a sibling (inheritance survives)" read_as "$OWNER_B" "$VAULT/other" || fail=1
    daemon_stop; return $fail
}

# --- scenario 8: audit → deny (per-object observe → enforce; no global mode) --
# Replaces the old global-permissive scenario. There is no enforce/permissive/off mode
# (DESIGN §15.6): observe-vs-enforce is per object, flipped by editing that object's
# rule. A `who="*" … audit` catch-all logs every read but blocks nothing; flipping the
# same rule to `deny` (a runtime `policy apply`) makes the identical access block + log.
scenario_audit_then_deny() {
    echo "### scenario: audit → deny (observe with a catch-all, then enforce by flipping it)"
    ws_new
    # Observe: an audit catch-all allows but logs every read of the vault.
    write_policy <<EOF
[[rule]]
who = "*"
where = "$VAULT"
action = "read"
policy = "audit"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "scraper reads under audit (observe, not enforce)" read_as "$SCRAPER" "$SECRET" || fail=1
    if wait_log 'audit pid=[0-9]+ exe=.* object=.* action=read'; then
        echo "  OK: the audit catch-all logged the read (allowed)"
    else
        echo "  FAIL: no audit record for the observed read"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi

    # Enforce: flip that one rule audit → deny and apply; the same object now blocks.
    cat > "$TMP/deny.toml" <<EOF
[[rule]]
who = "*"
where = "$VAULT"
action = "read"
policy = "deny"
EOF
    if "$CORDON" policy apply "$TMP/deny.toml" >/dev/null 2>&1; then
        echo "  OK: flip-to-deny applied at runtime"
    else
        echo "  FAIL: policy apply (audit→deny) errored"
        "$CORDON" policy apply "$TMP/deny.toml" 2>&1 | sed 's/^/  cli| /'; fail=1
    fi
    expect_deny "scraper denied after the flip to deny" read_as "$SCRAPER" "$SECRET" || fail=1
    # Drive reads to cross the in-kernel suppressor's 1s window, then assert a deny record.
    for _ in $(seq 1 40); do read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1; log_has 'deny pid=[0-9]+ exe=.* action=read' && break; sleep 0.1; done
    if log_has 'deny pid=[0-9]+ exe=.* object=.* action=read'; then
        echo "  OK: the same access now logs as deny (enforced)"
    else
        echo "  FAIL: no deny record after the flip to deny"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop; return $fail
}

# --- scenario 9: silence (deny without a log record) -------------------------
scenario_silence() {
    echo "### scenario: silence (deny enforced, but NO log record)"
    ws_new
    write_policy <<EOF
[[rule]]
who = "$SCRAPER"
where = "$VAULT"
action = "read"
policy = "silence"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_deny "scraper denied under silence" read_as "$SCRAPER" "$SECRET" || fail=1
    # Give the (would-be) ring drain a moment, then assert nothing was logged.
    sleep 0.5
    if log_has 'deny pid=[0-9]+'; then
        echo "  FAIL: silence produced a log record (should be silent)"; sed 's/^/  daemon| /' "$LOG"; fail=1
    else
        echo "  OK: no log record for a silenced denial"
    fi
    daemon_stop; return $fail
}

# --- scenario 10: policy apply + show (runtime re-seed via the CLI) ----------
scenario_apply() {
    echo "### scenario: policy apply + show (runtime re-seed)"
    ws_new
    # Start protecting an *unrelated* dir, so the vault is initially unprotected.
    mkdir -p "$TMP/unrelated"
    write_policy <<EOF
[[rule]]
who = "$OWNER"
where = "$TMP/unrelated"
action = "read"
policy = "allow"
EOF
    daemon_start
    started || return 1
    local fail=0
    expect_allow "scraper reads before apply (vault unprotected)" read_as "$SCRAPER" "$SECRET" || fail=1

    # Apply a new policy that protects the vault for the owner only.
    cat > "$TMP/new.toml" <<EOF
[[rule]]
who = "$OWNER"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    if "$CORDON" policy apply "$TMP/new.toml" >/dev/null 2>&1; then
        echo "  OK: policy apply succeeded"
    else
        echo "  FAIL: policy apply errored"
        "$CORDON" policy apply "$TMP/new.toml" 2>&1 | sed 's/^/  cli| /'
        fail=1
    fi
    # The re-seed took effect: owner reads, scraper now denied.
    expect_allow "owner reads after apply" read_as "$OWNER" "$SECRET" || fail=1
    expect_deny "scraper denied after apply" read_as "$SCRAPER" "$SECRET" || fail=1
    # `show` reflects the applied policy.
    if "$CORDON" policy show 2>/dev/null | grep -qF "$VAULT"; then
        echo "  OK: policy show lists the applied object"
    else
        echo "  FAIL: policy show did not list the applied object"
        "$CORDON" policy show 2>&1 | sed 's/^/  cli| /'
        fail=1
    fi
    daemon_stop
    return $fail
}

# --- scenario 11: event coalescing (in-kernel suppressor + folded count) -----
scenario_coalesce() {
    echo "### scenario: coalescing (a repeat-open burst collapses to a few records + a count)"
    ws_new
    write_policy <<EOF
[[rule]]
who = "$SCRAPER"
where = "$VAULT"
action = "read"
policy = "deny"
EOF
    daemon_start; started || return 1
    local fail=0 n=40
    # A tight loop of denied reads of the SAME (exe, object, action): the in-kernel
    # suppressor (1s window) emits the first and folds the rest, so the ring sees a
    # handful of records, not `n`.
    for _ in $(seq 1 "$n"); do read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1; done
    # Cross the window, then one more open flushes the held-back count.
    sleep 1.2
    read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1
    sleep 0.8   # > one poll interval, so the final drain lands before we count

    local recs; recs=$(log_count 'deny pid=[0-9]+ .*action=read')
    if [ "$recs" -ge 1 ] && [ "$recs" -le 15 ]; then
        echo "  OK: $((n + 1)) denied opens collapsed to $recs ring record(s)"
    else
        echo "  FAIL: $recs deny records for $((n + 1)) opens — coalescing off (or nothing logged)"
        sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    # At least one record must carry a nonzero suppressed count (volume stays visible).
    if log_has 'deny .*suppressed=[1-9][0-9]*'; then
        echo "  OK: a suppressed>0 count was carried into a record"
    else
        echo "  FAIL: no record reported a folded suppressed count"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop; return $fail
}

# --- run all scenarios; fail the suite if any fails -------------------------
rc=0
scenario_enforce           || rc=1
scenario_selftest_negative || rc=1
scenario_per_action        || rc=1
scenario_subject_group     || rc=1
scenario_object_group      || rc=1
scenario_deny_wins         || rc=1
scenario_copydown          || rc=1
scenario_audit_then_deny   || rc=1
scenario_silence           || rc=1
scenario_apply             || rc=1
scenario_coalesce          || rc=1

echo
if [ "$rc" -eq 0 ]; then
    echo "PASS: bpf-lsm rule-model e2e — all scenarios green (in-kernel)"
else
    echo "FAILED: one or more bpf-lsm scenarios failed" >&2
fi
exit "$rc"
