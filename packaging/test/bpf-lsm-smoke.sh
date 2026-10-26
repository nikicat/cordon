#!/usr/bin/env bash
# End-to-end suite for the bpf-lsm boundary (DESIGN §15), in one VM boot. Each scenario
# starts a real cordond on its own policy, then checks the in-kernel verdicts and the
# daemon's JSON log; the comment on each scenario function says what it proves.
#
# The bless scenarios run the daemon in a NESTED cgroup, reproducing production's
# `Delegate=yes` service cgroup without needing systemd (the carrier root is then a
# non-root cgroup — the stricter case, since the cgroup2 root is exempt from the "no
# internal processes" rule).
#
# Needs guest-root and the kernel from the README's Requirements. Run under virtme-ng via
# packaging/test/run-bpf-lsm-vm.sh.
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
# bpffs holds the pinned LSM links. A hard precondition, not a per-scenario SKIP: the
# daemon pins unconditionally, so without bpffs *nothing* here can run. virtme-ng gives
# us a bare /sys, so mount it.
if [ "$(stat -f -c %t /sys/fs/bpf 2>/dev/null)" != "cafe4a11" ]; then
    mkdir -p /sys/fs/bpf 2>/dev/null
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null
fi
if [ "$(stat -f -c %t /sys/fs/bpf 2>/dev/null)" != "cafe4a11" ]; then
    echo "error: /sys/fs/bpf is not a bpffs mount and could not be mounted." >&2
    echo "       the daemon pins its LSM links there so the boundary survives its death." >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CORDOND="$ROOT_DIR/target/debug/cordond"
CORDON="$ROOT_DIR/target/debug/cordon"
OBJ="$ROOT_DIR/target/bpf/cordon.bpf.o"
[ -x "$CORDOND" ] || { echo "missing $CORDOND — cargo build -p cordon-daemon" >&2; exit 1; }
[ -x "$CORDON" ]  || { echo "missing $CORDON — cargo build -p cordon-cli" >&2; exit 1; }
[ -e "$OBJ" ]     || { echo "missing $OBJ — just build-ebpf" >&2; exit 1; }
command -v jq >/dev/null || { echo "missing jq — the daemon log is checked as JSON" >&2; exit 1; }

# --- shared per-scenario state + helpers -----------------------------------
TMP="" VAULT="" SECRET="" OWNER="" OWNER_B="" SCRAPER="" SOCK="" LOG="" DPID=""
# When set (the bless scenarios), the daemon is started *inside* this cgroup instead of
# the cgroup2 root — see `daemon_start`.
DCGROUP=""
# policy-edit symlink scenarios: the synthetic editor user + the root-only sentinel.
TUID="" TUSER="" SENTINEL="" EDITDIR=""
# Where the LSM links are pinned. Off the default (/sys/fs/bpf/cordon) so a suite run on a
# real box can't tear down that box's live boundary.
PIN_DIR="/sys/fs/bpf/cordon-smoke"

# A throwaway exe with a distinct inode identity — a copy of `bash`, so we can drive
# both reads (`exec 3<f`) and writes (`exec 3>f`) *as that subject*. Echoes its path.
mk_exe() { local p="$TMP/$1"; cp "$(command -v bash)" "$p"; echo "$p"; }

# Open FILE as the subject EXE, for read / write. A denied open makes the redirection
# (hence the exe) fail → non-zero. The process image is the exe copy, so the kernel
# sees *its* inode as the caller.
read_as()  { "$1" -c 'exec 3<"$1"' bash "$2" 2>/dev/null; }   # $1 exe  $2 file
write_as() { "$1" -c 'exec 3>"$1"' bash "$2" 2>/dev/null; }   # opens O_WRONLY|O_CREAT|O_TRUNC
# Read FILE as EXE *dropped to UID* (real uid the kernel records) — for the audit-log
# user/`~` scenario. setpriv sheds root before exec so the open is attributed to UID.
read_as_uid() { setpriv --reuid "$1" --regid "$1" --clear-groups "$2" -c 'exec 3<"$1"' bash "$3" 2>/dev/null; } # $1 uid $2 exe $3 file

# Commands queued by `on_cleanup` for the current scenario.
CLEANUPS=()
# Queues CMD [ARGS] to run when the current scenario ends, however it returns, after its
# daemon is stopped; the latest queued runs first. Arguments are captured now, so a
# scenario's locals may be passed.
on_cleanup() { CLEANUPS+=("$(printf '%q ' "$@")"); }

# Runs scenario_$1, then stops its daemon (freeing its workspace) and runs its queued
# cleanups, whichever path it returned by. Returns the scenario's status.
run_scenario() {
    CLEANUPS=()
    "scenario_$1"; local rc=$? i
    daemon_stop
    for ((i = ${#CLEANUPS[@]} - 1; i >= 0; i--)); do eval "${CLEANUPS[i]}" 2>/dev/null; done
    return $rc
}

# Removes the synthetic /etc/passwd entry for user $1.
drop_user() { sed -i "/^$1:/d" /etc/passwd; }
# Kills the given pids and reaps them.
kill_and_reap() { kill "$@"; wait "$@"; }

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

# Write a config naming POLICY (a file or a conf.d dir) and SOCKET (default $SOCK), then
# point the daemon and CLI at it. Every scenario goes through here so the config always
# carries the off-default $PIN_DIR: `daemon_stop` runs `cordond --teardown`, and a config
# without it would tear down the real /sys/fs/bpf/cordon.
write_config() { # $1 policy path  [$2 socket]
    cat > "$TMP/config.toml" <<EOF
backend = "bpf-lsm"
socket = "${2:-$SOCK}"
bpf_object = "$OBJ"
policy = "$1"
bpf_pin_dir = "$PIN_DIR"
EOF
    export CORDON_CONFIG="$TMP/config.toml"
}

# One `[[rule]]` table, for a policy heredoc as `$(rule WHO WHERE ACTION POLICY)`. A field
# holding several space-separated values becomes a TOML array; the workspace paths come
# from mktemp, so they never contain a space.
rule() {
    printf '[[rule]]\n'
    local key vals
    for key in who where action policy; do
        read -ra vals <<<"$1"; shift
        if [ "${#vals[@]}" -eq 1 ]; then
            printf '%s = "%s"\n' "$key" "${vals[0]}"
        else
            printf '%s = [%s]\n' "$key" "$(printf '"%s", ' "${vals[@]}" | sed 's/, $//')"
        fi
    done
}

# Write the policy (rules on stdin) + a matching config. Absolute paths only, so no `~`
# ambiguity.
write_policy() { # rules on stdin
    cat > "$TMP/policy.toml"
    write_config "$TMP/policy.toml"
}

# Start the daemon (env assignments as args). With `$DCGROUP` set, it is started *inside*
# that cgroup (the nested shape from the header). The daemon must already be in the cgroup
# when it starts (it resolves its carrier root from /proc/self/cgroup), hence
# join-then-exec.
daemon_start() {
    if [ -n "$DCGROUP" ]; then
        mkdir -p "$DCGROUP"
        RUST_LOG="${RUST_LOG:-info}" env "$@" \
            sh -c 'echo $$ > "$1/cgroup.procs" && shift && exec "$@"' _ "$DCGROUP" "$CORDOND" --log-format json >"$LOG" 2>&1 &
    else
        RUST_LOG="${RUST_LOG:-info}" env "$@" "$CORDOND" --log-format json >"$LOG" 2>&1 &
    fi
    DPID=$!
    wait_until 50 socket_or_exit
}
# Whether the daemon has bound its socket or already exited.
socket_or_exit() { [ -S "$SOCK" ] || gone "$DPID"; }

daemon_stop() {
    [ -n "$DPID" ] && { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
    DPID=""
    # Stopping the daemon does not stop enforcement. Without this, each scenario would
    # leave a live boundary whose PROTECTED entries name inodes the `rm -rf` below is
    # about to free, and inode reuse would contaminate the next scenario. Runs before the
    # config it reads is deleted; the singleton lock is free now that the daemon is reaped.
    [ -n "$TMP" ] && [ -f "$TMP/config.toml" ] && "$CORDOND" --teardown >/dev/null 2>&1
    if [ -n "$DCGROUP" ]; then
        # Best-effort: the daemon's own cgroup is empty once it exits; a carrier that
        # still has members is left for the next daemon's reconcile to adopt.
        rmdir "$DCGROUP"/cordon-bless-* 2>/dev/null
        rmdir "$DCGROUP" 2>/dev/null
        DCGROUP=""
    fi
    # Retried, because teardown is asynchronous (see `PinDir::teardown`). Until it lands
    # the workspace is still protected and the unlink is refused — itself a small proof
    # that the pins were doing their job.
    if [ -n "$TMP" ]; then
        wait_until 50 rm -rf "$TMP" 2>/dev/null
    fi
}

# 0 once the program is attached, self-tested, AND the policy is seeded (the `ready`
# event, which the daemon logs only after seeding); 1 on a fatal backend error / timeout.
wait_active() { wait_until 80 ready_or_failed; log_has '.event == "ready"'; }
ready_or_failed() { log_has '.event == "ready"' || log_has '.event == "backend_failed"' || gone "$DPID"; }

# Runs CMD [ARGS] every 0.1s until it succeeds, at most TRIES times. Fails if it never does.
wait_until() {
    local tries="$1" i; shift
    for ((i = 0; i < tries; i++)); do "$@" && return 0; sleep 0.1; done
    return 1
}
# Whether no process PID is left.
gone() { ! kill -0 "$1" 2>/dev/null; }

# The records of a `--log-format json` log (one object per line, fields as top-level keys)
# that satisfy the jq condition $2; extra args (e.g. `--arg v "$X"`) go to jq. Lines that
# aren't JSON, such as a panic message, are skipped.
records() { local file="$1" cond="$2"; shift 2; jq -cR "$@" "fromjson? | select($cond)" "$file"; }
# Whether the daemon log has a record matching the jq condition $1 (extra args to jq).
log_has() { [ -n "$(records "$LOG" "$@")" ]; }
# How many daemon-log records match — for the coalescing assertion.
log_count() { records "$LOG" "$@" | grep -c .; }

# Poll for a log line that the async ring drain produces (e.g. a deny record).
wait_log() { wait_until 30 log_has "$@"; }

# Reads the secret as the scraper, then checks the log for the jq condition $1 — for a
# record that only a repeat of the access past the suppressor's window produces.
read_then_log_has() { read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1; log_has "$1"; }
# Waits for a daemon-log record matching the jq condition $2 (extra args to jq), and
# reports it as $1. Dumps the log when none arrives.
expect_log() {
    local label="$1"; shift
    if wait_log "$@"; then echo "  OK: $label"; return 0; fi
    echo "  FAIL: $label — no such log record"; sed 's/^/  daemon| /' "$LOG"; return 1
}
expect_allow() { local l="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  OK: $l (allowed)"; else echo "  FAIL: $l — denied, expected ALLOW"; return 1; fi; }
# Like expect_allow, but tolerant of the teardown lag: the hooks stay attached for a
# moment after `--teardown` returns (see `PinDir::teardown`).
expect_allow_eventually() {
    local l="$1"; shift
    if wait_until 50 "$@" >/dev/null 2>&1; then echo "  OK: $l (allowed)"; return 0; fi
    echo "  FAIL: $l — still denied long after teardown"; return 1
}
expect_deny()  { local l="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL: $l — allowed, expected DENY"; return 1; else echo "  OK: $l (denied)"; fi; }

started() { # gate on the daemon being active; dumps the log + fails on timeout
    if ! wait_active; then echo "  FAIL: daemon did not become active"; sed 's/^/  daemon| /' "$LOG"; return 1; fi
}

# a rule allows the owner exe to read its secret (ALLOW); a scraper has no matching rule →
# default-deny (EPERM), reported on the ring buffer with the object's inode + the requested
# action.
scenario_enforce() {
    echo "### scenario: allow + default-deny (owner ALLOW + scraper default-DENY + record)"
    ws_new
    write_policy <<EOF
$(rule "$OWNER" "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads its secret"  read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper reads the secret" read_as "$SCRAPER" "$SECRET" || fail=1
    # root runs the readers, so the caller resolves to user=root (uid 0 → passwd), proving
    # the kernel-captured uid reaches the journal; root is not a regular user, so paths stay
    # absolute (no `~` collapse — that's exercised by the daemon's unit tests).
    expect_log "denial reported on the ring buffer (user + object + opened path + action, default-deny)" '.message == "deny" and (.pid | type == "number") and .user == "root" and has("exe")
            and (.object | endswith("vault")) and (.path | endswith("/vault/secret"))
            and .action == "read" and .policy == "default-deny"' || fail=1
    return $fail
}

# start with deliberately *wrong* field offsets; the program attaches but mediates nothing.
# The daemon's self-test MUST turn that silent no-op into a loud abort, never a "running"
# boundary.
scenario_selftest_negative() {
    echo "### scenario: self-test negative (wrong offsets MUST abort, not silently allow)"
    ws_new
    write_policy <<EOF
$(rule "$OWNER" "$VAULT" read allow)
EOF
    daemon_start CORDON_SELFTEST_POISON_OFFSETS=1
    local fail=0
    if wait_active; then
        echo "  FAIL: daemon went 'active' with poisoned offsets — self-test missed the no-op"; fail=1
    elif log_has '.event == "self_test_failed"'; then
        echo "  OK: daemon aborted (self-test caught the no-op: a protected open was allowed)"
    else
        echo "  FAIL: backend stopped, but not via the self-test guard:"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    return $fail
}

# a read-only allow does NOT cover a write: the owner reads (ALLOW) but writing the same
# object is default-denied. Proves f_mode/f_flags → read/write are distinguished.
scenario_per_action() {
    echo "### scenario: per-action (read allowed, write default-denied on the same object)"
    ws_new
    write_policy <<EOF
$(rule "$OWNER" "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads (action=read covered)"        read_as  "$OWNER" "$SECRET" || fail=1
    expect_deny  "owner writes (action=write not covered)"  write_as "$OWNER" "$SECRET" || fail=1
    return $fail
}

# `@tools = [a, b]`; both allowed, a third exe denied.
scenario_subject_group() {
    echo "### scenario: subject group (@tools allowed, third exe denied)"
    ws_new
    write_policy <<EOF
[group.subject.tools]
members = ["$OWNER", "$OWNER_B"]
$(rule @tools "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "first member reads"  read_as "$OWNER"   "$SECRET" || fail=1
    expect_allow "second member reads" read_as "$OWNER_B" "$SECRET" || fail=1
    expect_deny  "non-member reads"    read_as "$SCRAPER" "$SECRET" || fail=1
    return $fail
}

# one rule over `@creds = [v1, v2]` governs both dirs.
scenario_object_group() {
    echo "### scenario: object group (one rule governs @creds = two dirs)"
    ws_new
    local vault2="$TMP/vault2"; mkdir -p "$vault2"; echo S2 > "$vault2/secret"
    write_policy <<EOF
[group.object.creds]
members = ["$VAULT", "$vault2"]
$(rule "$OWNER" @creds read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads dir 1"   read_as "$OWNER"   "$SECRET"        || fail=1
    expect_allow "owner reads dir 2"   read_as "$OWNER"   "$vault2/secret" || fail=1
    expect_deny  "scraper denied dir 1" read_as "$SCRAPER" "$SECRET"        || fail=1
    expect_deny  "scraper denied dir 2" read_as "$SCRAPER" "$vault2/secret" || fail=1
    return $fail
}

# `allow * read` + `deny scraper read` on one object: the scraper loses the tie (fail-safe),
# everyone else still reads.
scenario_deny_wins() {
    echo "### scenario: deny > allow (scraper loses the tie, others still read)"
    ws_new
    write_policy <<EOF
$(rule '*' "$VAULT" read allow)
$(rule "$SCRAPER" "$VAULT" read deny)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads (matched by *)" read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper denied (deny wins)" read_as "$SCRAPER" "$SECRET" || fail=1
    return $fail
}

# DESIGN §15.6 step 2: a concrete subject outranks a `who="*"`
# catch-all on the SAME object. Both rules sit on $VAULT; without subject-specificity,
# deny>allow would sort the wildcard deny first and block the owner too. Proven by
# outcome (no log timing): owner allowed, scraper denied.
scenario_subject_specificity() {
    echo "### scenario: subject-specificity (concrete allow beats a who=* deny on one object)"
    ws_new
    write_policy <<EOF
$(rule '*' "$VAULT" read deny)
$(rule "$OWNER" "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads (concrete allow outranks the wildcard deny)" read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper denied (only the wildcard deny matches it)"      read_as "$SCRAPER" "$SECRET" || fail=1
    return $fail
}

# `allow {a,b} read DIR` + `deny b read DIR/secret`: a reads the secret (inherited allow), b
# is denied *that file* but still reads a sibling under DIR (inheritance survives the
# carve-out). The per-subject sub-object exception a "deepest bucket only" model can't
# express.
scenario_copydown() {
    echo "### scenario: copy-down (subtree allow + a file-specific deny for one subject)"
    ws_new
    write_policy <<EOF
$(rule "$OWNER $OWNER_B" "$VAULT" read allow)
$(rule "$OWNER_B" "$SECRET" read deny)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "A reads the carved-out file (inherited allow)" read_as "$OWNER"   "$SECRET"       || fail=1
    expect_deny  "B denied the carved-out file (more-specific)"  read_as "$OWNER_B" "$SECRET"       || fail=1
    expect_allow "B still reads a sibling (inheritance survives)" read_as "$OWNER_B" "$VAULT/other" || fail=1
    return $fail
}

# Observe-vs-enforce is per object, flipped by editing that object's rule. A
# `who="*" … audit` catch-all logs every read but blocks nothing; flipping the same rule
# to `deny` (a runtime `policy apply`) makes the identical access block + log.
scenario_audit_then_deny() {
    echo "### scenario: audit → deny (observe with a catch-all, then enforce by flipping it)"
    ws_new
    # Observe: an audit catch-all allows but logs every read of the vault.
    write_policy <<EOF
$(rule '*' "$VAULT" read audit)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "scraper reads under audit (observe, not enforce)" read_as "$SCRAPER" "$SECRET" || fail=1
    expect_log "the audit catch-all logged the read (allowed)" '.message == "audit" and .user == "root" and has("exe") and has("object") and .action == "read"' || fail=1

    # Enforce: flip that one rule audit → deny and apply; the same object now blocks.
    cat > "$TMP/deny.toml" <<EOF
$(rule '*' "$VAULT" read deny)
EOF
    if "$CORDON" policy apply "$TMP/deny.toml" >/dev/null 2>&1; then
        echo "  OK: flip-to-deny applied at runtime"
    else
        echo "  FAIL: policy apply (audit→deny) errored"
        "$CORDON" policy apply "$TMP/deny.toml" 2>&1 | sed 's/^/  cli| /'; fail=1
    fi
    expect_deny "scraper denied after the flip to deny" read_as "$SCRAPER" "$SECRET" || fail=1
    # Drive reads to cross the in-kernel suppressor's 1s window, then assert a deny record.
    local deny_read='.message == "deny" and .user == "root" and has("exe") and has("object") and .action == "read"'
    wait_until 40 read_then_log_has "$deny_read"
    expect_log "the same access now logs as deny (enforced)" "$deny_read" || fail=1
    return $fail
}

# a `silence` policy denies (EPERM) *without* a log record (vs a `deny`, which logs).
scenario_silence() {
    echo "### scenario: silence (deny enforced, but NO log record)"
    ws_new
    write_policy <<EOF
$(rule "$SCRAPER" "$VAULT" read silence)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_deny "scraper denied under silence" read_as "$SCRAPER" "$SECRET" || fail=1
    # Give the (would-be) ring drain a moment, then assert nothing was logged.
    sleep 0.5
    if log_has '.message == "deny"'; then
        echo "  FAIL: silence produced a log record (should be silent)"; sed 's/^/  daemon| /' "$LOG"; fail=1
    else
        echo "  OK: no log record for a silenced denial"
    fi
    return $fail
}

# `cordon policy apply` re-seeds the live maps at runtime (`Maps::seed`)
# (a previously-unprotected dir becomes protected with no restart), and `policy show`
# reflects it.
scenario_apply() {
    echo "### scenario: policy apply + show (runtime re-seed)"
    ws_new
    # Start protecting an *unrelated* dir, so the vault is initially unprotected.
    mkdir -p "$TMP/unrelated"
    write_policy <<EOF
$(rule "$OWNER" "$TMP/unrelated" read allow)
EOF
    daemon_start
    started || return 1
    local fail=0
    expect_allow "scraper reads before apply (vault unprotected)" read_as "$SCRAPER" "$SECRET" || fail=1

    # Apply a new policy that protects the vault for the owner only.
    cat > "$TMP/new.toml" <<EOF
$(rule "$OWNER" "$VAULT" read allow)
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
    if "$CORDON" --json policy show 2>/dev/null | json_field path | grep -qxF "$VAULT"; then
        echo "  OK: policy show lists the applied object"
    else
        echo "  FAIL: policy show did not list the applied object"
        "$CORDON" policy show 2>&1 | sed 's/^/  cli| /'
        fail=1
    fi
    return $fail
}

# a tight loop of identical denied opens collapses to a handful of ring records (the
# in-kernel suppressor, `throttle`), and the folded `suppressed` count is carried into a
# record so volume stays visible.
scenario_coalesce() {
    echo "### scenario: coalescing (a repeat-open burst collapses to a few records + a count)"
    ws_new
    write_policy <<EOF
$(rule "$SCRAPER" "$VAULT" read deny)
EOF
    daemon_start; started || return 1
    local fail=0 n=40
    # A tight loop of denied reads of the SAME (exe, opened file, action) — one suppressor
    # key — so the ring sees a handful of records, not `n`.
    for _ in $(seq 1 "$n"); do read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1; done
    # Cross the window, then one more open flushes the held-back count.
    sleep 1.2
    read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1
    sleep 0.8   # > one poll interval, so the final drain lands before we count

    local recs; recs=$(log_count '.message == "deny" and .action == "read"')
    if [ "$recs" -ge 1 ] && [ "$recs" -le 15 ]; then
        echo "  OK: $((n + 1)) denied opens collapsed to $recs ring record(s)"
    else
        echo "  FAIL: $recs deny records for $((n + 1)) opens — coalescing off (or nothing logged)"
        sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    # At least one record must carry a nonzero suppressed count (volume stays visible).
    expect_log "a suppressed>0 count was carried into a record" '.message == "deny" and (.suppressed | tonumber) > 0' || fail=1
    return $fail
}

# audit one exe over a dir; opening distinct files under it yields distinct records each
# carrying the ACTUAL opened path (DESIGN §15.10 flow B), incl. a depth-2 nested file, and
# siblings don't coalesce away (the suppressor keys on the opened file, see `SuppressKey`).
scenario_leaf_path() {
    echo "### scenario: leaf-path reconstruction (distinct files surface with their real path)"
    ws_new
    mkdir -p "$VAULT/sub"
    echo "DEEP" > "$VAULT/sub/nested"
    # Audit the owner across the whole vault (DESIGN §15.10 flow B "smart strace -efile").
    write_policy <<EOF
$(rule "$OWNER" "$VAULT" read audit)
EOF
    daemon_start; started || return 1
    local fail=0
    # Open three DISTINCT files under the one audited object.
    read_as "$OWNER" "$SECRET"           >/dev/null 2>&1   # $VAULT/secret      (depth 1)
    read_as "$OWNER" "$VAULT/other"      >/dev/null 2>&1   # $VAULT/other       (depth 1, sibling)
    read_as "$OWNER" "$VAULT/sub/nested" >/dev/null 2>&1   # $VAULT/sub/nested  (depth 2, nested)
    # Each distinct leaf surfaces its own audit record carrying the ACTUAL opened path —
    # not just the matched root ($VAULT). Proves the d_name walk + leaf-keyed suppressor.
    expect_log "leaf path reported ($VAULT/secret)" '.message == "audit" and .path == $p and .action == "read"' --arg p "$VAULT/secret" || fail=1
    expect_log "sibling surfaces separately ($VAULT/other)" '.message == "audit" and .path == $p and .action == "read"' --arg p "$VAULT/other" || fail=1
    expect_log "depth-2 nested path reconstructed ($VAULT/sub/nested)" '.message == "audit" and .path == $p and .action == "read"' --arg p "$VAULT/sub/nested" || fail=1
    return $fail
}

# A system fragment carries a system-tier rule AND an `[[include]]` pulling in a user-tier
# file scoped to root's home (~root = /root, always in passwd). The included rule must
# enforce in-kernel exactly like a system rule — proving the tier assembly
# (load_policy → include expansion → tier-aware compile → merged maps) reaches the kernel.
# The user vault sits under /root so it passes the home-scope check; the system vault is
# under $TMP (system tier has no scope limit). Exes/subjects are unscoped either way.
scenario_user_tier() {
    echo "### scenario: system + user tiers (a system rule and an [[include]]d user rule both enforce)"
    ws_new   # exes (OWNER/OWNER_B/SCRAPER), TMP, SOCK, LOG
    local sysvault="$TMP/sysvault"; mkdir -p "$sysvault"; echo SYS > "$sysvault/secret"
    local usrvault="/root/cordon-tier-$$"; mkdir -p "$usrvault"; echo USR > "$usrvault/secret"
    on_cleanup rm -rf "$usrvault"
    mkdir -p "$TMP/conf.d" "$TMP/users"
    # System fragment: a system-tier allow + the include binding root's user-tier file.
    cat > "$TMP/conf.d/00-system.toml" <<EOF
$(rule "$OWNER" "$sysvault" read allow)

[[include]]
user = "root"
path = "$TMP/users/root.toml"
EOF
    # User-tier file (objects must be under ~root): only OWNER_B may read the user vault.
    cat > "$TMP/users/root.toml" <<EOF
$(rule "$OWNER_B" "$usrvault" read allow)
EOF
    write_config "$TMP/conf.d"

    daemon_start
    if ! wait_active; then
        echo "  FAIL: daemon did not become active"; sed 's/^/  daemon| /' "$LOG"
        return 1
    fi
    local fail=0
    expect_allow "system-tier rule: OWNER reads the system vault"        read_as "$OWNER"   "$sysvault/secret" || fail=1
    expect_allow "user-tier (included) rule: OWNER_B reads the ~root vault" read_as "$OWNER_B" "$usrvault/secret" || fail=1
    expect_deny  "scraper denied the system vault (default-deny)"         read_as "$SCRAPER" "$sysvault/secret" || fail=1
    expect_deny  "scraper denied the ~root user vault (default-deny)"     read_as "$SCRAPER" "$usrvault/secret" || fail=1
    expect_deny  "OWNER denied the user vault (only OWNER_B is allowed there)" read_as "$OWNER" "$usrvault/secret" || fail=1
    return $fail
}

# The headline of the audit-log change (DESIGN §15.10): for a *regular* user the journal
# renders object=/path= with that user's home collapsed to ~, so a deny/audit line drops
# straight into the user's policy. We synthesize a throwaway regular user (uid in the
# [1000,60000] window) with a writable home under /tmp, audit a vault inside it, and read it
# *as* that user — the kernel records the uid, the daemon resolves it via /etc/passwd (its
# mtime-keyed cache picks up the appended line) and renders ~. The collapse is caller-driven,
# not tier-driven, so a plain system policy suffices. (Skips if the guest can't drop uid or
# edit /etc/passwd.)
scenario_user_home_tilde() {
    echo "### scenario: audit-log ~ collapse (a regular user's home renders as ~)"
    ws_new
    if ! command -v setpriv >/dev/null; then
        echo "  SKIP: setpriv unavailable — cannot run the reader as a non-root uid"; return 0
    fi
    local tuser="cordontilde$$" tuid=4242
    local thome="$TMP/home" tvault tsecret
    tvault="$thome/.creds"; tsecret="$tvault/key"
    mkdir -p "$tvault"; echo SECRET > "$tsecret"
    chown -R "$tuid:$tuid" "$thome"
    chmod 755 "$TMP"   # let $tuid traverse the workspace to its home and the exe
    # Register the synthetic user so the daemon's passwd lookup resolves uid → name + home.
    if ! printf '%s:x:%s:%s:Cordon Tilde:%s:/bin/sh\n' "$tuser" "$tuid" "$tuid" "$thome" >> /etc/passwd 2>/dev/null; then
        echo "  SKIP: /etc/passwd not writable in this guest — cannot synthesize a regular user"; return 0
    fi
    on_cleanup drop_user "$tuser"
    write_policy <<EOF
$(rule "$OWNER" "$tvault" read audit)
EOF
    daemon_start
    started || return 1
    local fail=0
    expect_allow "regular user reads its cred (audit)" read_as_uid "$tuid" "$OWNER" "$tsecret" || fail=1
    # The audit line names the user and collapses ~ on BOTH object= (the rule's dir) and
    # path= (the opened file): object=~/.creds, path=~/.creds/key — copy-pasteable into the
    # user's policy verbatim.
    expect_log "audit line shows user=$tuser with ~-collapsed object and path" '.message == "audit" and .user == $u and has("exe") and .object == "~/.creds"
            and .path == "~/.creds/key" and .action == "read"' --arg u "$tuser" || fail=1
    return $fail
}

# --- policy-edit symlink scenarios: shared setup -----------------------------
# The sudoedit-style boundary (DESIGN §15.8) drops to the invoking user for the editor while
# the root parent seeds/reads/writes the root-owned copy. Both scenarios exercise a same-uid
# symlink attack (the in-scope threat, DESIGN §2) on the user-owned temp copy; no daemon is
# needed — the attack is resolved before the apply.

# Synthesize a throwaway regular user (the editor drops to it), a root-only sentinel, and a
# config. Echoes SKIP + returns 1 when the guest can't support it; on success sets the
# TUID/TUSER/SENTINEL/EDITDIR globals + CORDON_CONFIG.
edit_env_setup() {
    ws_new
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; return 1; }
    TUID=4243; TUSER="cordonedit$$"
    local thome="$TMP/ehome"; mkdir -p "$thome"; chown "$TUID:$TUID" "$thome"; chmod 755 "$TMP"
    printf '%s:x:%s:%s:Cordon Edit:%s:/bin/sh\n' "$TUSER" "$TUID" "$TUID" "$thome" >> /etc/passwd 2>/dev/null \
        || { echo "  SKIP: /etc/passwd not writable"; return 1; }
    on_cleanup drop_user "$TUSER"
    SENTINEL="$TMP/root-secret"; echo "SENTINEL-XYZZY" > "$SENTINEL"; chown 0:0 "$SENTINEL"; chmod 600 "$SENTINEL"
    EDITDIR="${TMPDIR:-/tmp}"   # where cordon mints its per-edit temp dir
    write_config "$TMP/policy.toml" "$TMP/dead.sock"
}

# Run `cordon policy edit` as the synthetic user with EDITOR=$1; echoes its combined output.
# stdin is /dev/null so a re-edit prompt (only reached if the read-back regresses and accepts
# a bad buffer) gets EOF → Quit, failing fast instead of blocking the suite.
run_policy_edit() { SUDO_UID="$TUID" SUDO_GID="$TUID" EDITOR="$1" "$CORDON" policy edit "$TMP/policy.toml" </dev/null 2>&1; }

# The editor (running as the invoking user) swaps the temp copy for a symlink to a root-only
# file; the privileged read-back must NOT follow it (O_NOFOLLOW), so its contents never
# surface in the saved policy or the printed diagnostics.
scenario_policy_edit_leak() {
    echo "### scenario: policy edit read-back refuses a symlinked temp copy (no leak)"
    edit_env_setup || return 0
    cat > "$TMP/evil-editor.sh" <<EOF
#!/bin/sh
rm -f "\$1"; ln -s "$SENTINEL" "\$1"; exit 0
EOF
    chmod 755 "$TMP/evil-editor.sh"
    local fail=0 out; out="$(run_policy_edit "$TMP/evil-editor.sh")"
    if printf '%s' "$out" | grep -q "SENTINEL-XYZZY"; then
        echo "  FAIL: read-back followed the symlink — leaked the root sentinel:"; printf '%s\n' "$out" | sed 's/^/  cli| /'; fail=1
    elif [ -f "$TMP/policy.toml" ] && grep -q "SENTINEL-XYZZY" "$TMP/policy.toml"; then
        echo "  FAIL: the root sentinel's contents were written into the policy"; fail=1
    else
        echo "  OK: read-back refused the symlink (no sentinel leak)"
    fi
    return $fail
}

# A racing same-uid loop keeps swapping any cordon temp copy for a symlink to the sentinel
# while `policy edit` runs. The fd-based (`fchown`) hand-off makes this structurally safe, so
# across many runs the sentinel is never chowned to the invoker (a path `chown` would follow).
scenario_policy_edit_chown() {
    echo "### scenario: policy edit fd-based chown resists a temp-copy symlink race"
    edit_env_setup || return 0
    local flag="$TMP/race.on"; : > "$flag"
    cat > "$TMP/racer.sh" <<'RACER'
#!/bin/sh
while [ -e "$FLAG" ]; do
    for f in "$EDITDIR"/cordon-edit-*/policy.toml; do
        [ -e "$f" ] && [ ! -L "$f" ] && ln -sf "$SENTINEL" "$f" 2>/dev/null
    done
done
RACER
    chmod 755 "$TMP/racer.sh"
    FLAG="$flag" SENTINEL="$SENTINEL" EDITDIR="$EDITDIR" \
        setpriv --reuid "$TUID" --regid "$TUID" --clear-groups "$TMP/racer.sh" &
    local racer=$!
    for _ in $(seq 1 20); do run_policy_edit /bin/true >/dev/null 2>&1; done
    rm -f "$flag"; wait "$racer" 2>/dev/null
    local fail=0 owner; owner="$(stat -c '%u:%g' "$SENTINEL")"
    if [ "$owner" != "0:0" ]; then
        echo "  FAIL: the root sentinel was chowned to $owner (arbitrary-chown TOCTOU)"; fail=1
    elif [ "$(cat "$SENTINEL")" != "SENTINEL-XYZZY" ]; then
        echo "  FAIL: the root sentinel's content changed"; fail=1
    else
        echo "  OK: the sentinel stayed root-owned + intact across the chown race"
    fi
    return $fail
}

# --- bless scenarios: shared helpers -----------------------------------------
# The smoke runs as root, so most bless scenarios invoke the CLI directly (peer uid 0)
# and the blessed child stays root; `scenario_bless_unprivileged` runs it as an ordinary
# uid. All of them run the daemon in the nested cgroup $DCGROUP (see the header).

# The daemon's cgroup for the bless scenarios — stands in for the systemd service cgroup.
BLESS_DCGROUP="/sys/fs/cgroup/cordon-smoke.scope"

# cgroup2 is required for the carrier cgroups; mount it if the guest hasn't (virtme
# usually has). SKIP (like the setpriv guard) when it can't be made available. Also arms
# $DCGROUP so the daemon starts in a nested cgroup, as it does in production.
cgroup2_ready() {
    if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
        mkdir -p /sys/fs/cgroup 2>/dev/null
        if ! mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null; then
            echo "  SKIP: cgroup2 unavailable (cannot mount /sys/fs/cgroup)"
            return 1
        fi
    fi
    DCGROUP="$BLESS_DCGROUP"
    # `cordon bless` proves human presence through `$CORDON_SUDO` (crates/cli/src/bless.rs).
    # There is no sudo in the guest, and the suite already runs as root, so `env` is a
    # faithful stand-in: the helper really does connect as uid 0. `fake_sudo_start`
    # replaces it with a wrapper that elevates from an unprivileged CLI, which is the
    # shape a real sudo provides.
    export CORDON_SUDO="env"
    return 0
}

# A stand-in for sudo when the CLI itself is unprivileged: a root loop reads command
# lines off a FIFO and runs them, and $CORDON_SUDO points at a wrapper that just forwards
# its argv. No setuid binary (the guest's tmpfs may be nosuid) and no real sudo — and the
# helper genuinely runs as root, which is the property under test. Sets $CORDON_SUDO.
fake_sudo_start() {
    local fifo="$TMP/sudo.fifo"
    mkfifo "$fifo" && chmod 666 "$fifo" || return 1
    # Hold a writer open so the reader never sees EOF between wrapper invocations.
    exec 9<>"$fifo"
    ( while IFS= read -r line; do [ -n "$line" ] && eval "$line" & done <"$fifo" ) &
    FAKE_SUDO_PID=$!
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" > %s\n' "$fifo" > "$TMP/fakesudo"
    chmod 755 "$TMP/fakesudo"
    export CORDON_SUDO="$TMP/fakesudo"
    on_cleanup fake_sudo_stop
}

# A copy of the CLI an unprivileged uid can actually execute. $CORDON lives in the
# developer's source tree, which that uid cannot traverse into; the copy also becomes what
# `current_exe()` resolves to, so the helper `cordon bless` re-spawns is this same binary.
# Echoes the path.
unpriv_cordon() {
    chmod 755 "$TMP"
    cp "$CORDON" "$TMP/cordon" && chmod 755 "$TMP/cordon" && echo "$TMP/cordon"
}

fake_sudo_stop() {
    [ -n "${FAKE_SUDO_PID:-}" ] && kill "$FAKE_SUDO_PID" 2>/dev/null
    FAKE_SUDO_PID=""
    exec 9>&-
}

# The daemon's carrier root: its own cgroup dir (carriers are created under it).
bless_root() {
    local rel; rel="$(sed -n 's/^0:://p' "/proc/$DPID/cgroup")"
    echo "/sys/fs/cgroup${rel%/}"
}
# The live carrier dirs (cordon-bless-<id>.<class>), if any.
bless_dirs() { ls -d "$(bless_root)"/cordon-bless-* 2>/dev/null; }
# The values of every `"KEY": VALUE` field in `cordon --json` output, which pretty-prints
# one field per line, unquoted, one per line. Matches the reply's schema, not its rendering.
json_field() { sed -n 's/^ *"'"$1"'": "\{0,1\}\([^",]*\)"\{0,1\},\{0,1\}$/\1/p'; }
# The live blessing ids, one per line.
bless_ids() { "$CORDON" --json bless list 2>/dev/null | json_field id; }
# The first live blessing's id ("" when none).
bless_first_id() { bless_ids | head -n1; }

# The first carrier that actually has members; echoes its dir. NB: `cgroup.procs` is a
# kernfs file — its st_size is 0 even when populated, so `[ -s ]` would always be false
# and only reading it tells the truth.
bless_populated_dir() {
    local d
    for d in $(bless_dirs); do
        [ -n "$(cat "$d/cgroup.procs" 2>/dev/null)" ] && { echo "$d"; return 0; }
    done
    return 1
}
# Poll until some carrier has members (the CLI's pre_exec join landed); echoes its dir.
bless_wait_populated() { wait_until 50 bless_populated_dir; }

# Open FILE for read as subject EXE inside a fresh blessing of CLASS. The CLI mints,
# forks the exe into the carrier, and propagates its exit code.
bless_read_as() { "$CORDON" bless --class "$1" -- "$2" -c 'exec 3<"$1"' bash "$3" 2>/dev/null; } # $1 class $2 exe $3 file

# Poll until the daemon has reaped every blessing: list drained AND carrier dirs gone.
bless_drained() { wait_until 80 bless_none_left; }
bless_none_left() { [ -z "$(bless_dirs)" ] && [ -z "$(bless_ids)" ]; }

# `deny * read V` + `allow @blessed-ro read V` + a second protected V2: a blessed read of V
# is allowed (a concrete blessing outranks the catch-all), the SAME blessed exe is denied on
# V2 (the grant's scope is the object column), and the unblessed exe stays denied on V.
# This is also the end-to-end proof that the mkdir'd carrier's st_ino equals what
# bpf_get_current_cgroup_id() sees.
scenario_bless_scope() {
    echo "### scenario: bless scope (blessed read allowed on V, denied on V2, unblessed denied)"
    ws_new
    cgroup2_ready || return 0
    local vault2="$TMP/vault2"; mkdir -p "$vault2"; echo S2 > "$vault2/secret"
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule '*' "$VAULT" read deny)

$(rule @blessed-ro "$VAULT" read allow)

$(rule '*' "$vault2" read deny)
EOF
    daemon_start; started || return 1
    local fail=0
    # Guard the harness itself: if the daemon ever fell back to the cgroup2 root, every
    # bless scenario would silently stop covering the production (Delegate=yes) shape and
    # still pass. Assert the carrier root is the nested cgroup we started it in.
    if [ "$(bless_root)" = "$BLESS_DCGROUP" ]; then
        echo "  OK: daemon runs in a nested cgroup ($BLESS_DCGROUP) — the Delegate=yes shape"
    else
        echo "  FAIL: carrier root is $(bless_root), expected the nested $BLESS_DCGROUP"; fail=1
    fi
    # The blessed read must outrank the who="*" deny on the same object.
    expect_allow "blessed exe reads V (grant outranks the catch-all deny)" bless_read_as ro "$OWNER" "$SECRET" || fail=1
    expect_deny  "same exe unblessed is denied V"                          read_as "$OWNER" "$SECRET"          || fail=1
    expect_deny  "blessed exe denied V2 (grant scope = the object column)" bless_read_as ro "$OWNER" "$vault2/secret" || fail=1
    return $fail
}

# carrier membership IS the boundary: a non-root uid cannot write into the root-owned
# carrier's cgroup.procs (EACCES); `bless list` shows the live entry meanwhile.
scenario_bless_boundary() {
    echo "### scenario: bless boundary (non-root write to the carrier cgroup.procs fails)"
    ws_new
    cgroup2_ready || return 0
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; return 0; }
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule @blessed-ro "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    "$CORDON" bless --class ro -- sleep 300 &
    local clipid=$!
    # Wait for the carrier to exist and the sleep to have joined it.
    local dir=""
    if dir="$(bless_wait_populated)"; then
        echo "  OK: carrier populated ($(basename "$dir"))"
    else
        echo "  FAIL: no populated carrier appeared"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    if "$CORDON" --json bless list 2>/dev/null | json_field class | grep -qx ro; then
        echo "  OK: bless list shows the live entry"
    else
        echo "  FAIL: bless list does not show the entry"; "$CORDON" bless list 2>&1 | sed 's/^/  cli| /'; fail=1
    fi
    # THE membership boundary: a non-root uid must not be able to write itself into the
    # root-owned carrier (else any process could self-bless).
    expect_deny "non-root write to the carrier cgroup.procs" \
        setpriv --reuid 4242 --regid 4242 --clear-groups sh -c "echo \$\$ > '$dir/cgroup.procs'" || fail=1
    # Cleanup: revoke, let the CLI reap its child, and let GC drain the carrier.
    "$CORDON" bless revoke "$(bless_first_id)" >/dev/null 2>&1
    wait "$clipid" 2>/dev/null
    bless_drained || { echo "  FAIL: blessing did not drain after revoke"; fail=1; }
    return $fail
}

# a blessed bash's *grandchild* reads the secret (cgroup membership is inherited); after
# exit the daemon GC reaps everything — `bless list` drains AND the carrier dir is gone
# (BLESSED entry + table + cgroup, not just "re-open denied").
scenario_bless_inherit_gc() {
    echo "### scenario: bless inherit + GC (grandchild reads; carrier fully reaped after exit)"
    ws_new
    cgroup2_ready || return 0
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule '*' "$VAULT" read deny)

$(rule @blessed-ro "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    # The blessed child spawns a GRANDCHILD to do the read — cgroup membership (hence
    # the blessing) is inherited by the whole tree. The trailing sleep outlives a GC
    # tick so the daemon observes the carrier populated; without that, a fast exit would
    # defer the reap to the mint grace (`MINT_GRACE`) and stall this scenario.
    cat > "$TMP/blessed-read.sh" <<EOF
#!/bin/bash
bash -c 'exec 3<"$SECRET"'
rc=\$?
sleep 1.2
exit \$rc
EOF
    chmod 755 "$TMP/blessed-read.sh"
    expect_allow "blessed grandchild reads the secret (inherited)" "$CORDON" bless --class ro -- "$TMP/blessed-read.sh" || fail=1
    # After exit, the daemon must reap EVERYTHING: BLESSED entry + table row + cgroup
    # dir. "list drains and the dir is gone" proves all three ("re-open denied" alone
    # would hold regardless).
    if bless_drained; then
        echo "  OK: blessing fully reaped after exit (list empty, carrier dir gone)"
    else
        echo "  FAIL: blessing not reaped (list or carrier dir lingers)"
        "$CORDON" bless list 2>&1 | sed 's/^/  cli| /'; bless_dirs | sed 's/^/  dir| /'
        sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    return $fail
}

# `bless revoke <id>` kills the carrier tree promptly (cgroup.kill): the blessed sleep dies,
# list + dirs drain.
scenario_bless_revoke() {
    echo "### scenario: bless revoke (the blessed tree dies promptly; list + dirs drain)"
    ws_new
    cgroup2_ready || return 0
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule @blessed-ro "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    "$CORDON" bless --class ro -- sleep 300 &
    local clipid=$!
    local id=""
    bless_wait_populated >/dev/null && id="$(bless_first_id)"
    [ -n "$id" ] || { echo "  FAIL: no populated blessing appeared"; sed 's/^/  daemon| /' "$LOG"; kill "$clipid" 2>/dev/null; return 1; }
    if "$CORDON" --json bless revoke "$id" 2>/dev/null | json_field id | grep -qx "$id"; then
        echo "  OK: revoke accepted (id $id)"
    else
        echo "  FAIL: revoke errored"; "$CORDON" bless revoke "$id" 2>&1 | sed 's/^/  cli| /'; fail=1
    fi
    # cgroup.kill slays the tree → the CLI (waiting on the sleep) exits promptly.
    if wait_until 30 gone "$clipid"; then
        echo "  OK: the blessed sleep died promptly after revoke"
    else
        echo "  FAIL: the blessed sleep survived revoke"; kill "$clipid" 2>/dev/null; fail=1
    fi
    wait "$clipid" 2>/dev/null
    if bless_drained; then
        echo "  OK: list + carrier dirs drained after revoke"
    else
        echo "  FAIL: blessing lingered after revoke"; "$CORDON" bless list 2>&1 | sed 's/^/  cli| /'; fail=1
    fi
    return $fail
}

# bless is loud: a blessed read under an `audit @blessed-ro` rule journals with a trailing
# `blessing=ro` (class by NAME).
scenario_bless_journal() {
    echo "### scenario: bless journal (a blessed read logs blessing=ro — bless is loud)"
    ws_new
    cgroup2_ready || return 0
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule @blessed-ro "$VAULT" read audit)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "blessed read under the audit rule" bless_read_as ro "$OWNER" "$SECRET" || fail=1
    # The class is journaled by NAME, appended after the standard fields.
    expect_log "audit line carries blessing=ro" '.message == "audit" and .blessing == "ro"' || fail=1
    return $fail
}

# Runs `cordon bless` as an ordinary uid, with `$CORDON_SUDO` a FIFO wrapper that reaches
# root without setuid or a real sudo (the design is in crates/cli/src/bless.rs). The other
# bless scenarios run the CLI as root, so only this one guards that:
#   * the blessed child runs as the invoking uid;
#   * an environment variable set before the call survives into it;
#   * the blessed read still works, which proves an UNPRIVILEGED process successfully
#     wrote its pid into a root-owned cgroup.procs — the fd-delegation property.
scenario_bless_unprivileged() {
    echo "### scenario: unprivileged bless (runs as you, env survives, still blessed)"
    ws_new
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; return 0; }
    cgroup2_ready || return 0
    local buid=4244 bgid=4244
    local cordon; cordon="$(unpriv_cordon)"
    local out="$TMP/blessed.id"; : > "$out"; chmod 666 "$out"
    # Reports its identity + the canary, then does the blessed read (denied ⇒ nonzero).
    cat > "$TMP/blessed-id.sh" <<EOF
#!/bin/bash
{ id -u; echo "\$CORDON_CANARY"; } > "$out"
exec 3< "$SECRET"
EOF
    chmod 755 "$TMP/blessed-id.sh"
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule '*' "$VAULT" read deny)

$(rule @blessed-ro "$VAULT" read allow)
EOF
    daemon_start
    started || return 1
    fake_sudo_start || { echo "  SKIP: cannot build the elevation stand-in"; return 0; }
    local fail=0
    # The CLI itself is uid 4244 — only the helper it spawns reaches root.
    local blesslog="$TMP/bless.log"
    if setpriv --reuid "$buid" --regid "$bgid" --clear-groups \
         env CORDON_SUDO="$CORDON_SUDO" CORDON_CONFIG="$CORDON_CONFIG" CORDON_CANARY=alive \
         "$cordon" bless --class ro -- "$TMP/blessed-id.sh" >"$blesslog" 2>&1; then
        echo "  OK: an UNPRIVILEGED bless read the secret (fd delegation joined the carrier)"
    else
        echo "  FAIL: unprivileged bless failed — handshake or fd-join regression?"
        sed 's/^/  cordon| /' "$blesslog"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    local got_uid got_canary
    got_uid="$(sed -n 1p "$out")"; got_canary="$(sed -n 2p "$out")"
    if [ "$got_uid" = "$buid" ]; then
        echo "  OK: the blessed child ran as uid $buid (no drop needed — it never was root)"
    else
        echo "  FAIL: child uid=${got_uid:-<none>}, expected $buid"; fail=1
    fi
    if [ "$got_canary" = alive ]; then
        echo "  OK: the caller's environment survived into the blessed child"
    else
        echo "  FAIL: \$CORDON_CANARY=${got_canary:-<empty>} — the environment was scrubbed"; fail=1
    fi
    # And the security property the seam rests on: a faked elevation that never reaches
    # root produces a non-root helper, whose approval the daemon refuses.
    local refused="$TMP/refused.log"
    CORDON_SUDO="setpriv --reuid $buid --regid $bgid --clear-groups" \
        "$CORDON" bless --class ro -- /bin/true >"$refused" 2>&1 && fail=1
    if grep -qi 'requires root' "$refused"; then
        echo "  OK: a faked elevation is refused by the daemon (uid gate, not the tool)"
    else
        echo "  FAIL: a non-root helper was not refused: $(head -2 "$refused")"; fail=1
    fi
    return $fail
}

# The socket is 0666 and its mode carries no security weight; the daemon's `authorize()`
# decides. This asserts both halves at once — an unprivileged uid can read (status /
# policy show / bless list) and CANNOT apply.
scenario_socket_authz() {
    echo "### scenario: socket authorization — unprivileged reads work, apply is refused"
    ws_new
    if ! command -v setpriv >/dev/null; then
        echo "  SKIP: setpriv unavailable — cannot run the CLI as a non-root uid"; return 0
    fi
    local uid=4246
    chmod 755 "$TMP"   # let $uid traverse to the socket, config and policy
    write_policy <<EOF
$(rule "$OWNER" "$VAULT" read deny)
EOF
    daemon_start
    started || return 1
    local fail=0
    # `cordon` as an ordinary user, with the workspace config it can read.
    as_uid() { setpriv --reuid "$uid" --regid "$uid" --clear-groups "$CORDON" "$@"; }

    local mode; mode="$(stat -c %a "$SOCK")"
    if [ "$mode" = 666 ]; then
        echo "  OK: the socket is 0666 (connectable by any local user)"
    else
        echo "  FAIL: socket mode is $mode, expected 666 — unprivileged connect(2) needs write"; fail=1
    fi
    expect_allow "unprivileged status"      as_uid status      || fail=1
    expect_allow "unprivileged policy show" as_uid policy show || fail=1
    expect_allow "unprivileged bless list"  as_uid bless list  || fail=1
    # The write. It must fail *in the daemon*, naming root — not fail to connect, and not
    # succeed: guards against "whoever can reach the socket can apply".
    local out; out="$(as_uid policy apply 2>&1)"
    if [ -n "$out" ] && ! as_uid policy apply >/dev/null 2>&1 && printf '%s' "$out" | grep -q "requires root"; then
        echo "  OK: unprivileged policy apply refused by the daemon (peer uid gate)"
    else
        echo "  FAIL: unprivileged policy apply was not refused with a root message: ${out:-<no output>}"; fail=1
    fi
    return $fail
}

# The CLI must refuse a daemon end that isn't root (the confused-deputy reasoning is on
# `require_root_daemon` in crates/cli/src/bless.rs). Here a genuinely unprivileged
# process squats a socket and the CLI must refuse it — and crucially must refuse BEFORE
# spawning the elevation helper, so the human is never even prompted. The wrapper drops a
# marker file when it runs; the absence of that marker is the assertion.
scenario_bless_rejects_fake_daemon() {
    echo "### scenario: bless refuses a non-root daemon (no nonce, no password prompt)"
    ws_new
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; return 0; }
    command -v python3 >/dev/null || { echo "  SKIP: python3 unavailable (needed to bind a fake socket)"; return 0; }
    local buid=4247
    local cordon; cordon="$(unpriv_cordon)"
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule @blessed-ro "$VAULT" read allow)
EOF
    daemon_start
    started || return 1
    local fail=0

    # The squatter: an unprivileged process listening where the client will look. Its
    # own directory, since $TMP is root-owned — a real squatter binds inside
    # $XDG_RUNTIME_DIR or /tmp, both of which it can write.
    local squatdir="$TMP/squat"; mkdir -p "$squatdir"; chown "$buid:$buid" "$squatdir"
    local fake="$squatdir/cordon.sock"
    setpriv --reuid "$buid" --regid "$buid" --clear-groups python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1]); s.listen(8)
while True: s.accept()
' "$fake" &
    local squatter=$!
    if ! wait_until 50 test -S "$fake"; then
        echo "  SKIP: could not bind a fake socket as uid $buid"; kill "$squatter" 2>/dev/null; return 0
    fi

    # An elevation wrapper that records the fact it was reached. It must never run.
    local marker="$TMP/elevation-was-spawned"
    printf '#!/bin/sh\ntouch %s\nexec "$@"\n' "$marker" > "$TMP/marker-sudo"
    chmod 755 "$TMP/marker-sudo"

    local out="$TMP/fake.log"
    setpriv --reuid "$buid" --regid "$buid" --clear-groups \
        env CORDON_SUDO="$TMP/marker-sudo" CORDON_CONFIG="$CORDON_CONFIG" \
        "$cordon" --socket "$fake" bless --class ro -- /bin/true >"$out" 2>&1
    if [ $? -ne 0 ] && grep -q 'not root' "$out"; then
        echo "  OK: the CLI refused a non-root daemon ($(head -1 "$out" | cut -c1-60)…)"
    else
        echo "  FAIL: a non-root daemon was not refused: $(head -2 "$out")"; fail=1
    fi
    if [ ! -e "$marker" ]; then
        echo "  OK: the elevation helper was never spawned (no password prompt to hijack)"
    else
        echo "  FAIL: the elevation ran before the daemon was vetted"; fail=1
    fi

    kill "$squatter" 2>/dev/null
    return $fail
}

# --- scenario: the carrier lands where the user is still attributable ------
# Build a fake user subtree in the shapes a real desktop and a real tty produce, and set
# the P_* globals naming each requester cgroup. `user-N.slice` is root-owned as systemd
# leaves it; `user@N.service` is chowned to the user, because it is *delegated* — that is
# precisely why a carrier may not live there. Returns 1 (with a SKIP) if it can't be built.
placement_tree_make() { # $1 uid
    P_USLICE="/sys/fs/cgroup/user.slice/user-$1.slice"
    P_DESKTOP="$P_USLICE/user@$1.service/app.slice/app-terminal.scope"
    P_TTY="$P_USLICE/session-99.scope"
    P_ROGUE="$P_USLICE/session-98.scope"     # user-owned: must be refused
    mkdir -p "$P_DESKTOP" "$P_TTY" "$P_ROGUE" 2>/dev/null || {
        echo "  SKIP: cannot build a user subtree under /sys/fs/cgroup"; return 1
    }
    chown -R "$1:$1" "$P_USLICE/user@$1.service"   # delegated, as systemd does
    chown "$1:$1" "$P_ROGUE"
    on_cleanup placement_tree_clean
}

placement_tree_clean() {
    rmdir "$P_USLICE"/*/cordon-bless-* "$P_USLICE"/cordon-bless-* 2>/dev/null
    rmdir "$P_DESKTOP" "$(dirname "$P_DESKTOP")" "$(dirname "$(dirname "$P_DESKTOP")")" \
          "$P_TTY" "$P_ROGUE" "$P_USLICE" 2>/dev/null
}

# Bless from inside $1, leaving the blessed child alive; echoes its carrier's cgroup path
# (mount-relative, as /proc/self/cgroup reports it).
#
# Runs in a command substitution, i.e. a subshell — so the pid to reap later travels
# through a file rather than a variable, which would never reach the caller.
bless_from() { # $1 requester cgroup  $2 uid  $3 cordon binary  $4 marker prefix
    rm -f "$4" "$4.cg" "$4.pid"
    sh -c 'echo $$ > "$1/cgroup.procs" && shift && exec "$@"' _ "$1" \
        setpriv --reuid "$2" --regid "$2" --clear-groups \
        env CORDON_SUDO="$CORDON_SUDO" CORDON_CONFIG="$CORDON_CONFIG" \
        "$3" bless --class ro -- /bin/sh -c "cat /proc/self/cgroup > '$4.cg'; touch '$4'; sleep 5" &
    echo $! > "$4.pid"
    wait_until 60 test -e "$4" || return 1
    sed -n 's/^0:://p' "$4.cg"
}

# Reap the blessed tree started by `bless_from` and wait for the carrier to drain.
end_bless() { # $1 marker prefix
    local pid; pid="$(cat "$1.pid" 2>/dev/null)"
    [ -n "$pid" ] && { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; }
    bless_drained >/dev/null 2>&1
}

# One placement case: bless from $1 and require the carrier's parent to be exactly $2.
expect_placement() { # $1 requester cgroup  $2 expected parent (mount-relative)  $3 label
    local marker="$P_READY/$(basename "$1")" got
    got="$(bless_from "$1" "$P_UID" "$P_CORDON" "$marker")" || {
        echo "  FAIL: $3 — the blessed child never started"; end_bless "$marker"; return 1
    }
    end_bless "$marker"
    case "$got" in
        "$2"/cordon-bless-*) echo "  OK: $3" ;;
        *) echo "  FAIL: $3 — carrier at ${got:-<none>}, expected under $2"; return 1 ;;
    esac
}

# Each requester shape must get a carrier logind can still attribute to the user (why:
# `carrier_parent` in crates/daemon/src/backend/bpf_lsm/bless.rs):
#   a) DESKTOP — the terminal is under the *delegated* user@UID.service/app.slice, with no
#      session scope anywhere above it → the user slice.
#   b) TTY — the requester is in a session-N.scope → that scope (more precise).
#   c) NO USER SUBTREE — a requester under system.slice → the daemon's cgroup.
#   d) USER-OWNED parent — refused → the daemon's cgroup.
# All four are covered because a tty-only test passes while the desktop case is broken.
# The assertion in (a) and (b) is the property logind consumes, not just a path: the
# carrier's cgroup must still contain `user-<uid>.slice`.
scenario_bless_placement() {
    echo "### scenario: the carrier lands where logind can still attribute the user"
    ws_new
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; return 0; }
    cgroup2_ready || return 0
    P_UID=4248
    P_CORDON="$(unpriv_cordon)"
    P_READY="$TMP/ready"; mkdir -p "$P_READY"; chown "$P_UID:$P_UID" "$P_READY"
    placement_tree_make "$P_UID" || return 0
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule @blessed-ro "$VAULT" read allow)
EOF
    daemon_start
    started || return 1
    fake_sudo_start || { echo "  SKIP: cannot build the elevation stand-in"; return 0; }
    local fail=0
    local slice="/user.slice/user-$P_UID.slice"

    # The desktop shape: no session scope anywhere above the requester. This is the common
    # case — the carrier must still land in the user slice.
    expect_placement "$P_DESKTOP" "$slice" \
        "desktop requester (delegated user@.service, no session scope) → the user slice" || fail=1
    # A tty login has a session scope, which is more precise, so it wins.
    expect_placement "$P_TTY" "$slice/session-99.scope" \
        "tty requester → its own session-99.scope" || fail=1
    # Nothing user-attributable at all ⇒ the daemon's cgroup.
    expect_placement "$DCGROUP" "${DCGROUP#/sys/fs/cgroup}" \
        "requester with no user subtree → the daemon's cgroup" || fail=1
    # A user-owned parent is refused however plausible its name.
    expect_placement "$P_ROGUE" "${DCGROUP#/sys/fs/cgroup}" \
        "user-owned session scope is refused → falls back to the daemon's cgroup" || fail=1
    return $fail
}

# On restart the daemon adopts only root-owned leftover carriers (see `adoptable`).
#
# Plant two populated carriers in a session scope before the daemon starts: one root-owned,
# one chowned to a user. Exactly the first may come back in `bless list`.
scenario_bless_reconcile_ownership() {
    echo "### scenario: reconcile adopts a root-owned leftover, ignores a planted one"
    ws_new
    cgroup2_ready || return 0
    local buid=4249
    local uslice="/sys/fs/cgroup/user.slice/user-$buid.slice"
    local scope="$uslice/session-97.scope"
    if ! mkdir -p "$scope" 2>/dev/null; then
        echo "  SKIP: cannot create a session scope under /sys/fs/cgroup"; return 0
    fi
    # Both placements must be scanned (see `carrier_roots`); the user slice is the desktop
    # one.
    local ours="$scope/cordon-bless-70.ro" theirs="$scope/cordon-bless-71.ro"
    local desktop="$uslice/cordon-bless-72.ro"
    mkdir -p "$ours" "$theirs" "$desktop"
    chown "$buid:$buid" "$theirs"          # as if planted by that user
    # Populated, or reconcile just removes them as empty leftovers.
    sleep 30 & local a=$!; echo $a > "$ours/cgroup.procs"
    sleep 30 & local b=$!; echo $b > "$theirs/cgroup.procs"
    sleep 30 & local c=$!; echo $c > "$desktop/cgroup.procs"
    on_cleanup rmdir "$ours" "$theirs" "$desktop" "$scope" "$uslice"
    on_cleanup kill_and_reap "$a" "$b" "$c"
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule @blessed-ro "$VAULT" read allow)
EOF
    daemon_start
    started || return 1
    local fail=0
    local listing; listing="$(bless_ids)"
    if printf '%s\n' "$listing" | grep -qx 70; then
        echo "  OK: the root-owned leftover was adopted"
    else
        echo "  FAIL: the root-owned leftover was not adopted: $listing"; fail=1
    fi
    if printf '%s\n' "$listing" | grep -qx 71; then
        echo "  FAIL: a NON-ROOT-OWNED carrier was adopted — self-bless primitive"; fail=1
    else
        echo "  OK: the planted (user-owned) carrier was ignored"
    fi
    if printf '%s\n' "$listing" | grep -qx 72; then
        echo "  OK: a leftover in the user slice (the desktop placement) was adopted"
    else
        echo "  FAIL: the user-slice leftover was not adopted — reconcile does not scan"
        echo "        where placement puts desktop carriers; it would leak and then block"
        echo "        every later mint on EEXIST. listing: $listing"; fail=1
    fi
    expect_log "the refusal is journaled" '.event == "carrier_not_adopted"' || fail=1
    return $fail
}

# --- scenario: rename-over ---------------------------------------------------
# `rename(2)` onto an existing name *destroys* the destination inode, and `inode_rename`
# is the only hook the kernel fires for it. Both cases below are invisible to the
# source/destination-*directory* classification — one looks like an internal shuffle, the
# other like nothing protected moving at all — so only the destination dentry's own lookup
# sees them (see `decide_reparent`). The daemon self-test covers the mechanism on a
# deny-all probe; this covers the two shapes that matter under a real policy, and the
# atomic-save case that must NOT break.
#
# `who = "*"` throughout: the question here is which *object* answers for the destination,
# not which subject asked, so plain `mv` is the right actor and needs no exe copy.
scenario_rename_over() {
    echo "### scenario: rename-over (atomic save survives; a destroyed object refuses)"
    ws_new
    local lonely="$TMP/lonely"; echo "LONELY" > "$lonely"
    echo "TOKEN" > "$VAULT/token"
    write_policy <<EOF
$(rule '*' "$VAULT" "read write" allow)
$(rule '*' "$VAULT/token" '*' deny)
$(rule '*' "$lonely" '*' deny)
EOF
    daemon_start; started || return 1
    local fail=0
    # The pattern the internal-shuffle short-circuit exists for. The destroy check asks the
    # vault, which allows write, so it still goes through.
    echo save > "$VAULT/.save"
    expect_allow "atomic save inside the vault (temp beside target, rename over)" \
        mv -f "$VAULT/.save" "$SECRET" || fail=1
    # Same shuffle, but the destination carries a tighter rule of its own. Guards against
    # allowing it as an internal shuffle, which would destroy the more-specific object.
    echo t > "$VAULT/.t"
    expect_deny "rename over a nested, more-specific object" \
        mv -f "$VAULT/.t" "$VAULT/token" || fail=1
    [ -f "$VAULT/.t" ] && echo "  OK: the source survived (no copy+unlink fallback)" \
        || { echo "  FAIL: the source is gone — the rename took effect"; fail=1; }
    # A protected *file* whose parent is not protected: both walks miss. Guards against the
    # `(None, None)` allow — `rm lonely` refused while `mv x lonely` destroys it.
    echo evil > "$TMP/evil"
    expect_deny "rename over a file object whose parent is unprotected" \
        mv -f "$TMP/evil" "$lonely" || fail=1
    # The *source* is what discriminates: the destination exists either way, since a
    # successful rename just replaces its inode with the attacker's.
    [ -f "$TMP/evil" ] && echo "  OK: the protected file's inode survived" \
        || { echo "  FAIL: the protected file was destroyed and replaced"; fail=1; }
    return $fail
}

# --- scenario: bprm_check_security -------------------------------------------
# `execute` is its own capability (see `decide_exec`): this checks readable but not
# runnable, expressed with an explicit `deny`.
scenario_execute() {
    echo "### scenario: execute is a capability distinct from read"
    ws_new
    # `bash`, not `true`: `command -v true` resolves to the shell *builtin* and copies
    # nothing. Invoked below as `-c :` so the copy exits immediately instead of going
    # interactive. Same idiom as `mk_exe`.
    cp "$(command -v bash)" "$VAULT/runnable"
    cp "$(command -v bash)" "$VAULT/readonly"
    write_policy <<EOF
$(rule '*' "$VAULT" "read execute" allow)
$(rule '*' "$VAULT/readonly" execute deny)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "exec a binary the object grants execute on" "$VAULT/runnable" -c ':' || fail=1
    expect_deny  "exec a binary the policy denies execute on" "$VAULT/readonly" -c ':' || fail=1
    # The point of the hook: the same file is still perfectly readable.
    expect_allow "…and that same binary is still readable" cat "$VAULT/readonly" || fail=1
    return $fail
}

# --- scenario: inode_mkdir ---------------------------------------------------
# Guards that a subject that cannot remove a directory inside an object cannot add one
# either. The verdict comes from the *parent* (see `decide_create`) — which is what this
# checks, on both polarities, in one policy.
scenario_mkdir() {
    echo "### scenario: mkdir inside a protected object takes the parent's verdict"
    ws_new
    mkdir -p "$VAULT/locked"
    write_policy <<EOF
$(rule '*' "$VAULT" "read write create" allow)
$(rule '*' "$VAULT/locked" '*' deny)
EOF
    daemon_start; started || return 1
    local fail=0
    # A writable object must keep working — this hook must not break legitimate structure.
    expect_allow "mkdir inside an object that allows create/write" \
        mkdir "$VAULT/allowed" || fail=1
    # The gap this hook closes: nested, more specific, denying.
    expect_deny "mkdir inside a denying nested object" \
        mkdir "$VAULT/locked/evil" || fail=1
    [ -d "$VAULT/locked/evil" ] && { echo "  FAIL: the directory was created anyway"; fail=1; } \
        || echo "  OK: no directory appeared under the denied object"
    return $fail
}

# Swap two names via `renameat2(RENAME_EXCHANGE)`. Exits non-zero when the kernel refuses,
# and 3 when the syscall is unavailable — which the scenario's preflight separates from a
# deny, since "the helper is broken" and "the boundary refused" both look like failure.
exchange() {
    python3 -c '
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
if not hasattr(libc, "renameat2"):
    sys.exit(3)
AT_FDCWD, RENAME_EXCHANGE = -100, 2
sys.exit(0 if libc.renameat2(AT_FDCWD, sys.argv[1].encode(), AT_FDCWD,
                             sys.argv[2].encode(), RENAME_EXCHANGE) == 0 else 1)
' "$1" "$2"
}

# --- scenario: renameat2(RENAME_EXCHANGE) ------------------------------------
# An exchange re-parents *both* inodes and destroys neither, so the destroy check — which
# gives the destination object a `write` floor — does not cover it. The protected side
# leaving is an escape, but only if the hook is asked about that side at all:
# `security_inode_rename` calls it a second time with the pair swapped when RENAME_EXCHANGE
# is set. This scenario is what verifies that second call, rather than believing it. On a
# *writable* object the first call sees nothing but an allowed clobber, so if the kernel
# made only that one call the secret would walk out of its object.
scenario_rename_exchange() {
    echo "### scenario: renameat2(RENAME_EXCHANGE) — a protected inode cannot be swapped out"
    ws_new
    command -v python3 >/dev/null || { echo "  SKIP: python3 unavailable (needed for renameat2)"; return 0; }
    local outside="$TMP/outside"; echo "OUTSIDE" > "$outside"
    # Preflight while nothing is enforcing: an unavailable syscall must not read as a deny.
    echo A > "$TMP/xa"; echo B > "$TMP/xb"
    if ! exchange "$TMP/xa" "$TMP/xb"; then
        echo "  SKIP: renameat2(RENAME_EXCHANGE) unavailable on this kernel/libc"; return 0
    fi
    grep -q B "$TMP/xa" || { echo "  FAIL: preflight exchange did not swap the inodes"; return 1; }
    # Deliberately permissive: `write` must be *allowed* on the vault, or the destroy and
    # clobber checks would refuse the exchange for an unrelated reason and prove nothing.
    write_policy <<EOF
$(rule '*' "$VAULT" "read write create" allow)
EOF
    daemon_start; started || return 1
    local fail=0
    # The case only the swapped call can catch.
    expect_deny "exchange moving a protected inode out (unprotected side passed first)" \
        exchange "$outside" "$SECRET" || fail=1
    grep -q TOPSECRET "$SECRET" && echo "  OK: the protected inode stayed in its object" \
        || { echo "  FAIL: the secret was swapped out of the vault"; fail=1; }
    grep -q OUTSIDE "$outside" && echo "  OK: the outside name kept its own inode" \
        || { echo "  FAIL: the vault's inode is now reachable outside the object"; fail=1; }
    # The mirror image, which the *first* call already refuses via the escape check.
    expect_deny "exchange moving a protected inode out (protected side passed first)" \
        exchange "$SECRET" "$outside" || fail=1
    # An exchange wholly inside the object is an internal shuffle and must keep working.
    expect_allow "exchange of two names inside the same object" \
        exchange "$SECRET" "$VAULT/other" || fail=1
    return $fail
}

# --- fail-safe pinning: the boundary outlives the daemon --------------------
# The one thing no other scenario can show: every other scenario proves the boundary works
# *while the daemon runs*. This one guards that killing the daemon leaves it enforcing.
scenario_pinned_survives_daemon_death() {
    echo "### scenario: fail-safe pinning (SIGKILL the daemon — the verdicts stand; teardown lifts them)"
    ws_new
    write_policy <<EOF
$(rule "$OWNER" "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads while the daemon is up"    read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper denied while the daemon is up" read_as "$SCRAPER" "$SECRET" || fail=1

    if [ ! -d "$PIN_DIR" ] || [ -z "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
        echo "  FAIL: nothing pinned under $PIN_DIR — the links were never pinned"; return 1
    fi
    echo "  OK: links pinned under $PIN_DIR ($(ls "$PIN_DIR"))"

    # SIGKILL, not SIGTERM: nothing runs on the way out, so this is the *crash* path.
    kill -9 "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; DPID=""
    if "$CORDON" status >/dev/null 2>&1; then
        echo "  FAIL: the daemon still answers — the kill did not take"; fail=1
    else
        echo "  OK: the daemon is gone (nothing answers the socket)"
    fi

    # No process holds the boundary, and it holds.
    expect_deny  "scraper STILL denied with NO daemon"  read_as "$SCRAPER" "$SECRET" || fail=1
    expect_allow "owner STILL allowed with NO daemon"   read_as "$OWNER"   "$SECRET" || fail=1

    # …and teardown is what lifts it. Without this step the two asserts above would also
    # pass if the reads were failing for some reason unrelated to the pins.
    local t1="$TMP/teardown1.log" t2="$TMP/teardown2.log"
    if "$CORDOND" --log-format json --teardown >"$t1" 2>&1; then
        echo "  OK: --teardown removed the pins with no daemon running"
    else
        echo "  FAIL: --teardown errored"; sed 's/^/  daemon| /' "$t1"; fail=1
    fi

    # Teardown reports the *posture* (see `Swept`): guards against both runs printing
    # "enforcement torn down — the boundary is OFF", a false statement on an
    # already-unenforced box. Both halves are asserted: checking only the second would pass
    # if BOTH said "already off".
    "$CORDOND" --log-format json --teardown >"$t2" 2>&1
    if [ -n "$(records "$t1" '.event == "teardown" and .generations > 0')" ]; then
        echo "  OK: the teardown that removed pins reports a disarm"
    else
        echo "  FAIL: the real teardown did not report a disarm:"; sed 's/^/  daemon| /' "$t1"; fail=1
    fi
    if [ -n "$(records "$t2" '.event == "teardown" and .generations == 0')" ]; then
        echo "  OK: a second teardown says the box was already off, not that it disarmed one"
    else
        echo "  FAIL: a no-op teardown misreports the posture:"; sed 's/^/  daemon| /' "$t2"; fail=1
    fi

    expect_allow_eventually "scraper allowed once the pins are gone" read_as "$SCRAPER" "$SECRET" || fail=1

    return $fail
}

# --- upgrade under a running daemon -----------------------------------------
# Guards the upgrade case: a package upgrade renames a new binary over the running
# daemon's, after which /proc/<pid>/exe reads "… (deleted)"; the next `policy apply` must
# still re-seed (the identity is resolved once, see `daemon_exe`).
scenario_apply_survives_binary_upgrade() {
    echo "### scenario: upgrade under a running daemon (binary replaced; policy apply still works)"
    ws_new
    write_policy <<EOF
$(rule "$OWNER" "$VAULT" read allow)
EOF
    # Run from a copy we are allowed to replace, the way an upgrade replaces /usr/bin/cordond.
    cp "$CORDOND" "$TMP/cordond"
    local saved="$CORDOND"
    CORDOND="$TMP/cordond"
    daemon_start
    CORDOND="$saved"          # restored before any early return; teardown can use either
    started || return 1
    local fail=0
    expect_allow "owner reads before the upgrade"    read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper denied before the upgrade" read_as "$SCRAPER" "$SECRET" || fail=1

    # The upgrade itself: a NEW inode renamed over the running daemon's binary.
    cp "$CORDOND" "$TMP/cordond.new"
    mv "$TMP/cordond.new" "$TMP/cordond"
    # Assert we actually reproduced the condition — without this the scenario would pass
    # even if the replacement silently did nothing, proving exactly nothing.
    if readlink "/proc/$DPID/exe" 2>/dev/null | grep -q '(deleted)'; then
        echo "  OK: the daemon's binary was replaced under it (/proc/$DPID/exe is now deleted)"
    else
        echo "  FAIL: could not reproduce the upgrade — /proc/$DPID/exe = $(readlink "/proc/$DPID/exe" 2>&1)"
        return 1
    fi

    # THE assertion: the daemon can still re-seed.
    cat > "$TMP/new.toml" <<EOF
$(rule "$SCRAPER" "$VAULT" read allow)
EOF
    if "$CORDON" policy apply "$TMP/new.toml" >/dev/null 2>&1; then
        echo "  OK: policy apply succeeded after the binary was replaced"
    else
        echo "  FAIL: policy apply errored after the upgrade"
        "$CORDON" policy apply "$TMP/new.toml" 2>&1 | sed 's/^/  cli| /'
        fail=1
    fi
    # …and the re-seed really landed, rather than the CLI just returning OK: the rules are
    # now the *new* ones, so the two subjects have swapped verdicts.
    expect_allow "scraper allowed by the newly applied policy" read_as "$SCRAPER" "$SECRET" || fail=1
    expect_deny  "owner denied — the old rule is gone"         read_as "$OWNER"   "$SECRET" || fail=1

    return $fail
}

# --- singleton: one daemon per socket ---------------------------------------
# Guards against a second daemon unlinking the first one's *live* socket and binding its
# own (see `acquire_singleton`).
scenario_singleton_refuses_a_second_daemon() {
    echo "### scenario: singleton (a second cordond refuses to start; the first is untouched)"
    ws_new
    write_policy <<EOF
$(rule "$OWNER" "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0 out rc2

    out="$("$CORDOND" --log-format json 2>&1)"
    rc2=$?
    if [ "$rc2" -eq 0 ]; then
        echo "  FAIL: a second cordond started successfully"; fail=1
    else
        echo "  OK: the second cordond refused to start (exit $rc2)"
    fi
    if printf '%s\n' "$out" | jq -eR 'fromjson? | select(.event == "already_running")' >/dev/null; then
        echo "  OK: it named the conflict instead of failing obscurely"
    else
        echo "  FAIL: no 'already running' diagnostic:"; printf '%s\n' "$out" | sed 's/^/  second| /'; fail=1
    fi

    # The first daemon kept its socket, and the boundary is intact.
    expect_allow "the first daemon still answers status"   "$CORDON" status || fail=1
    expect_deny  "the boundary is intact (scraper denied)" read_as "$SCRAPER" "$SECRET" || fail=1

    return $fail
}

# --- run all scenarios; fail the suite if any fails -------------------------
rc=0
for scenario in \
    enforce \
    selftest_negative \
    per_action \
    rename_over \
    rename_exchange \
    mkdir \
    execute \
    subject_group \
    object_group \
    deny_wins \
    subject_specificity \
    copydown \
    audit_then_deny \
    silence \
    apply \
    coalesce \
    leaf_path \
    user_tier \
    user_home_tilde \
    policy_edit_leak \
    policy_edit_chown \
    bless_scope \
    bless_boundary \
    bless_inherit_gc \
    bless_revoke \
    bless_journal \
    bless_unprivileged \
    socket_authz \
    bless_rejects_fake_daemon \
    bless_placement \
    bless_reconcile_ownership \
    pinned_survives_daemon_death \
    apply_survives_binary_upgrade \
    singleton_refuses_a_second_daemon; do
    run_scenario "$scenario" || rc=1
done
echo
if [ "$rc" -eq 0 ]; then
    echo "PASS: bpf-lsm rule-model e2e — all scenarios green (in-kernel)"
else
    echo "FAILED: one or more bpf-lsm scenarios failed" >&2
fi
exit "$rc"
