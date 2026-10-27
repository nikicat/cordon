#!/usr/bin/env bash
# End-to-end tests of the bpf-lsm boundary (DESIGN §15), run in one VM boot. Each scenario
# starts a real cordond on its own policy and checks the in-kernel verdicts and the
# daemon's JSON log. The comment above each scenario function says what it proves.
#
# The bless scenarios run the daemon in a nested cgroup. This reproduces the `Delegate=yes`
# service cgroup of production without needing systemd. It also makes the carrier root a
# non-root cgroup, which is the stricter case, because the cgroup2 root is exempt from the
# "no internal processes" rule.
#
# Needs root in the guest and the kernel that the README's Requirements describe. Run it
# under virtme-ng through packaging/test/run-bpf-lsm-vm.sh.
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
# bpffs holds the pinned LSM links. It is a hard precondition rather than a per-scenario
# SKIP, because the daemon always pins, so no scenario can run without bpffs. virtme-ng
# provides a bare /sys, so the suite mounts it.
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

# --- shared per-scenario state and helpers ---------------------------------
TMP="" VAULT="" SECRET="" OWNER="" OWNER_B="" SCRAPER="" SOCK="" LOG="" DPID=""
# The cgroup that the daemon starts in instead of the cgroup2 root. Only the bless
# scenarios set it.
DCGROUP=""
# The throwaway user that the policy-edit symlink scenarios drop the editor to, and the
# directory where cordon mints its per-edit temp dir.
TUID=4243 TUSER="cordonedit$$" EDITDIR="${TMPDIR:-/tmp}"
# The root-only sentinel file that `edit_env_setup` creates.
SENTINEL=""
# The directory the LSM links are pinned under. It differs from the default
# /sys/fs/bpf/cordon, so a suite run on a real machine cannot tear down that machine's live
# boundary.
PIN_DIR="/sys/fs/bpf/cordon-smoke"

# Copies `bash` to $1 in the workspace and echoes the copy's path. The copy has its own
# inode, so it acts as a distinct subject that can both read (`exec 3<f`) and write
# (`exec 3>f`).
mk_exe() { local p="$TMP/$1"; cp "$(command -v bash)" "$p"; echo "$p"; }

# Opens a file for read or for write as the subject exe. Fails when the open is denied.
# The exe copy itself is the process image, so the kernel sees its inode as the caller.
read_as()  { "$1" -c 'exec 3<"$1"' bash "$2" 2>/dev/null; }   # $1 exe  $2 file
write_as() { "$1" -c 'exec 3>"$1"' bash "$2" 2>/dev/null; }   # opens O_WRONLY|O_CREAT|O_TRUNC
# Opens a file for read as the exe, running as the given uid instead of root. Fails when
# the open is denied. setpriv drops root before the exec, so the kernel attributes the
# open to that uid.
read_as_uid() { setpriv --reuid "$1" --regid "$1" --clear-groups "$2" -c 'exec 3<"$1"' bash "$3" 2>/dev/null; } # $1 uid $2 exe $3 file

# Commands queued by `on_cleanup` for the current scenario.
CLEANUPS=()
# Queues CMD [ARGS] to run after the current scenario's daemon stops, however the scenario
# returns. The latest queued command runs first. The arguments are captured at the call,
# so a scenario may pass its locals.
on_cleanup() { CLEANUPS+=("$(printf '%q ' "$@")"); }

# Runs scenario_$1 and returns its status. However the scenario returns, its daemon is
# stopped, its workspace is freed and its queued cleanups run.
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

# Creates a fresh workspace with a vault that holds a secret and a sibling file, and three
# distinct exes.
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

# Writes a config that names the policy (a file or a conf.d dir) and the socket (default
# $SOCK), and points the daemon and CLI at it. Every scenario writes its config here, so
# the config always carries the off-default $PIN_DIR. `daemon_stop` runs
# `cordond --teardown`, and without that key it would tear down the real /sys/fs/bpf/cordon.
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

# Prints one `[[rule]]` table, for use in a policy heredoc as
# `$(rule WHO WHERE ACTION POLICY)`. A field with several space-separated values becomes a
# TOML array. That split is safe because the workspace paths come from mktemp and never
# contain a space.
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

# Writes the policy read from stdin and a config that names it. The scenario policies use
# absolute paths only, so `~` never needs resolving.
write_policy() { # rules on stdin
    cat > "$TMP/policy.toml"
    write_config "$TMP/policy.toml"
}

# Starts the daemon with the given env assignments and waits until it binds its socket or
# exits. With $DCGROUP set, the daemon starts inside that cgroup (the nested shape from the
# header).
daemon_start() {
    if [ -n "$DCGROUP" ]; then
        mkdir -p "$DCGROUP"
        # The daemon resolves its carrier root from /proc/self/cgroup when it starts, so
        # the shell joins the cgroup before it execs the daemon.
        RUST_LOG="${RUST_LOG:-info}" env "$@" \
            sh -c 'echo $$ > "$1/cgroup.procs" && shift && exec "$@"' _ "$DCGROUP" "$CORDOND" --log-format json >"$LOG" 2>&1 &
    else
        RUST_LOG="${RUST_LOG:-info}" env "$@" "$CORDOND" --log-format json >"$LOG" 2>&1 &
    fi
    DPID=$!
    wait_until 50 socket_or_exit
}
# Checks whether the daemon has bound its socket or has already exited.
socket_or_exit() { [ -S "$SOCK" ] || gone "$DPID"; }

daemon_stop() {
    [ -n "$DPID" ] && { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
    DPID=""
    # Stopping the daemon does not stop enforcement. Without this teardown, each scenario
    # would leave a live boundary whose PROTECTED entries name inodes that the `rm -rf`
    # below frees, and inode reuse would contaminate the next scenario. The teardown runs
    # before the config it reads is deleted. The singleton lock is free by now, because
    # the daemon has been reaped.
    [ -n "$TMP" ] && [ -f "$TMP/config.toml" ] && "$CORDOND" --teardown >/dev/null 2>&1
    if [ -n "$DCGROUP" ]; then
        # Best effort. The daemon's own cgroup is empty once the daemon exits. A carrier
        # that still has members stays for the next daemon's reconcile to adopt.
        rmdir "$DCGROUP"/cordon-bless-* 2>/dev/null
        rmdir "$DCGROUP" 2>/dev/null
        DCGROUP=""
    fi
    # The removal is retried, because teardown is asynchronous (see `PinDir::teardown`).
    # Until the teardown lands, the workspace is still protected and the unlink is
    # refused. That is itself a small proof that the pins were doing their job.
    if [ -n "$TMP" ]; then
        wait_until 50 rm -rf "$TMP" 2>/dev/null
    fi
}

# Waits for the daemon's `ready` event, which it logs once the program is attached and
# self-tested and the policy is seeded. Fails on a fatal backend error, a daemon exit or a
# timeout.
wait_active() { wait_until 80 ready_or_failed; log_has '.event == "ready"'; }
ready_or_failed() { log_has '.event == "ready"' || log_has '.event == "backend_failed"' || gone "$DPID"; }

# Runs CMD [ARGS] every 0.1s until it succeeds, at most TRIES times. Fails if it never does.
wait_until() {
    local tries="$1" i; shift
    for ((i = 0; i < tries; i++)); do "$@" && return 0; sleep 0.1; done
    return 1
}
# Checks whether process $1 is gone.
gone() { ! kill -0 "$1" 2>/dev/null; }

# Prints the records of the `--log-format json` log $1 that satisfy the jq condition $2.
# The log holds one object per line, with fields as top-level keys. Extra arguments, such
# as `--arg v "$X"`, go to jq. Lines that are not JSON, such as a panic message, are
# skipped.
records() { local file="$1" cond="$2"; shift 2; jq -cR "$@" "fromjson? | select($cond)" "$file"; }
# Checks whether the daemon log has a record that matches the jq condition $1. Extra
# arguments go to jq.
log_has() { [ -n "$(records "$LOG" "$@")" ]; }
# Prints how many daemon log records match the jq condition $1.
log_count() { records "$LOG" "$@" | grep -c .; }

# Waits for a daemon log record that matches the jq condition $1. It polls, because the
# ring drain writes records such as a deny asynchronously.
wait_log() { wait_until 30 log_has "$@"; }

# Reads the secret as the scraper and checks whether the daemon log has a record that
# matches the jq condition $1. A record that the suppressor holds back appears only after a
# repeat of the access past its window, so callers retry this.
read_then_log_has() { read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1; log_has "$1"; }
# Waits for a daemon log record that matches the jq condition $2, with extra arguments
# passed to jq, and reports the check as $1. Fails and dumps the log when none arrives.
expect_log() {
    local label="$1"; shift
    if wait_log "$@"; then echo "  OK: $label"; return 0; fi
    echo "  FAIL: $label — no such log record"; sed 's/^/  daemon| /' "$LOG"; return 1
}
expect_allow() { local l="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  OK: $l (allowed)"; else echo "  FAIL: $l — denied, expected ALLOW"; return 1; fi; }
# Like expect_allow, but retries the command for up to 5s. The hooks stay attached for a
# moment after `--teardown` returns (see `PinDir::teardown`).
expect_allow_eventually() {
    local l="$1"; shift
    if wait_until 50 "$@" >/dev/null 2>&1; then echo "  OK: $l (allowed)"; return 0; fi
    echo "  FAIL: $l — still denied long after teardown"; return 1
}
expect_deny()  { local l="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL: $l — allowed, expected DENY"; return 1; else echo "  OK: $l (denied)"; fi; }

# Waits until the daemon is active. Fails and dumps the log when it never becomes active.
started() {
    if ! wait_active; then echo "  FAIL: daemon did not become active"; sed 's/^/  daemon| /' "$LOG"; return 1; fi
}

# Checks that a rule lets the owner exe read its secret, and that a scraper with no
# matching rule is default-denied with EPERM. The denial must reach the ring buffer with the
# object's inode and the requested action.
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
    # Root runs the readers, so the caller resolves through passwd to user=root. That
    # proves the uid the kernel captured reaches the journal. Root is not a regular user, so
    # the paths stay absolute. The daemon's unit tests cover the `~` collapse.
    expect_log "denial reported on the ring buffer (user + object + opened path + action, default-deny)" '.message == "deny" and (.pid | type == "number") and .user == "root" and has("exe")
            and (.object | endswith("vault")) and (.path | endswith("/vault/secret"))
            and .action == "read" and .policy == "default-deny"' || fail=1
    return $fail
}

# Checks that the daemon aborts when it starts with deliberately wrong field offsets. With
# them the program attaches but mediates nothing, and the self-test must turn that silent
# no-op into a loud abort rather than a running boundary.
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

# Checks that a read-only allow does not cover a write. The owner may read the object, but
# its write to the same object is default-denied. This proves that f_mode and f_flags tell
# read from write.
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

# Checks that a rule on the subject group `@tools = [a, b]` allows both members and denies
# a third exe.
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

# Checks that one rule over the object group `@creds = [v1, v2]` governs both dirs.
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

# Checks that `deny scraper read` wins over `allow * read` on one object. The scraper loses
# the tie (fail-safe), and everyone else still reads.
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

# Checks DESIGN §15.6 step 2, under which a concrete subject outranks a `who="*"`
# catch-all on the same object. Both rules sit on $VAULT. Without subject specificity,
# deny-beats-allow would sort the wildcard deny first and block the owner too. The check
# reads outcomes, not log timing.
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

# Checks copy-down with `allow {a,b} read DIR` and `deny b read DIR/secret`. Subject a reads
# the secret through the inherited allow. Subject b is denied that file but still reads a
# sibling under DIR, so inheritance survives the carve-out. A "deepest bucket only" model
# cannot express this per-subject exception.
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

# Checks that observing or enforcing is a per-object choice, made by editing that object's
# rule. A `who="*" … audit` catch-all logs every read but blocks nothing. Flipping the same
# rule to `deny` with a runtime `policy apply` makes the identical access block and log.
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

    # Enforce: flip that one rule from audit to deny and apply it. The same object now
    # blocks.
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
    # Repeat the read until one lands past the in-kernel suppressor's 1s window and logs.
    local deny_read='.message == "deny" and .user == "root" and has("exe") and has("object") and .action == "read"'
    wait_until 40 read_then_log_has "$deny_read"
    expect_log "the same access now logs as deny (enforced)" "$deny_read" || fail=1
    return $fail
}

# Checks that a `silence` policy denies with EPERM but, unlike a `deny`, writes no log
# record.
scenario_silence() {
    echo "### scenario: silence (deny enforced, but NO log record)"
    ws_new
    write_policy <<EOF
$(rule "$SCRAPER" "$VAULT" read silence)
EOF
    daemon_start; started || return 1
    local fail=0
    expect_deny "scraper denied under silence" read_as "$SCRAPER" "$SECRET" || fail=1
    # Give the ring drain time to deliver a record, if there were one.
    sleep 0.5
    if log_has '.message == "deny"'; then
        echo "  FAIL: silence produced a log record (should be silent)"; sed 's/^/  daemon| /' "$LOG"; fail=1
    else
        echo "  OK: no log record for a silenced denial"
    fi
    return $fail
}

# Checks that `cordon policy apply` re-seeds the live maps at runtime (`Maps::seed`), so a
# previously unprotected dir becomes protected with no restart. Also checks that
# `policy show` reflects the applied policy.
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
    # The re-seed took effect, so the owner reads and the scraper is now denied.
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

# Checks that the in-kernel suppressor (`throttle`) collapses a tight loop of identical
# denied opens into a handful of ring records. The folded `suppressed` count must reach a
# record, so the volume stays visible.
scenario_coalesce() {
    echo "### scenario: coalescing (a repeat-open burst collapses to a few records + a count)"
    ws_new
    write_policy <<EOF
$(rule "$SCRAPER" "$VAULT" read deny)
EOF
    daemon_start; started || return 1
    local fail=0 n=40
    # Every read shares one exe, opened file and action, which make one suppressor key. So
    # the ring sees a handful of records, not `n`.
    for _ in $(seq 1 "$n"); do read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1; done
    # Wait out the window. One more open after it flushes the held-back count.
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
    # At least one record must carry a nonzero suppressed count.
    expect_log "a suppressed>0 count was carried into a record" '.message == "deny" and (.suppressed | tonumber) > 0' || fail=1
    return $fail
}

# Checks that auditing one exe over a dir yields a separate record for each distinct file
# it opens, with the actual opened path (DESIGN §15.10 flow B). That includes a nested file
# at depth 2. Siblings do not coalesce away, because the suppressor keys on the opened file
# (see `SuppressKey`).
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
    # Each distinct leaf gets its own audit record with the actual opened path, not just
    # the matched root ($VAULT). This proves the d_name walk and the leaf-keyed suppressor.
    expect_log "leaf path reported ($VAULT/secret)" '.message == "audit" and .path == $p and .action == "read"' --arg p "$VAULT/secret" || fail=1
    expect_log "sibling surfaces separately ($VAULT/other)" '.message == "audit" and .path == $p and .action == "read"' --arg p "$VAULT/other" || fail=1
    expect_log "depth-2 nested path reconstructed ($VAULT/sub/nested)" '.message == "audit" and .path == $p and .action == "read"' --arg p "$VAULT/sub/nested" || fail=1
    return $fail
}

# Checks that a rule from an `[[include]]`d user-tier file enforces in-kernel exactly like
# a system rule. This proves that the tier assembly (load_policy, include expansion,
# tier-aware compile, merged maps) reaches the kernel. The include is scoped to root's home,
# /root, which passwd always has, so the user vault sits under /root to pass the home-scope
# check. The system vault is under $TMP, because the system tier has no scope limit.
# Subjects are unscoped in either tier.
scenario_user_tier() {
    echo "### scenario: system + user tiers (a system rule and an [[include]]d user rule both enforce)"
    ws_new   # exes (OWNER/OWNER_B/SCRAPER), TMP, SOCK, LOG
    local sysvault="$TMP/sysvault"; mkdir -p "$sysvault"; echo SYS > "$sysvault/secret"
    local usrvault="/root/cordon-tier-$$"; mkdir -p "$usrvault"; echo USR > "$usrvault/secret"
    on_cleanup rm -rf "$usrvault"
    mkdir -p "$TMP/conf.d" "$TMP/users"
    # The system fragment holds a system-tier allow and the include of root's user-tier
    # file.
    cat > "$TMP/conf.d/00-system.toml" <<EOF
$(rule "$OWNER" "$sysvault" read allow)

[[include]]
user = "root"
path = "$TMP/users/root.toml"
EOF
    # In the user-tier file, objects must be under ~root. Only OWNER_B may read the user
    # vault.
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

# Checks that the journal renders object= and path= with a regular user's home collapsed
# to ~, so that a deny or audit line drops straight into the user's policy (DESIGN §15.10).
# The collapse depends on the caller rather than the tier, so a plain system policy is
# enough. Skips when the guest cannot drop the uid or edit /etc/passwd.
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
    # Register a throwaway regular user (uid in the [1000,60000] window) so the daemon's
    # passwd lookup resolves its uid to a name and a home. The daemon's mtime-keyed passwd
    # cache picks up the appended line.
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
    # The audit line names the user and collapses ~ in both object= (the rule's dir) and
    # path= (the opened file), giving object=~/.creds and path=~/.creds/key.
    expect_log "audit line shows user=$tuser with ~-collapsed object and path" '.message == "audit" and .user == $u and has("exe") and .object == "~/.creds"
            and .path == "~/.creds/key" and .action == "read"' --arg u "$tuser" || fail=1
    return $fail
}

# --- policy-edit symlink scenarios: shared setup -----------------------------
# The sudoedit-style boundary (DESIGN §15.8) runs the editor as the invoking user, while the
# root parent seeds, reads and writes the root-owned copy. Both scenarios mount a same-uid
# symlink attack on the user-owned temp copy, which is the threat DESIGN §2 puts in scope.
# They need no daemon, because the attack is resolved before the apply.

# Creates a fresh workspace, the passwd entry for $TUSER, the root-only $SENTINEL and a
# config. Echoes a SKIP and fails when the guest cannot support that.
edit_env_setup() {
    ws_new
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; return 1; }
    local thome="$TMP/ehome"; mkdir -p "$thome"; chown "$TUID:$TUID" "$thome"; chmod 755 "$TMP"
    printf '%s:x:%s:%s:Cordon Edit:%s:/bin/sh\n' "$TUSER" "$TUID" "$TUID" "$thome" >> /etc/passwd 2>/dev/null \
        || { echo "  SKIP: /etc/passwd not writable"; return 1; }
    on_cleanup drop_user "$TUSER"
    SENTINEL="$TMP/root-secret"; echo "SENTINEL-XYZZY" > "$SENTINEL"; chown 0:0 "$SENTINEL"; chmod 600 "$SENTINEL"
    write_config "$TMP/policy.toml" "$TMP/dead.sock"
}

# Runs `cordon policy edit` as the synthetic user with EDITOR=$1 and echoes its combined
# output. stdin is /dev/null, so a re-edit prompt gets EOF and quits instead of blocking the
# suite. That prompt appears only if the read-back regresses and accepts a bad buffer.
run_policy_edit() { SUDO_UID="$TUID" SUDO_GID="$TUID" EDITOR="$1" "$CORDON" policy edit "$TMP/policy.toml" </dev/null 2>&1; }

# Checks that the privileged read-back does not follow a symlink (O_NOFOLLOW). The editor,
# running as the invoking user, swaps the temp copy for a symlink to a root-only file. That
# file's contents must surface in neither the saved policy nor the printed diagnostics.
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

# Checks that the fd-based hand-off (`fchown`) never chowns the root sentinel to the
# invoker across many runs. Meanwhile a racing same-uid loop keeps swapping any cordon temp
# copy for a symlink to the sentinel, which a path-based `chown` would follow.
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
# The suite runs as root, so most bless scenarios invoke the CLI directly as peer uid 0,
# and the blessed child stays root. `scenario_bless_unprivileged` runs the CLI as an
# ordinary uid. All of them run the daemon in the nested cgroup $DCGROUP (see the header).

# The daemon's cgroup in the bless scenarios. It stands in for the systemd service cgroup.
BLESS_DCGROUP="/sys/fs/cgroup/cordon-smoke.scope"

# Prepares a bless scenario. Mounts cgroup2 for the carrier cgroups if the guest has not
# (virtme usually has), sets $DCGROUP so the daemon starts in a nested cgroup as in
# production, and exports $CORDON_SUDO until the scenario ends. Echoes a SKIP and fails
# when cgroup2 cannot be made available.
bless_env_ready() {
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
    # faithful stand-in, and the helper really does connect as uid 0. `fake_sudo_start`
    # replaces it with a wrapper that elevates from an unprivileged CLI, as a real sudo
    # does.
    export CORDON_SUDO="env"
    on_cleanup unset CORDON_SUDO
    return 0
}

# Sets $CORDON_SUDO to a stand-in for sudo that works when the CLI itself is unprivileged,
# and queues its cleanup. The helper genuinely runs as root, which is the property under
# test, with no real sudo and no setuid binary (the guest's tmpfs may be nosuid). Fails
# when the FIFO cannot be created.
fake_sudo_start() {
    local fifo="$TMP/sudo.fifo"
    mkfifo "$fifo" && chmod 666 "$fifo" || return 1
    # A root loop reads command lines off the FIFO and runs them, and the wrapper only
    # forwards its argv into the FIFO. Hold a writer open so the reader never sees EOF
    # between wrapper invocations.
    exec 9<>"$fifo"
    ( while IFS= read -r line; do [ -n "$line" ] && eval "$line" & done <"$fifo" ) &
    FAKE_SUDO_PID=$!
    # `%q` quotes each argument, so the root loop's `eval` gets back the same argv.
    printf '#!/bin/bash\n{ printf "%%q " "$@"; echo; } > %s\n' "$fifo" > "$TMP/fakesudo"
    chmod 755 "$TMP/fakesudo"
    export CORDON_SUDO="$TMP/fakesudo"
    on_cleanup fake_sudo_stop
}

# Copies the CLI to where an unprivileged uid can execute it, and echoes the copy's path.
# $CORDON lives in the developer's source tree, which that uid cannot traverse. The copy is
# also what `current_exe()` resolves to, so the helper that `cordon bless` re-spawns is this
# same binary.
unpriv_cordon() {
    chmod 755 "$TMP"
    cp "$CORDON" "$TMP/cordon" && chmod 755 "$TMP/cordon" && echo "$TMP/cordon"
}

fake_sudo_stop() {
    [ -n "${FAKE_SUDO_PID:-}" ] && kill "$FAKE_SUDO_PID" 2>/dev/null
    FAKE_SUDO_PID=""
    exec 9>&-
}

# Prints the daemon's own cgroup dir, which is the carrier root that carriers are created
# under.
bless_root() {
    local rel; rel="$(sed -n 's/^0:://p' "/proc/$DPID/cgroup")"
    echo "/sys/fs/cgroup${rel%/}"
}
# Prints the live carrier dirs (cordon-bless-<id>.<class>), if any.
bless_dirs() { ls -d "$(bless_root)"/cordon-bless-* 2>/dev/null; }
# Prints the value of every `"$1"` field, at any depth, in the `cordon --json` output on
# stdin. Strings print unquoted, one per line.
json_field() { jq -r --arg k "$1" '.. | objects | select(has($k)) | .[$k] | scalars'; }
# Prints the live blessing ids, one per line.
bless_ids() { "$CORDON" --json bless list 2>/dev/null | json_field id; }
# Prints the first live blessing's id, or nothing when there is none.
bless_first_id() { bless_ids | head -n1; }

# Prints the dir of the first carrier that has members. Fails when no carrier has any.
bless_populated_dir() {
    local d
    for d in $(bless_dirs); do
        # `cgroup.procs` is a kernfs file whose st_size is 0 even when populated, so
        # `[ -s ]` would always be false. Only reading it tells the truth.
        [ -n "$(cat "$d/cgroup.procs" 2>/dev/null)" ] && { echo "$d"; return 0; }
    done
    return 1
}
# Waits until some carrier has members, which means the CLI's pre_exec join landed, and
# prints that carrier's dir.
bless_wait_populated() { wait_until 50 bless_populated_dir; }

# Opens a file for read as the subject exe inside a fresh blessing of the class. Fails when
# the open is denied, because the CLI propagates the exe's exit code.
bless_read_as() { "$CORDON" bless --class "$1" -- "$2" -c 'exec 3<"$1"' bash "$3" 2>/dev/null; } # $1 class $2 exe $3 file

# Waits until the daemon has reaped every blessing, so that `bless list` is empty and no
# carrier dir is left. Fails on timeout.
bless_drained() { wait_until 80 bless_none_left; }
bless_none_left() { [ -z "$(bless_dirs)" ] && [ -z "$(bless_ids)" ]; }

# Checks the scope of a grant under `deny * read V`, `allow @blessed-ro read V` and a second
# protected V2. A blessed read of V is allowed, because a concrete blessing outranks the
# catch-all. The same blessed exe is denied on V2, because the object column scopes the
# grant, and the unblessed exe stays denied on V. This is also the end-to-end proof that the
# st_ino of the carrier made by mkdir equals what bpf_get_current_cgroup_id() sees.
scenario_bless_scope() {
    echo "### scenario: bless scope (blessed read allowed on V, denied on V2, unblessed denied)"
    ws_new
    bless_env_ready || return 0
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
    # Guard the harness itself. If the daemon ever fell back to the cgroup2 root, every
    # bless scenario would silently stop covering the production (Delegate=yes) shape and
    # still pass. Assert that the carrier root is the nested cgroup the daemon started in.
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

# Checks that a non-root uid cannot write into the root-owned carrier's cgroup.procs
# (EACCES), because carrier membership is the boundary. Also checks that `bless list` shows
# the live entry meanwhile.
scenario_bless_boundary() {
    echo "### scenario: bless boundary (non-root write to the carrier cgroup.procs fails)"
    ws_new
    bless_env_ready || return 0
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
    # The membership boundary. A non-root uid must not be able to write itself into the
    # root-owned carrier, or any process could bless itself.
    expect_deny "non-root write to the carrier cgroup.procs" \
        setpriv --reuid 4242 --regid 4242 --clear-groups sh -c "echo \$\$ > '$dir/cgroup.procs'" || fail=1
    # Clean up by revoking, letting the CLI reap its child and letting GC drain the carrier.
    "$CORDON" bless revoke "$(bless_first_id)" >/dev/null 2>&1
    wait "$clipid" 2>/dev/null
    bless_drained || { echo "  FAIL: blessing did not drain after revoke"; fail=1; }
    return $fail
}

# Checks that a blessed bash's grandchild reads the secret, because cgroup membership is
# inherited. After the exit, the daemon's GC must reap everything, so `bless list` drains
# and the carrier dir is gone.
scenario_bless_inherit_gc() {
    echo "### scenario: bless inherit + GC (grandchild reads; carrier fully reaped after exit)"
    ws_new
    bless_env_ready || return 0
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

$(rule '*' "$VAULT" read deny)

$(rule @blessed-ro "$VAULT" read allow)
EOF
    daemon_start; started || return 1
    local fail=0
    # The blessed child spawns a grandchild to do the read. The whole tree inherits cgroup
    # membership, and with it the blessing. The trailing sleep outlives a GC tick, so the
    # daemon sees the carrier populated. Without it, a fast exit would defer the reap to
    # the mint grace (`MINT_GRACE`) and stall this scenario.
    cat > "$TMP/blessed-read.sh" <<EOF
#!/bin/bash
bash -c 'exec 3<"$SECRET"'
rc=\$?
sleep 1.2
exit \$rc
EOF
    chmod 755 "$TMP/blessed-read.sh"
    expect_allow "blessed grandchild reads the secret (inherited)" "$CORDON" bless --class ro -- "$TMP/blessed-read.sh" || fail=1
    # After the exit, the daemon must reap the BLESSED entry, the table row and the cgroup
    # dir. An empty list and a missing dir prove all three, while "re-open denied" alone
    # would hold regardless.
    if bless_drained; then
        echo "  OK: blessing fully reaped after exit (list empty, carrier dir gone)"
    else
        echo "  FAIL: blessing not reaped (list or carrier dir lingers)"
        "$CORDON" bless list 2>&1 | sed 's/^/  cli| /'; bless_dirs | sed 's/^/  dir| /'
        sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    return $fail
}

# Checks that `bless revoke <id>` kills the carrier tree promptly through cgroup.kill. The
# blessed sleep dies, and the list and the carrier dirs drain.
scenario_bless_revoke() {
    echo "### scenario: bless revoke (the blessed tree dies promptly; list + dirs drain)"
    ws_new
    bless_env_ready || return 0
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
    # cgroup.kill kills the tree, so the CLI, which waits on the sleep, exits promptly.
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

# Checks that bless is loud. A blessed read under an `audit @blessed-ro` rule is journaled
# with a trailing `blessing=ro`, which names the class.
scenario_bless_journal() {
    echo "### scenario: bless journal (a blessed read logs blessing=ro — bless is loud)"
    ws_new
    bless_env_ready || return 0
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

# Runs `cordon bless` as an ordinary uid, with `$CORDON_SUDO` set to a FIFO wrapper that
# reaches root without setuid or a real sudo (the design is in crates/cli/src/bless.rs). The
# other bless scenarios run the CLI as root, so only this one guards that:
#   * the blessed child runs as the invoking uid;
#   * an environment variable set before the call survives into it;
#   * the blessed read still works, which proves that an unprivileged process wrote its pid
#     into a root-owned cgroup.procs. That is the fd-delegation property.
scenario_bless_unprivileged() {
    echo "### scenario: unprivileged bless (runs as you, env survives, still blessed)"
    ws_new
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; return 0; }
    bless_env_ready || return 0
    local buid=4244 bgid=4244
    local cordon; cordon="$(unpriv_cordon)"
    local out="$TMP/blessed.id"; : > "$out"; chmod 666 "$out"
    # The script records its uid and the canary, and its blessed read exits nonzero when
    # denied.
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
    # The CLI itself runs as uid 4244. Only the helper it spawns reaches root.
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
    # The security property the seam rests on. A faked elevation that never reaches root
    # produces a non-root helper, and the daemon refuses that helper's approval.
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

# Checks that an unprivileged uid can read (status, policy show, bless list) but cannot
# apply. The socket is 0666 and its mode carries no security weight, because the daemon's
# `authorize()` decides.
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
    # Runs `cordon` as an ordinary user, with the workspace config it can read.
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
    # The write must fail in the daemon with a message that names root. Failing to connect
    # or succeeding would both be wrong. This guards against "whoever can reach the socket
    # can apply".
    local out; out="$(as_uid policy apply 2>&1)"
    if [ -n "$out" ] && ! as_uid policy apply >/dev/null 2>&1 && printf '%s' "$out" | grep -q "requires root"; then
        echo "  OK: unprivileged policy apply refused by the daemon (peer uid gate)"
    else
        echo "  FAIL: unprivileged policy apply was not refused with a root message: ${out:-<no output>}"; fail=1
    fi
    return $fail
}

# Checks that the CLI refuses a daemon end that is not root, here a socket squatted by a
# genuinely unprivileged process. The refusal must come before the CLI spawns the elevation
# helper, so the human is never even prompted. The confused-deputy reasoning is on
# `require_root_daemon` in crates/cli/src/bless.rs.
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

    # The squatter is an unprivileged process listening where the client will look. It
    # gets its own directory because $TMP is root-owned. A real squatter binds inside
    # $XDG_RUNTIME_DIR or /tmp, which it can write.
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

    # An elevation wrapper that drops a marker file when it runs. It must never run, so the
    # absence of the marker is the assertion.
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
# Builds a fake subtree for user $1 in the shapes that a real desktop and a real tty
# produce, and sets the P_* globals that name each requester cgroup. `user-N.slice` stays
# root-owned, as systemd leaves it. `user@N.service` is chowned to the user because it is
# delegated, which is exactly why a carrier may not live there. Echoes a SKIP and fails
# when the subtree cannot be built.
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

# Blesses a child from inside the requester cgroup and leaves it alive. Echoes the child's
# carrier cgroup path, mount-relative as /proc/self/cgroup reports it. Fails when the child
# never starts.
#
# Callers run it in a command substitution, which is a subshell. So the pid to reap later
# travels through a file, because a variable would never reach the caller.
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

# Reaps the blessed tree that `bless_from` started and waits for the carrier to drain.
end_bless() { # $1 marker prefix
    local pid; pid="$(cat "$1.pid" 2>/dev/null)"
    [ -n "$pid" ] && { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; }
    bless_drained >/dev/null 2>&1
}

# Blesses from the requester cgroup and checks that the carrier's parent is exactly the
# expected one.
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

# Checks that each requester shape gets a carrier that logind can still attribute to the
# user. The reason is on `carrier_parent` in crates/daemon/src/backend/bpf_lsm/bless.rs.
#   a) DESKTOP. The terminal is under the delegated user@UID.service/app.slice, with no
#      session scope anywhere above it, so the carrier goes in the user slice.
#   b) TTY. The requester is in a session-N.scope, and that more precise scope wins.
#   c) NO USER SUBTREE. A requester under system.slice gets the daemon's cgroup.
#   d) USER-OWNED parent. It is refused, and the daemon's cgroup is used instead.
# All four are covered, because a tty-only test passes while the desktop case is broken.
# In (a) and (b) the assertion is the property logind consumes, not just a path. The
# carrier's cgroup must still contain `user-<uid>.slice`.
scenario_bless_placement() {
    echo "### scenario: the carrier lands where logind can still attribute the user"
    ws_new
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; return 0; }
    bless_env_ready || return 0
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

    # The desktop shape has no session scope anywhere above the requester. It is the common
    # case, and the carrier must still land in the user slice.
    expect_placement "$P_DESKTOP" "$slice" \
        "desktop requester (delegated user@.service, no session scope) → the user slice" || fail=1
    # A tty login has a session scope, which is more precise, so it wins.
    expect_placement "$P_TTY" "$slice/session-99.scope" \
        "tty requester → its own session-99.scope" || fail=1
    # With nothing attributable to a user, the carrier goes in the daemon's cgroup.
    expect_placement "$DCGROUP" "${DCGROUP#/sys/fs/cgroup}" \
        "requester with no user subtree → the daemon's cgroup" || fail=1
    # A user-owned parent is refused however plausible its name.
    expect_placement "$P_ROGUE" "${DCGROUP#/sys/fs/cgroup}" \
        "user-owned session scope is refused → falls back to the daemon's cgroup" || fail=1
    return $fail
}

# Checks that on restart the daemon adopts only root-owned leftover carriers (see
# `adoptable`). Before the daemon starts, the scenario plants a root-owned and a user-owned
# populated carrier in a session scope, and a root-owned one in the user slice. Only the
# root-owned ones may come back in `bless list`.
scenario_bless_reconcile_ownership() {
    echo "### scenario: reconcile adopts a root-owned leftover, ignores a planted one"
    ws_new
    bless_env_ready || return 0
    local buid=4249
    local uslice="/sys/fs/cgroup/user.slice/user-$buid.slice"
    local scope="$uslice/session-97.scope"
    if ! mkdir -p "$scope" 2>/dev/null; then
        echo "  SKIP: cannot create a session scope under /sys/fs/cgroup"; return 0
    fi
    # Reconcile must scan both placements (see `carrier_roots`). The user slice is the
    # desktop one.
    local ours="$scope/cordon-bless-70.ro" theirs="$scope/cordon-bless-71.ro"
    local desktop="$uslice/cordon-bless-72.ro"
    mkdir -p "$ours" "$theirs" "$desktop"
    chown "$buid:$buid" "$theirs"          # as if planted by that user
    # Each carrier needs a member, or reconcile just removes it as an empty leftover.
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
# `rename(2)` onto an existing name destroys the destination inode, and `inode_rename` is
# the only hook the kernel fires for it. The classification by source and destination
# directory cannot see either case below. One looks like an internal shuffle, and the
# other looks like nothing protected moving at all. Only the destination dentry's own
# lookup sees them (see `decide_reparent`). The daemon self-test covers the mechanism on a
# deny-all probe. This scenario checks the two shapes that matter under a real policy, and
# the atomic-save case that must not break.
#
# Every rule uses `who = "*"`, because the question is which object answers for the
# destination, not which subject asked. So plain `mv` is the right actor and needs no exe
# copy.
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
    # A protected file whose parent is not protected, so both walks miss. This guards
    # against the `(None, None)` allow, under which `rm lonely` is refused while
    # `mv x lonely` destroys the file.
    echo evil > "$TMP/evil"
    expect_deny "rename over a file object whose parent is unprotected" \
        mv -f "$TMP/evil" "$lonely" || fail=1
    # Only the source tells the outcomes apart. The destination exists either way, since a
    # successful rename just replaces its inode with the attacker's.
    [ -f "$TMP/evil" ] && echo "  OK: the protected file's inode survived" \
        || { echo "  FAIL: the protected file was destroyed and replaced"; fail=1; }
    return $fail
}

# --- scenario: bprm_check_security -------------------------------------------
# Checks that `execute` is a capability of its own (see `decide_exec`). An explicit `deny`
# makes a file readable but not runnable.
scenario_execute() {
    echo "### scenario: execute is a capability distinct from read"
    ws_new
    # Copy `bash`, not `true`, because `command -v true` resolves to the shell builtin and
    # copies nothing. The copies are invoked below as `-c :`, so they exit immediately
    # instead of going interactive. `mk_exe` uses the same idiom.
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
# Checks that a subject that cannot remove a directory inside an object cannot add one
# either. The verdict comes from the parent (see `decide_create`), and the scenario checks
# both polarities in one policy.
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
    # A writable object must keep working, because this hook must not break legitimate
    # structure.
    expect_allow "mkdir inside an object that allows create/write" \
        mkdir "$VAULT/allowed" || fail=1
    # The gap this hook closes is a nested, more specific object that denies.
    expect_deny "mkdir inside a denying nested object" \
        mkdir "$VAULT/locked/evil" || fail=1
    [ -d "$VAULT/locked/evil" ] && { echo "  FAIL: the directory was created anyway"; fail=1; } \
        || echo "  OK: no directory appeared under the denied object"
    return $fail
}

# Swaps two names through `renameat2(RENAME_EXCHANGE)`. Exits 1 when the kernel refuses,
# and 3 when the syscall is unavailable.
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
# Checks that a protected inode cannot be swapped out of its object. An exchange
# re-parents both inodes and destroys neither, so the destroy check, which gives the
# destination object a `write` floor, does not cover it. The protected side leaving is an
# escape, but the hook can catch it only if it is asked about that side at all. When
# RENAME_EXCHANGE is set, `security_inode_rename` calls the hook a second time with the
# pair swapped, and this scenario verifies that second call rather than trusting it. On a
# writable object the first call sees only an allowed clobber, so with that call alone the
# secret would walk out of its object.
scenario_rename_exchange() {
    echo "### scenario: renameat2(RENAME_EXCHANGE) — a protected inode cannot be swapped out"
    ws_new
    command -v python3 >/dev/null || { echo "  SKIP: python3 unavailable (needed for renameat2)"; return 0; }
    local outside="$TMP/outside"; echo "OUTSIDE" > "$outside"
    # Preflight while nothing is enforcing, so that an unavailable syscall does not read as
    # a deny.
    echo A > "$TMP/xa"; echo B > "$TMP/xb"
    if ! exchange "$TMP/xa" "$TMP/xb"; then
        echo "  SKIP: renameat2(RENAME_EXCHANGE) unavailable on this kernel/libc"; return 0
    fi
    grep -q B "$TMP/xa" || { echo "  FAIL: preflight exchange did not swap the inodes"; return 1; }
    # Deliberately permissive. `write` must be allowed on the vault, or the destroy and
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
# Checks that killing the daemon leaves the boundary enforcing, and that teardown lifts it.
# Every other scenario proves the boundary works only while the daemon runs.
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

    # SIGKILL, not SIGTERM, so that nothing runs on the way out and this is the crash path.
    kill -9 "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; DPID=""
    if "$CORDON" status >/dev/null 2>&1; then
        echo "  FAIL: the daemon still answers — the kill did not take"; fail=1
    else
        echo "  OK: the daemon is gone (nothing answers the socket)"
    fi

    # No process holds the boundary, and it holds.
    expect_deny  "scraper STILL denied with NO daemon"  read_as "$SCRAPER" "$SECRET" || fail=1
    expect_allow "owner STILL allowed with NO daemon"   read_as "$OWNER"   "$SECRET" || fail=1

    # Teardown is what lifts the boundary. Without this step, the two asserts above would
    # also pass if the reads were failing for some reason unrelated to the pins.
    local t1="$TMP/teardown1.log" t2="$TMP/teardown2.log"
    if "$CORDOND" --log-format json --teardown >"$t1" 2>&1; then
        echo "  OK: --teardown removed the pins with no daemon running"
    else
        echo "  FAIL: --teardown errored"; sed 's/^/  daemon| /' "$t1"; fail=1
    fi

    # Teardown reports the posture (see `Swept`). This guards against both runs printing
    # "enforcement torn down — the boundary is OFF", which is false on a box that was
    # already unenforced. Both halves are asserted, because checking only the second would
    # pass if both said "already off".
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
# Checks that `policy apply` still re-seeds after a package upgrade renames a new binary
# over the running daemon's, which makes /proc/<pid>/exe read "… (deleted)". The daemon
# resolves its identity once (see `daemon_exe`).
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
    # Restored before any early return. Teardown works with either binary.
    CORDOND="$saved"
    started || return 1
    local fail=0
    expect_allow "owner reads before the upgrade"    read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper denied before the upgrade" read_as "$SCRAPER" "$SECRET" || fail=1

    # The upgrade itself: a NEW inode renamed over the running daemon's binary.
    cp "$CORDOND" "$TMP/cordond.new"
    mv "$TMP/cordond.new" "$TMP/cordond"
    # Assert that the condition was reproduced. Without this check, the scenario would pass
    # even if the replacement silently did nothing.
    if readlink "/proc/$DPID/exe" 2>/dev/null | grep -q '(deleted)'; then
        echo "  OK: the daemon's binary was replaced under it (/proc/$DPID/exe is now deleted)"
    else
        echo "  FAIL: could not reproduce the upgrade — /proc/$DPID/exe = $(readlink "/proc/$DPID/exe" 2>&1)"
        return 1
    fi

    # The main assertion is that the daemon can still re-seed.
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
    # Check that the re-seed really landed, rather than the CLI just returning OK. The rules
    # are now the new ones, so the two subjects have swapped verdicts.
    expect_allow "scraper allowed by the newly applied policy" read_as "$SCRAPER" "$SECRET" || fail=1
    expect_deny  "owner denied — the old rule is gone"         read_as "$OWNER"   "$SECRET" || fail=1

    return $fail
}

# --- singleton: one daemon per socket ---------------------------------------
# Checks that a second daemon refuses to start instead of unlinking the first one's live
# socket and binding its own (see `acquire_singleton`).
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

# --- run all scenarios and fail the suite if any fails ----------------------
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
