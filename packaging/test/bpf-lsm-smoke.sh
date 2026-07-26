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
#   7. subject-spec   — `deny * read` + `allow owner read` on one object: the concrete
#                       `allow owner` outranks the `who="*"` deny (§15.6 step 2), so the
#                       owner reads while everyone else is denied. Without subject-
#                       specificity, deny>allow would sort the wildcard deny first and
#                       block the owner too — proven by outcome, no log timing.
#   8. copy-down      — `allow {a,b} read DIR` + `deny b read DIR/secret`: a reads the
#                       secret (inherited allow), b is denied *that file* but still reads
#                       a sibling under DIR (inheritance survives the carve-out). The
#                       per-subject sub-object exception a "deepest bucket only" model
#                       can't express.
#   9. audit → deny   — there is no global mode (§15.6): a `who="*" … audit` catch-all
#                       *observes* (allow + log); flipping that one rule to `deny`
#                       *enforces* (block + log) — the per-object observe→enforce
#                       progression that replaces SELinux's global permissive→enforce.
#  10. silence        — a `silence` policy denies (EPERM) *without* a log record (vs a
#                       `deny`, which logs).
#  11. apply + show    — `cordon policy apply` re-seeds the live maps at runtime via the
#                       atomic double-buffer swap (a previously-unprotected dir becomes
#                       protected with no restart), and `policy show` reflects it.
#  12. coalescing      — a tight loop of identical denied opens collapses to a handful of
#                       ring records (the in-kernel 1s suppressor), and the folded
#                       `suppressed` count is carried into a record so volume stays
#                       visible (M1 §1g).
#  13. leaf path      — audit one exe over a dir; opening distinct files under it yields
#                       distinct records each carrying the ACTUAL opened path (DESIGN
#                       §15.10 flow B), incl. a depth-2 nested file. The kernel walks
#                       d_name (no bpf_d_path at file_open); the suppressor keys on the
#                       opened file, so siblings don't coalesce away.
#  14. user tier      — a system fragment `[[include]]`s a user-tier file scoped to a
#                       user's home (DESIGN §15.8); BOTH a system-tier rule and the
#                       included user-tier rule enforce in-kernel, proving the tier
#                       assembly (load_policy include-expansion → merged maps) wires all
#                       the way through. Home-scope *validation* is a userspace compile
#                       check (unit-tested); this proves the enforcement path.
#  15. audit ~ collapse — the audit line names the caller's user (kernel-captured uid →
#                       passwd) and, for a *regular* user, renders object=/path= with their
#                       home collapsed to `~` (DESIGN §15.10) — so a logged access is
#                       copy-pasteable into that user's policy. Reads a vault as a
#                       synthesized regular uid and asserts the ~-collapsed line.
#  16. edit no-leak    — `cordon policy edit` (sudoedit analog, §15.8) drops to the invoking
#                       user for the editor. A same-uid editor swaps the temp copy for a
#                       symlink to a root-only file; the privileged read-back must refuse to
#                       follow it (O_NOFOLLOW), so the file never leaks into the policy/output.
#  17. edit no-chown   — a racing same-uid loop swaps the temp copy for a symlink while
#                       `policy edit` runs; the fd-based (`fchown`) hand-off keeps a root-owned
#                       sentinel from ever being chowned to the invoker (a path chown would
#                       follow the symlink — an arbitrary-chown → local-root TOCTOU).
#  18. bless scope     — `deny * read V` + `allow @blessed-ro read V` + a second protected
#                       V2: a blessed read of V is allowed (a concrete blessing outranks the
#                       catch-all), the SAME blessed exe is denied on V2 (the grant's scope
#                       is the object column), and the unblessed exe stays denied on V.
#                       End-to-end proof that mkdir-inode == bpf_get_current_cgroup_id.
#  19. bless boundary  — carrier membership IS the boundary: a non-root uid cannot write
#                       into the root-owned carrier's cgroup.procs (EACCES); `bless list`
#                       shows the live entry meanwhile.
#  20. bless inherit+GC — a blessed bash's *grandchild* reads the secret (cgroup membership
#                       is inherited); after exit the daemon GC reaps everything — `bless
#                       list` drains AND the carrier dir is gone (BLESSED entry + table +
#                       cgroup, not just "re-open denied").
#  21. bless revoke    — `bless revoke <id>` kills the carrier tree promptly (cgroup.kill):
#                       the blessed sleep dies, list + dirs drain.
#  22. bless journal   — bless is loud: a blessed read under an `audit @blessed-ro` rule
#                       journals with a trailing `blessing=ro` (class by NAME).
#  23. bless drop      — the `sudo` shape: SUDO_UID/SUDO_GID is the ENTIRE interface sudo
#                       gives the CLI, so setting them as root is byte-identical to a real
#                       `sudo cordon bless` (same substitution 16/17 make for `policy
#                       edit`). The blessed child is dropped to a non-root user and must
#                       STILL read the secret — true only if the carrier join preceded the
#                       drop. Also: the invoker's supplementary groups survive
#                       (getgrouplist) and $HOME is theirs, not root's.
#  24. socket authz    — the socket is 0666 so any local user can connect(2) (which needs
#                       *write* — without it even the ungated reads were root-only, which is
#                       what made `bless list` unusable from a user account). The boundary is
#                       the daemon's peer-uid gate, not the file mode: an unprivileged uid
#                       reads (status / policy show / bless list) but is REFUSED on
#                       `policy apply`.
#
# The bless scenarios run the daemon in a NESTED cgroup, reproducing production's
# `Delegate=yes` service cgroup without needing systemd (the carrier root is then a
# non-root cgroup — the stricter case, since the cgroup2 root is exempt from the "no
# internal processes" rule).
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
[ -x "$CORDOND" ] || { echo "missing $CORDOND — cargo build -p cordon-daemon" >&2; exit 1; }
[ -x "$CORDON" ]  || { echo "missing $CORDON — cargo build -p cordon-cli" >&2; exit 1; }
[ -e "$OBJ" ]     || { echo "missing $OBJ — just build-ebpf" >&2; exit 1; }

# --- shared per-scenario state + helpers -----------------------------------
TMP="" VAULT="" SECRET="" OWNER="" OWNER_B="" SCRAPER="" SOCK="" LOG="" DPID=""
# When set (the bless scenarios), the daemon is started *inside* this cgroup instead of
# the cgroup2 root — see `daemon_start`.
DCGROUP=""
# policy-edit symlink scenarios (16/17): the synthetic editor user + the root-only sentinel.
TUID="" TUSER="" SENTINEL="" EDITDIR=""

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

# Start the daemon (env assignments as args). With `$DCGROUP` set, it is started *inside*
# that cgroup — the production shape under `Delegate=yes`, where carriers are created in a
# **nested** cgroup rather than the cgroup2 root. Worth reproducing precisely because the
# root cgroup is *exempt* from cgroup-v2's "no internal processes" rule and a nested one is
# not, so this is the stricter case. The daemon must already be in the cgroup when it
# starts (it resolves its carrier root from /proc/self/cgroup), hence join-then-exec.
daemon_start() {
    if [ -n "$DCGROUP" ]; then
        mkdir -p "$DCGROUP"
        RUST_LOG="${RUST_LOG:-info}" env "$@" \
            sh -c 'echo $$ > "$1/cgroup.procs" && shift && exec "$@"' _ "$DCGROUP" "$CORDOND" >"$LOG" 2>&1 &
    else
        RUST_LOG="${RUST_LOG:-info}" env "$@" "$CORDOND" >"$LOG" 2>&1 &
    fi
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
    if [ -n "$DCGROUP" ]; then
        # Best-effort: the daemon's own cgroup is empty once it exits; a carrier that
        # still has members is left for the next daemon's reconcile to adopt.
        rmdir "$DCGROUP"/cordon-bless-* 2>/dev/null
        rmdir "$DCGROUP" 2>/dev/null
        DCGROUP=""
    fi
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
    # root runs the readers, so the caller resolves to user=root (uid 0 → passwd), proving
    # the kernel-captured uid reaches the journal; root is not a regular user, so paths stay
    # absolute (no `~` collapse — that's exercised by the daemon's unit tests).
    if wait_log 'deny pid=[0-9]+ user=root exe=.* object=.*vault path=.*/vault/secret action=read policy=default-deny'; then
        echo "  OK: denial reported on the ring buffer (user + object + opened path + action, default-deny)"
    else
        echo "  FAIL: no deny record with the user, object, opened path, and action"; sed 's/^/  daemon| /' "$LOG"; fail=1
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

# --- scenario 7: subject-specificity (concrete allow beats a who=* deny) ------
# DESIGN §15.6 step 2 / PLAN refinement 2: a concrete subject outranks a `who="*"`
# catch-all on the SAME object. Both rules sit on $VAULT; without subject-specificity,
# deny>allow would sort the wildcard deny first and block the owner too. Proven by
# outcome (no log timing): owner allowed, scraper denied.
scenario_subject_specificity() {
    echo "### scenario: subject-specificity (concrete allow beats a who=* deny on one object)"
    ws_new
    write_policy <<EOF
[[rule]]
who = "*"
where = "$VAULT"
action = "read"
policy = "deny"
[[rule]]
who = "$OWNER"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "owner reads (concrete allow outranks the wildcard deny)" read_as "$OWNER"   "$SECRET" || fail=1
    expect_deny  "scraper denied (only the wildcard deny matches it)"      read_as "$SCRAPER" "$SECRET" || fail=1
    daemon_stop; return $fail
}

# --- scenario 8: copy-down (per-subject sub-object exception) ----------------
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

# --- scenario 9: audit → deny (per-object observe → enforce; no global mode) --
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
    if wait_log 'audit pid=[0-9]+ user=root exe=.* object=.* action=read'; then
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
    for _ in $(seq 1 40); do read_as "$SCRAPER" "$SECRET" >/dev/null 2>&1; log_has 'deny pid=[0-9]+ user=root exe=.* action=read' && break; sleep 0.1; done
    if log_has 'deny pid=[0-9]+ user=root exe=.* object=.* action=read'; then
        echo "  OK: the same access now logs as deny (enforced)"
    else
        echo "  FAIL: no deny record after the flip to deny"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop; return $fail
}

# --- scenario 10: silence (deny without a log record) -------------------------
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

# --- scenario 11: policy apply + show (runtime re-seed via the CLI) ----------
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

# --- scenario 12: event coalescing (in-kernel suppressor + folded count) -----
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

# --- scenario 13: leaf-path reconstruction (the actual opened file surfaces) ---
scenario_leaf_path() {
    echo "### scenario: leaf-path reconstruction (distinct files surface with their real path)"
    ws_new
    mkdir -p "$VAULT/sub"
    echo "DEEP" > "$VAULT/sub/nested"
    # Audit the owner across the whole vault (DESIGN §15.10 flow B "smart strace -efile").
    write_policy <<EOF
[[rule]]
who = "$OWNER"
where = "$VAULT"
action = "read"
policy = "audit"
EOF
    daemon_start; started || return 1
    local fail=0
    # Open three DISTINCT files under the one audited object.
    read_as "$OWNER" "$SECRET"           >/dev/null 2>&1   # $VAULT/secret      (depth 1)
    read_as "$OWNER" "$VAULT/other"      >/dev/null 2>&1   # $VAULT/other       (depth 1, sibling)
    read_as "$OWNER" "$VAULT/sub/nested" >/dev/null 2>&1   # $VAULT/sub/nested  (depth 2, nested)
    # Each distinct leaf surfaces its own audit record carrying the ACTUAL opened path —
    # not just the matched root ($VAULT). Proves the d_name walk + leaf-keyed suppressor.
    if wait_log "audit pid=[0-9]+ .*path=$VAULT/secret action=read"; then
        echo "  OK: leaf path reported ($VAULT/secret)"
    else
        echo "  FAIL: no audit record with path=$VAULT/secret"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    if log_has "audit .*path=$VAULT/other action=read"; then
        echo "  OK: sibling surfaces separately ($VAULT/other)"
    else
        echo "  FAIL: no audit record with path=$VAULT/other (siblings coalesced away?)"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    if log_has "audit .*path=$VAULT/sub/nested action=read"; then
        echo "  OK: depth-2 nested path reconstructed ($VAULT/sub/nested)"
    else
        echo "  FAIL: no audit record with path=$VAULT/sub/nested"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop; return $fail
}

# --- scenario 14: system + user tiers (an [[include]]d user rule enforces) ---
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
    mkdir -p "$TMP/conf.d" "$TMP/users"
    # System fragment: a system-tier allow + the include binding root's user-tier file.
    cat > "$TMP/conf.d/00-system.toml" <<EOF
[[rule]]
who = "$OWNER"
where = "$sysvault"
action = "read"
policy = "allow"

[[include]]
user = "root"
path = "$TMP/users/root.toml"
EOF
    # User-tier file (objects must be under ~root): only OWNER_B may read the user vault.
    cat > "$TMP/users/root.toml" <<EOF
[[rule]]
who = "$OWNER_B"
where = "$usrvault"
action = "read"
policy = "allow"
EOF
    cat > "$TMP/config.toml" <<EOF
backend = "bpf-lsm"
socket = "$SOCK"
bpf_object = "$OBJ"
policy = "$TMP/conf.d"
EOF
    export CORDON_CONFIG="$TMP/config.toml"

    daemon_start
    if ! wait_active; then
        echo "  FAIL: daemon did not become active"; sed 's/^/  daemon| /' "$LOG"
        daemon_stop; rm -rf "$usrvault"; return 1
    fi
    local fail=0
    expect_allow "system-tier rule: OWNER reads the system vault"        read_as "$OWNER"   "$sysvault/secret" || fail=1
    expect_allow "user-tier (included) rule: OWNER_B reads the ~root vault" read_as "$OWNER_B" "$usrvault/secret" || fail=1
    expect_deny  "scraper denied the system vault (default-deny)"         read_as "$SCRAPER" "$sysvault/secret" || fail=1
    expect_deny  "scraper denied the ~root user vault (default-deny)"     read_as "$SCRAPER" "$usrvault/secret" || fail=1
    expect_deny  "OWNER denied the user vault (only OWNER_B is allowed there)" read_as "$OWNER" "$usrvault/secret" || fail=1
    daemon_stop
    rm -rf "$usrvault"
    return $fail
}

# --- scenario 15: audit-log ~ collapse for a regular user --------------------
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
        echo "  SKIP: setpriv unavailable — cannot run the reader as a non-root uid"; daemon_stop; return 0
    fi
    local tuser="cordontilde$$" tuid=4242
    local thome="$TMP/home" tvault tsecret
    tvault="$thome/.creds"; tsecret="$tvault/key"
    mkdir -p "$tvault"; echo SECRET > "$tsecret"
    chown -R "$tuid:$tuid" "$thome"
    chmod 755 "$TMP"   # let $tuid traverse the workspace to its home and the exe
    # Register the synthetic user so the daemon's passwd lookup resolves uid → name + home.
    if ! printf '%s:x:%s:%s:Cordon Tilde:%s:/bin/sh\n' "$tuser" "$tuid" "$tuid" "$thome" >> /etc/passwd 2>/dev/null; then
        echo "  SKIP: /etc/passwd not writable in this guest — cannot synthesize a regular user"; daemon_stop; return 0
    fi
    write_policy <<EOF
[[rule]]
who = "$OWNER"
where = "$tvault"
action = "read"
policy = "audit"
EOF
    daemon_start
    if ! started; then sed -i "/^$tuser:/d" /etc/passwd 2>/dev/null; return 1; fi
    local fail=0
    expect_allow "regular user reads its cred (audit)" read_as_uid "$tuid" "$OWNER" "$tsecret" || fail=1
    # The audit line names the user and collapses ~ on BOTH object= (the rule's dir) and
    # path= (the opened file): object=~/.creds, path=~/.creds/key — copy-pasteable into the
    # user's policy verbatim.
    if wait_log "audit pid=[0-9]+ user=$tuser exe=.* object=~/\.creds path=~/\.creds/key action=read"; then
        echo "  OK: audit line shows user=$tuser with ~-collapsed object and path"
    else
        echo "  FAIL: no audit line with user=$tuser and ~-collapsed paths"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop
    sed -i "/^$tuser:/d" /etc/passwd 2>/dev/null   # undo the synthetic passwd entry (ephemeral VM)
    return $fail
}

# --- policy-edit symlink scenarios (16 + 17): shared setup ------------------
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
    SENTINEL="$TMP/root-secret"; echo "SENTINEL-XYZZY" > "$SENTINEL"; chown 0:0 "$SENTINEL"; chmod 600 "$SENTINEL"
    EDITDIR="${TMPDIR:-/tmp}"   # where cordon mints its per-edit temp dir
    cat > "$TMP/config.toml" <<EOF
backend = "bpf-lsm"
socket = "$TMP/dead.sock"
bpf_object = "$OBJ"
policy = "$TMP/policy.toml"
EOF
    export CORDON_CONFIG="$TMP/config.toml"
}

# Undo edit_env_setup: drop the synthetic passwd line + free the workspace.
edit_env_teardown() { sed -i "/^$TUSER:/d" /etc/passwd 2>/dev/null; daemon_stop; }

# Run `cordon policy edit` as the synthetic user with EDITOR=$1; echoes its combined output.
# stdin is /dev/null so a re-edit prompt (only reached if the read-back regresses and accepts
# a bad buffer) gets EOF → Quit, failing fast instead of blocking the suite.
run_policy_edit() { SUDO_UID="$TUID" SUDO_GID="$TUID" EDITOR="$1" "$CORDON" policy edit "$TMP/policy.toml" </dev/null 2>&1; }

# --- scenario 16: read-back refuses a symlinked temp copy (no leak) ----------
# The editor (running as the invoking user) swaps the temp copy for a symlink to a root-only
# file; the privileged read-back must NOT follow it (O_NOFOLLOW), so its contents never
# surface in the saved policy or the printed diagnostics.
scenario_policy_edit_leak() {
    echo "### scenario: policy edit read-back refuses a symlinked temp copy (no leak)"
    edit_env_setup || { daemon_stop; return 0; }
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
    edit_env_teardown; return $fail
}

# --- scenario 17: fd-based chown resists a temp-copy symlink race ------------
# A racing same-uid loop keeps swapping any cordon temp copy for a symlink to the sentinel
# while `policy edit` runs. The fd-based (`fchown`) hand-off makes this structurally safe, so
# across many runs the sentinel is never chowned to the invoker (a path `chown` would follow).
scenario_policy_edit_chown() {
    echo "### scenario: policy edit fd-based chown resists a temp-copy symlink race"
    edit_env_setup || { daemon_stop; return 0; }
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
    edit_env_teardown; return $fail
}

# --- bless scenarios (18–23): shared helpers ---------------------------------
# The smoke runs as root, so the CLI is invoked directly (peer uid 0 — the daemon's
# SO_PEERCRED gate passes). Scenarios 18–22 leave the blessed child as root; scenario 23
# covers the real `sudo` shape by setting SUDO_UID/SUDO_GID, which is the *entire*
# interface between sudo and the CLI (crates/cli/src/bless.rs reads nothing else from it)
# — the same substitution the policy-edit scenarios already make. All of them run the
# daemon in a nested cgroup ($DCGROUP), reproducing `Delegate=yes` without systemd.

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
    return 0
}

# The daemon's carrier root: its own cgroup dir (carriers are created under it).
bless_root() {
    local rel; rel="$(sed -n 's/^0:://p' "/proc/$DPID/cgroup")"
    echo "/sys/fs/cgroup${rel%/}"
}
# The live carrier dirs (cordon-bless-<id>.<class>), if any.
bless_dirs() { ls -d "$(bless_root)"/cordon-bless-* 2>/dev/null; }
# The first live blessing's id from `bless list` ("" when none).
bless_first_id() { "$CORDON" bless list 2>/dev/null | awk '/class=/{print $1; exit}'; }

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
bless_wait_populated() { for _ in $(seq 1 50); do bless_populated_dir && return 0; sleep 0.1; done; return 1; }

# Open FILE for read as subject EXE inside a fresh blessing of CLASS. The CLI mints,
# forks the exe into the carrier, and propagates its exit code.
bless_read_as() { "$CORDON" bless --class "$1" -- "$2" -c 'exec 3<"$1"' bash "$3" 2>/dev/null; } # $1 class $2 exe $3 file

# Poll until the daemon has reaped every blessing: list drained AND carrier dirs gone.
bless_drained() {
    for _ in $(seq 1 40); do
        [ -z "$(bless_dirs)" ] && "$CORDON" bless list 2>/dev/null | grep -q "no live blessings" && return 0
        sleep 0.2
    done
    return 1
}

# --- scenario 18: bless scope (grant outranks catch-all; scoped to the object) --
scenario_bless_scope() {
    echo "### scenario: bless scope (blessed read allowed on V, denied on V2, unblessed denied)"
    ws_new
    cgroup2_ready || { daemon_stop; return 0; }
    local vault2="$TMP/vault2"; mkdir -p "$vault2"; echo S2 > "$vault2/secret"
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

[[rule]]
who = "*"
where = "$VAULT"
action = "read"
policy = "deny"

[[rule]]
who = "@blessed-ro"
where = "$VAULT"
action = "read"
policy = "allow"

[[rule]]
who = "*"
where = "$vault2"
action = "read"
policy = "deny"
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
    # The blessed read must outrank the who="*" deny on the same object (B1 decision #5)
    # — this is also the end-to-end proof that the mkdir'd carrier's st_ino equals what
    # bpf_get_current_cgroup_id() sees.
    expect_allow "blessed exe reads V (grant outranks the catch-all deny)" bless_read_as ro "$OWNER" "$SECRET" || fail=1
    expect_deny  "same exe unblessed is denied V"                          read_as "$OWNER" "$SECRET"          || fail=1
    expect_deny  "blessed exe denied V2 (grant scope = the object column)" bless_read_as ro "$OWNER" "$vault2/secret" || fail=1
    daemon_stop; return $fail
}

# --- scenario 19: bless boundary (non-root cannot join the carrier) ----------
scenario_bless_boundary() {
    echo "### scenario: bless boundary (non-root write to the carrier cgroup.procs fails)"
    ws_new
    cgroup2_ready || { daemon_stop; return 0; }
    command -v setpriv >/dev/null || { echo "  SKIP: setpriv unavailable"; daemon_stop; return 0; }
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

[[rule]]
who = "@blessed-ro"
where = "$VAULT"
action = "read"
policy = "allow"
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
    if "$CORDON" bless list 2>/dev/null | grep -q "class=ro"; then
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
    daemon_stop; return $fail
}

# --- scenario 20: bless inheritance + GC --------------------------------------
scenario_bless_inherit_gc() {
    echo "### scenario: bless inherit + GC (grandchild reads; carrier fully reaped after exit)"
    ws_new
    cgroup2_ready || { daemon_stop; return 0; }
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

[[rule]]
who = "*"
where = "$VAULT"
action = "read"
policy = "deny"

[[rule]]
who = "@blessed-ro"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    daemon_start; started || return 1
    local fail=0
    # The blessed child spawns a GRANDCHILD to do the read — cgroup membership (hence
    # the blessing) is inherited by the whole tree. The trailing sleep outlives a GC
    # tick (500ms) so the daemon observes the carrier populated; without that, a fast
    # exit would defer the reap to the 30s mint grace and stall this scenario.
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
    daemon_stop; return $fail
}

# --- scenario 21: bless revoke (cgroup.kill; prompt death; drain) -------------
scenario_bless_revoke() {
    echo "### scenario: bless revoke (the blessed tree dies promptly; list + dirs drain)"
    ws_new
    cgroup2_ready || { daemon_stop; return 0; }
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

[[rule]]
who = "@blessed-ro"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    daemon_start; started || return 1
    local fail=0
    "$CORDON" bless --class ro -- sleep 300 &
    local clipid=$!
    local id=""
    bless_wait_populated >/dev/null && id="$(bless_first_id)"
    [ -n "$id" ] || { echo "  FAIL: no populated blessing appeared"; sed 's/^/  daemon| /' "$LOG"; kill "$clipid" 2>/dev/null; daemon_stop; return 1; }
    if "$CORDON" bless revoke "$id" 2>/dev/null | grep -q "revoked: $id"; then
        echo "  OK: revoke accepted (id $id)"
    else
        echo "  FAIL: revoke errored"; "$CORDON" bless revoke "$id" 2>&1 | sed 's/^/  cli| /'; fail=1
    fi
    # cgroup.kill slays the tree → the CLI (waiting on the sleep) exits promptly.
    local died=0
    for _ in $(seq 1 30); do kill -0 "$clipid" 2>/dev/null || { died=1; break; }; sleep 0.1; done
    if [ "$died" -eq 1 ]; then
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
    daemon_stop; return $fail
}

# --- scenario 22: bless journal (blessing=<name> on the audit line) -----------
scenario_bless_journal() {
    echo "### scenario: bless journal (a blessed read logs blessing=ro — bless is loud)"
    ws_new
    cgroup2_ready || { daemon_stop; return 0; }
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

[[rule]]
who = "@blessed-ro"
where = "$VAULT"
action = "read"
policy = "audit"
EOF
    daemon_start; started || return 1
    local fail=0
    expect_allow "blessed read under the audit rule" bless_read_as ro "$OWNER" "$SECRET" || fail=1
    # The class is journaled by NAME, appended after the standard fields.
    if wait_log 'audit .*blessing=ro'; then
        echo "  OK: audit line carries blessing=ro"
    else
        echo "  FAIL: no audit line with blessing=ro"; sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    daemon_stop; return $fail
}

# --- scenario 23: bless drops to the invoking user (the sudo path) -----------
# `sudo` hands the CLI exactly two things: SUDO_UID and SUDO_GID. Setting them as root is
# therefore byte-identical to a real `sudo cordon bless` from the code's point of view —
# the same substitution scenarios 16/17 already make for `policy edit`. This covers what
# 18–22 structurally cannot: the child is dropped to a NON-ROOT user and must *still* be
# blessed, which holds only if the carrier join happened **before** the privilege drop
# (both in one pre_exec). It also exercises the invoker's supplementary groups
# (getgrouplist, resolved pre-fork) and their $HOME replacing root's.
scenario_bless_drop_to_invoker() {
    echo "### scenario: bless drops to the invoking user (SUDO_UID + groups + still blessed)"
    ws_new
    cgroup2_ready || { daemon_stop; return 0; }
    local buid=4244 bgid=4244 sgid=4245
    local buser="cordonbless$$" bgroup="cordonextra$$"
    local bhome="$TMP/bhome"; mkdir -p "$bhome"; chown "$buid:$bgid" "$bhome"
    chmod 755 "$TMP"   # the dropped child must traverse to its exe + the secret
    if ! printf '%s:x:%s:%s:Cordon Bless:%s:/bin/sh\n' "$buser" "$buid" "$bgid" "$bhome" >> /etc/passwd 2>/dev/null; then
        echo "  SKIP: /etc/passwd not writable in this guest"; daemon_stop; return 0
    fi
    # A supplementary group the invoker belongs to — getgrouplist must carry it through
    # the drop (the editor drop deliberately clears groups; the bless drop must not).
    printf '%s:x:%s:%s\n' "$bgroup" "$sgid" "$buser" >> /etc/group 2>/dev/null
    local out="$TMP/blessed.id"; : > "$out"; chmod 666 "$out"
    # Reports its identity, then does the blessed read (a denied read fails the script).
    cat > "$TMP/blessed-id.sh" <<EOF
#!/bin/bash
{ id -u; id -G; echo "\$HOME"; } > "$out"
exec 3< "$SECRET"
EOF
    chmod 755 "$TMP/blessed-id.sh"
    write_policy <<EOF
[group.subject.blessed-ro]
blessing = "ro"

[[rule]]
who = "*"
where = "$VAULT"
action = "read"
policy = "deny"

[[rule]]
who = "@blessed-ro"
where = "$VAULT"
action = "read"
policy = "allow"
EOF
    bless_drop_cleanup() { sed -i "/^$buser:/d" /etc/passwd 2>/dev/null; sed -i "/^$bgroup:/d" /etc/group 2>/dev/null; }
    daemon_start
    if ! started; then bless_drop_cleanup; return 1; fi
    local fail=0
    if SUDO_UID="$buid" SUDO_GID="$bgid" "$CORDON" bless --class ro -- "$TMP/blessed-id.sh" 2>/dev/null; then
        echo "  OK: a NON-ROOT blessed child read the secret (join happened before the drop)"
    else
        echo "  FAIL: the dropped child was denied — join-before-drop regression?"
        sed 's/^/  daemon| /' "$LOG"; fail=1
    fi
    local got_uid got_groups got_home
    got_uid="$(sed -n 1p "$out")"; got_groups="$(sed -n 2p "$out")"; got_home="$(sed -n 3p "$out")"
    if [ "$got_uid" = "$buid" ]; then
        echo "  OK: child ran as uid $buid (dropped from root via SUDO_UID)"
    else
        echo "  FAIL: child uid=${got_uid:-<none>}, expected $buid"; fail=1
    fi
    if printf '%s' "$got_groups" | tr ' ' '\n' | grep -qx "$sgid"; then
        echo "  OK: the invoker's supplementary group $sgid survived the drop (getgrouplist)"
    else
        echo "  FAIL: supplementary group $sgid missing (groups=${got_groups:-<none>})"; fail=1
    fi
    if [ "$got_home" = "$bhome" ]; then
        echo "  OK: \$HOME is the invoker's, not root's"
    else
        echo "  FAIL: HOME=${got_home:-<none>}, expected $bhome"; fail=1
    fi
    daemon_stop; bless_drop_cleanup; return $fail
}

# --- scenario 24: socket authorization (reads open, writes root-only) --------
# The socket is 0666 so any local user can `connect(2)` — which needs *write*, and without
# it even the ungated read verbs were root-only in practice, making `cordon bless list`
# unusable from a user account. The file mode therefore carries NO security weight: the
# boundary is the daemon's `authorize()` peer-uid gate. This asserts both halves at once —
# an unprivileged uid can read (status / policy show / bless list) and CANNOT apply.
scenario_socket_authz() {
    echo "### scenario: socket authorization — unprivileged reads work, apply is refused"
    ws_new
    if ! command -v setpriv >/dev/null; then
        echo "  SKIP: setpriv unavailable — cannot run the CLI as a non-root uid"; daemon_stop; return 0
    fi
    local uid=4246
    chmod 755 "$TMP"   # let $uid traverse to the socket, config and policy
    write_policy <<EOF
[[rule]]
who = "$OWNER"
where = "$VAULT"
action = "read"
policy = "deny"
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
    # succeed: before this gate existed, "whoever can reach the socket can apply" was true.
    local out; out="$(as_uid policy apply 2>&1)"
    if [ -n "$out" ] && ! as_uid policy apply >/dev/null 2>&1 && printf '%s' "$out" | grep -q "requires root"; then
        echo "  OK: unprivileged policy apply refused by the daemon (peer uid gate)"
    else
        echo "  FAIL: unprivileged policy apply was not refused with a root message: ${out:-<no output>}"; fail=1
    fi
    daemon_stop
    return $fail
}

# --- run all scenarios; fail the suite if any fails -------------------------
rc=0
scenario_enforce           || rc=1
scenario_selftest_negative || rc=1
scenario_per_action        || rc=1
scenario_subject_group     || rc=1
scenario_object_group      || rc=1
scenario_deny_wins         || rc=1
scenario_subject_specificity || rc=1
scenario_copydown          || rc=1
scenario_audit_then_deny   || rc=1
scenario_silence           || rc=1
scenario_apply             || rc=1
scenario_coalesce          || rc=1
scenario_leaf_path         || rc=1
scenario_user_tier         || rc=1
scenario_user_home_tilde   || rc=1
scenario_policy_edit_leak  || rc=1
scenario_policy_edit_chown || rc=1
scenario_bless_scope       || rc=1
scenario_bless_boundary    || rc=1
scenario_bless_inherit_gc  || rc=1
scenario_bless_revoke      || rc=1
scenario_bless_journal     || rc=1
scenario_bless_drop_to_invoker || rc=1
scenario_socket_authz      || rc=1

echo
if [ "$rc" -eq 0 ]; then
    echo "PASS: bpf-lsm rule-model e2e — all scenarios green (in-kernel)"
else
    echo "FAILED: one or more bpf-lsm scenarios failed" >&2
fi
exit "$rc"
