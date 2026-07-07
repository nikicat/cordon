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

echo
if [ "$rc" -eq 0 ]; then
    echo "PASS: bpf-lsm rule-model e2e — all scenarios green (in-kernel)"
else
    echo "FAILED: one or more bpf-lsm scenarios failed" >&2
fi
exit "$rc"
