#!/usr/bin/env bash
# B2 derisk spike (docs/PLAN-bless3.md B0) — throwaway, self-cleaning, host-only.
#
# Part B of the plan rests on two assumptions that the VM cannot test. Either one failing
# changes the design, so test them before writing any code. Run as root on a systemd host:
#
#   sudo bash packaging/test/bless-b2-derisk.sh
#
#  1. Can an UNPRIVILEGED process join a root-owned cgroup through an fd passed over
#     SCM_RIGHTS? The kernel is expected to check migration permission against the
#     credentials of whoever *opened* cgroup.procs (`of->file->f_cred`), which is what makes
#     cgroup-v2 delegation-by-fd work. If so, `cordon bless` never needs to be root, and the
#     blessed process can simply be a child of the user's shell.
#  2. Does a process in `session-N.scope/<child>` keep its logind session? polkit resolves
#     the session from the caller's cgroup, so this decides whether run0/pkexec work inside
#     a blessed shell. Also watches whether systemd cleans the directory (session scopes are
#     not Delegate=yes).
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

UID_UNPRIV="${SUDO_UID:-1000}"
GID_UNPRIV="${SUDO_GID:-$UID_UNPRIV}"
rc=0

# --- 1. SCM_RIGHTS fd → unprivileged cgroup join -----------------------------
echo "### 1. unprivileged join via an SCM_RIGHTS cgroup.procs fd (uid $UID_UNPRIV)"
CG1=/sys/fs/cgroup/cordon-derisk-fd
mkdir -p "$CG1"
python3 - "$CG1" "$UID_UNPRIV" "$GID_UNPRIV" <<'PY'
import os, socket, sys
cg, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
# root opens cgroup.procs; ONLY this fd is handed over — the child never gets privilege.
fd = os.open(os.path.join(cg, "cgroup.procs"), os.O_WRONLY)
a, b = socket.socketpair()
pid = os.fork()
if pid == 0:
    a.close()
    os.setgroups([]); os.setgid(gid); os.setuid(uid)          # fully unprivileged now
    _, fds, _, _ = socket.recv_fds(b, 1, 1)
    try:
        os.write(fds[0], str(os.getpid()).encode())
        print("  OK: unprivileged process wrote its pid into a root-owned cgroup.procs")
    except OSError as e:
        print(f"  FAIL: write refused ({e}) — fd delegation does NOT work; Part B needs a redesign")
        os._exit(1)
    # prove it actually landed in the cgroup
    own = open(f"/proc/{os.getpid()}/cgroup").read().strip().split("::")[-1]
    ok = own.endswith(os.path.basename(cg))
    print(f"  {'OK' if ok else 'FAIL'}: resulting cgroup = {own}")
    os._exit(0 if ok else 1)
b.close()
socket.send_fds(a, [b"x"], [fd])
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
PY
[ $? -eq 0 ] || rc=1
rmdir "$CG1" 2>/dev/null

# --- 2. does a child cgroup of session-N.scope keep its logind session? -------
echo "### 2. logind session inside session-N.scope/<child> (decides run0/polkit)"
SESSION="$(loginctl list-sessions --no-legend | awk -v u="$UID_UNPRIV" '$2==u {print $1; exit}')"
SCOPE="/sys/fs/cgroup/user.slice/user-${UID_UNPRIV}.slice/session-${SESSION}.scope"
if [ -z "$SESSION" ] || [ ! -d "$SCOPE" ]; then
    echo "  SKIP: no session scope found for uid $UID_UNPRIV"
else
    owner="$(stat -c '%U:%G' "$SCOPE")"
    echo "  session-$SESSION.scope owner = $owner  (must be root:root — a user-owned parent"
    echo "    would let the invoker rmdir an empty carrier and recycle its inode = its cgroup id)"
    [ "$owner" = "root:root" ] || { echo "  FAIL: parent is user-owned; carrier cannot live here"; rc=1; }

    CG2="$SCOPE/cordon-derisk"
    if ! mkdir -p "$CG2" 2>/dev/null; then
        echo "  FAIL: cannot mkdir under the session scope"; rc=1
    else
        # NB: there is no useful "baseline" to take from here — a setpriv'd child of this
        # root script inherits the *script's* cgroup (root's sudo session), not the user's.
        # The question is simply whether the child cgroup resolves to the user's OWN session.
        # Under test: does logind still see session $SESSION from inside the child cgroup?
        inside="$(sh -c 'echo $$ > "$1/cgroup.procs" && exec setpriv --reuid "$2" --regid "$3" \
                    --clear-groups loginctl session-status --no-pager' _ \
                    "$CG2" "$UID_UNPRIV" "$GID_UNPRIV" 2>&1 | head -1)"
        echo "  inside session-$SESSION.scope/child: ${inside:-<none>}"
        # And the status quo for comparison: a child of the daemon's own cgroup.
        CG3=/sys/fs/cgroup/system.slice/cordond.service/cordon-derisk
        if mkdir -p "$CG3" 2>/dev/null; then
            daemonside="$(sh -c 'echo $$ > "$1/cgroup.procs" && exec setpriv --reuid "$2" --regid "$3" \
                            --clear-groups loginctl session-status --no-pager' _ \
                            "$CG3" "$UID_UNPRIV" "$GID_UNPRIV" 2>&1 | head -1)"
            echo "  inside cordond.service/child:    ${daemonside:-<none>}  <- today's behaviour"
            rmdir "$CG3" 2>/dev/null
        fi
        # Pass = logind reports the invoking user's own session (id + uid), not an error.
        if printf '%s' "$inside" | grep -qE "^${SESSION} .*\(${UID_UNPRIV}\)"; then
            echo "  OK: session $SESSION survives inside the session-scope child — carrier can live there"
        else
            echo "  FAIL: no session resolved there; polkit/run0 would still be broken"
            rc=1
        fi
        sleep 1
        [ -d "$CG2" ] && echo "  OK: systemd left the directory alone (1s)" || echo "  NOTE: systemd removed it"
        rmdir "$CG2" 2>/dev/null
    fi
fi

echo
[ "$rc" -eq 0 ] && echo "PASS: both B2 assumptions hold — PLAN-bless3 Part B is buildable as written" \
                || echo "ATTENTION: an assumption failed — see above; Part B needs revising" >&2
exit "$rc"
