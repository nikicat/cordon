# ADR 0013: Bless authenticates by client-side elevation

Status: Accepted (shipped in B2); PAM in the daemon is the planned upgrade (B3 in
[todo.md](../../todo.md))

## Context

A mint must prove that a human at the keyboard acts ([ADR 0012](0012-blessing.md)), and the
daemon must never trust a client's claim about who it is.

## Decision

The requirement from [ADR 0012](0012-blessing.md) is that a human at the keyboard proves
presence at mint time. What satisfies it is reaching uid 0. The daemon refuses to approve a
mint for any other peer, and every elevation tool worth the name puts a human in front of that
transition. Which tool is used is not cordon's business, deliberately so, and `$CORDON_SUDO` is
the seam.

- **The boundary is uid 0, as `SO_PEERCRED` reports it, on `BlessApprove`.** The kernel attests
  it, and the client never asserts it. The rest of the verb table is the socket authorization
  in [ADR 0010](0010-policy-storage.md). `BlessRequest` is open, because asking is not
getting, and the backend checks ownership for `BlessRevoke`.

- **The mint is a handshake over two connections**, because the two facts it needs come from
  two different peers:

  | | connection | verb | what it establishes |
  |---|---|---|---|
  | 1 | `cordon bless`, as the user | `BlessRequest`, answered by `BlessPending{nonce}` | the session the carrier belongs in ([ADR 0014](0014-blessing-lifecycle.md)) |
  | 2 | the helper, as root | `BlessApprove{nonce}` | that a human authenticated |
  | 3 | back down connection 1 | `BlessMinted` plus the carrier fd | — |

  **The daemon is the rendezvous, not the helper.** The obvious shape would have the root
  helper mint the carrier and forward the descriptor to the unprivileged parent. That cannot
  work, because the helper's own credentials say nothing about whose session this is. Under
  `run0`, the helper lives in a transient unit with no session at all. Having the helper
  *claim* a pid instead would be worse. A caller could name another user's process and get a
  carrier created inside that user's session. So each fact is read from the one peer that
  cannot lie about it.

  The nonce is 128 bits from `getrandom(2)`. It is single-use and bound to the requesting
  connection. It need not be *secret*, because approving a request requires uid 0 regardless,
  and the descriptor returns to the requester rather than to the approver. But it must be
  unguessable. A predictable value would let an attacker register a request and have someone
  else's authenticated helper approve the attacker's request.

- **`$CORDON_SUDO` (default `sudo`) chooses the elevation tool.** That is not a hole, and the
  reason is structural. A faked elevation just yields a helper that is not root, and the daemon
  refuses its approval. Security lives in the daemon's uid check, never in the client's choice
  of tool. That is also what makes the variable safe to expose as the seam that the smoke VM
  without systemd needs.

- **The client checks the daemon too.** `cordon bless` checks that `SO_PEERCRED` reports uid 0
  on the daemon's end *before* it sends anything, and it passes the same `--socket` to the
  helper. Without that check, the nonce would be a bearer token handed to whoever answers the
  socket. A local user squatting the client's socket path could park its own request on the
  real daemon and answer the victim with that nonce. The human's authentication would then
  mint a carrier for the attacker. The human really did authenticate, just not for their own
  request. A blessing from a daemon that is not root could not grant anything anyway ([ADR
0012](0012-blessing.md)), so refusing costs nothing.

## Consequences

- **Known deltas, accepted:**
  - **An elevation tool's authentication cache is a grace window.** [ADR
    0012](0012-blessing.md) argues for *no* cache, but sudo has one (5 minutes by default). So
    a resident adversary who runs `cordon bless` inside that window mints without a human.
    *Deployment note:* setting `Defaults!/usr/bin/cordon timestamp_timeout=0` in sudoers
    restores the no-grace property for this command.
  - **Only sudoers can bless.** A non-sudoer cannot bless their own tools, because they cannot
    reach uid 0 to approve. PAM in the daemon would authenticate *the requesting user* instead,
    and it needs no admin rights at all. That is why it remains the intended upgrade.
- **Why not PAM in the daemon now.** Exploring the implementation found it much heavier than
  specified. It needs a PAM conversation proxied over the control socket as IPC with many
  frames, stdio fd passing so that the modules can reach the tty, and children spawned by the
  daemon with degraded job control. The smoke VM without systemd also cannot test transient
  scopes at all. The design below is kept verbatim as the upgrade path.
  > **Future (PAM upgrade).** Authentication runs against a `cordon` PAM service
  > (`/etc/pam.d/cordon`) in the root daemon, which needs access to `/etc/shadow`. The daemon's
  > PAM *conversation function* sends prompt and info frames over the control socket to the
  > `cordon bless` front end. The front end renders them on the tty (with echo off for a
  > password, or "swipe now" for a fingerprint) and returns the input. A malicious front end
  > controls only the I/O channel, never the verdict. Real modules in the daemon verify the
  > answer, so a wrong or missing answer simply fails. Identity still comes from
  > `SO_PEERCRED`.
  >
  > **B2 did the structural work.** The `SCM_RIGHTS` hand-off and the unprivileged CLI already
  > ship, and this upgrade would otherwise have had to invent them. So B3 reduces to swapping
  > what proves that a human is present. It replaces the helper's uid-0 approval with a PAM
  > conversation against the requesting peer. It then relaxes the gate rather than tightening
  > it, because a non-sudoer can bless their own tools. And it restores "no grace window" by
  > construction. *Deployment consideration:* a method that needs the user's session bus (some
  > `pam_fprintd` setups) is awkward for a system service.

- **Environment: nothing is restored, because nothing was ever taken.** `cordon bless` runs as
  the user, as an ordinary child of their shell. So the blessed command inherits its
  environment, cwd, tty, job control and logind session by construction. The only thing the
  grant adds is cgroup membership. This is why the unprivileged CLI is the spawner. A target
  spawned by the root helper would be born under a privilege tool that had already scrubbed the
  environment. Under `run0` there would be no parent chain left to recover the environment
  from. So keeping the environment can't be separated from who spawns the target. `$SHELL` is
  authoritative for the same reason.
