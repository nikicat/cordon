# Limitations

What cordon does not stop, as built.

- **No boundary without BPF-LSM.** On a kernel with `CONFIG_BPF_LSM` off, or without `bpf` in
  the LSM list, there is no hardened Linux boundary at all. Where it runs, the pinned links
  ([ADR 0002](adr/0002-bpf-lsm-boundary.md)) keep enforcing across a daemon crash or restart.
- **Only some operations are mediated.** The program hooks `file_open`, link, rename,
  unlink, rmdir, mkdir and exec ([ADR 0007](adr/0007-action-hook-map.md); the list is the
  `#[lsm]` programs in crates/bpf/src/main.rs). Other operations on a protected inode are not
  hooked. These include changing its mode or owner, changing its extended attributes, and
  truncating it by path.
- **Identity beyond the exe is best-effort.** The exe `(dev,inode)` is race-free. But a double
  fork launders the parent chain, and argv is untrusted. Interpreted tools surface as their
  interpreter (`python3`), so they need the opt-in argv0, ancestor or hash predicates ([ADR
  0006](adr/0006-subject-predicates.md)). Ancestry raises the cost, and it is never the
  boundary ([ADR 0003](adr/0003-exe-inode-identity.md)).
-  **First-access friction.** When a tool with no matching rule hits a protected object, it is
  denied by default. Granting access means editing the root-owned policy and running
  `cordon policy apply`. Autolearn ([ADR 0011](adr/0011-autolearn.md)) is the assisted path.
  There is no interactive prompt on each open.
- **Confused deputy.** Gating an open does not stop a tool's own export surface, and that is
  out of scope.
- **Only the root `bpf-lsm` backend is a boundary.** A dev daemon in a user session is for
  iteration, not protection. The boundary runs as a root service with `CAP_BPF` and
  `CAP_MAC_ADMIN`, and macOS ES needs a restricted entitlement.
- **The planned macOS backend shares ES's ceiling.** It mediates only at `open()` time, because
  ES has no `read(2)` event. It does not follow symlinks, and binaries in the ES "default mute
  set" are not mediated. Santa's FAA hits the same limits ([SANTA.md](SANTA.md)), and they are
  inherent to ES.

## Blessing

- **`bless -- bash` trusts the whole subtree.** A scraper you run *inside* a blessed shell
  inherits the blessing. That is the grant working as designed, not a bypass. But it means
  that bless is for tools and shells you trust *in that moment*. Prefer a bless for each
  command, and treat a blessed shell as a deliberate, loud and ideally short-lived "vault
  session."
- **ptrace.** A long-lived blessed process is a fat target for the conceded resident adversary
  ([threat model](threat-model.md)), who can ptrace it as the same uid and make it read the
  secret. The default yama `ptrace_scope` of 1 or more restricts ptrace to descendants, so a
  scraper that is *not* a descendant can't touch it. We recommend that setting as a deployment
  note. It is one more argument for short-lived blesses, one per command.
- **Already-open fds.** cordon gates `open()`, not `read()`. A blessed process that opens
  a secret and passes the fd on hands the content to a process that is not blessed. It can pass
  the fd with SCM_RIGHTS, or leak it across exec without CLOEXEC. This is inherent, and the
  blessed process is trusted not to do it.
- **Every bless is journaled.** The matched class is on `DecisionEvent` ([ADR
  0012](adr/0012-blessing.md)), so even the conceded cases leave an audit trail.
