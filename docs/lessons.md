# Lessons

Facts that cost real time to learn, and changes that were tried and reverted. Read these
before re-deriving one from first principles.

## Kernel facts

- **A pinned `bpf_link` keeps its whole apparatus alive.** The link holds a reference to its
  program, and the program holds references to its maps. So one pinned link per hook keeps
  the programs and the seeded policy resident with no process attached. This is why only the
  links are pinned.
- **Unlinking a pin detaches asynchronously.** This was measured on 2026-07-28 in the VM, and
  it will bite anyone who assumes otherwise. Removing the bpffs entry only drops the link's
  last reference. The kernel frees the link, and detaches the hooks, from a workqueue. So
  enforcement outlives the return of `cordond --teardown` by a beat. The first version of the
  smoke suite failed on exactly this, and its `rm -rf` of the workspace was refused because
  the boundary was still up. Poll for the effect, and never assume it is immediate.
- **`BPF_OBJ_PIN` refuses a path outside a bpffs with `EINVAL`.** So a `statfs`
  `BPF_FS_MAGIC` pre-check buys nothing but a nicer message. The kernel already makes it
  impossible to pin into a regular directory and silently keep working.
- **`/proc/self/exe` stops being resolvable once the binary is replaced.** This was measured
  on 2026-07-28. After a package upgrade renames a new file over a running daemon's
  executable, `readlink` gives `…/cordond (deleted)`, and `std::fs::canonicalize` fails with
  `ENOENT`. So `proc::file_id`, which canonicalizes before it consults the mount table,
  returns `None`. A `stat` through the magic link still reports the original inode, but cordon
  uses the path-based route. This is why `seed::daemon_exe` resolves once and memoizes the
  result (its doc has the full argument). Do not "simplify" it back into a lookup on every
  call.
- `bpf_d_path` is not allowed at `file_open`. So identity is the inode `(dev, inode)` pair,
  never a path, and the daemon resolves it at seed time.
- The daemon takes the device from the mount table (`/proc/self/mountinfo`). That device
  matches the kernel's `sb->s_dev` on overlayfs and btrfs, where `stat`'s `st_dev` does not.
- Loading an LSM program needs `CAP_BPF` and `CAP_MAC_ADMIN`, with `lockdown` off. An object
  built against one kernel runs on another, because BTF-resolved field offsets are injected
  at load time. rustc can't emit CO-RE relocations.
- On cgroup2 (kernfs), a directory's `st_ino` is the id that `bpf_get_current_cgroup_id()`
  returns. That is what lets the daemon key `BLESSED` by a carrier it just created.
- **logind is not needed to test carrier placement.** A session scope is a root-owned cgroup
  directory in the shape that systemd makes, and everything under test is kernel mechanics.
  Only the claim that polkit is then satisfied is host-only.
- **Overlayfs does not bypass the ancestor walk.** This was measured on 2026-07-27 on
  7.1.4-zen, against the live `deny` on `~/.npmrc`. An unprivileged `unshare -Urm` with an
  overlay over `$HOME`, read through the overlay, journaled
  `object=~/.config path=~/.config/dconf/user`. That is the real object and the real dentry
  chain. Overlayfs hands `security_file_open` the underlying dentry, so no `sb_mount` gating
  is needed. Do not re-derive this from first principles. The argument that `f_path` is the
  overlay path predicts the opposite, and it is wrong here.
- **Browsers really do separate the JS from the secrets**, measured on 2026-07-27. The
  measurement and its Chrome caveat are in [ADR 0015](adr/0015-fixed-code-grants.md)
  (*Sandbox state*).
- **BPF passes at most five arguments in registers**, and it has no call stack for the rest.
  So a wider function must be `#[inline(always)]`, or it fails to link with "stack arguments
  are not supported". Inlining is more than a linkage workaround, too. Outlining `emit` added
  a fifth call frame, and the v6.12 verifier rejected the whole object with `E2BIG` and a
  storm of `mark_precise: frame4` lines. `consult` sits exactly at the five-argument ceiling.
- **`RENAME_EXCHANGE` fires `inode_rename` twice**, verified on 2026-07-28 in the VM. Why the
  `rename_exchange` scenario must use a writable object is in
  [ADR 0007](adr/0007-action-hook-map.md).
- At the mutation hooks, the trusted context argument is a dentry, not a `file`. The verifier
  range-checks offsets applied to trusted pointers against `.rodata`. So the `dentry_d_*`
  offsets must stay real in `maybe_poison_offsets`, or the failure-path test aborts at load
  time instead of at the self-test.

## Tried and reverted

- **Replacing `PathBuf` with `Box<Path>` for stored path fields was tried wholesale and
  reverted.** The premise was that the type would say "built once, never mutated". It doesn't
  say that. Anything holding `&mut self` can reassign a `Box<Path>` field just the same, so the
  change only removes in-place growth, which nothing was calling. What it adds is real. It
  needs `.into()` at every construction, `.to_path_buf()` at every owned read, and
  `.as_os_str()` because `Box<Path>` is not `AsRef<OsStr>`. It also adds a rule about fields
  versus transient values that everyone has to keep straight forever. If the intent needs
  recording, a doc line on the field costs nothing.
