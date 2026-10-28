# ADR 0007: Actions map to LSM hooks, and escapes are refused

Status: Accepted

## Context

A rule names an action, and each action must be mediated by some LSM hook. The hooks are not
uniform: some fire on every open, some on a mutation, and some are hot paths.

## Decision

| action | LSM hook | notes |
|---|---|---|
| read / write / create | `file_open` | `f_flags` and `f_mode` already encode RDONLY, WRONLY, RDWR and `O_CREAT`, so three actions come free at open time. |
| execute | `bprm_check_security` | The exec of a binary. It is not implied by `read` (see below). |
| unlink / rmdir / mkdir / rename | `inode_unlink/_rmdir/_mkdir/_rename` | One program per hook. Each fires only on a mutation, which is cheap. |
| link | `inode_link` | A distinct hook. `rename` does not cover it (see below). |
| listdir | `file_open` of a directory (coarse) | It compiles but never fires (see below). Anything finer needs the hot `file_permission` hook. |

**The second-name escape, and why `link` is not optional.** A *directory* object protects its
children by ancestry. The kernel walks `d_parent` from the opened file up to a `PROTECTED`
`(dev,ino)`. So a file's membership depends on its position. Any second name for the same
inode outside the object has a different ancestry and matches nothing:

```
open ~/.ssh/id_ed25519 → leaf ino (miss) → .ssh ino (HIT)  → deny
ln ~/.ssh/id_ed25519 ~/x
open ~/x               → leaf ino (miss) → ~ (miss) → / (miss) → unprotected → ALLOW
```

Both `rename` and `link` create that second name, and `link` is the cheaper attack.
`rename(2)` needs write and execute permission on both directories, and it is destructive.
The secret vanishes from `~/.ssh`, the owning tool breaks, and you notice. `link(2)` needs
write permission only on the destination directory. It needs no read permission on the
secret, and it leaves the original untouched, so it is silent and non-destructive.
`protected_hardlinks=1` does not help. It only restricts linking files that the caller does
not own, and here the adversary *is* the owner.

So the invariant is not "gate rename". The invariant is that a protected inode must not
acquire a name outside its object, and that needs both `inode_link` and `inode_rename`.

**Shipped.** Both hooks, plus `inode_unlink`, `inode_rmdir` and `inode_mkdir`, share one
resolver built on `find_object`. There are four cases. `dst` is the destination directory
(`new_dentry.parent()`). `target` is the destination dentry itself, which is a distinct
question (see below):

| | condition | verdict |
|---|---|---|
| **destroy** | `target` is protected (a rename over an existing name) | That object's `write` verdict. It is asked first, before the shuffle short-circuit. |
| internal | `src == dst` | Allow. An atomic save writes a temp file beside the target and renames it over the target, and that must keep working inside a protected directory. |
| **escape** | `src` is protected, and `dst != src` | Deny, unconditionally. |
| clobber | `src` is unprotected, and `dst` is protected | The subject's `create` or `write` verdict on `dst`. |

`inode_unlink` and `inode_rmdir` have no destination, so they take the subject's `write`
verdict. They are gated because objects resolve once, at `policy apply`, and nothing checks
them again. Without the gate, `rm -rf ~/.ssh && mkdir ~/.ssh` would leave the `PROTECTED`
entry dangling and the path unprotected forever.

## Consequences

**`listdir` does not fire, and the failure is a trap worth naming.** There is no hook for each
`getdents`, so listing a directory *is* a `file_open` on it. `requested_action` derives only
`read`, `write` and `create` from `f_mode` and `f_flags`. So a directory open requests `read`,
and nothing ever requests `listdir`.

The consequence is not a no-op. A rule that names only `listdir` matches no request, so the
open falls through to the default deny. `allow @tools listdir @secrets` therefore denies the
listing that it looks like it grants. It fails *closed*, so this is a usability trap rather
than a hole. But for now, a policy must spell directory listing as `read`. Making `listdir`
fire means tagging the request when the opened inode is a directory (`i_mode & S_IFMT`), and
that costs one more BTF offset. It is deliberately not done yet, because `read` already covers
the case correctly.

**`execute` is its own capability.** An exec *opens* the file (`FMODE_EXEC | FMODE_READ`). So
`file_open` already refuses to run the contents of an object that denies reads.
`bprm_check_security` adds the converse, so an object may be readable and not runnable. The
subject is the process that *performs* the exec, because at that hook the caller still has its
old image. Note how this interacts with copy-down. A narrower `allow` on a child does not
remove a capability that the parent granted, because a child rule that doesn't match the
requested action falls through to the parent's rules. So "readable but not runnable" is
written as an explicit `deny` on `execute`, not as an `allow` that leaves `execute` out.

`inode_mkdir` is the mirror of `rmdir`, and it is the one hook whose dentry is negative. There
is no inode yet, so the dentry matches nothing itself, and the verdict comes from its parent,
like the clobber case above. Adding a name inside an object is an ordinary `create` or `write`
on that object. Note that this does *not* cover the `rm -rf` case above. Once the object's own
directory is gone, there is no protected ancestor left to find, and that is exactly why
`rmdir` is the hook that closes the case.

**Why escape consults no rule.** An escape publishes the inode to *every* subject,
permanently and silently. Afterwards `find_object` misses, so nothing is ever logged again.
Gating the escape on the acting subject's read verdict was considered and rejected. With that
gate, `allow /usr/bin/ssh read ~/.ssh` would let an allowed subject that is scriptable or
running under `LD_PRELOAD` convert a scoped, logged grant into an unscoped, permanent one. So
no subject may escape, not an allowed exe and not a blessed session. Blessing grants *read*,
not re-parenting.

The cost is deliberate and one-sided. This rule enforces even where the matching rule says
`audit`, which otherwise never enforces. So renames *out of* `~/.config` now fail with `EPERM`,
for example in an app's config migration or a manual `mv ~/.config/foo ~/backup/`. Renames
inside the object are unaffected, and they are the common case. Whether an escape is
*journaled* still follows the matching rule's policy. So under a `silence` rule it is refused
silently, and the split between `{allow,deny}` and `{log,silent}` holds. If the cost ever
bites, a one-line softening would be to allow the escape where a `*` subject may already read
the object. The journal cause is a distinct synthetic `escape-deny` (like `default-deny`),
because "structurally refused" and "a rule of yours blocked it" need different fixes.

Also note an asymmetry that the walk creates. The leaf's own id is tested first. So a rule
that names a file matches that inode under any name, and it was hardlink-proof even before
these hooks. A rule that names a directory protects children only by ancestry. Listing secret
files as objects was therefore a real mitigation, and it was rejected anyway. It requires
listing every secret, so a key generated tomorrow would be silently unprotected. Directory
objects had to become sound on their own.

For contrast, these are *not* bypasses:
- **Symlinks**, because `file_open` sees the dentry of the resolved target.
- **A reopen through `/proc/PID/fd/N`**, for the same reason.
- **Bind mounts**, because `d_parent` belongs to the file system, not to the mount. Walking
  the dentry chain instead of a path string buys this for free.
- **Copying**, because a copy needs a read, which is mediated.
- **Overlayfs in a user namespace.** This was measured rather than assumed (2026-07-27,
  7.1.4-zen). Mounting an overlay over `$HOME` and reading through it journaled
  `object=~/.config path=~/.config/dconf/user`. So the ancestor walk resolved the *real*
  object, and the path reconstruction walked the *real* dentry chain. Overlayfs presents the
  underlying dentry to `security_file_open`, so the read is mediated and needs no `sb_mount`
  gating.

**Why the destination is classified twice.** The destination directory answers the escape and
clobber cases, but it cannot answer for the name being overwritten. `rename(2)` onto an
existing name destroys that inode, and `inode_rename` is the only hook the kernel fires for it
(`decide_reparent` in `crates/bpf/src/main.rs` has the call path). If the target were left
unclassified, its sibling syscall could bypass the `inode_unlink` gate. `rm secret` would
be refused, while `mv anything secret` destroyed the same inode and left the `PROTECTED` entry
dangling permanently. Two shapes are invisible to the classification by directory pair:

- **The destination is an object whose parent is not.** Take `deny * * ~/.ssh/authorized_keys`
  with no rule on `~/.ssh`. Both directory walks miss, so the pair reads as `(None, None)`,
  meaning "nothing protected is moving".
-  **The destination is a nested object that is more specific.**
  `mv ~/.aws/tmp ~/.aws/.danger-token` reads as an internal shuffle, because both sides resolve
  to `~/.aws`. But the object it overwrites is a different and tighter one, under a `silence`
  rule. Precedence ([ADR 0008](0008-precedence.md)) says that the more specific object wins,
  and
taking the directory's verdict inverts that.

So `find_object` runs on `new_dentry` itself, first, before the shuffle short-circuit. A hit
takes that object's own `write` verdict. That is the same treatment `inode_unlink` gives,
because it is the same event. `link` is unaffected, because its target is always negative.
Atomic save still works. A rename over a name in an object that the
subject may already write takes that same `allow`, so the shuffle proceeds. The check bites
only where the destination carries a tighter rule, which is the case worth biting on.

`renameat2(RENAME_EXCHANGE)` re-parents both inodes rather than destroying one, so the destroy
check alone does not cover it. The protected side that moves *out* needs the unconditional
escape refusal. It gets that refusal, because `security_inode_rename` calls the hook a second
time with the pair swapped when `RENAME_EXCHANGE` is set. This was verified in the VM, and the
smoke suite's `rename_exchange` scenario pins it. The scenario runs against a *writable*
object, so that the destroy and clobber checks cannot refuse first and hide a missing second
call.

`file_permission` and `inode_permission` run on every I/O, so they are hot paths, and any
action checked on each access is opt-in. Identity is the inode across all hooks, through the
dentry walk, and never the path ([ADR 0002](0002-bpf-lsm-boundary.md)).
