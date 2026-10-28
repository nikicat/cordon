# Authoring flows

How a policy is written in practice. [ADR 0010](adr/0010-policy-storage.md) covers where it lives and how it is applied.

Both flows come down to editing the root-owned text policy and running `cordon policy apply`.
`cordon policy edit` does both in one safe step ([ADR 0010](adr/0010-policy-storage.md)). It edits as you, then validates,
applies and saves. There is no global mode and no wizard in the daemon. The journal is the
whole feedback loop. Its lines are `audit`, `deny` and `default-deny`, and each carries the
caller's `user` and the matched `exe`, `object`, `action` and `policy`. The `user` is the
caller's real uid, captured in the kernel and resolved to a login name. For a *regular* user
([ADR 0010](adr/0010-policy-storage.md)), `object=` and `path=` print with that user's home collapsed to `~`. So a `deny` line
can be copied straight into their user-tier policy.

**A. Protect a known directory: observe, admit, enforce.** *(The middle step adds static
`allow` rules. It is unrelated to the runtime `cordon bless` grant of [ADR 0012](adr/0012-blessing.md), which is why it is
called "admit" and not "bless".)*
1. *Observe.* Add the directory with a `who="*" … policy="audit"` catch-all. Every access is
   logged as `audit`, and nothing is blocked. This previews the blast radius.
2. *Admit.* For each legitimate exe and directory pair that the log shows, add
   `who=<exe> … policy="allow"`. Subject specificity ([ADR 0008](adr/0008-precedence.md)) makes the specific allow win over
   the `*` catch-all. So an admitted exe goes silent, and the catch-all keeps logging only the
   exes not yet admitted.
3. *Enforce.* When the audit stream is quiet, flip the catch-all from `policy="audit"` to
   `"deny"`. Admitted exes stay silent, and everything else is blocked and logged (`deny`). So
   a tool you broke shows up, and you add an allow for it. You do this one directory at a
   time, on your own schedule.

**B. Discover where an app hides secrets, like a smart `strace -efile`.**
Audit one exe across your home with `who=<app> where="~" action="*" policy="audit"`. This has
two advantages over `strace`. The `where="~"` scope leaves `/usr/lib/*.so`, `/dev` and `/proc`
unprotected, so they are never logged, and only access inside the home surfaces. And
coalescing prevents a flood. The discovered paths then graduate into `@secrets` under flow A.
Each opened file surfaces with its real `path=`. That is because the record carries the leaf
path rebuilt from `d_name`, and the suppressor keys on the opened file ([ADR 0002](adr/0002-bpf-lsm-boundary.md)). Autolearn
([ADR 0011](adr/0011-autolearn.md)) needs the same mechanism to collapse per-file opens into a subtree rule.
