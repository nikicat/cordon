# Prior art

What the incumbents do about a same-uid scraper, and the projects cordon draws from.

## What the incumbents actually do to a scraper

Insight 3 is checkable, so check it. The in-scope adversary is a scraper running at your uid
that copies `~/.aws/credentials` and Chrome's cookie DB. Against it, stock AppArmor and SELinux
do essentially nothing, with enforcement fully on and no denial logged:

- **Fedora and RHEL targeted policy** runs the login session as `unconfined_t` and labels
  everything in `$HOME` as `user_home_t`. `unconfined_t` can read `user_home_t`. Confined user
  domains (`user_u`, `staff_u`, `xguest_u`) exist, but they are opt-in and rarely deployed.
  Even under `staff_u`, one user app is not separated from another app's data by default.
- **Ubuntu's AppArmor** ships profiles for daemons and a handful of apps. Anything else, such
  as `curl`, a pip install or a binary you downloaded, has no profile, and a program without a
  profile is unconfined.

This is not an oversight. It is the model. Confinement is a property of the *program*, and the
default for an unknown program is no confinement. A scraper is by definition a program without
a profile, so the entire class sits outside the deployment. That is insight 3, restated as an
observation rather than a claim. Both systems *can* express "only Firefox reads the cookie
DB". The gap is in policy coverage, not in capability. But expressing it means confining the
user, retyping the object, and writing a domain for every legitimate reader.

Credit where it is due. Containing a compromised *service* is what these systems were built
for, and they do it well. `httpd_t` cannot read `user_home_t`, so an nginx or mysqld exploit
does not become a sweep of home directories. Where a browser profile does ship, it points in
the opposite direction to what we want. It protects the system from Firefox, not Firefox's
cookie DB from everything else.

**Android is the counterexample, and it is SELinux.** Per-app uids, per-app domains and default
deny together are this exact protection, and it works at scale. So the mechanism is proven.
What Android has and a desktop does not is a step that assigns identity at install time.
Desktop programs arrive by tarball, pip, npm and `curl | sh`, so no such step exists. That is
why cordon assigns identity to the *object* instead and lets subjects stay anonymous.

**This prior art does solve the problem, and each piece has something to take from it:**

- **Flatpak and snap** genuinely confine. A Flatpak cannot see `~/.ssh`, and its file access
  goes through portals. But they are gated on packaging, and a scraper will not arrive as a
  Flatpak.
- **macOS TCC** is the closest existing thing to this design. It gates on the object side,
  grants per app, and prompts on first access. It is mainstream and effective. Its two failure
  modes are ours to avoid. The first is consent fatigue. [authoring flows](authoring.md)'s
  audit, admit, enforce flow exists partly for this, because it admits from observed evidence
  rather than from a modal prompt. The second is identity that rests on a code signature, which
  is the same question that [ADR 0015](adr/0015-fixed-code-grants.md) works through.
- **Windows has the right shape twice, and points it at the wrong verb both times.**
  *Controlled Folder Access* is almost exactly this design, with designated folders and an app
  allowlist. But it gates writes only, because it was built against ransomware. A scraper
  reads, so CFA never sees it. *WDAC/AppLocker* is genuinely default-deny. With DLL-level
  enforcement it is the closest shipping analogue to the fixed-code invariant of [ADR
  0015](adr/0015-fixed-code-grants.md), because an unsigned DLL cannot load into a signed
  process. But it governs what may execute, not what a running program may read, and consumer
  machines effectively never run it in enforcement mode. *Credential Guard* shows that
  Microsoft can do hard isolation when a target matters enough. VBS puts the LSA secrets in
  VTL1, out of reach of an admin. It also shows that this was done for one target, not as a
  general mechanism.
- **Chrome's app-bound encryption** (Windows, 2024) is the piece of prior art that tried
  *this* architecture, so it is the most instructive. It shipped because infostealers were
  reading the cookie DB, which shows that the threat is real and unaddressed at the OS layer.
  It replaced DPAPI's user-bound key, which any process at your uid could use to decrypt.
  That was our problem, with encryption that does not move the trust boundary. The
  replacement is a privileged SYSTEM service that validates the calling executable before it
  returns the key. That is insight 2, implemented at scale by someone else. It was bypassed
  within months. Attackers injected into Chrome and asked as an authorized process, abused the
  elevation service, or simply ran elevated. Google has kept hardening it since, and its
  current state is not verified here. But the lesson is stable, and it is the strongest
  external argument for ADR 0015: *a privileged broker that authenticates by executable identity is
  only as strong as its code-identity story, and injection into the authorized process
  defeats it.* Our `allow /usr/bin/ssh read ~/.ssh` is structurally the same grant and fails
  the same way. That is why ADR 0015 is not an optional hardening pass. On Linux, Chrome uses the
  login keyring, which any process at your uid can reach over D-Bus. So the file gate is the
  only control available there at all.
- **Per-app file gating exists commercially.** Examples are ThreatLocker's Storage Control and
  Ringfencing, AppGuard, and the previous generation of HIPS products (Comodo, Online Armor).
  A decade ago those products let you write "only firefox.exe may read this path". The
  category is largely dead. It died of prompt fatigue and the burden of managing rules, not of
  being wrong. That is the same verdict as for TCC, reached from a second direction. It is
  also the same reason why the audit, admit, enforce flow is the interesting part of this
  design, rather than the enforcement primitive.
- **EDR behavioural detection** (CrowdStrike, SentinelOne, Defender for Endpoint) is the
  mainstream commercial answer, and it is not signature-based. It flags a process that opens
  `Login Data`, archives it and then sends it out. But it races the exfiltration rather than
  bounding it, because it kills the process after the read. A boundary and a detector are
  different products. We are the former, and the journal is not a detector.

**The approach that is actually winning is orthogonal: make the loot worthless.** Device Bound
Session Credentials tie a session cookie to a TPM key, so a stolen cookie will not authenticate
elsewhere. A passkey's private key never leaves the secure element. That is the strongest
structural answer to *credential* theft on any OS. It complements cordon rather than competing
with it. It covers session secrets, and it does nothing for `~/.aws/credentials`, SSH keys,
`.env` files or a password store, which is most of what `@secrets` names. Where a secret *can*
be made impossible to exfiltrate, prefer that over gating it.

So the gap this project targets is specific: object-first default deny for desktop programs
that share a uid. Android proves that the enforcement works, and TCC proves that the model is
usable. Windows ships the two halves separately and never joins them, and none of it exists for
the Linux desktop.

## Related work

These are the references we draw from. None of them is a drop-in for "deny reads of secret
config directories to everyone but the owner, transparently, cross-platform, with no per-tool
policy."

#### Closest architectural cousins (authorizer daemon + rule store)
- **Santa** (macOS, North Pole Security) is the closest existing tool. Its File Access
  Authorization (FAA) is a real object-centric file gater on Endpoint Security, keyed on code
  identity. It covers about 80% of our macOS gater. But Santa is macOS-only, with no
  cross-platform plans. And FAA is static admin policy. It has no interactive prompt and no
  TOFU, and it reloads by polling (every 15 seconds at the fastest). Its interactive TOFU
  (standalone mode) covers execution only. So it can't do cordon's autolearn or runtime
  grants for files. The full analysis of its functionality and roadmap, and the
  decision between reuse and building our own, are in [SANTA.md](SANTA.md). We borrow its ES
  deadline-safety pattern and its identity-match schema, which are Apache-2.0.
- **OpenSnitch** (Linux), **Little Snitch** and **LuLu** (macOS) are interactive application
  *firewalls*. They are a reference for a grant UX (allow once, for X minutes or
  forever, with rules by exe) and for attribution to a process. But they gate network egress,
  not file reads. They would catch an exfiltration *connection*. Yet a scraper that stages to a
  local file, or leaves over a channel that is already allowed (the browser, DNS), slips by.
  They are a complementary layer, not a substitute.

#### Mandatory Access Control (the per-tool-policy family we reject as primary)
- **AppArmor, SELinux and macOS Seatbelt (`sandbox-exec`)**: see [ADR
  0001](adr/0001-object-centric-gating.md) and [ADR 0002](adr/0002-bpf-lsm-boundary.md). They
  are subject-centric. Each program needs its own profile or policy, and a program without a
  profile is unconfined, so an unknown scraper is unrestricted. SELinux *can* be object-centric
  through labels. But its policy is compiled, it works through domain transitions, and it is
  Linux-only. We want one object-centric rule that covers all subjects, including unknown ones.
- **Landlock** (Linux, an unprivileged LSM) lets a process restrict its own file system access
  and its children's. It is modern and needs no root. But it is *self*-confinement, so it is
  useless against a scraper that won't opt in. It is the inverse of what we need.
- **bubblewrap, firejail and Flatpak** are namespace sandboxes. Flatpak even gives each app its
  own data directory (`~/.var/app/<id>`), which is the north star for per-app isolation. But
  they are subject-centric and opt-in for each app. CLI dev tools aren't packaged, and you
  can't wrap a scraper you've never seen.

#### Secret brokers / keystores (our deferred [ADR 0004](adr/0004-no-encryption.md) + orthogonal capability brokering)
- **ssh-agent and gpg-agent** never release the key, and perform the operation instead. That
  is the broker pattern in miniature, but it covers only ssh and gpg and is bound to their
  protocols.
- **HashiCorp Vault (with its agent), aws-vault, envchain, the 1Password CLI and
  git-credential-manager** broker short-lived credentials and keep custody in an OS keystore.
  Several are cross-platform. We borrow the idea of a short-lived capability. But each one
  needs integration with each tool, and none of them transparently protects the long tail of
  existing flat config files.
- **OS keystores** (Keychain, Secret Service, the kernel keyring) and **SOPS, age and
  git-crypt** make the secret something other than a readable file, or encrypt it at rest. We
  borrow them for the deferred at-rest bundle. But tools must adopt them, and they don't gate
  live reads of directories that already exist.

#### Filesystem-view / redirection (evaluated and rejected earlier)
- **fakechroot and proot** remap paths with `LD_PRELOAD` or `ptrace`. They are cooperative, or
  a same-UID process can bypass them, so they are not a boundary (see the preload discussion).
- **FUSE (bindfs, gocryptfs, fuse-t).** A userspace file system can gate on the caller's pid,
  and fuse-t does it on macOS without a kext. But the mount is global rather than per
  process, PID identity is racy, and macFUSE's kext *lowers* platform security. We use a
  kernel authorizer (bpf-lsm or ES) instead, and keep fuse-t only for the deferred
  transparency layer.

#### Observability & eBPF enforcement
- **auditd, fanotify in notify mode, and inotify** can *watch* file access by path, but they
  cannot deny. We need the permission path, which can veto, and not just logging.
- **Tetragon and Falco** (eBPF, LSM-BPF) do runtime security, and Tetragon can even enforce,
  by overriding or killing. Architecturally, Tetragon is the same as our LSM-BPF backend. But
  it is oriented to containers and Kubernetes, and it is heavyweight to drive as a secret gate
  for one desktop user.

#### aya-ecosystem peers (our toolchain — pure-Rust eBPF via aya)
The eBPF enforcers above (Tetragon, Falco, KubeArmor and bpflock) are the precedent for the
mechanism, but all of them use Go and libbpf. Some projects share cordon's actual toolchain:
a `no_std` `aya-ebpf` kernel crate, an `aya` userspace loader, maps and ring buffers, and the
same CO-RE and BTF offset problem (rustc can't emit CO-RE relocations,
<https://github.com/rust-lang/rust/issues/158412>). They are listed in
[`aya-rs/awesome-aya`](https://github.com/aya-rs/awesome-aya). Every security project there is
subject-centric, and most only observe. None is an object-centric file authorizer for a
personal box. So cordon shares their plumbing, not their shape:
- **lockc** is an eBPF LSM-based MAC for *containers* (Docker, Kubernetes), written in Rust
  with aya. It is the closest cousin by mechanism, because it turns LSM hooks into MAC. But it
  is centred on containers and profiles, and it is framed around audit and experimental. It
  restricts the confined workload, not an *object* the way we protect a subtree.
- **suidsnoop** uses aya LSM programs, and it is the only peer that actually denies, with an
  audit or enforce mode. But it is scoped to suid `execve` and keyed on the uid, so it is
  subject-centric. It is a research demo, not a gate on file reads.
- **bombini** uses aya LSM-BPF, but it only observes. Its modular "detectors" (exec, connect,
  file access) emit JSON and never veto. It is subject-centric runtime security for
  Kubernetes.
- **kunai** uses aya with kprobes and tracepoints, not LSM enforcement. It only observes, for
  host threat hunting, like Sysmon for Linux. It is the most mature of the set and the least
  like cordon, because it logs events and doesn't gate opens.

So cordon's niche in the aya world is empty. That niche is object-centric, enforcing, on a
personal desktop. The Go tools above are the precedent for the
*use*, which is allow and deny on LSM hooks. These aya projects are the precedent for the
*stack*. They all answer "what may this subject do?", and never "who may touch this
resource?"

#### Authorization-agent architecture
- **polkit** pairs a privileged daemon with an unprivileged agent in each session that draws
  the prompt. cordon's bless reuses that agent rather than copying it, because the elevation
  tool's prompt is what proves a human is present ([ADR
  0013](adr/0013-bless-authentication.md)). But polkit authorizes privileged D-Bus *actions*,
  not file reads.
