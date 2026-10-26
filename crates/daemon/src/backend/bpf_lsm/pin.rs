//! bpffs pinning — what makes the boundary outlive the daemon (M5, DESIGN §4).
//!
//! ## Why links, and only links
//! A pinned `bpf_link` holds a reference to its program, and a loaded program holds
//! references to its maps. So pinning the LSM links alone keeps the whole apparatus alive
//! — programs, and the seeded policy sitting in `PROTECTED`/`RULES`/`RULE_COUNT`/
//! `SETTINGS` — with **no holding process**. Until this shipped, `Ebpf` dropping at the end
//! of `Backend::run` detached every hook, so a daemon crash silently switched enforcement
//! off (fail-open).
//!
//! Nothing is *adopted* on startup. A restarting daemon always loads its own object with
//! its own private maps, exactly as before, and the pins only decide how long the
//! **previous** generation keeps enforcing. That is what keeps the single-writer invariant
//! in [`super::seed`] true: no map is ever shared between processes, so the banked flip
//! can't be torn by a second writer, and an upgraded package can never find itself talking
//! to the old kernel program.
//!
//! ## Generations
//! Each run pins under `<pin_dir>/<pid>/`. The directory exists because the new links must
//! be pinned *before* the old ones are removed — `BPF_OBJ_PIN` fails `EEXIST` on a path
//! that is already taken, so a single shared directory would force a
//! detach-then-attach window with nothing enforcing. With generations the handover is:
//! attach → self-test → seed → pin the new → sweep the old, and the previous boundary
//! stands until the replacement is *proven*.

use super::super::Swept;
use aya::Ebpf;
use aya::programs::Lsm;
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::lsm::LsmLinkId;
use cordon_core::{Context, Error, Result};
use std::path::{Path, PathBuf};
use tracing::info;

/// The bpffs directory that holds every run's generation of pinned links.
pub struct PinDir(pub PathBuf);

impl PinDir {
    /// This run's generation directory.
    fn generation(&self) -> PathBuf {
        self.0.join(std::process::id().to_string())
    }

    /// Pin this run's links, then remove every other generation.
    ///
    /// Order matters and is the whole fail-safe property: the previous generation is swept
    /// only after ours is pinned, so there is no instant with nothing attached. Callers must
    /// therefore have already run the self-test and seeded the real policy — a daemon that
    /// aborts before this point leaves the old boundary standing rather than disarming it.
    ///
    /// The returned handles are held for the daemon's lifetime. They are *not* what keeps the
    /// links alive (the bpffs entries are), but holding them means a stray `rm` of the pin
    /// files cannot silently detach a boundary this daemon still believes it is enforcing.
    pub(super) fn pin_links(
        &self,
        ebpf: &mut Ebpf,
        links: Vec<(&'static str, LsmLinkId)>,
    ) -> Result<Vec<PinnedLink>> {
        let generation = self.generation();
        std::fs::create_dir_all(&generation).map_err(|e| {
            Error::msg(format!(
                "bpf-lsm: create pin dir {}: {e}",
                generation.display()
            ))
        })?;

        let mut pinned = Vec::with_capacity(links.len());
        for (hook, id) in links {
            let program: &mut Lsm = ebpf
                .program_mut(hook)
                .ok_or_else(|| {
                    Error::msg(format!("bpf-lsm: program '{hook}' vanished before pin"))
                })?
                .try_into()
                .with_context(|| format!("bpf-lsm: '{hook}' is not an LSM program"))?;
            let link = program
                .take_link(id)
                .with_context(|| format!("bpf-lsm: take link {hook}"))?;
            let path = generation.join(hook);
            // No bpffs pre-check: `BPF_OBJ_PIN` itself refuses any path outside a bpffs with
            // `EINVAL`, so a `statfs` here would only duplicate the kernel's own guard. What it
            // would add is a better message, which this does instead.
            pinned.push(FdLink::from(link).pin(&path).map_err(|e| {
                Error::msg(format!(
                    "bpf-lsm: pin {}: {e} — is {} on a bpffs mount? (systemd mounts one at \
                 /sys/fs/bpf; otherwise `mount -t bpf bpf /sys/fs/bpf`)",
                    path.display(),
                    self.0.display()
                ))
            })?);
        }

        // The handover. Worth a line rather than a silent discard: this is the moment the
        // previous boundary stops enforcing, and "did the old generation actually go away?" is
        // the first question when a box is behaving like two policies at once.
        match self.sweep(Some(&generation))? {
            // First boot after a teardown or a reboot — nothing to supersede.
            Swept::Nothing => {}
            Swept::Generations(n) => info!(
                superseded = n.get(),
                "bpf-lsm: replaced the previously pinned generation(s)"
            ),
        }
        Ok(pinned)
    }

    /// Remove every pinned generation, disarming enforcement. This is the explicit teardown:
    /// stopping the daemon deliberately does **not** do it, so that a restart — or a crash — is
    /// gapless and a stopped log-drainer never drops the boundary.
    ///
    /// Needs no daemon and no BPF handle, because the pins are the only state: removing the
    /// last reference to a link detaches its program, which frees its maps.
    ///
    /// **Asynchronous.** Unlinking the pin only drops the reference; the kernel frees the link
    /// — and so detaches the hooks — from a workqueue, so enforcement outlives this call by a
    /// beat. Anything that must observe the boundary down (the smoke suite's teardown, a
    /// script deleting a formerly-protected tree) has to poll rather than assume.
    pub fn teardown(&self) -> Result<Swept> {
        self.sweep(None)
    }

    /// Remove every generation except `keep`.
    fn sweep(&self, keep: Option<&Path>) -> Result<Swept> {
        let entries = match std::fs::read_dir(&self.0) {
            Ok(entries) => entries,
            // Nothing pinned yet (first run) or nothing left to tear down — both are success.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Swept::Nothing),
            Err(e) => {
                return Err(Error::msg(format!(
                    "bpf-lsm: read pin dir {}: {e}",
                    self.0.display()
                )));
            }
        };

        let mut removed = 0;
        for entry in entries {
            let path = entry.context("bpf-lsm: read pin dir")?.path();
            if keep == Some(path.as_path()) {
                continue;
            }
            let result = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            result.with_context(|| format!("bpf-lsm: unpin {}", path.display()))?;
            removed += 1;
        }
        Ok(Swept::from_count(removed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generations(n: usize) -> Swept {
        Swept::Generations(std::num::NonZeroUsize::new(n).unwrap())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cordon-pin-{name}.{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The handover property, on a plain filesystem: sweeping keeps exactly this run's
    /// generation and drops every other one. If this ever kept none, a restart would
    /// silently disarm the boundary; if it kept all, dead generations would accumulate and
    /// keep enforcing a policy nobody can see.
    #[test]
    fn sweep_keeps_only_the_named_generation() {
        let pins = PinDir(scratch("sweep"));
        let pin_dir = &pins.0;
        let ours = pins.generation();
        std::fs::create_dir_all(&ours).unwrap();
        std::fs::create_dir_all(pin_dir.join("999999")).unwrap();
        std::fs::write(pin_dir.join("999999/file_open"), b"x").unwrap();
        // A stray non-directory must not stall the sweep.
        std::fs::write(pin_dir.join("stray"), b"x").unwrap();

        assert_eq!(pins.sweep(Some(&ours)).unwrap(), generations(2));
        assert!(ours.exists(), "this run's generation survives");
        assert!(!pin_dir.join("999999").exists(), "the old one is gone");

        // …and teardown takes ours too — that is what disarms enforcement.
        assert_eq!(pins.teardown().unwrap(), generations(1));
        assert!(!ours.exists());

        // A second teardown is `Nothing`, not `Generations(0)` — the type makes the
        // already-off case unrepresentable as a count, so callers can't log it as a
        // disarming that happened.
        assert_eq!(pins.teardown().unwrap(), Swept::Nothing);

        std::fs::remove_dir_all(pin_dir).unwrap();
    }

    /// Teardown on a box that never pinned anything is a no-op, not an error: it is the
    /// documented "turn it off" command and must be safe to run blind.
    #[test]
    fn teardown_of_an_absent_pin_dir_succeeds() {
        assert_eq!(
            PinDir(PathBuf::from("/nonexistent/cordon-pins"))
                .teardown()
                .unwrap(),
            Swept::Nothing
        );
    }
}
