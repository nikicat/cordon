//! Keeps the boundary up with no daemon running, by pinning the LSM links in bpffs
//! (ADR 0002). See [`PinDir::pin_links`] for what is pinned and how a new run takes over,
//! and [`PinDir::teardown`] for how it comes down.

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
    /// Returns this run's generation directory.
    fn generation(&self) -> PathBuf {
        self.0.join(std::process::id().to_string())
    }

    /// Pins this run's links, then removes every other generation, and returns the
    /// handles of the new pins.
    ///
    /// Only the LSM links are pinned. A pinned `bpf_link` holds its program, and a loaded
    /// program holds its maps, so the links alone keep the programs and the seeded policy
    /// enforcing with no holding process. A stop, a restart or a crash leaves the boundary
    /// standing. No map is pinned and nothing is adopted on startup. Every run loads its
    /// own object with its own private maps, and the pins only decide how long the
    /// previous generation keeps enforcing. That keeps [`Maps`](super::seed::Maps) the
    /// single writer of every map, and an upgraded daemon never talks to an old program.
    /// It also means a new run's `BLESSED` starts empty, for `Blessings::reconcile` to
    /// rebuild.
    ///
    /// Each run pins under its own generation directory, `<pin_dir>/<pid>/`, because
    /// `BPF_OBJ_PIN` fails with `EEXIST` on a taken path. One shared directory would force
    /// a window between detach and attach with nothing enforcing. The previous generation
    /// is swept only after this one is pinned, so there is no instant with nothing
    /// attached. That is the fail-safe property, and it is why the self-test and the real
    /// seed come before this call. A daemon that aborts before it leaves the old boundary
    /// standing rather than disarming it.
    ///
    /// Errors when the generation directory cannot be created, a link cannot be pinned
    /// (for example because the pin directory is not on a bpffs), or an old generation
    /// cannot be removed.
    ///
    /// The daemon holds the returned handles for its lifetime. They are not what keeps the
    /// links alive, because the bpffs entries do that. Holding them means a stray `rm` of
    /// the pin files cannot silently detach a boundary this daemon still believes it is
    /// enforcing.
    pub(super) fn pin_links(
        &self,
        ebpf: &mut Ebpf,
        links: Vec<(String, LsmLinkId)>,
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
                .program_mut(&hook)
                .ok_or_else(|| {
                    Error::msg(format!("bpf-lsm: program '{hook}' vanished before pin"))
                })?
                .try_into()
                .with_context(|| format!("bpf-lsm: '{hook}' is not an LSM program"))?;
            let link = program
                .take_link(id)
                .with_context(|| format!("bpf-lsm: take link {hook}"))?;
            let path = generation.join(&hook);
            // No bpffs pre-check, because `BPF_OBJ_PIN` itself refuses any path outside a
            // bpffs with `EINVAL`. A `statfs` here would only duplicate the kernel's own
            // guard. All it would add is a better message, and the error below adds that.
            pinned.push(FdLink::from(link).pin(&path).map_err(|e| {
                Error::msg(format!(
                    "bpf-lsm: pin {}: {e} — is {} on a bpffs mount? (systemd mounts one at \
                 /sys/fs/bpf; otherwise `mount -t bpf bpf /sys/fs/bpf`)",
                    path.display(),
                    self.0.display()
                ))
            })?);
        }

        // The handover. It is worth a log line rather than a silent discard, because this
        // is the moment the previous boundary stops enforcing. "Did the old generation
        // actually go away?" is the first question when a box behaves like two policies at
        // once.
        match self.sweep(Some(&generation))? {
            // The first boot after a teardown or a reboot has nothing to supersede.
            Swept::Nothing => {}
            Swept::Generations(n) => info!(
                superseded = n.get(),
                "bpf-lsm: replaced the previously pinned generation(s)"
            ),
        }
        Ok(pinned)
    }

    /// Removes every pinned generation, which disarms enforcement, and returns what was
    /// removed. This is the explicit off switch. Stopping the daemon deliberately is not
    /// one, so a restart or a crash leaves no gap, and a stopped log drainer never drops
    /// the boundary.
    ///
    /// It needs no daemon and no BPF handle, because the pins are the only state. Removing
    /// the last reference to a link detaches its program, which frees its maps.
    ///
    /// Errors when the pin directory cannot be read or a generation cannot be removed.
    ///
    /// The effect is asynchronous. Unlinking the pin only drops the reference, and the
    /// kernel frees the link, which detaches the hooks, from a workqueue. So enforcement
    /// outlives this call by a beat. Anything that must observe the boundary down, such as
    /// the smoke suite's teardown or a script deleting a formerly protected tree, has to
    /// poll rather than assume.
    pub fn teardown(&self) -> Result<Swept> {
        self.sweep(None)
    }

    /// Removes every generation except `keep`, and returns what was removed. A missing pin
    /// directory counts as nothing removed.
    fn sweep(&self, keep: Option<&Path>) -> Result<Swept> {
        let entries = match std::fs::read_dir(&self.0) {
            Ok(entries) => entries,
            // Nothing is pinned yet (a first run), or nothing is left to tear down. Both
            // are success.
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

    /// Checks the handover property on a plain filesystem. Sweeping keeps exactly this
    /// run's generation and drops every other one. If this ever kept none, a restart would
    /// silently disarm the boundary. If it kept all, dead generations would accumulate and
    /// keep enforcing a policy nobody can see.
    #[test]
    fn sweep_keeps_only_the_named_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let pins = PinDir(tmp.path().to_path_buf());
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

        // …and teardown takes ours too, which is what disarms enforcement.
        assert_eq!(pins.teardown().unwrap(), generations(1));
        assert!(!ours.exists());

        // A second teardown is `Nothing` (see `Swept`).
        assert_eq!(pins.teardown().unwrap(), Swept::Nothing);
    }

    /// Checks that teardown on a box that never pinned anything is a no-op, not an error.
    /// It is the documented "turn it off" command, and it must be safe to run blind.
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
