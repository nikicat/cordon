//! Linux **BPF-LSM** enforcement backend — the hardened boundary (DESIGN §4).
//!
//! The split from `fanotify` is the control-plane / data-plane split:
//!   - **Data plane (in-kernel):** an eBPF program (`crates/bpf`) attached to the
//!     `file_open` LSM hook returns the verdict *in-kernel* (`0` allow / `-EPERM`
//!     deny) by reading policy from BPF maps. It is the boundary; this Rust code
//!     never sees — let alone answers — an individual open.
//!   - **Control plane (this file):** load the program, seed the maps from the
//!     SQLite store, and drain the ring buffer of denials into the journal. The
//!     daemon is still required (DESIGN §4) — for logging/learning — but the
//!     verdict no longer depends on it being scheduled in time.
//!
//! Requires **root** with `CAP_BPF` + `CAP_MAC_ADMIN`, a kernel built with
//! `CONFIG_BPF_LSM=y`, **and `bpf` in the active LSM list** (`lsm=…,bpf` on the
//! kernel cmdline) — without the last, the hook loads but never mediates.
//!
//! ## Scope (increment 1)
//! Mirrors the capability `fanotify` ships today — deny a non-owner's open under an
//! owned subtree — but in-kernel. Subtree matching is a dentry **(dev, inode)**
//! ancestor walk; identity is the FNV-1a hash of the caller's exe path (matching
//! the path-keyed store). **Not yet** done here and explicitly deferred to the next
//! increment: TOFU-on-create via the learn path, and fail-safe **pinning** (pin the
//! program + maps + link to bpffs so enforcement survives daemon death). Until
//! pinning lands this backend, like `fanotify`, stops enforcing when the daemon
//! exits. Full load/verify/enforce validation happens in a virtme-ng VM booted with
//! `lsm=…,bpf` (this host's running kernel omits `bpf` from its LSM list).

use aya::maps::{Array, HashMap as BpfHashMap, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};
use cordon_bpf_common::{
    Decision, Dev, Ino, LearnEvent, MAP_EVENTS, MAP_OWNER_IDS, MAP_SETTINGS, MAP_SUBTREES,
    Mode as BpfMode, OwnerId, OwnerKey, Pid, Settings, SubtreeKey, exe_hash,
};
use cordon_core::backend::{Backend, Shutdown};
use cordon_core::config::Mode;
use cordon_core::engine::Engine;
use cordon_core::{Error, Result};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Poll wakeup cadence so the ring-buffer reader re-checks the shutdown flag.
const POLL_TIMEOUT_MS: u16 = 500;

/// The LSM hook we attach to, and the name of the program in the ELF (the eBPF
/// function is `#[lsm(hook = "file_open")] fn file_open(..)`).
const HOOK: &str = "file_open";

pub struct BpfLsmBackend {
    mode: Mode,
    /// The compiled eBPF object (`just build-ebpf` output / packaged install).
    object: PathBuf,
    /// bpffs directory for fail-safe pinning (reserved; see module scope note).
    #[allow(dead_code)]
    pin_dir: PathBuf,
}

impl BpfLsmBackend {
    pub fn new(mode: Mode, object: PathBuf, pin_dir: PathBuf) -> Self {
        BpfLsmBackend {
            mode,
            object,
            pin_dir,
        }
    }
}

impl Backend for BpfLsmBackend {
    fn name(&self) -> &str {
        "bpf-lsm"
    }

    fn run(self: Box<Self>, engine: Arc<Mutex<Engine>>, shutdown: Arc<Shutdown>) -> Result<()> {
        // Kernel BTF drives CO-RE relocation in the object and resolves the LSM
        // hook's BTF id for attach.
        let btf =
            Btf::from_sys_fs().map_err(|e| Error::msg(format!("bpf-lsm: kernel BTF: {e}")))?;

        let mut ebpf = EbpfLoader::new()
            .btf(Some(&btf))
            .load_file(&self.object)
            .map_err(|e| {
                Error::msg(format!(
                    "bpf-lsm: load {}: {e} (build it with `just build-ebpf`)",
                    self.object.display()
                ))
            })?;

        // Seed the maps from the store *before* attaching, so the program never
        // sees an empty policy window.
        let mode = if self.mode.enforces() {
            BpfMode::ENFORCE
        } else {
            BpfMode::AUDIT
        };
        seed_maps(&mut ebpf, &engine, mode)?;

        // Attach the in-kernel verdict to the file_open LSM hook.
        let program: &mut Lsm = ebpf
            .program_mut(HOOK)
            .ok_or_else(|| Error::msg(format!("bpf-lsm: program '{HOOK}' missing from object")))?
            .try_into()
            .map_err(|e| Error::msg(format!("bpf-lsm: '{HOOK}' is not an LSM program: {e}")))?;
        program
            .load(HOOK, &btf)
            .map_err(|e| Error::msg(format!("bpf-lsm: load program: {e}")))?;
        program
            .attach()
            .map_err(|e| Error::msg(format!("bpf-lsm: attach {HOOK}: {e}")))?;

        info!(
            mode = self.mode.as_str(),
            object = %self.object.display(),
            "bpf-lsm active on the file_open hook",
        );

        // Drain the ring buffer of denials/would-denies into the journal until
        // shutdown. The verdict already happened in-kernel; this is the learn path.
        drain_events(&mut ebpf, &shutdown)
    }
}

/// A snapshot of the store's policy, taken under the engine lock so the kernel
/// maps can be written without holding the lock across syscalls.
struct PolicySnapshot {
    subtrees: Vec<SubtreeSeed>,
    identities: Vec<IdentitySeed>,
}

/// One owned subtree to install: its directory (resolved to an inode at seed time)
/// and the owner group that owns it.
struct SubtreeSeed {
    path: PathBuf,
    owner_id: i64,
}

/// One owner identity to install: the owner group and one of its executable paths.
struct IdentitySeed {
    owner_id: i64,
    exe: PathBuf,
}

/// Fill `SUBTREES`, `OWNER_IDS`, and `SETTINGS` from the current store snapshot.
fn seed_maps(ebpf: &mut Ebpf, engine: &Arc<Mutex<Engine>>, mode: BpfMode) -> Result<()> {
    let policy = snapshot_policy(engine)?;
    let seeded = seed_subtrees(ebpf, &policy.subtrees)?;
    seed_owner_ids(ebpf, &policy.identities)?;
    seed_settings(ebpf, mode)?;
    info!(
        subtrees = seeded,
        identities = policy.identities.len(),
        "bpf-lsm seeded policy maps"
    );
    Ok(())
}

/// Read the owned subtrees and their owner identities under the engine lock.
fn snapshot_policy(engine: &Arc<Mutex<Engine>>) -> Result<PolicySnapshot> {
    let guard = engine.lock().unwrap();
    let store = guard.store();
    let rows = store.subtrees()?;
    let mut identities = Vec::new();
    for st in &rows {
        for exe in store.owner_identities(st.owner_id)? {
            identities.push(IdentitySeed {
                owner_id: st.owner_id,
                exe,
            });
        }
    }
    let subtrees = rows
        .into_iter()
        .map(|s| SubtreeSeed {
            path: s.path,
            owner_id: s.owner_id,
        })
        .collect();
    Ok(PolicySnapshot {
        subtrees,
        identities,
    })
}

/// Install each owned subtree as a (dev, inode) → owner entry. Returns how many
/// were seeded; a subtree we can't `stat` is skipped (logged), not fatal.
fn seed_subtrees(ebpf: &mut Ebpf, subtrees: &[SubtreeSeed]) -> Result<usize> {
    let mut map: BpfHashMap<_, SubtreeKey, OwnerId> =
        BpfHashMap::try_from(map_mut(ebpf, MAP_SUBTREES)?)
            .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_SUBTREES}: {e}")))?;
    let mut seeded = 0usize;
    for st in subtrees {
        match dev_ino(&st.path) {
            Some((dev, ino)) => {
                map.insert(SubtreeKey::new(dev, ino), OwnerId(st.owner_id), 0)
                    .map_err(|e| Error::msg(format!("bpf-lsm: insert subtree: {e}")))?;
                seeded += 1;
            }
            None => {
                warn!(path = %st.path.display(), "bpf-lsm: cannot stat owned subtree; skipping")
            }
        }
    }
    Ok(seeded)
}

/// Install each owner identity as an (owner id, exe-hash) membership entry.
fn seed_owner_ids(ebpf: &mut Ebpf, identities: &[IdentitySeed]) -> Result<()> {
    let mut map: BpfHashMap<_, OwnerKey, u8> = BpfHashMap::try_from(map_mut(ebpf, MAP_OWNER_IDS)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_OWNER_IDS}: {e}")))?;
    for id in identities {
        let key = OwnerKey::new(
            OwnerId(id.owner_id),
            exe_hash(id.exe.as_os_str().as_bytes()),
        );
        map.insert(key, 1u8, 0)
            .map_err(|e| Error::msg(format!("bpf-lsm: insert owner id: {e}")))?;
    }
    Ok(())
}

/// Set the one-element `SETTINGS` record: our pid (fast-allowed so we never
/// deadlock on our own opens) and the enforce/audit mode.
fn seed_settings(ebpf: &mut Ebpf, mode: BpfMode) -> Result<()> {
    let mut settings: Array<_, Settings> = Array::try_from(map_mut(ebpf, MAP_SETTINGS)?)
        .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_SETTINGS}: {e}")))?;
    settings
        .set(0, Settings::new(Pid(std::process::id()), mode), 0)
        .map_err(|e| Error::msg(format!("bpf-lsm: set settings: {e}")))?;
    Ok(())
}

/// Poll the ring buffer and log each mediated denial / would-deny until shutdown.
fn drain_events(ebpf: &mut Ebpf, shutdown: &Arc<Shutdown>) -> Result<()> {
    let mut ring = RingBuf::try_from(
        ebpf.take_map(MAP_EVENTS)
            .ok_or_else(|| Error::msg(format!("bpf-lsm: {MAP_EVENTS} missing from object")))?,
    )
    .map_err(|e| Error::msg(format!("bpf-lsm: {MAP_EVENTS}: {e}")))?;

    let raw = ring.as_raw_fd();
    while !shutdown.is_triggered() {
        // SAFETY: `raw` is the ring buffer's fd, owned by `ring` for this scope.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(POLL_TIMEOUT_MS)) {
            Ok(0) => continue, // timeout → re-check shutdown
            Ok(_) => {
                while let Some(item) = ring.next() {
                    log_event(&item);
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::msg(format!("bpf-lsm: poll: {e}"))),
        }
    }
    Ok(())
}

/// Parse one ring-buffer record and log it at the right level.
fn log_event(bytes: &[u8]) {
    let Some(event) = parse_event(bytes) else {
        warn!(
            len = bytes.len(),
            "bpf-lsm: short ring-buffer record; dropped"
        );
        return;
    };
    let path = String::from_utf8_lossy(event.path_bytes());
    let exe = String::from_utf8_lossy(event.exe_bytes());
    if event.decision == Decision::WOULD_DENY {
        warn!(pid = event.pid.0, %exe, %path, owner = event.owner.0, "would deny (audit mode)");
    } else {
        info!(pid = event.pid.0, %exe, %path, owner = event.owner.0, "deny");
    }
}

/// Reinterpret a ring-buffer record as a [`LearnEvent`]. Returns `None` if the
/// record is shorter than the struct (a truncated/garbage write).
fn parse_event(bytes: &[u8]) -> Option<LearnEvent> {
    if bytes.len() < std::mem::size_of::<LearnEvent>() {
        return None;
    }
    // SAFETY: length checked above; `LearnEvent` is `repr(C)` POD (any bit pattern
    // is valid) and the kernel reserved exactly `size_of::<LearnEvent>()` bytes.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const LearnEvent) })
}

/// A path's (device, inode) in the **kernel's** `s_dev` encoding, so it matches
/// what the eBPF side reads from `inode->i_sb->s_dev`.
fn dev_ino(path: &Path) -> Option<(Dev, Ino)> {
    let md = std::fs::metadata(path).ok()?;
    Some((kernel_dev(md.st_dev()), Ino(md.st_ino())))
}

/// Convert a glibc `st_dev` to the kernel's internal `dev_t` (`MKDEV` form,
/// `MINORBITS = 20`). glibc and the kernel encode major/minor differently, so the
/// device number the kernel stores in `super_block->s_dev` is **not** the integer
/// `stat(2)` reports — we have to re-pack it, or the (dev, inode) keys won't match
/// and every protected file would read as unprotected.
fn kernel_dev(st_dev: u64) -> Dev {
    let major = nix::libc::major(st_dev) as u64;
    let minor = nix::libc::minor(st_dev) as u64;
    Dev((major << 20) | (minor & 0x000f_ffff))
}

/// `ebpf.map_mut(name)` with a uniform error.
fn map_mut<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut aya::maps::Map> {
    ebpf.map_mut(name)
        .ok_or_else(|| Error::msg(format!("bpf-lsm: map '{name}' missing from object")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_dev_repacks_major_minor() {
        // glibc encodes (major=8, minor=2) — a typical /dev/sda2 — as this st_dev.
        let st_dev = nix::libc::makedev(8, 2);
        // Kernel MKDEV(8, 2) = (8 << 20) | 2.
        assert_eq!(kernel_dev(st_dev), Dev((8u64 << 20) | 2));
    }

    #[test]
    fn kernel_dev_handles_large_minor() {
        let st_dev = nix::libc::makedev(259, 1234);
        assert_eq!(kernel_dev(st_dev), Dev((259u64 << 20) | 1234));
    }
}
