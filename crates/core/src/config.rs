//! Location resolution shared by the daemon and the CLI so they always agree on
//! where the socket, the store, and the default zone roots live.
//!
//! Dev (`--user`): socket `$XDG_RUNTIME_DIR/cordon.sock`, store
//! `$XDG_STATE_HOME/cordon/cordon.db`. Prod (root): `/run/cordon.sock`,
//! `/var/lib/cordon/cordon.db` (root-owned — a scraper must not be able to write
//! itself in as owner, DESIGN §5). Every path honors an env override so tests
//! can run fully hermetic.

use std::env;
use std::path::PathBuf;

/// Effective uid, via a direct libc symbol so the core pulls in no extra crate.
pub fn euid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

pub fn is_root() -> bool {
    euid() == 0
}

fn home() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Path to the daemon's IPC socket. `CORDON_SOCK` overrides everything.
pub fn socket_path() -> PathBuf {
    if let Some(p) = env::var_os("CORDON_SOCK") {
        return PathBuf::from(p);
    }
    if is_root() {
        return PathBuf::from("/run/cordon.sock");
    }
    if let Some(rt) = env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("cordon.sock");
    }
    env::temp_dir().join(format!("cordon-{}.sock", euid()))
}

/// Path to the SQLite store file. `CORDON_STORE` overrides everything.
pub fn store_path() -> PathBuf {
    if let Some(p) = env::var_os("CORDON_STORE") {
        return PathBuf::from(p);
    }
    if is_root() {
        return PathBuf::from("/var/lib/cordon/cordon.db");
    }
    let base = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/state"));
    base.join("cordon/cordon.db")
}

/// The zone roots seeded into a fresh store: configured
/// traversable-but-never-owned roots inside which the first subtree level is
/// claimable. `CORDON_ZONES` (colon-separated) overrides the HOME-derived
/// defaults — used by the hermetic test harness to point at a throwaway `$HOME`.
pub fn default_zones() -> Vec<PathBuf> {
    if let Some(list) = env::var_os("CORDON_ZONES") {
        return env::split_paths(&list)
            .filter(|p| !p.as_os_str().is_empty())
            .collect();
    }
    let h = home();
    vec![
        h.clone(),
        h.join(".config"),
        h.join(".local/share"),
        h.join(".cache"),
    ]
}

/// The backend name the daemon should run. Phase 0 ships only `mock`.
pub fn backend_name() -> String {
    env::var("CORDON_BACKEND").unwrap_or_else(|_| "mock".to_string())
}
