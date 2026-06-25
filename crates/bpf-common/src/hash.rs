//! Identity hashing.
//!
//! Owner identity is a variable-length executable path (e.g. `/usr/bin/python3`),
//! but a BPF map key is fixed-width — so we key on a hash of the path. The kernel
//! side (looking up the *caller's* exe) and the userspace loader (installing the
//! *owner's* exe) MUST compute the byte-identical value, so both call this one
//! function, which wraps the canonical [`fnv`] crate rather than re-deriving the
//! algorithm. FNV-1a is deterministic and seedless, which is exactly what cross-
//! process agreement needs.
//!
//! This is **best-effort identity, not the boundary** (DESIGN §3): a path hash is
//! not collision-resistant against an adversary who can place a binary at a path
//! of their choosing. The hardened replacement is content-digest identity
//! (`bpf_ima_file_hash` / fsverity); FNV-of-path is the increment-1 stand-in that
//! matches the path-keyed ownership store.

use crate::ids::ExeHash;
use core::hash::Hasher;
use fnv::FnvHasher;

/// FNV-1a (64-bit) over `bytes`. `FnvHasher::default()` seeds with the standard
/// offset basis, so this is stable across processes and builds.
pub fn exe_hash(bytes: &[u8]) -> ExeHash {
    let mut h = FnvHasher::default();
    h.write(bytes);
    ExeHash(h.finish())
}
