//! Layout shared, byte-for-byte, between the eBPF data plane (`crates/bpf`) and
//! the userspace control plane (`crates/daemon`, `bpf-lsm` feature).
//!
//! The eBPF program is the boundary: it reads policy from BPF maps and returns a
//! verdict in-kernel (DESIGN §4, "BPF-LSM"). The daemon fills those maps from the
//! SQLite store and drains the ring buffer. For that to work the two sides must
//! agree exactly on every key, value, and record — so they live here, once:
//!
//! - [`ids`] — the scalar domain newtypes (`Dev`, `Ino`, `OwnerId`, `Pid`, `Mode`,
//!   `Decision`).
//! - [`maps`] — the map names and the POD key/value/record types.
//!
//! `#![no_std]` with no `aya` dependency by default, so the eBPF crate consumes it
//! cleanly. The userspace loader turns on `features = ["user"]`, which adds the
//! `aya::Pod` marker impls (required to use a type as a map key/value).

#![no_std]

pub mod ids;
pub mod maps;

pub use ids::{Decision, Dev, Ino, Mode, OwnerId, Pid};
pub use maps::{
    FileId, LearnEvent, MAP_EVENTS, MAP_OWNER_IDS, MAP_SETTINGS, MAP_SUBTREES, OwnerKey, Settings,
};
