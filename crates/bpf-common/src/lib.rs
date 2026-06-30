//! Layout shared, byte-for-byte, between the eBPF data plane (`crates/bpf`) and
//! the userspace control plane (`crates/daemon`, `bpf-lsm` feature).
//!
//! The eBPF program is the boundary: it reads policy from BPF maps and returns a
//! verdict in-kernel (DESIGN §4, "BPF-LSM"). The daemon fills those maps from the
//! SQLite store and drains the ring buffer. For that to work the two sides must
//! agree exactly on every key, value, and record — so they live here, once:
//!
//! - [`ids`] — the scalar domain newtypes (`Dev`, `Ino`, `Pid`, `Decision`, `Bank`).
//! - [`maps`] — the map names and the POD key/value/record types.
//! - [`offsets`] — the running-kernel field offsets the daemon resolves from BTF
//!   and injects into the program's `.rodata` (the CO-RE-substitute portability
//!   shim).
//!
//! `#![no_std]` with no `aya` dependency by default, so the eBPF crate consumes it
//! cleanly. The userspace loader turns on `features = ["user"]`, which adds the
//! `aya::Pod` marker impls (required to use a type as a map key/value or global).

#![no_std]

pub mod ids;
pub mod maps;
pub mod offsets;
pub mod policy_maps;

pub use ids::{Bank, Decision, Dev, Ino, Nanos, Opens, Pid, Suppressed, SuppressedTotal, Uid};
pub use maps::{
    DecisionEvent, FileId, MAP_EVENTS, MAP_SETTINGS, MAP_SUPPRESS, PATH_MAX_DEPTH, PATH_NAME_MAX,
    PathComp, Settings, SuppressKey, SuppressVal,
};
pub use offsets::Offsets;
pub use policy_maps::{
    Action, BankedFile, BankedObj, CompiledRule, MAP_PROTECTED, MAP_RULE_COUNT, MAP_RULES,
    MAX_OBJECTS, MAX_RULES_PER_OBJ, NUM_BANKS, ObjId, Policy, SubjectMatch, rule_slot,
};
