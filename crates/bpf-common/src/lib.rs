//! The one definition of every map key, map value and ring record that the eBPF data plane
//! (`crates/bpf`) and the userspace control plane (`crates/daemon`, `bpf-lsm` feature)
//! exchange. Both sides compile against these types, so they cannot drift apart by a byte.
//!
//! The eBPF program reads policy from BPF maps and returns a verdict in the kernel (DESIGN
//! §4, "BPF-LSM"). The daemon fills those maps from the compiled policy and drains the ring
//! buffer.
//!
//! The crate is `#![no_std]` and has no `aya` dependency by default, so the eBPF crate can
//! use it. The userspace loader turns on `features = ["user"]`, which adds the `aya::Pod`
//! marker impls that a map key, a map value or a global requires.

#![no_std]

// `layout` defines `padded_pod!`. Macro scoping is textual, so `#[macro_use]` and declaring
// `layout` first make the macro visible to `maps` and `policy_maps` below.
#[macro_use]
mod layout;

pub mod ids;
pub mod maps;
pub mod offsets;
pub mod policy_maps;

pub use ids::{Bank, CgroupId, Dev, Ino, Nanos, Pid, Suppressed, Uid};
pub use maps::{
    DecisionEvent, FileId, MAP_EVENTS, MAP_SETTINGS, PATH_MAX_DEPTH, PATH_NAME_MAX, PathComp,
    Settings, SuppressKey, SuppressVal,
};
pub use offsets::Offsets;
pub use policy_maps::{
    Action, BankedFile, BankedObj, ClassId, CompiledRule, MAP_BLESSED, MAP_PROTECTED,
    MAP_RULE_COUNT, MAP_RULES, MAX_BLESSED, MAX_OBJECTS, MAX_RULES_PER_OBJ, NUM_BANKS, ObjId,
    Policy, SubjectFlags, SubjectMatch, rule_slot,
};
