//! Running-kernel struct field offsets — the portability shim that replaces a
//! build-time-pinned `vmlinux.rs`.
//!
//! The eBPF program cannot generate CO-RE relocations (rustc has no
//! `preserve_access_index`; see rust-lang/rust#158412), so it cannot hard-code the
//! layout of `struct file`, `dentry`, `inode`, … against the kernel it was *built*
//! on and expect those offsets to hold on the kernel it *runs* on. Instead the
//! program reads every field at an offset taken from this struct, which the daemon
//! fills by parsing the **running** kernel's BTF (`/sys/kernel/btf/vmlinux`) and
//! injects into the program's `.rodata` at load time (aya `override_global`). One
//! object, every kernel — CO-RE's portability, done in userspace.
//!
//! Each field is the **byte** offset of one kernel field, named
//! `struct_field` (or `struct_field_subfield` for a nested hop). They are read on
//! the hot path, so they are plain `u32` (every real offset fits) laid out `repr(C)`
//! to match byte-for-byte across the two crates. The daemon resolves them by member
//! *name*, transparently descending anonymous unions — so a field the kernel tucks
//! inside an anonymous union (e.g. `mm_struct.exe_file`) is still found.

/// Symbol name of the eBPF-side `.rodata` global the daemon injects offsets into.
/// The program declares `#[unsafe(no_mangle)] static OFFSETS: Offsets` (the attribute
/// needs a literal, so the two can't share this const directly — they must match by
/// hand); the loader patches it by this name (aya `override_global`).
pub const GLOBAL_OFFSETS: &str = "OFFSETS";

/// Byte offsets of the kernel fields the `file_open` hook chases, for the running
/// kernel. Injected into the eBPF program's `.rodata` by the daemon (see module
/// docs). Field order is the resolution order in the daemon; keep the two in step.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offsets {
    /// `file -> f_path.dentry` (the opened dentry; the ancestor-walk entry point).
    pub file_f_path_dentry: u32,
    /// `file -> f_inode` (the opened inode; the caller-exe identity path).
    pub file_f_inode: u32,
    /// `file -> f_mode` (`fmode_t`).
    pub file_f_mode: u32,
    /// `file -> f_flags`.
    pub file_f_flags: u32,
    /// `dentry -> d_inode`.
    pub dentry_d_inode: u32,
    /// `dentry -> d_sb` (super_block, for the device number).
    pub dentry_d_sb: u32,
    /// `dentry -> d_parent` (next ancestor; self-parent == mount root).
    pub dentry_d_parent: u32,
    /// `dentry -> d_name.name` — the component name pointer the leaf-path walk reads (see
    /// [`DecisionEvent::comps`](crate::DecisionEvent::comps)). It addresses a
    /// NUL-terminated string, so the program reads it with `bpf_probe_read_kernel_str` and
    /// needs no separate length field.
    pub dentry_d_name_name: u32,
    /// `inode -> i_ino`.
    pub inode_i_ino: u32,
    /// `inode -> i_sb` (super_block, for the device number).
    pub inode_i_sb: u32,
    /// `super_block -> s_dev`.
    pub sb_s_dev: u32,
    /// `task_struct -> mm`.
    pub task_mm: u32,
    /// `mm_struct -> exe_file`.
    pub mm_exe_file: u32,
    /// `linux_binprm -> file` — the binary being exec'd, at `bprm_check_security`. Applied
    /// to that hook's trusted context pointer, so like `file_f_*` and `dentry_d_*` it stays
    /// real under poisoning (see the daemon's `maybe_poison_offsets`).
    pub binprm_file: u32,
}

impl Offsets {
    /// The eBPF-side initializer: every offset poisoned to `u32::MAX`. If the loader
    /// ever fails to inject the real offsets, every field read targets a wild
    /// address, faults, and fails **open**, which the daemon's `self_test` catches.
    pub const POISON: Offsets = Offsets {
        file_f_path_dentry: u32::MAX,
        file_f_inode: u32::MAX,
        file_f_mode: u32::MAX,
        file_f_flags: u32::MAX,
        dentry_d_inode: u32::MAX,
        dentry_d_sb: u32::MAX,
        dentry_d_parent: u32::MAX,
        dentry_d_name_name: u32::MAX,
        inode_i_ino: u32::MAX,
        inode_i_sb: u32::MAX,
        sb_s_dev: u32::MAX,
        task_mm: u32::MAX,
        mm_exe_file: u32::MAX,
        binprm_file: u32::MAX,
    };
}

// ---- userspace-only: pass the whole struct to aya's `override_global` -------

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: a `repr(C)` aggregate of `u32`s — every bit pattern is a valid value
    // and the type is `Copy` with a fixed layout, satisfying aya's `Pod` contract
    // (used here to splice the struct's bytes into the program's `.rodata`).
    unsafe impl aya::Pod for Offsets {}
}
