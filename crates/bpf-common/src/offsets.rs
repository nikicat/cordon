//! The running kernel's struct field offsets, which stand in for a `vmlinux.rs` pinned at
//! build time.
//!
//! The eBPF program cannot generate CO-RE relocations, because rustc has no
//! `preserve_access_index` (rust-lang/rust#158412). So it cannot hard-code the layout of
//! `struct file`, `dentry`, `inode` and the rest from the kernel it was built on and expect
//! that layout on the kernel it runs on. Instead the program reads every field at an offset
//! from [`Offsets`]. The daemon fills that struct by parsing the running kernel's BTF
//! (`/sys/kernel/btf/vmlinux`) and injects it into the program's `.rodata` at load time
//! (aya `override_global`). One object then runs on every kernel, which is CO-RE's
//! portability done in userspace.
//!
//! Each field is the byte offset of one kernel field, named `struct_field`, or
//! `struct_field_subfield` for a nested hop. The fields are read on the hot path, so they
//! are plain `u32`s, which every real offset fits, laid out `repr(C)` to match across the
//! two crates. The daemon resolves them by member name and descends into anonymous unions,
//! so it still finds a field that the kernel tucks inside one, such as
//! `mm_struct.exe_file`.

/// The symbol name of the eBPF-side `.rodata` global that the loader patches with the
/// offsets, through aya's `override_global`. The program declares it as
/// `#[unsafe(no_mangle)] static OFFSETS: Offsets`. That attribute needs a literal, so the
/// program cannot use this const, and the two names must be kept equal by hand.
pub const GLOBAL_OFFSETS: &str = "OFFSETS";

/// The byte offsets of the kernel fields that the LSM hooks read, as the running kernel
/// lays them out. The daemon resolves the fields in declaration order, and the two orders
/// must stay the same.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offsets {
    /// `file -> f_path.dentry`, the opened dentry, where the ancestor walk starts.
    pub file_f_path_dentry: u32,
    /// `file -> f_inode`, the opened inode, which gives the caller's exe its identity.
    pub file_f_inode: u32,
    /// `file -> f_mode`, an `fmode_t`.
    pub file_f_mode: u32,
    /// `file -> f_flags`.
    pub file_f_flags: u32,
    /// `dentry -> d_inode`.
    pub dentry_d_inode: u32,
    /// `dentry -> d_sb`, the super_block that holds the device number.
    pub dentry_d_sb: u32,
    /// `dentry -> d_parent`, the next ancestor. The mount root is its own parent.
    pub dentry_d_parent: u32,
    /// `dentry -> d_name.name`, the pointer to the component name that the leaf-path walk
    /// reads (see [`DecisionEvent::comps`](crate::DecisionEvent::comps)). It points to a
    /// NUL-terminated string, which the program reads with `bpf_probe_read_kernel_str`, so
    /// no separate length field is needed.
    pub dentry_d_name_name: u32,
    /// `inode -> i_ino`.
    pub inode_i_ino: u32,
    /// `inode -> i_sb`, the super_block that holds the device number.
    pub inode_i_sb: u32,
    /// `super_block -> s_dev`.
    pub sb_s_dev: u32,
    /// `task_struct -> mm`.
    pub task_mm: u32,
    /// `mm_struct -> exe_file`.
    pub mm_exe_file: u32,
    /// `linux_binprm -> file`, the binary that `bprm_check_security` is about to execute.
    /// The program applies it to that hook's trusted context pointer, so like `file_f_*`
    /// and `dentry_d_*` it stays real under poisoning (see the daemon's
    /// `maybe_poison_offsets`).
    pub binprm_file: u32,
}

impl Offsets {
    /// The eBPF-side initializer, with every offset set to `u32::MAX`. If the loader fails
    /// to inject the real offsets, every field read targets a wild address and faults,
    /// which fails open, and the daemon's `self_test` catches that.
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

// ---- userspace only, so that aya's `override_global` takes the whole struct ----

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: a `repr(C)` aggregate of `u32`s has a valid value for every bit pattern and a
    // fixed layout, and it is `Copy`, which satisfies aya's `Pod` contract. The loader
    // relies on it to splice the struct's bytes into the program's `.rodata`.
    unsafe impl aya::Pod for Offsets {}
}
