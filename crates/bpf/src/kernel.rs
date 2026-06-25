//! The unsafe boundary: every read of kernel memory lives here, behind safe typed
//! handles, so the decision flow in `main.rs` is `unsafe`-free.
//!
//! [`read`] (a `bpf_probe_read_kernel`, the *safe* way to read possibly-bad kernel
//! pointers: it faults into an error instead of crashing) does all the actually-
//! unsafe work. The handles (`File`, `Dentry`, …) are `Copy` newtypes over a raw
//! pointer; each accessor chases one field. Forming a field pointer
//! (`&raw const (*p).field`) still dereferences a raw pointer, so it needs
//! `unsafe` — but it's confined here. Accessors return [`Option`] — `None`
//! ("couldn't read") becomes a fail-open allow in the caller.
//!
//! There is **no path resolution** here: `bpf_d_path` is not allowed at the
//! `file_open` LSM hook, so both subtrees and executables are identified by inode
//! ([`FileId`]). `file.f_path` and `mm_struct.exe_file` sit inside anonymous
//! unions in the kernel BTF, hence the `__bindgen_anon_1` hops.

use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use cordon_bpf_common::{Decision, Dev, FileId, Ino, LearnEvent, Mode, OwnerId, Pid};

use crate::vmlinux::{dentry, file, inode, mm_struct, super_block, task_struct};

/// The one place kernel memory is read. `bpf_probe_read_kernel` is the kernel's
/// fault-safe reader, so exposing it as a safe `fn` is sound for the POD field
/// types we use (pointers and integers — every bit pattern is valid). `None` on a
/// bad read.
fn read<T>(ptr: *const T) -> Option<T> {
    unsafe { bpf_probe_read_kernel(ptr).ok() }
}

/// The thread-group id (userspace pid) of the current task.
pub fn current_pid() -> Pid {
    Pid((bpf_get_current_pid_tgid() >> 32) as u32)
}

/// A `struct file *`.
#[derive(Clone, Copy)]
pub struct File(*const file);

impl File {
    /// The nth pointer argument of the LSM hook (arg 0 of `file_open` is the file).
    pub fn from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> File {
        File(unsafe { ctx.arg(n) })
    }
    /// The file's dentry (entry point for the ancestor walk).
    pub fn dentry(self) -> Option<Dentry> {
        let p = unsafe { &raw const (*self.0).__bindgen_anon_1.f_path.dentry };
        Some(Dentry(read(p)? as *const dentry))
    }
    /// The file's inode (via the direct `f_inode` field).
    pub fn inode(self) -> Option<Inode> {
        let p = unsafe { &raw const (*self.0).f_inode };
        Some(Inode(read(p)? as *const inode))
    }
}

/// A `struct dentry *`. `PartialEq` compares the pointer (a dentry that is its own
/// parent is the mount root — the walk's stop condition).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Dentry(*const dentry);

impl Dentry {
    pub fn inode(self) -> Option<Inode> {
        let p = unsafe { &raw const (*self.0).d_inode };
        Some(Inode(read(p)? as *const inode))
    }
    pub fn super_block(self) -> Option<SuperBlock> {
        let p = unsafe { &raw const (*self.0).d_sb };
        Some(SuperBlock(read(p)? as *const super_block))
    }
    pub fn parent(self) -> Option<Dentry> {
        let p = unsafe { &raw const (*self.0).d_parent };
        Some(Dentry(read(p)? as *const dentry))
    }
}

/// A `struct inode *`.
#[derive(Clone, Copy)]
pub struct Inode(*const inode);

impl Inode {
    pub fn ino(self) -> Option<Ino> {
        let p = unsafe { &raw const (*self.0).i_ino };
        Some(Ino(read(p)?)) // i_ino is c_ulong == u64
    }
    pub fn super_block(self) -> Option<SuperBlock> {
        let p = unsafe { &raw const (*self.0).i_sb };
        Some(SuperBlock(read(p)? as *const super_block))
    }
    /// The inode's `(dev, inode)` identity.
    pub fn file_id(self) -> Option<FileId> {
        Some(FileId::new(self.super_block()?.dev()?, self.ino()?))
    }
}

/// A `struct super_block *`.
#[derive(Clone, Copy)]
pub struct SuperBlock(*const super_block);

impl SuperBlock {
    /// The device number in the kernel's `s_dev` encoding (matches what the daemon
    /// re-packs `stat(2)`'s `st_dev` into).
    pub fn dev(self) -> Option<Dev> {
        let p = unsafe { &raw const (*self.0).s_dev };
        Some(Dev(read(p)? as u64))
    }
}

/// The current task's executable identity (`mm->exe_file`'s inode). `None` for a
/// kernel thread (no `mm`) or an unreadable chain — the caller fails open.
pub fn caller_exe() -> Option<FileId> {
    current_exe_file()?.inode()?.file_id()
}

/// Push one denial / would-deny record to the ring buffer. Best-effort: a full
/// ring drops the *observation*, never the verdict.
pub fn emit(pid: Pid, owner: OwnerId, subtree: FileId, exe: FileId, mode: Mode) {
    let Some(mut entry) = EVENTS.reserve::<LearnEvent>(0) else {
        return;
    };
    let decision = if mode.enforces() {
        Decision::DENY
    } else {
        Decision::WOULD_DENY
    };
    let e = entry.as_mut_ptr();
    // SAFETY: `e` is a freshly reserved `LearnEvent` slot in ring memory; the write
    // initializes the whole record before `submit`.
    unsafe {
        e.write(LearnEvent {
            pid,
            decision,
            owner,
            subtree,
            exe,
        });
    }
    entry.submit(0);
}

/// The current task's `mm->exe_file`, if any (kernel threads have no `mm`).
fn current_exe_file() -> Option<File> {
    let task = unsafe { bpf_get_current_task() } as *const task_struct;
    let mm: *const mm_struct = read(unsafe { &raw const (*task).mm })?;
    if mm.is_null() {
        return None;
    }
    let exe_file: *const file = read(unsafe { &raw const (*mm).__bindgen_anon_1.exe_file })?;
    (!exe_file.is_null()).then_some(File(exe_file))
}

/// The learn-path ring buffer drained by the daemon.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
