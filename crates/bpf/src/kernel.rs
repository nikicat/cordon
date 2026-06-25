//! The unsafe boundary: every read of kernel memory lives here, behind safe typed
//! handles, so the decision flow in `main.rs` is `unsafe`-free.
//!
//! Two primitives do all the actually-unsafe work — [`read`] (a `bpf_probe_read_
//! kernel`, the *safe* way to read possibly-bad kernel pointers: it faults into an
//! error instead of crashing) and [`d_path_into`] (`bpf_d_path`). The handles
//! (`File`, `Dentry`, …) are `Copy` newtypes over a raw pointer; each accessor
//! chases one field. Forming a field pointer (`&raw const (*p).field`) still
//! dereferences a raw pointer, so it needs `unsafe` — but it's confined here. The
//! accessors return [`Option`] — `None` ("couldn't read") becomes a fail-open allow
//! in the caller; no errno is surfaced because we never act on one.
//!
//! Field paths follow the kernel BTF: `file.f_path` and `mm_struct.exe_file` sit
//! inside anonymous unions, hence the `__bindgen_anon_1` hops.

use aya_ebpf::cty::c_char;
use aya_ebpf::helpers::r#gen::bpf_d_path;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{PerCpuArray, RingBuf};
use cordon_bpf_common::{
    exe_hash, Decision, Dev, ExeHash, Ino, LearnEvent, Mode, OwnerId, Pid, PATH_CAP,
};

use crate::vmlinux::{dentry, file, inode, mm_struct, path, super_block, task_struct};

/// The one place kernel memory is read. `bpf_probe_read_kernel` is the kernel's
/// fault-safe reader, so exposing it as a safe `fn` is sound for the POD field
/// types we use (pointers and integers — every bit pattern is valid). `None` on a
/// bad read.
fn read<T>(ptr: *const T) -> Option<T> {
    unsafe { bpf_probe_read_kernel(ptr).ok() }
}

/// `bpf_d_path` a `struct path` into `buf`; returns the valid byte length
/// (excluding the trailing NUL), clamped to the buffer. 0 on any error. The
/// `as *mut _` bridges our BTF `path` to the one in `bpf_d_path`'s signature.
fn d_path_into(p: PathRef, buf: *mut [u8; PATH_CAP]) -> usize {
    let ret = unsafe { bpf_d_path(p.0 as *mut _, buf as *mut c_char, PATH_CAP as u32) };
    if ret <= 0 {
        return 0;
    }
    ((ret as usize) - 1).min(PATH_CAP)
}

/// The thread-group id (userspace pid) of the current task.
pub fn current_pid() -> Pid {
    Pid((bpf_get_current_pid_tgid() >> 32) as u32)
}

/// A `struct path *` — opaque to callers; only `kernel` resolves it.
#[derive(Clone, Copy)]
pub struct PathRef(*const path);

/// A `struct file *`.
#[derive(Clone, Copy)]
pub struct File(*const file);

impl File {
    /// The nth pointer argument of the LSM hook (arg 0 of `file_open` is the file).
    pub fn from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> File {
        File(unsafe { ctx.arg(n) })
    }
    pub fn dentry(self) -> Option<Dentry> {
        let p = unsafe { &raw const (*self.0).__bindgen_anon_1.f_path.dentry };
        Some(Dentry(read(p)? as *const dentry))
    }
    pub fn path(self) -> PathRef {
        PathRef(unsafe { &raw const (*self.0).__bindgen_anon_1.f_path })
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

/// FNV-1a of the current task's executable path, via the off-stack scratch buffer.
/// `None` when there is no exe (kernel thread) or the path can't be resolved — the
/// caller fails open.
pub fn caller_exe_hash() -> Option<ExeHash> {
    let exe = current_exe_file()?;
    let scratch = SCRATCH.get_ptr_mut(0)?;
    let n = d_path_into(exe.path(), unsafe { &raw mut (*scratch).exe });
    let bytes = unsafe { (*scratch).exe.get(..n) }.unwrap_or(&[]);
    Some(exe_hash(bytes))
}

/// Push one denial / would-deny record to the ring buffer. Best-effort: a full
/// ring drops the *observation*, never the verdict. Filled in place in ring
/// memory (a `LearnEvent` is too big for the 512-byte BPF stack).
pub fn emit(file: File, pid: Pid, owner: OwnerId, dev: Dev, ino: Ino, exe: ExeHash, mode: Mode) {
    let Some(mut entry) = EVENTS.reserve::<LearnEvent>(0) else {
        return;
    };
    let e = entry.as_mut_ptr();
    let decision = if mode.enforces() {
        Decision::DENY
    } else {
        Decision::WOULD_DENY
    };
    // SAFETY: `e` points at a freshly reserved `LearnEvent` slot in ring memory; we
    // initialize every field before `submit`. `d_path_into` writes its buffer.
    unsafe {
        (*e).pid = pid;
        (*e).decision = decision;
        (*e).owner = owner;
        (*e).exe_hash = exe;
        (*e).dev = dev;
        (*e).ino = ino;
        (*e).path_len = d_path_into(file.path(), &raw mut (*e).path) as u32;
        (*e).exe_len = current_exe_file()
            .map(|exe| d_path_into(exe.path(), &raw mut (*e).exe))
            .unwrap_or(0) as u32;
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

// ---- plumbing maps (not policy; live with the unsafe that uses them) -------

/// Off-stack scratch for path resolution. Per-CPU so concurrent hooks don't clash.
#[repr(C)]
pub struct Scratch {
    exe: [u8; PATH_CAP],
}
#[map]
static SCRATCH: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);

/// The learn-path ring buffer drained by the daemon.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
