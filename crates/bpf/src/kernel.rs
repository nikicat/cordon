//! The unsafe boundary: every read of kernel memory lives here, behind safe typed
//! handles, so the decision flow in `main.rs` is `unsafe`-free.
//!
//! ## No committed struct layout — offsets come from the running kernel
//! There is no `vmlinux.rs` here. rustc can't emit CO-RE relocations
//! (rust-lang/rust#158412), so a generated binding would pin this object to the
//! layout of whatever kernel it was *built* against and silently read garbage on any
//! other. Instead every field is read at a byte offset taken from [`OFFSETS`] — a
//! `.rodata` global the daemon fills from the running kernel's BTF and injects at
//! load time. The handles below (`File`, `Dentry`, …) are `Copy` newtypes over a raw
//! base address; each accessor reads one field at its injected offset.
//!
//! [`read_at`] (a `bpf_probe_read_kernel`, the kernel's *fault-safe* reader: a bad
//! address faults into an `Err` instead of crashing) does all the actually-unsafe
//! work. Accessors return [`Option`] — `None` ("couldn't read") becomes a fail-open
//! allow in the caller.
//!
//! There is **no path resolution** here: `bpf_d_path` is not allowed at the
//! `file_open` LSM hook, so both subtrees and executables are identified by inode
//! ([`FileId`]).

use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{LruHashMap, RingBuf};
use cordon_bpf_common::{
    Action, DecisionEvent, Dev, FileId, Ino, ObjId, Offsets, Pid, SuppressKey, SuppressVal,
};

/// Running-kernel field offsets, injected into `.rodata` by the daemon
/// (`override_global("OFFSETS", …)`) after it parses the kernel BTF. The initializer
/// is [`Offsets::POISON`] (all-ones) so a missing injection fails open + trips the
/// daemon's self-test rather than silently mis-reading; see `offsets` module docs.
#[unsafe(no_mangle)]
static OFFSETS: Offsets = Offsets::POISON;

/// Read one field of [`OFFSETS`]. Volatile so the optimizer can't fold in the POISON
/// initializer — the loader overwrites these bytes before the program is verified.
macro_rules! offset {
    ($field:ident) => {
        // SAFETY: `&raw const OFFSETS.$field` addresses an initialized `u32` in the
        // `.rodata` global; the volatile read forces the load the loader's value backs.
        unsafe { core::ptr::read_volatile(&raw const OFFSETS.$field) }
    };
}

/// Read a `T` from kernel memory at `base + off`, fault-safely. The address is pure
/// integer arithmetic (`base` is never dereferenced in Rust — only handed to the
/// probe helper), so a wild offset can't be UB, only an `Err`. `T` is POD here
/// (a pointer or an integer — every bit pattern is valid).
fn read_at<T>(base: *const u8, off: u32) -> Option<T> {
    let src = base.wrapping_add(off as usize) as *const T;
    unsafe { bpf_probe_read_kernel(src).ok() }
}

/// Read a pointer field (the common case: chasing one `struct foo *` to the next).
fn ptr_at(base: *const u8, off: u32) -> Option<*const u8> {
    read_at::<*const u8>(base, off)
}

/// The thread-group id (userspace pid) of the current task.
pub fn current_pid() -> Pid {
    Pid((bpf_get_current_pid_tgid() >> 32) as u32)
}

/// A `struct file *`.
#[derive(Clone, Copy)]
pub struct File(*const u8);

impl File {
    /// The nth pointer argument of the LSM hook (arg 0 of `file_open` is the file).
    pub fn from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> File {
        File(unsafe { ctx.arg(n) })
    }
    /// The file's dentry (entry point for the ancestor walk).
    pub fn dentry(self) -> Option<Dentry> {
        Some(Dentry(ptr_at(self.0, offset!(file_f_path_dentry))?))
    }
    /// The file's inode (via the direct `f_inode` field).
    pub fn inode(self) -> Option<Inode> {
        Some(Inode(ptr_at(self.0, offset!(file_f_inode))?))
    }
    /// `f_mode` (`fmode_t`): `FMODE_READ`/`FMODE_WRITE` encode read/write intent at open.
    pub fn f_mode(self) -> Option<u32> {
        read_at::<u32>(self.0, offset!(file_f_mode))
    }
    /// `f_flags`: `O_CREAT` encodes create intent at open.
    pub fn f_flags(self) -> Option<u32> {
        read_at::<u32>(self.0, offset!(file_f_flags))
    }
}

/// A `struct dentry *`. `PartialEq` compares the pointer (a dentry that is its own
/// parent is the mount root — the walk's stop condition).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Dentry(*const u8);

impl Dentry {
    pub fn inode(self) -> Option<Inode> {
        Some(Inode(ptr_at(self.0, offset!(dentry_d_inode))?))
    }
    pub fn super_block(self) -> Option<SuperBlock> {
        Some(SuperBlock(ptr_at(self.0, offset!(dentry_d_sb))?))
    }
    pub fn parent(self) -> Option<Dentry> {
        Some(Dentry(ptr_at(self.0, offset!(dentry_d_parent))?))
    }
}

/// A `struct inode *`.
#[derive(Clone, Copy)]
pub struct Inode(*const u8);

impl Inode {
    pub fn ino(self) -> Option<Ino> {
        // i_ino is c_ulong == u64.
        Some(Ino(read_at::<u64>(self.0, offset!(inode_i_ino))?))
    }
    pub fn super_block(self) -> Option<SuperBlock> {
        Some(SuperBlock(ptr_at(self.0, offset!(inode_i_sb))?))
    }
    /// The inode's `(dev, inode)` identity.
    pub fn file_id(self) -> Option<FileId> {
        Some(FileId::new(self.super_block()?.dev()?, self.ino()?))
    }
}

/// A `struct super_block *`.
#[derive(Clone, Copy)]
pub struct SuperBlock(*const u8);

impl SuperBlock {
    /// The device number in the kernel's `s_dev` encoding (matches what the daemon
    /// re-packs `stat(2)`'s `st_dev` into).
    pub fn dev(self) -> Option<Dev> {
        // s_dev is dev_t == u32.
        Some(Dev(read_at::<u32>(self.0, offset!(sb_s_dev))? as u64))
    }
}

/// The current task's executable identity (`mm->exe_file`'s inode). `None` for a
/// kernel thread (no `mm`) or an unreadable chain — the caller fails open.
pub fn caller_exe() -> Option<FileId> {
    current_exe_file()?.inode()?.file_id()
}

/// Push one logged decision to the ring buffer. Best-effort: a full ring drops the
/// *observation*, never the verdict. The caller builds the record (it knows the
/// matched policy and the mode-dependent decision); we just reserve + write + submit.
pub fn emit(event: DecisionEvent) {
    let Some(mut entry) = EVENTS.reserve::<DecisionEvent>(0) else {
        return;
    };
    let e = entry.as_mut_ptr();
    // SAFETY: `e` is a freshly reserved `DecisionEvent` slot in ring memory; the write
    // initializes the whole record before `submit`.
    unsafe {
        e.write(event);
    }
    entry.submit(0);
}

/// The suppression window: at most one ring record per `(exe, object, action)` per this
/// many nanoseconds (1s). The audit found tools re-open the same config hundreds of
/// times per run; a 1s window collapses each such burst to its first occurrence + a
/// count, keeping the ring (and the learn path) quiet without losing the event.
const SUPPRESS_WINDOW_NS: u64 = 1_000_000_000;

/// The in-kernel event suppressor (M1 §1g): the hottest decision keys and when each
/// last emitted. **LRU** so a full map evicts the coldest key rather than refusing a
/// new hot one. Kernel-internal — the daemon never touches it.
#[map]
static SUPPRESS: LruHashMap<SuppressKey, SuppressVal> = LruHashMap::with_max_entries(4096, 0);

/// Throttle a logged decision. Returns `Some(suppressed)` when this open should emit a
/// ring record — `suppressed` being how many identical decisions were folded in since
/// the previous emit for this key — or `None` when it falls inside the window and is
/// suppressed (its only effect a bumped counter). Best-effort: a failed map write just
/// means a slightly off count, never a missed *first* occurrence.
pub fn throttle(exe: FileId, obj: ObjId, action: Action) -> Option<u32> {
    let now = now_ns();
    let key = SuppressKey::new(exe, obj, action);
    match suppress_get(&key) {
        // Seen before, still inside the window → suppress, bump the pending count.
        Some(prev) if now.wrapping_sub(prev.last_ns) < SUPPRESS_WINDOW_NS => {
            let _ = SUPPRESS.insert(
                &key,
                &SuppressVal::new(prev.last_ns, prev.suppressed.saturating_add(1)),
                0,
            );
            None
        }
        // Window elapsed → emit, reporting the burst we held back, and reset.
        Some(prev) => {
            let _ = SUPPRESS.insert(&key, &SuppressVal::new(now, 0), 0);
            Some(prev.suppressed)
        }
        // First occurrence → emit immediately, start tracking.
        None => {
            let _ = SUPPRESS.insert(&key, &SuppressVal::new(now, 0), 0);
            Some(0)
        }
    }
}

/// Copy the suppressor value for `key` out from behind aya's `unsafe` map ref (which
/// borrows concurrently-mutable map memory) — keeps the decision flow `unsafe`-free.
fn suppress_get(key: &SuppressKey) -> Option<SuppressVal> {
    unsafe { SUPPRESS.get(key).copied() }
}

/// Monotonic nanoseconds since boot (`bpf_ktime_get_ns`), the suppressor's clock.
fn now_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

/// The current task's `mm->exe_file`, if any (kernel threads have no `mm`).
fn current_exe_file() -> Option<File> {
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let mm = ptr_at(task, offset!(task_mm))?;
    if mm.is_null() {
        return None;
    }
    let exe_file = ptr_at(mm, offset!(mm_exe_file))?;
    (!exe_file.is_null()).then_some(File(exe_file))
}

/// The learn-path ring buffer drained by the daemon.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
