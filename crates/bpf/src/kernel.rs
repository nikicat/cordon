//! The unsafe boundary. Every read of kernel memory lives here, behind safe typed handles,
//! so the decision flow in `main.rs` has no `unsafe` code.
//!
//! ## Offsets come from the running kernel
//! There is no `vmlinux.rs` here. Every field is read at a byte offset taken from
//! [`OFFSETS`], which the daemon fills from the running kernel's BTF (see
//! `cordon_bpf_common::offsets` for why). The handles below, such as `File` and `Dentry`,
//! are `Copy` newtypes over a raw base address, and each accessor reads one field at its
//! injected offset.
//!
//! [`read_at`] does all the truly unsafe work through `bpf_probe_read_kernel`, the kernel's
//! fault-safe reader, which turns a bad address into an `Err` instead of a crash. Accessors
//! return [`Option`], where `None` means that the read failed, and the decision flow fails
//! open on it. Files are identified by inode ([`FileId`]), never by path.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_task,
    bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{LruHashMap, PerCpuArray, RingBuf};
use cordon_bpf_common::{
    Action, CgroupId, ClassId, DecisionEvent, Dev, FileId, Ino, Nanos, Offsets, PathComp, Pid,
    Policy, SuppressKey, SuppressVal, Suppressed, Uid, PATH_MAX_DEPTH, PATH_NAME_MAX,
};

/// The running kernel's field offsets, which the daemon injects into `.rodata` with
/// `override_global("OFFSETS", …)`. The initializer is [`Offsets::POISON`], and its doc
/// says what a missing injection does.
#[unsafe(no_mangle)]
static OFFSETS: Offsets = Offsets::POISON;

/// Reads one field of [`OFFSETS`]. The read is volatile so that the optimizer cannot fold
/// in the `POISON` initializer, because the loader overwrites these bytes before the
/// program is verified.
macro_rules! offset {
    ($field:ident) => {
        // SAFETY: `&raw const OFFSETS.$field` addresses an initialized `u32` in the
        // `.rodata` global, and the volatile read forces a load of the value that the
        // loader wrote.
        unsafe { core::ptr::read_volatile(&raw const OFFSETS.$field) }
    };
}

/// Returns the `T` at `base + off` in kernel memory, or `None` when the address faults.
/// `T` is a pointer or an integer here, so every bit pattern is a valid value.
fn read_at<T>(base: *const u8, off: u32) -> Option<T> {
    // The address is integer arithmetic only. Rust never dereferences `base`, which only
    // the probe helper sees, so a wild offset is an `Err`, never UB.
    let src = base.wrapping_add(off as usize) as *const T;
    unsafe { bpf_probe_read_kernel(src).ok() }
}

/// Returns the pointer field at `base + off`, which is how a walk follows one
/// `struct foo *` to the next.
fn ptr_at(base: *const u8, off: u32) -> Option<*const u8> {
    read_at::<*const u8>(base, off)
}

/// Returns the thread-group id, which is the userspace pid, of the current task.
pub fn current_pid() -> Pid {
    Pid((bpf_get_current_pid_tgid() >> 32) as u32)
}

/// Returns the real uid of the current task, which is the low 32 bits of
/// `bpf_get_current_uid_gid`. The high 32 bits are the gid.
pub fn current_uid() -> Uid {
    Uid(bpf_get_current_uid_gid() as u32)
}

/// Returns the current task's cgroup-v2 id (`bpf_get_current_cgroup_id`). The verifier
/// accepts this general helper at the `file_open` LSM hook on the CI-pinned kernel.
pub fn current_cgroup_id() -> CgroupId {
    // SAFETY: the helper takes no arguments and returns a scalar id, so it touches no
    // pointers and is always callable.
    CgroupId(unsafe { bpf_get_current_cgroup_id() })
}

/// A `struct file *`.
#[derive(Clone, Copy)]
pub struct File(*const u8);

impl File {
    /// Returns the `n`th pointer argument of the LSM hook as a file. Arg 0 of `file_open`
    /// is the file.
    pub fn from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> File {
        File(unsafe { ctx.arg(n) })
    }
    /// Returns the file's dentry, where the ancestor walk starts.
    pub fn dentry(self) -> Option<Dentry> {
        Some(Dentry(ptr_at(self.0, offset!(file_f_path_dentry))?))
    }
    /// Returns the file's inode, read from its `f_inode` field.
    pub fn inode(self) -> Option<Inode> {
        Some(Inode(ptr_at(self.0, offset!(file_f_inode))?))
    }
    /// Returns the file's mode (an `fmode_t`). Its `FMODE_READ` and `FMODE_WRITE` bits
    /// encode the intent to read and write.
    pub fn f_mode(self) -> Option<u32> {
        read_at::<u32>(self.0, offset!(file_f_mode))
    }
    /// Returns the file's open flags. Their `O_CREAT` bit encodes the intent to create.
    pub fn f_flags(self) -> Option<u32> {
        read_at::<u32>(self.0, offset!(file_f_flags))
    }
}

/// A `struct linux_binprm *`, which describes the exec in progress at
/// `bprm_check_security`.
#[derive(Clone, Copy)]
pub struct Binprm(*const u8);

impl Binprm {
    /// Returns the `n`th pointer argument of the LSM hook as a binprm. Arg 0 of
    /// `bprm_check_security` is the binprm.
    pub fn from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> Binprm {
        Binprm(unsafe { ctx.arg(n) })
    }
    /// Returns the binary about to be executed (`bprm->file`). It is not the caller (see
    /// `decide_exec`).
    pub fn file(self) -> Option<File> {
        Some(File(ptr_at(self.0, offset!(binprm_file))?))
    }
}

/// A `struct dentry *`. Equality compares the pointers, which is how a walk detects the
/// mount root, since the mount root is the one dentry that is its own parent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Dentry(*const u8);

impl Dentry {
    /// Returns the `n`th pointer argument of the LSM hook as a dentry, for the hooks whose
    /// arguments are dentries rather than a `struct file`. For example, `old_dentry` is
    /// arg 0 of `inode_link` and arg 1 of `inode_rename`, and `inode_unlink` and
    /// `inode_rmdir` take the dentry as arg 1.
    ///
    /// The caller owns the index, and nothing type-checks it. Reading an `inode *`
    /// argument as a dentry yields a plausible but wrong pointer whose field reads fail,
    /// and that fails open, silently. The daemon's `self_test` exercises every hook, so a
    /// wrong index fails loudly at startup.
    pub fn from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> Dentry {
        Dentry(unsafe { ctx.arg(n) })
    }
    /// Returns the dentry's inode, or `None` when the dentry is negative, meaning that
    /// `d_inode` is NULL because the name does not exist yet.
    ///
    /// The distinction decides a verdict, since a positive rename destination is about to
    /// be destroyed (see `decide_reparent`). So the NULL is tested here rather than left to
    /// fault on the next read.
    pub fn inode(self) -> Option<Inode> {
        let inode = ptr_at(self.0, offset!(dentry_d_inode))?;
        (!inode.is_null()).then_some(Inode(inode))
    }
    pub fn super_block(self) -> Option<SuperBlock> {
        Some(SuperBlock(ptr_at(self.0, offset!(dentry_d_sb))?))
    }
    pub fn parent(self) -> Option<Dentry> {
        Some(Dentry(ptr_at(self.0, offset!(dentry_d_parent))?))
    }
    /// Reads this dentry's component name (`d_name.name`, a NUL-terminated string) into
    /// `slot` for leaf-path reconstruction. Returns the number of bytes read, not counting
    /// the NUL that the helper writes, or `None` when the name pointer or the string is
    /// unreadable. A return of `PATH_NAME_MAX - 1` or more means that the name was
    /// truncated into the slot.
    pub fn name_into(self, slot: &mut PathComp) -> Option<usize> {
        let name = ptr_at(self.0, offset!(dentry_d_name_name))?;
        // SAFETY: `name` is a kernel `const char *` to a NUL-terminated string. The helper
        // is fault-safe, so a bad address yields `Err` and never UB, and it writes at most
        // `slot.len()` bytes, always NUL-terminating them.
        let read = unsafe { bpf_probe_read_kernel_str_bytes(name, &mut slot.0) }.ok()?;
        Some(read.len())
    }
}

/// A `struct inode *`.
#[derive(Clone, Copy)]
pub struct Inode(*const u8);

impl Inode {
    pub fn ino(self) -> Option<Ino> {
        // `i_ino` is a `c_ulong`, which is a u64 on BPF.
        Some(Ino(read_at::<u64>(self.0, offset!(inode_i_ino))?))
    }
    pub fn super_block(self) -> Option<SuperBlock> {
        Some(SuperBlock(ptr_at(self.0, offset!(inode_i_sb))?))
    }
    /// Returns the inode's `(dev, ino)` identity.
    pub fn file_id(self) -> Option<FileId> {
        Some(FileId::new(self.super_block()?.dev()?, self.ino()?))
    }
}

/// A `struct super_block *`.
#[derive(Clone, Copy)]
pub struct SuperBlock(*const u8);

impl SuperBlock {
    /// Returns the device number in the kernel's `s_dev` encoding. It matches the device
    /// that the daemon's `proc::file_id` takes from the mount table, not `stat(2)`'s
    /// `st_dev`.
    pub fn dev(self) -> Option<Dev> {
        // `s_dev` is a `dev_t`, which is a u32 in the kernel.
        Some(Dev(read_at::<u32>(self.0, offset!(sb_s_dev))? as u64))
    }
}

/// Returns the identity of the current task's executable, which is the inode of
/// `mm->exe_file`. Returns `None` for a kernel thread, which has no `mm`, or when the chain
/// is unreadable.
pub fn caller_exe() -> Option<FileId> {
    current_exe_file()?.inode()?.file_id()
}

/// Per-CPU scratch space for assembling one [`DecisionEvent`] off the stack. The record
/// carries the reconstructed path and is too large for the BPF 512-byte stack, so [`emit`]
/// fills this slot and copies it into the ring. The slot is per CPU, and the program
/// cannot be preempted at this hook, so no other invocation clobbers it between the fill
/// and the copy.
#[map]
static SCRATCH: PerCpuArray<DecisionEvent> = PerCpuArray::with_max_entries(1, 0);

/// One logged decision, which the caller assembles and hands to [`emit`] as a unit.
///
/// It is a struct rather than a parameter list for two reasons. BPF passes at most five
/// arguments in registers and has no stack for the rest, so a long positional `emit` links
/// only while LLVM happens to inline it, and a second call site turns that into "stack
/// arguments are not supported". Also, three of these fields are [`FileId`]s, which a
/// positional call site could transpose in complete silence, for example swapping the
/// object and the leaf in every journal line. Named fields cost nothing and make both
/// problems structural.
///
/// It never materializes at runtime. [`emit`] is `#[inline(always)]`, so LLVM promotes
/// these fields straight to registers. That inlining is also required, as the note on
/// `emit` explains.
pub struct Record {
    /// The acting task.
    pub pid: Pid,
    /// The acting task's real uid, which the daemon resolves to a login name.
    pub uid: Uid,
    /// The subject, identified by the inode of `mm->exe_file`.
    pub exe: FileId,
    /// The matched protected object's identity.
    pub object: FileId,
    /// The affected file's own identity. It equals `object` when the rule names the file.
    pub leaf: FileId,
    /// The actions that the journal records, which can be several bits, such as read, write
    /// and create for one open.
    pub action: Action,
    /// How the access was handled and why: an explicit `deny` rule, the `default-deny`
    /// fallthrough, the structural `escape-deny`, or an `audit`.
    pub policy: Policy,
    /// The repeats that the in-kernel throttle folded into this record.
    pub suppressed: Suppressed,
    /// The caller's resolved blessing class, or [`ClassId::UNBLESSED`] if it has none.
    pub blessing: ClassId,
    /// The dentry where the `d_name` walk starts.
    pub leaf_dentry: Dentry,
    /// The dentry where the `d_name` walk stops, found by a pointer compare.
    pub object_dentry: Dentry,
}

/// Pushes one logged decision to the ring buffer, with the affected file's leaf path
/// relative to the matched protected object. It is best-effort, so a full ring or a
/// missing scratch slot drops the observation, never the verdict.
///
/// `#[inline(always)]` is load-bearing, not a hint. Outlined, `emit` becomes a fifth call
/// frame (hook → decide → consult → emit → memcpy), and the v6.12 verifier loses its
/// backtracking precision across it. `BPF_PROG_LOAD` then fails with `E2BIG` and a storm
/// of `mark_precise: frame4` lines. Inlined, [`Record`] is scalarized away, and the frame
/// disappears with it.
#[inline(always)]
pub fn emit(rec: &Record) {
    let Some(ev) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: `ev` is this CPU's scratch `DecisionEvent`. Every field below is written, the
    // scalars directly and the path through `fill_comps`, before the record is copied to
    // the ring. The writes go straight into map memory, with no large stack temporary.
    unsafe {
        (*ev).exe = rec.exe;
        (*ev).object = rec.object;
        (*ev).leaf = rec.leaf;
        (*ev).action = rec.action;
        (*ev).pid = rec.pid;
        (*ev).uid = rec.uid;
        (*ev).suppressed = rec.suppressed;
        (*ev).policy = rec.policy;
        (*ev).blessing = rec.blessing;
        let (depth, trunc) = fill_comps(rec.leaf_dentry, rec.object_dentry, &mut (*ev).comps);
        (*ev).depth = depth;
        (*ev).trunc = trunc as u8;
    }

    let Some(mut entry) = EVENTS.reserve::<DecisionEvent>(0) else {
        return;
    };
    // SAFETY: both regions are exactly `size_of::<DecisionEvent>()` and do not overlap,
    // since one is the per-CPU scratch and the other a ring slot. Copying from map to ring
    // avoids any stack-sized temporary.
    unsafe {
        core::ptr::copy_nonoverlapping(
            ev as *const u8,
            entry.as_mut_ptr() as *mut u8,
            core::mem::size_of::<DecisionEvent>(),
        );
    }
    entry.submit(0);
}

/// Fills `comps` with the affected file's path components in leaf-first order, from
/// `leaf_dentry` up to but not including `object_dentry`, which is the matched protected
/// object's dentry. Returns the number of valid components, and whether the path was cut
/// short because it was deeper than [`PATH_MAX_DEPTH`], a name was longer than
/// [`PATH_NAME_MAX`], or a component was unreadable.
///
/// It takes a dentry rather than a file, so the mutation hooks, which never see a
/// `struct file`, reconstruct paths through the same code as `file_open`.
fn fill_comps(
    leaf_dentry: Dentry,
    object_dentry: Dentry,
    comps: &mut [PathComp; PATH_MAX_DEPTH],
) -> (u8, bool) {
    let mut dentry = leaf_dentry;
    let mut depth = 0usize;
    for _ in 0..PATH_MAX_DEPTH {
        if dentry == object_dentry {
            return (depth as u8, false); // the object ends a complete path
        }
        // `get_mut` keeps each write in bounds for the verifier, and the same bound caps
        // the walk.
        let Some(slot) = comps.get_mut(depth) else {
            return (depth as u8, true);
        };
        match dentry.name_into(slot) {
            // A name that fills the slot was probably truncated.
            Some(n) if n >= PATH_NAME_MAX - 1 => return (depth as u8 + 1, true),
            Some(_) => depth += 1,
            None => return (depth as u8, true), // unreadable, so the path is partial
        }
        let Some(parent) = dentry.parent() else {
            return (depth as u8, true);
        };
        if parent == dentry {
            return (depth as u8, true); // the mount root before the object, never expected
        }
        dentry = parent;
    }
    // The walk hit the depth cap before the object, so the path has more components than
    // slots.
    (depth as u8, true)
}

/// The suppression window of 1s, within which each [`SuppressKey`] emits at most one ring
/// record. The audit found that tools re-open the same config hundreds of times per run. A
/// 1s window collapses each such burst to its first occurrence and a count, which keeps
/// the ring and the learn path quiet without losing the event.
const SUPPRESS_WINDOW_NS: Nanos = Nanos(1_000_000_000);

/// The in-kernel event suppressor's state, which holds the hottest decision keys and when
/// each last emitted. It is an LRU map, so a full map evicts the coldest key rather than
/// refusing a new hot one. It is internal to the kernel, and the daemon never touches it.
#[map]
static SUPPRESS: LruHashMap<SuppressKey, SuppressVal> = LruHashMap::with_max_entries(4096, 0);

/// Decides whether a logged decision for `(exe, leaf, action)` emits a ring record, and
/// records the decision in `SUPPRESS`. Returns the number of identical decisions folded in
/// since the key's previous record when it emits, or `None` when the decision falls inside
/// the suppression window and only bumps the key's count. A failed map write costs a
/// slightly wrong count, never a missed first occurrence.
pub fn throttle(exe: FileId, leaf: FileId, action: Action) -> Option<Suppressed> {
    let now = now_ns();
    let key = SuppressKey::new(exe, leaf, action);
    match suppress_get(&key) {
        // Seen before and still inside the window, so suppress it and bump the count.
        Some(prev) if now.wrapping_sub(prev.last_ns) < SUPPRESS_WINDOW_NS => {
            let _ = SUPPRESS.insert(
                &key,
                &SuppressVal::new(
                    prev.last_ns,
                    Suppressed(prev.suppressed.0.saturating_add(1)),
                ),
                0,
            );
            None
        }
        // The window has elapsed, so emit with the held-back count and reset it.
        Some(prev) => {
            let _ = SUPPRESS.insert(&key, &SuppressVal::new(now, Suppressed(0)), 0);
            Some(prev.suppressed)
        }
        // A first occurrence emits at once and starts the key's window.
        None => {
            let _ = SUPPRESS.insert(&key, &SuppressVal::new(now, Suppressed(0)), 0);
            Some(Suppressed(0))
        }
    }
}

/// Returns a copy of the suppressor value for `key`, or `None` when the key is absent.
fn suppress_get(key: &SuppressKey) -> Option<SuppressVal> {
    // aya's map reference borrows map memory that can change concurrently, so it is
    // `unsafe`. Copying the value out keeps the decision flow free of `unsafe`.
    unsafe { SUPPRESS.get(key).copied() }
}

/// Returns the monotonic nanoseconds since boot (`bpf_ktime_get_ns`), which is the
/// suppressor's clock.
fn now_ns() -> Nanos {
    Nanos(unsafe { bpf_ktime_get_ns() })
}

/// Returns the current task's `mm->exe_file`, or `None` for a kernel thread, which has no
/// `mm`, or when a read fails.
fn current_exe_file() -> Option<File> {
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let mm = ptr_at(task, offset!(task_mm))?;
    if mm.is_null() {
        return None;
    }
    let exe_file = ptr_at(mm, offset!(mm_exe_file))?;
    (!exe_file.is_null()).then_some(File(exe_file))
}

/// The ring buffer of logged decisions that the daemon drains for the learn path.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
