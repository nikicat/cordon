//! Reads the byte offsets of kernel struct fields from the running kernel's
//! `/sys/kernel/btf/vmlinux`. The eBPF object carries no struct layout of its own (see
//! [`Offsets`] for why), so the daemon resolves the few field offsets the hooks chase here
//! and injects them into the program's `.rodata` (see `backend::bpf_lsm`).
//!
//! aya-obj already parses BTF, but its member and offset accessors are `pub(crate)`, so
//! this module parses the small part of the format it needs (`Documentation/bpf/btf.rst`).

use cordon_bpf_common::Offsets;
use cordon_core::{Context, Error, Result};
use std::path::Path;

/// Where the kernel exports its own BTF.
const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// BTF magic (`btf_header.magic`), in the blob's own byte order.
const BTF_MAGIC: u16 = 0xeb9f;

// A btf_type's `info` field holds the kind in bits 24..=28, vlen in bits 0..=15 and
// kind_flag in bit 31.
const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_FLOAT: u32 = 16;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

/// A STRUCT or UNION member, kept so that resolution can match it by name and add up its
/// offset. The bit offset is already masked free of any bitfield-width bits.
struct Member {
    name_off: u32,
    type_id: u32,
    bit_offset: u32,
}

/// The part of a BTF type that offset resolution reads. A kind that resolution neither
/// descends into nor follows (INT, PTR, ENUM, …) becomes `Other`, which keeps nothing.
enum Ty {
    /// A STRUCT or a UNION, which take the same offset math.
    Aggregate {
        name_off: u32,
        members: Vec<Member>,
    },
    /// A transparent wrapper (TYPEDEF, CONST, VOLATILE, RESTRICT or TYPE_TAG), which
    /// resolution follows through `ref_id` to reach the real type.
    Modifier {
        ref_id: u32,
    },
    Other,
}

/// The running kernel's type information, parsed so that [`KernelBtf::offsets`] can
/// resolve the fields the hooks read.
pub struct KernelBtf {
    /// The types indexed by BTF id, where id 0 is the void placeholder.
    types: Vec<Ty>,
    /// The string section that type and member names point into.
    strings: Vec<u8>,
}

impl KernelBtf {
    /// Returns the running kernel's BTF.
    ///
    /// Errors when `/sys/kernel/btf/vmlinux` cannot be read or does not parse.
    pub fn from_running_kernel() -> Result<Self> {
        Self::from_path(Path::new(VMLINUX_BTF))
    }

    fn from_path(path: &Path) -> Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("bpf-lsm: read {}", path.display()))?;
        Self::parse(&bytes)
    }

    /// Returns the BTF that the raw blob `bytes` holds.
    ///
    /// Errors when the blob is truncated, is not BTF, or holds a type kind newer than this
    /// parser.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        parse_btf(bytes).ok_or_else(|| Error::msg("bpf-lsm: malformed or unsupported kernel BTF"))
    }

    /// Returns the offset of every field the hooks read.
    ///
    /// Errors when any of those fields is missing. A missing field means the kernel's layout
    /// changed, and a guessed offset would make the hooks read the wrong memory.
    pub fn offsets(&self) -> Result<Offsets> {
        let m = |s: &str, p: &[&str]| {
            self.member_offset(s, p)
                .ok_or_else(|| Error::msg(format!("bpf-lsm: BTF has no {s}.{}", p.join("."))))
        };
        Ok(Offsets {
            file_f_path_dentry: m("file", &["f_path", "dentry"])?,
            file_f_inode: m("file", &["f_inode"])?,
            file_f_mode: m("file", &["f_mode"])?,
            file_f_flags: m("file", &["f_flags"])?,
            dentry_d_inode: m("dentry", &["d_inode"])?,
            dentry_d_sb: m("dentry", &["d_sb"])?,
            dentry_d_parent: m("dentry", &["d_parent"])?,
            // `d_name` is a `struct qstr`. Its `name` is a NUL-terminated string pointer,
            // read with `bpf_probe_read_kernel_str`, so no separate `len` is needed.
            dentry_d_name_name: m("dentry", &["d_name", "name"])?,
            inode_i_ino: m("inode", &["i_ino"])?,
            inode_i_sb: m("inode", &["i_sb"])?,
            sb_s_dev: m("super_block", &["s_dev"])?,
            task_mm: m("task_struct", &["mm"])?,
            mm_exe_file: m("mm_struct", &["exe_file"])?,
            binprm_file: m("linux_binprm", &["file"])?,
        })
    }

    /// Returns the byte offset of `struct_name.path[0].path[1]…`, or `None` when a hop is
    /// missing. A hop may sit inside an anonymous struct or union, as
    /// `mm_struct.exe_file` does, and the path does not name that anonymous member.
    fn member_offset(&self, struct_name: &str, path: &[&str]) -> Option<u32> {
        let mut agg = self.named_aggregate(struct_name)?;
        let mut total = 0u32;
        for (i, want) in path.iter().enumerate() {
            let found = self.find_member(agg, want)?;
            total = total.checked_add(found.byte_offset)?;
            if i + 1 < path.len() {
                agg = self.aggregate_of(found.type_id)?; // must be an aggregate to descend
            }
        }
        Some(total)
    }

    /// Returns the member called `want` in the aggregate `agg_id`, or `None` when there is
    /// none. The member may sit inside an anonymous member, but a direct member of that
    /// name wins.
    fn find_member(&self, agg_id: usize, want: &str) -> Option<MemberAt> {
        let Ty::Aggregate { members, .. } = self.types.get(agg_id)? else {
            return None;
        };
        for m in members {
            if self.name(m.name_off) == want {
                return Some(MemberAt {
                    byte_offset: m.bit_offset / 8,
                    type_id: m.type_id,
                });
            }
        }
        for m in members {
            if self.name(m.name_off).is_empty()
                && let Some(inner) = self.aggregate_of(m.type_id)
                && let Some(found) = self.find_member(inner, want)
            {
                return Some(MemberAt {
                    byte_offset: m.bit_offset / 8 + found.byte_offset,
                    ..found
                });
            }
        }
        None
    }

    /// Returns the id of the STRUCT or UNION that `type_id` names through any modifier
    /// wrappers, or `None` when it names another kind.
    fn aggregate_of(&self, mut type_id: u32) -> Option<usize> {
        for _ in 0..16 {
            match self.types.get(type_id as usize)? {
                Ty::Aggregate { .. } => return Some(type_id as usize),
                Ty::Modifier { ref_id } => type_id = *ref_id,
                Ty::Other => return None,
            }
        }
        None // modifier cycle guard
    }

    /// Returns the id of the first STRUCT or UNION called `name`.
    fn named_aggregate(&self, name: &str) -> Option<usize> {
        self.types.iter().position(
            |t| matches!(t, Ty::Aggregate { name_off, .. } if self.name(*name_off) == name),
        )
    }

    /// Returns the string at `off` in the string section. The string is empty for offset
    /// 0, for an offset out of range, and for invalid UTF-8.
    fn name(&self, off: u32) -> &str {
        let start = off as usize;
        let tail = self.strings.get(start..).unwrap_or(&[]);
        let end = tail.iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&tail[..end]).unwrap_or("")
    }
}

/// A member that [`KernelBtf::find_member`] found, placed relative to the aggregate it
/// was looked up in.
struct MemberAt {
    byte_offset: u32,
    type_id: u32,
}

/// A bounds-checked cursor over the blob, in either byte order.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    le: bool,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.buf.get(self.pos..self.pos + 4)?.try_into().ok()?;
        self.pos += 4;
        Some(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n)?;
        (self.pos <= self.buf.len()).then_some(())
    }
}

/// Returns the types and strings of the BTF blob `bytes`, or `None` when the blob is
/// truncated or its layout is unknown.
fn parse_btf(bytes: &[u8]) -> Option<KernelBtf> {
    // Detect byte order from the magic. The blob is the running kernel's, so it is
    // native, but honoring the magic costs little and avoids a latent assumption.
    let magic = bytes.get(0..2)?;
    let le = if magic == BTF_MAGIC.to_le_bytes() {
        true
    } else if magic == BTF_MAGIC.to_be_bytes() {
        false
    } else {
        return None;
    };
    // Skip the magic and the one-byte version and flags, which nothing here depends on.
    let mut hdr = Reader {
        buf: bytes,
        pos: 4,
        le,
    };
    let hdr_len = hdr.u32()?;
    let type_off = hdr.u32()?;
    let type_len = hdr.u32()?;
    let str_off = hdr.u32()?;
    let str_len = hdr.u32()?;

    // Each section's offset is relative to the end of the header.
    let section = |off: u32, len: u32| {
        let start = (hdr_len as usize).checked_add(off as usize)?;
        Some(start..start.checked_add(len as usize)?)
    };
    let type_sec = section(type_off, type_len)?;
    let strings = bytes.get(section(str_off, str_len)?)?.to_vec();

    let mut r = Reader {
        buf: bytes.get(..type_sec.end)?,
        pos: type_sec.start,
        le,
    };
    let mut types = Vec::new();
    types.push(Ty::Other); // id 0 == void
    while r.pos < type_sec.end {
        types.push(parse_type(&mut r)?);
    }
    Some(KernelBtf { types, strings })
}

/// Reads one `btf_type` record and returns the part that resolution needs, or `None` when
/// the record is truncated or its kind is unknown. A record is a 12-byte common header and
/// a kind-specific tail, and the reader is left at the next record.
fn parse_type(r: &mut Reader) -> Option<Ty> {
    let name_off = r.u32()?;
    let info = r.u32()?;
    let size_or_type = r.u32()?;
    let vlen = (info & 0xffff) as usize;
    let kind = (info >> 24) & 0x1f;
    let kind_flag = (info >> 31) & 1 == 1;

    match kind {
        KIND_STRUCT | KIND_UNION => {
            let mut members = Vec::with_capacity(vlen);
            for _ in 0..vlen {
                let m_name = r.u32()?;
                let m_type = r.u32()?;
                let raw = r.u32()?;
                // With kind_flag, the low 24 bits are the bit offset and the high 8 are
                // the bitfield width. Without it, the whole word is the bit offset. The
                // target fields are never bitfields, so masking is enough.
                let bit_offset = if kind_flag { raw & 0x00ff_ffff } else { raw };
                members.push(Member {
                    name_off: m_name,
                    type_id: m_type,
                    bit_offset,
                });
            }
            Some(Ty::Aggregate { name_off, members })
        }
        KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
            Some(Ty::Modifier {
                ref_id: size_or_type,
            })
        }
        // Resolution never looks inside the other kinds, but the reader must still step
        // over each one's tail to reach the next record.
        KIND_PTR | KIND_FWD | KIND_FUNC | KIND_FLOAT => Some(Ty::Other),
        KIND_INT | KIND_VAR | KIND_DECL_TAG => r.skip(4).map(|()| Ty::Other),
        KIND_ARRAY => r.skip(12).map(|()| Ty::Other),
        KIND_ENUM | KIND_FUNC_PROTO => r.skip(vlen * 8).map(|()| Ty::Other),
        KIND_DATASEC | KIND_ENUM64 => r.skip(vlen * 12).map(|()| Ty::Other),
        // A newer kernel's kind has a tail of unknown length, so every later record would
        // be misread.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny well-formed BTF blob under construction. It exercises the parser against
    /// known offsets, including an anonymous-union descent, without a real kernel.
    struct BtfBuilder {
        types: Vec<u8>,
        strings: Vec<u8>,
    }

    impl BtfBuilder {
        fn new() -> Self {
            BtfBuilder {
                types: Vec::new(),
                strings: vec![0], // offset 0 == empty string
            }
        }
        fn str(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }
        fn ty(&mut self, name_off: u32, kind: u32, vlen: u32, kind_flag: bool, size_or_type: u32) {
            let info = ((kind_flag as u32) << 31) | (kind << 24) | (vlen & 0xffff);
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size_or_type.to_le_bytes());
        }
        /// Appends a STRUCT or UNION member record.
        fn member(&mut self, name_off: u32, type_id: u32, bit_offset: u32) {
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&type_id.to_le_bytes());
            self.types.extend_from_slice(&bit_offset.to_le_bytes());
        }
        fn build(self) -> Vec<u8> {
            let hdr_len = 24u32;
            let mut out = Vec::new();
            out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            out.push(1); // version
            out.push(0); // flags
            out.extend_from_slice(&hdr_len.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // type_off
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // type_len
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes()); // str_len
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// Returns a blob for the layout below. It exercises a direct member, a hop from one
    /// named member to another, and descent into an anonymous union to reach `f_path`.
    ///
    /// `file { f_inode @0; <anon union> @16 { path f_path @0 { _ mnt@0; * dentry@8 } } }`
    fn sample() -> Vec<u8> {
        let mut b = BtfBuilder::new();
        let n_int = b.str("int");
        let n_path = b.str("path");
        let n_mnt = b.str("mnt");
        let n_dentry = b.str("dentry");
        let n_f_path = b.str("f_path");
        let n_f_inode = b.str("f_inode");
        let n_file = b.str("file");

        // id1: INT "int"
        b.ty(n_int, KIND_INT, 0, false, 4);
        b.types.extend_from_slice(&0u32.to_le_bytes()); // INT trailing word
        // id2: PTR -> id1
        b.ty(0, KIND_PTR, 0, false, 1);
        // id3: STRUCT "path" { mnt@bit0 (id2), dentry@bit64 (id2) }, size 16
        b.ty(n_path, KIND_STRUCT, 2, false, 16);
        b.member(n_mnt, 2, 0);
        b.member(n_dentry, 2, 64);
        // id4: UNION anon { f_path@bit0 (id3), dummy@bit0 (id1) }, size 16
        b.ty(0, KIND_UNION, 2, false, 16);
        b.member(n_f_path, 3, 0);
        b.member(n_int, 1, 0);
        // id5: STRUCT "file" { f_inode@bit0 (id2), <anon id4>@bit128 }, size 32
        b.ty(n_file, KIND_STRUCT, 2, false, 32);
        b.member(n_f_inode, 2, 0);
        b.member(0, 4, 128);
        b.build()
    }

    #[test]
    fn resolves_direct_member() {
        let btf = KernelBtf::parse(&sample()).unwrap();
        assert_eq!(btf.member_offset("file", &["f_inode"]), Some(0));
    }

    #[test]
    fn resolves_through_anonymous_union_and_named_hop() {
        let btf = KernelBtf::parse(&sample()).unwrap();
        // file -> (anon union @16) -> f_path @0 -> path.dentry @8  ==> 24
        assert_eq!(btf.member_offset("file", &["f_path", "dentry"]), Some(24));
    }

    #[test]
    fn missing_member_is_none() {
        let btf = KernelBtf::parse(&sample()).unwrap();
        assert_eq!(btf.member_offset("file", &["nope"]), None);
        assert_eq!(btf.member_offset("nostruct", &["x"]), None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(KernelBtf::parse(b"not btf at all").is_err());
        assert!(KernelBtf::parse(&[]).is_err());
    }

    #[test]
    fn rejects_an_unknown_kind() {
        let mut b = BtfBuilder::new();
        b.ty(0, 31, 0, false, 0);
        assert!(KernelBtf::parse(&b.build()).is_err());
    }
}
