//! A minimal read-only BTF parser — just enough to resolve struct field **byte
//! offsets** from the running kernel's `/sys/kernel/btf/vmlinux`.
//!
//! This is the userspace half of the CO-RE-substitute: rustc can't emit CO-RE
//! relocations (rust-lang/rust#158412), so the eBPF object carries no struct layout
//! of its own. Here we read the running kernel's BTF, resolve the handful of field
//! offsets the `file_open` hook chases, and hand them back as an [`Offsets`] the
//! daemon injects into the program's `.rodata` (see `backend::bpf_lsm`).
//!
//! aya-obj already parses BTF, but its member/offset accessors are `pub(crate)`, so
//! we parse the slice ourselves. The format is small and stable
//! (`Documentation/bpf/btf.rst`); we implement only the type kinds we must *traverse*
//! (STRUCT/UNION + the modifier kinds) and correctly *skip* the rest. Resolution
//! follows member **names** and transparently descends anonymous unions/structs, so
//! a field the kernel tucks inside an anonymous union (e.g. `mm_struct.exe_file`) is
//! still found without hard-coding bindgen's `__bindgen_anon_N` names.

use cordon_bpf_common::Offsets;
use cordon_core::{Error, Result};
use std::path::Path;

/// Where the kernel exports its own BTF.
const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// BTF magic (`btf_header.magic`), in the blob's own byte order.
const BTF_MAGIC: u16 = 0xeb9f;

// btf_type `info` field: kind in bits 24..=28, vlen in bits 0..=15, kind_flag bit 31.
const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

/// One STRUCT/UNION member: its name, its type, and its bit offset within the
/// aggregate (already masked free of any bitfield-width bits).
struct Member {
    name_off: u32,
    type_id: u32,
    bit_offset: u32,
}

/// The slice of each BTF type we care about. Everything we neither traverse into nor
/// follow (INT, PTR, ENUM, …) collapses to `Other` — we still parsed past its
/// trailing bytes to stay aligned, we just keep nothing.
enum Ty {
    /// STRUCT or UNION (offset math is identical for both).
    Aggregate {
        name_off: u32,
        members: Vec<Member>,
    },
    /// A transparent wrapper (TYPEDEF/CONST/VOLATILE/RESTRICT/TYPE_TAG) → follow to
    /// `ref_id` to reach the real aggregate.
    Modifier {
        ref_id: u32,
    },
    Other,
}

/// The parsed kernel BTF: types indexed by id (id 0 is the void placeholder) plus the
/// string section names are resolved from.
pub struct KernelBtf {
    types: Vec<Ty>,
    strings: Vec<u8>,
}

impl KernelBtf {
    /// Parse the running kernel's BTF.
    pub fn from_running_kernel() -> Result<Self> {
        Self::from_path(Path::new(VMLINUX_BTF))
    }

    fn from_path(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::msg(format!("bpf-lsm: read {}: {e}", path.display())))?;
        Self::parse(&bytes)
    }

    /// Parse a raw BTF blob.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        parse_btf(bytes).ok_or_else(|| Error::msg("bpf-lsm: malformed kernel BTF"))
    }

    /// Resolve every offset the hook needs into an [`Offsets`], failing **loudly** if
    /// any field is absent — a kernel this different is not one we silently mis-read.
    pub fn offsets(&self) -> Result<Offsets> {
        let m = |s: &str, p: &[&str]| {
            self.member_offset(s, p)
                .ok_or_else(|| Error::msg(format!("bpf-lsm: BTF has no {s}.{}", p.join("."))))
        };
        Ok(Offsets {
            file_f_path_dentry: m("file", &["f_path", "dentry"])?,
            file_f_inode: m("file", &["f_inode"])?,
            dentry_d_inode: m("dentry", &["d_inode"])?,
            dentry_d_sb: m("dentry", &["d_sb"])?,
            dentry_d_parent: m("dentry", &["d_parent"])?,
            inode_i_ino: m("inode", &["i_ino"])?,
            inode_i_sb: m("inode", &["i_sb"])?,
            sb_s_dev: m("super_block", &["s_dev"])?,
            task_mm: m("task_struct", &["mm"])?,
            mm_exe_file: m("mm_struct", &["exe_file"])?,
        })
    }

    /// Byte offset of a nested member, named hop by hop, transparently descending
    /// anonymous struct/union members along the way. E.g. `("file", ["f_path",
    /// "dentry"])` sums `file`'s offset to `f_path` (wherever the kernel keeps it,
    /// even inside an anonymous union) and `path`'s offset to `dentry`.
    fn member_offset(&self, struct_name: &str, path: &[&str]) -> Option<u32> {
        let mut agg = self.named_aggregate(struct_name)?;
        let mut total = 0u32;
        for (i, want) in path.iter().enumerate() {
            let (off, member_ty) = self.find_member(agg, want)?;
            total = total.checked_add(off)?;
            if i + 1 < path.len() {
                agg = self.aggregate_of(member_ty)?; // must be an aggregate to descend
            }
        }
        Some(total)
    }

    /// Find `want` among an aggregate's members: a direct named member wins;
    /// otherwise descend each anonymous (`name == ""`) aggregate member, adding its
    /// own offset. Returns the member's byte offset and its type id.
    fn find_member(&self, agg_id: usize, want: &str) -> Option<(u32, u32)> {
        let Ty::Aggregate { members, .. } = self.types.get(agg_id)? else {
            return None;
        };
        for m in members {
            if self.name(m.name_off) == want {
                return Some((m.bit_offset / 8, m.type_id));
            }
        }
        for m in members {
            if self.name(m.name_off).is_empty()
                && let Some(inner) = self.aggregate_of(m.type_id)
                && let Some((off, ty)) = self.find_member(inner, want)
            {
                return Some((m.bit_offset / 8 + off, ty));
            }
        }
        None
    }

    /// Follow modifier wrappers (typedef/const/volatile/…) from a type id; if it
    /// lands on a STRUCT/UNION, return its index, else `None`.
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

    /// The id of the first named STRUCT/UNION matching `name`.
    fn named_aggregate(&self, name: &str) -> Option<usize> {
        self.types.iter().position(
            |t| matches!(t, Ty::Aggregate { name_off, .. } if self.name(*name_off) == name),
        )
    }

    /// Resolve a name-section offset to a `&str` (empty for offset 0 / out of range /
    /// invalid UTF-8).
    fn name(&self, off: u32) -> &str {
        let start = off as usize;
        let tail = self.strings.get(start..).unwrap_or(&[]);
        let end = tail.iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&tail[..end]).unwrap_or("")
    }
}

/// A bounds-checked little/big-endian cursor over the blob.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    le: bool,
}

impl<'a> Reader<'a> {
    fn u16(&mut self) -> Option<u16> {
        let b: [u8; 2] = self.buf.get(self.pos..self.pos + 2)?.try_into().ok()?;
        self.pos += 2;
        Some(if self.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }
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

/// Parse the header + type section into [`KernelBtf`]. Returns `None` on any
/// truncation or unknown layout (surfaced as a loud error by the caller).
fn parse_btf(bytes: &[u8]) -> Option<KernelBtf> {
    // Detect byte order from the magic (the blob is the running kernel's, so it's
    // native — but honoring the magic costs little and avoids a latent assumption).
    let le = match bytes.get(0..2)? {
        [0x9f, 0xeb] => true,
        [0xeb, 0x9f] => false,
        _ => return None,
    };
    let mut hdr = Reader {
        buf: bytes,
        pos: 0,
        le,
    };
    if hdr.u16()? != BTF_MAGIC {
        return None;
    }
    let _version = bytes.get(2)?;
    let _flags = bytes.get(3)?;
    hdr.pos = 4;
    let hdr_len = hdr.u32()?;
    let type_off = hdr.u32()?;
    let type_len = hdr.u32()?;
    let str_off = hdr.u32()?;
    let str_len = hdr.u32()?;

    let type_start = (hdr_len as usize).checked_add(type_off as usize)?;
    let type_end = type_start.checked_add(type_len as usize)?;
    let str_start = (hdr_len as usize).checked_add(str_off as usize)?;
    let str_end = str_start.checked_add(str_len as usize)?;
    let strings = bytes.get(str_start..str_end)?.to_vec();

    let mut r = Reader {
        buf: bytes.get(..type_end)?,
        pos: type_start,
        le,
    };
    let mut types = Vec::new();
    types.push(Ty::Other); // id 0 == void
    while r.pos < type_end {
        types.push(parse_type(&mut r)?);
    }
    Some(KernelBtf { types, strings })
}

/// Parse one `btf_type` record (the 12-byte common header + kind-specific trailing),
/// keeping only what we traverse and skipping the rest to stay aligned.
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
                // With kind_flag, the low 24 bits are the bit offset and the high 8
                // are the bitfield width; without it, the whole word is the bit
                // offset. Our target fields are never bitfields, so masking suffices.
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
        // Kinds we don't follow but must skip the trailing bytes of.
        KIND_INT => r.skip(4).map(|()| Ty::Other),
        KIND_ARRAY => r.skip(12).map(|()| Ty::Other),
        KIND_ENUM => r.skip(vlen * 8).map(|()| Ty::Other),
        KIND_FUNC_PROTO => r.skip(vlen * 8).map(|()| Ty::Other),
        KIND_VAR => r.skip(4).map(|()| Ty::Other),
        KIND_DATASEC => r.skip(vlen * 12).map(|()| Ty::Other),
        KIND_DECL_TAG => r.skip(4).map(|()| Ty::Other),
        KIND_ENUM64 => r.skip(vlen * 12).map(|()| Ty::Other),
        KIND_PTR => Some(Ty::Other), // no trailing
        // FWD/FUNC/FLOAT and anything else: no trailing we depend on.
        _ => Some(Ty::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builder for a tiny well-formed BTF blob, so the parser is exercised against
    /// known offsets (including an anonymous-union descent) without a real kernel.
    #[derive(Default)]
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
        /// Append a STRUCT/UNION member record (name, type, bit offset).
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

    /// `file { f_inode @0; <anon union> @16 { path f_path @0 { _ mnt@0; * dentry@8 } } }`
    /// — exercises a direct member, a named->named hop, and descent into an
    /// anonymous union to reach `f_path`.
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
}
