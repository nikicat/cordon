//! Path → inode identity for the bpf-lsm backend.
//!
//! The backend keys policy on a file's `(device, inode)`. The device must equal what
//! the kernel's eBPF reads — `inode->i_sb->s_dev`, the *mount's* super_block device —
//! which is **not** `stat(2)`'s `st_dev` on overlayfs (containers) or btrfs
//! (per-subvolume device). So we resolve it from `/proc/self/mountinfo`. (The
//! owner-model `/proc` caller-identity helpers were retired with the rule-model
//! migration; the rule model identifies the caller in-kernel via `mm->exe_file`.)

#[cfg(feature = "bpf-lsm")]
pub use fsid::file_id;

#[cfg(feature = "bpf-lsm")]
mod fsid {
    use cordon_bpf_common::{Dev, FileId, Ino};
    use std::os::linux::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    /// A path's [`FileId`] matching the eBPF view: device from the mount table, inode
    /// number from `stat` (which does match the kernel's `i_ino`). `None` if the path
    /// can't be resolved.
    pub fn file_id(path: &Path) -> Option<FileId> {
        let canonical = std::fs::canonicalize(path).ok()?;
        let dev = mount_dev(&canonical)?;
        let ino = Ino(std::fs::metadata(&canonical).ok()?.st_ino());
        Some(FileId::new(dev, ino))
    }

    /// The device of the longest mount-point prefixing `canonical`, from
    /// `/proc/self/mountinfo`.
    fn mount_dev(canonical: &Path) -> Option<Dev> {
        let contents = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        dev_from_mountinfo(&contents, canonical)
    }

    /// Parse `/proc/self/mountinfo` for the device of the longest mount-point that
    /// prefixes `path`. Field 3 (`major:minor`) is `MAJOR(s_dev):MINOR(s_dev)` of the
    /// mount's super_block — exactly the value `inode->i_sb->s_dev` holds. Split out
    /// (pure) for testing.
    fn dev_from_mountinfo(contents: &str, path: &Path) -> Option<Dev> {
        let mut best: Option<(usize, Dev)> = None;
        for line in contents.lines() {
            // mountinfo: id parent MAJ:MIN root mount_point options... — fields 2 and 4.
            let mut fields = line.split(' ');
            let majmin = fields.nth(2)?;
            let mount_point = PathBuf::from(unescape_mountinfo(fields.nth(1)?));
            if !path.starts_with(&mount_point) {
                continue;
            }
            let depth = mount_point.components().count();
            if best.is_none_or(|(d, _)| depth > d) {
                let (major, minor) = majmin.split_once(':')?;
                best = Some((depth, mkdev(major.parse().ok()?, minor.parse().ok()?)));
            }
        }
        best.map(|(_, dev)| dev)
    }

    /// Pack a major/minor into the kernel's `dev_t` (`MKDEV`, `MINORBITS = 20`).
    fn mkdev(major: u64, minor: u64) -> Dev {
        Dev((major << 20) | (minor & 0x000f_ffff))
    }

    /// Decode `mountinfo`'s octal escapes (`\040` space, `\011` tab, `\012` newline,
    /// `\134` backslash) in a mount-point field.
    fn unescape_mountinfo(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            let oct: String = chars.clone().take(3).collect();
            match u8::from_str_radix(&oct, 8) {
                Ok(byte) if oct.len() == 3 => {
                    out.push(byte as char);
                    chars.nth(2); // consume the 3 octal digits
                }
                _ => out.push('\\'),
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn mkdev_packs_major_minor() {
            assert_eq!(mkdev(8, 2), Dev((8 << 20) | 2));
            assert_eq!(mkdev(259, 1234), Dev((259 << 20) | 1234));
        }

        #[test]
        fn dev_from_mountinfo_longest_prefix() {
            let mi = "23 1 0:23 / / rw - ext4 /dev/sda1 rw\n\
                      40 23 0:48 / /tmp overlay rw - overlay overlay rw\n\
                      50 40 0:49 / /tmp/sub tmpfs rw - tmpfs t rw";
            assert_eq!(
                dev_from_mountinfo(mi, Path::new("/tmp/foo")),
                Some(mkdev(0, 48))
            );
            assert_eq!(
                dev_from_mountinfo(mi, Path::new("/tmp/sub/x")),
                Some(mkdev(0, 49))
            );
            assert_eq!(
                dev_from_mountinfo(mi, Path::new("/etc")),
                Some(mkdev(0, 23))
            );
        }

        #[test]
        fn unescape_handles_spaces() {
            assert_eq!(unescape_mountinfo(r"/mnt/a\040b"), "/mnt/a b");
            assert_eq!(unescape_mountinfo("/plain"), "/plain");
        }
    }
}
