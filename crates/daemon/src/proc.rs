//! Path → inode identity for the bpf-lsm backend (see `file_id`).

#[cfg(feature = "bpf-lsm")]
pub use fsid::file_id;

#[cfg(feature = "bpf-lsm")]
mod fsid {
    use cordon_bpf_common::{Dev, FileId, Ino};
    use std::os::linux::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    /// Returns a path's [`FileId`] as the eBPF program sees it, or `None` if the path
    /// can't be resolved. The device must equal `inode->i_sb->s_dev`, the mount's
    /// super_block device, which is not `stat(2)`'s `st_dev` on overlayfs (containers) or
    /// btrfs (per-subvolume device); so it comes from `/proc/self/mountinfo`. The inode
    /// number comes from `stat`, which does match the kernel's `i_ino`.
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

        /// Guards the premise `seed::daemon_exe`'s memoization rests on: this lookup is
        /// path-based, so its answer changes, or disappears, when a package upgrade renames
        /// a new binary over the running one.
        #[test]
        fn file_id_follows_the_name_not_the_inode() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().to_path_buf();
            let path = dir.join("cordond");
            std::fs::write(&path, b"old").unwrap();

            let before = file_id(&path).expect("a live path resolves");

            // The upgrade: a *new* inode renamed over the running binary's name.
            let replacement = dir.join("cordond.new");
            std::fs::write(&replacement, b"new").unwrap();
            std::fs::rename(&replacement, &path).unwrap();

            let after = file_id(&path).expect("the replacement resolves");
            assert_ne!(
                before.ino, after.ino,
                "rename-over yields a different inode — re-resolving would name the new \
                 binary, which the running process never exec'd"
            );

            // …and once the name is gone there is no id to be had by path at all: the
            // `(deleted)` case, where re-resolving would refuse `policy apply` after an
            // upgrade.
            std::fs::remove_file(&path).unwrap();
            assert!(file_id(&path).is_none(), "a vanished path has no FileId");
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
