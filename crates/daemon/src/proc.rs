//! Resolves a path to the inode identity that the bpf-lsm program sees (see `file_id`).

#[cfg(feature = "bpf-lsm")]
pub use fsid::file_id;

#[cfg(feature = "bpf-lsm")]
mod fsid {
    use cordon_bpf_common::{Dev, FileId, Ino};
    use std::os::linux::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    /// Returns the [`FileId`] that the eBPF program sees for `path`, or `None` when the
    /// path cannot be resolved.
    pub fn file_id(path: &Path) -> Option<FileId> {
        let canonical = std::fs::canonicalize(path).ok()?;
        // The device must equal `inode->i_sb->s_dev`, which is the device of the mount's
        // super_block. That is not `stat(2)`'s `st_dev` on overlayfs (containers) or btrfs
        // (a device per subvolume), so it comes from `/proc/self/mountinfo`. The inode
        // number comes from `stat`, which does match the kernel's `i_ino`.
        let dev = mount_dev(&canonical)?;
        let ino = Ino(std::fs::metadata(&canonical).ok()?.st_ino());
        Some(FileId::new(dev, ino))
    }

    /// Returns the device of the deepest mount point that contains `canonical`, or `None`
    /// when `/proc/self/mountinfo` cannot be read or parsed.
    fn mount_dev(canonical: &Path) -> Option<Dev> {
        let contents = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        dev_from_mountinfo(&contents, canonical)
    }

    /// Returns the device of the deepest mount point in `contents` that contains `path`,
    /// or `None` when no mount point does or a line does not parse. `contents` is the text
    /// of `/proc/self/mountinfo`.
    fn dev_from_mountinfo(contents: &str, path: &Path) -> Option<Dev> {
        let mut best: Option<(usize, Dev)> = None;
        for line in contents.lines() {
            // A line reads `id parent MAJ:MIN root mount_point options...`, and only
            // fields 2 and 4 matter. `MAJ:MIN` is `MAJOR(s_dev):MINOR(s_dev)` of the
            // mount's super_block, which is exactly the value `inode->i_sb->s_dev` holds.
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

    /// Returns the kernel's `dev_t` for `major` and `minor`, packed as `MKDEV` packs it
    /// (`MINORBITS = 20`).
    fn mkdev(major: u64, minor: u64) -> Dev {
        Dev((major << 20) | (minor & 0x000f_ffff))
    }

    /// Returns the mount-point field `s` with `mountinfo`'s octal escapes decoded (`\040`
    /// space, `\011` tab, `\012` newline, `\134` backslash).
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

        /// Guards the premise that `seed::daemon_exe`'s memoization rests on. This lookup
        /// is path-based, so its answer changes, or disappears, when a package upgrade
        /// renames a new binary over the running one.
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

            // …and once the name is gone, no id can be had by path at all. This is the
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
