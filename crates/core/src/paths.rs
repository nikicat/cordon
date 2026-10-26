//! Lexical path arithmetic that subtree matching relies on. Nothing here touches the
//! filesystem, so a caller must pass absolute paths that are already free of symlinks.

use std::path::{Component, Path, PathBuf};

/// Returns `path` with `.` and `..` resolved lexically. A `..` removes the component
/// before it, `/..` stays `/`, and a relative path keeps a leading `..`. Symlinks are not
/// resolved, and the filesystem is never touched.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out: Vec<Component> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match out.last() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // `/..` is `/`.
                Some(Component::RootDir) => {}
                // A relative path keeps its leading `..`.
                _ => out.push(comp),
            },
            Component::RootDir => {
                out.clear();
                out.push(comp);
            }
            other => out.push(other),
        }
    }
    out.iter().map(|c| c.as_os_str()).collect()
}

/// Checks whether `path` equals `prefix` or lies beneath it. The comparison goes by
/// component, so `/a/bc` is not within `/a/b`.
pub fn is_within(path: &Path, prefix: &Path) -> bool {
    path.starts_with(prefix)
}

/// Returns the number of components in `path`.
pub fn depth(path: &Path) -> usize {
    path.components().count()
}

/// Returns the claimable subtree that holds `path`. It is the deepest zone that is a
/// strict ancestor of `path`, extended by exactly one component. Returns `None` when
/// `path` is itself a zone or lies outside every zone, because a zone root is never
/// claimable (DESIGN §5).
///
/// For example, `~/.config/ctest-xdg/secret` with the zones `{~, ~/.config}` has
/// `~/.config` as its deepest strict-ancestor zone, so its subtree is
/// `~/.config/ctest-xdg`.
pub fn claimable_subtree(path: &Path, zones: &[PathBuf]) -> Option<PathBuf> {
    let path = normalize(path);
    let zone = zones
        .iter()
        .map(|z| normalize(z))
        .filter(|z| path.starts_with(z) && path != *z)
        .max_by_key(|z| depth(z))?;
    let rest = path.strip_prefix(&zone).ok()?;
    let first = rest.components().next()?;
    Some(zone.join(first.as_os_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_resolves_dot_and_dotdot() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), Path::new("/a/c"));
        assert_eq!(normalize(Path::new("/a/b/../../c")), Path::new("/c"));
        assert_eq!(normalize(Path::new("/../a")), Path::new("/a"));
        assert_eq!(normalize(Path::new("/a/../../b")), Path::new("/b"));
        assert_eq!(normalize(Path::new("../a")), Path::new("../a"));
    }

    #[test]
    fn within_is_component_wise() {
        assert!(is_within(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(is_within(Path::new("/a/b"), Path::new("/a/b")));
        assert!(!is_within(Path::new("/a/bc"), Path::new("/a/b")));
    }

    #[test]
    fn claimable_picks_deepest_zone_plus_one() {
        let zones = vec![PathBuf::from("/home/u"), PathBuf::from("/home/u/.config")];
        assert_eq!(
            claimable_subtree(Path::new("/home/u/.config/ctest-xdg/secret"), &zones),
            Some(PathBuf::from("/home/u/.config/ctest-xdg"))
        );
        assert_eq!(
            claimable_subtree(Path::new("/home/u/.ctest-old/secret"), &zones),
            Some(PathBuf::from("/home/u/.ctest-old"))
        );
    }

    #[test]
    fn zone_itself_is_never_claimable() {
        let zones = vec![PathBuf::from("/home/u/.config")];
        assert_eq!(
            claimable_subtree(Path::new("/home/u/.config"), &zones),
            None
        );
        // outside every zone
        assert_eq!(claimable_subtree(Path::new("/etc/passwd"), &zones), None);
    }
}
