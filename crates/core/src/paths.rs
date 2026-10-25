//! Lexical path helpers used by the decision flow. None of these touch the
//! filesystem — backends are responsible for handing us already-resolved
//! (symlink-free) absolute paths; this module only does component-wise
//! normalization and prefix arithmetic so that subtree matching is reliable.

use std::path::{Component, Path, PathBuf};

/// Lexically normalize a path: drop `.`, pop a prior component on `..`, reset on
/// a root. Does **not** resolve symlinks or hit the filesystem.
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

/// True if `path` equals `prefix` or lies beneath it. Component-wise, so
/// `/a/bc` is **not** within `/a/b`.
pub fn is_within(path: &Path, prefix: &Path) -> bool {
    path.starts_with(prefix)
}

/// Number of path components — used to pick the most specific (longest) match
/// among nested subtrees or rule prefixes.
pub fn depth(path: &Path) -> usize {
    path.components().count()
}

/// Given an access path and the configured zone roots, return the claimable
/// first-level subtree: the **deepest zone that is a strict ancestor** of the
/// path, extended by exactly one component. Returns `None` when the path is not
/// strictly inside any zone (it *is* a zone, or lives entirely outside all of
/// them) — zone roots themselves are never claimable (DESIGN §5).
///
/// e.g. `~/.config/ctest-xdg/secret` with zones `{~, ~/.config}`
///      → deepest strict-ancestor zone `~/.config` → `~/.config/ctest-xdg`.
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
