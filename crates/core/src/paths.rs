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
}
