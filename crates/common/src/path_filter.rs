//! Consistent workspace-relative path filtering.
//!
//! Compiler, retrieval, security, and CLI surfaces all accept the same path
//! spellings. Keeping their normalization here prevents a query from selecting
//! a different file set depending on which facade happens to execute it.

use std::path::{Path, PathBuf};

/// Normalize a user-facing path for comparison across Unix and Windows.
#[must_use]
pub fn normalize_path_for_filter(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let normalized = normalized
        .strip_prefix("//?/UNC/")
        .map(|path| format!("//{path}"))
        .unwrap_or_else(|| normalized.strip_prefix("//?/").unwrap_or(&normalized).to_string());
    normalized.trim_start_matches("./").to_string()
}

/// Canonicalize a path, or its existing parent when the final component does
/// not exist yet.
#[must_use]
pub fn canonicalize_path_or_existing_parent(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let parent = path.parent()?;
    let canonical_parent = parent.canonicalize().ok()?;
    Some(match path.file_name() {
        Some(file_name) => canonical_parent.join(file_name),
        None => canonical_parent,
    })
}

/// Render `path` relative to `root` when both identify the same filesystem
/// tree. The normalized original path is returned when no relative form can be
/// proven.
#[must_use]
pub fn workspace_relative_filter_path(root: Option<&Path>, path: &str) -> String {
    let normalized_path = normalize_path_for_filter(path);
    let Some(root) = root else {
        return normalized_path;
    };
    let path_obj = Path::new(path);
    if let Ok(relative) = path_obj.strip_prefix(root) {
        return normalize_path_for_filter(&relative.to_string_lossy());
    }
    if let Some(canonical_path) = canonicalize_path_or_existing_parent(path_obj) {
        if let Ok(relative) = canonical_path.strip_prefix(root) {
            return normalize_path_for_filter(&relative.to_string_lossy());
        }
        if let Some(canonical_root) = canonicalize_path_or_existing_parent(root) {
            if let Ok(relative) = canonical_path.strip_prefix(canonical_root) {
                return normalize_path_for_filter(&relative.to_string_lossy());
            }
        }
    }
    let normalized_root = normalize_path_for_filter(&root.to_string_lossy());
    let normalized_root = normalized_root.trim_end_matches('/');
    if normalized_root.is_empty() {
        return normalized_path;
    }
    if normalized_path == normalized_root {
        return String::new();
    }
    normalized_path
        .strip_prefix(&format!("{normalized_root}/"))
        .map(ToOwned::to_owned)
        .unwrap_or(normalized_path)
}

/// Return whether a normalized path contains a non-empty normalized filter.
#[must_use]
pub fn normalized_path_contains(path: &str, filter: &str) -> bool {
    let filter = normalize_path_for_filter(filter);
    !filter.is_empty() && normalize_path_for_filter(path).contains(&filter)
}

/// Return whether a filter explicitly names an absolute Unix or Windows path.
#[must_use]
pub fn filter_looks_like_absolute_path(filter: &str) -> bool {
    let normalized = normalize_path_for_filter(filter);
    if normalized.len() >= 3 && normalized.as_bytes()[1] == b':' && normalized.as_bytes()[2] == b'/' {
        return true;
    }
    let unix_absolute = normalized.starts_with('/') && normalized.trim_matches('/').contains('/');
    unix_absolute || (Path::new(filter).is_absolute() && normalized.trim_matches('/').contains('/'))
}

/// Match a normalized path with substring semantics for bare names and
/// component-aware semantics for filters with a leading or trailing slash.
#[must_use]
pub fn path_filter_matches(path: &str, filter: &str) -> bool {
    let path = normalize_path_for_filter(path);
    let filter = normalize_path_for_filter(filter);
    if filter.is_empty() {
        return false;
    }
    if filter.contains('/') {
        return path_filter_with_separator_matches(&path, &filter);
    }
    path.contains(filter.as_str())
}

/// Match a workspace-relative path and, only for an explicit absolute filter,
/// fall back to the absolute spelling.
#[must_use]
pub fn path_filter_matches_with_root(root: Option<&Path>, path: &str, filter: &str) -> bool {
    let relative = workspace_relative_filter_path(root, path);
    path_filter_matches(&relative, filter)
        || (filter_looks_like_absolute_path(filter) && normalized_path_contains(path, filter))
}

/// Match a precomputed relative/absolute path pair. A leading `^` anchors the
/// filter to the workspace root; this spelling is used by compiler ingestion
/// include/exclude filters.
#[must_use]
pub fn scoped_path_filter_matches(relative: &str, absolute: &str, filter: &str) -> bool {
    let normalized_filter = normalize_path_for_filter(filter);
    if let Some(root_relative) = normalized_filter.strip_prefix('^') {
        let root_relative = root_relative.trim_matches('/');
        if root_relative.is_empty() {
            return false;
        }
        let relative = normalize_path_for_filter(relative);
        let relative = relative.trim_start_matches('/');
        return relative == root_relative || relative.starts_with(&format!("{root_relative}/"));
    }
    path_filter_matches(relative, &normalized_filter)
        || (filter_looks_like_absolute_path(filter) && path_filter_matches(absolute, &normalized_filter))
}

fn path_filter_with_separator_matches(path: &str, filter: &str) -> bool {
    let trimmed = filter.trim_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    if filter.starts_with('/') || filter.ends_with('/') {
        let anchored = path.trim_start_matches('/');
        return anchored == trimmed
            || anchored.starts_with(&format!("{trimmed}/"))
            || path.contains(&format!("/{trimmed}/"));
    }
    path.contains(filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_filters_are_cross_platform_and_component_aware() {
        assert!(path_filter_matches(r"repo\tests\test_app.py", "tests/"));
        assert!(path_filter_matches("repo/pkg/service_test.go", "_test.go"));
        assert!(!path_filter_matches("repo/contest/test_app.py", "test/"));
        assert!(!path_filter_matches("repo/latest/app.py", "test/"));
    }

    #[test]
    fn workspace_relative_filters_do_not_match_ancestor_components() {
        let root = Path::new("/repo/target/chosen-workspace");
        assert!(!path_filter_matches_with_root(
            Some(root),
            "/repo/target/chosen-workspace/app.py",
            "target/"
        ));
        assert!(path_filter_matches_with_root(
            Some(root),
            "/repo/target/chosen-workspace/tests/app.py",
            "tests/"
        ));
    }

    #[test]
    fn windows_verbatim_paths_relativize_against_ordinary_workspace_roots() {
        let root = Path::new(r"C:\repo\chosen-workspace");
        assert_eq!(
            workspace_relative_filter_path(Some(root), r"\\?\C:\repo\chosen-workspace\src\app.py"),
            "src/app.py"
        );
        assert!(path_filter_matches_with_root(
            Some(root),
            r"\\?\C:\repo\chosen-workspace\src\app.py",
            "src/"
        ));
    }

    #[test]
    fn rooted_filters_are_anchored_to_the_selected_workspace() {
        assert!(scoped_path_filter_matches(
            "src/app.py",
            "/repo/src/app.py",
            "^src/"
        ));
        assert!(!scoped_path_filter_matches(
            "nested/src/app.py",
            "/repo/nested/src/app.py",
            "^src/"
        ));
    }

    #[test]
    fn absolute_filters_do_not_leak_into_relative_matching() {
        assert!(filter_looks_like_absolute_path("/repo/src/app.py"));
        assert!(filter_looks_like_absolute_path(r"C:\repo\src\app.py"));
        assert_eq!(
            normalize_path_for_filter(r"\\?\C:\repo\src\app.py"),
            "C:/repo/src/app.py"
        );
        assert_eq!(
            normalize_path_for_filter(r"\\?\UNC\server\share\app.py"),
            "//server/share/app.py"
        );
        assert!(!filter_looks_like_absolute_path("src/app.py"));
        assert!(!normalized_path_contains("src/app.py", ""));
    }
}
