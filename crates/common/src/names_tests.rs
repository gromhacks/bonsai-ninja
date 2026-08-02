use std::path::Path;

use super::{
    callable_reference_variants, default_workspace_bonsai_dir, is_bonsai_case_probe_path,
    qualified_names_match, short_qualified_tail,
};

#[test]
fn default_workspace_cache_is_external_stable_and_namespaced() {
    let cache_root = Path::new("/cache-root");
    let first = default_workspace_bonsai_dir(Path::new("/work/acme project"), Some(cache_root));
    let repeated = default_workspace_bonsai_dir(Path::new("/work/acme project"), Some(cache_root));
    let other = default_workspace_bonsai_dir(Path::new("/other/acme project"), Some(cache_root));

    assert_eq!(first, repeated);
    assert!(first.starts_with(cache_root.join("bonsai-ninja/workspaces")));
    assert!(
        first
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("acme-project-")),
        "{}",
        first.display()
    );
    assert_ne!(first, other, "same basename in a different root must not collide");
    assert!(!first.starts_with("/work/acme project"));
}

#[test]
fn qualified_tail_uses_rightmost_supported_separator() {
    assert_eq!(short_qualified_tail("a.b.c"), "c");
    assert_eq!(short_qualified_tail("std::fs::read"), "read");
    assert_eq!(short_qualified_tail("ptr->call"), "call");
    assert_eq!(short_qualified_tail("Module:function"), "function");
    assert_eq!(short_qualified_tail("App\\Service\\run"), "run");
    assert_eq!(short_qualified_tail("plain"), "plain");
}

#[test]
fn single_colon_does_not_split_inside_double_colon_tail() {
    assert_eq!(short_qualified_tail("A::B:C"), "C");
    assert_eq!(short_qualified_tail("A::B::C"), "C");
}

#[test]
fn qualified_name_matching_uses_the_canonical_non_empty_tail() {
    assert!(qualified_names_match("App::Service.run", "run"));
    assert!(qualified_names_match("App\\Service\\run", "Service.run"));
    assert!(!qualified_names_match("App::read", "App::write"));
    assert!(!qualified_names_match("App::", "Other::"));
}

#[test]
fn callable_reference_variants_normalize_common_forms() {
    assert!(callable_reference_variants("&executor/1").contains(&"executor".to_string()));
    assert!(callable_reference_variants("fun executor/1").contains(&"executor".to_string()));
    assert!(callable_reference_variants("\\&executor").contains(&"executor".to_string()));
    assert!(callable_reference_variants("'executor'").contains(&"executor".to_string()));
    assert!(callable_reference_variants("method(:executor)").contains(&"executor".to_string()));
    assert!(callable_reference_variants("App::executor").contains(&"executor".to_string()));
}

#[test]
fn case_probe_path_matches_only_vfs_temp_shape() {
    assert!(is_bonsai_case_probe_path(Path::new(".bonsai_case_probe_123_456")));
    assert!(is_bonsai_case_probe_path(Path::new(
        "/tmp/.BONSAI_CASE_PROBE_123_456"
    )));
    assert!(!is_bonsai_case_probe_path(Path::new(".bonsai_case_probe_123")));
    assert!(!is_bonsai_case_probe_path(Path::new(
        ".bonsai_case_probe_123_456.py"
    )));
    assert!(!is_bonsai_case_probe_path(Path::new(
        ".bonsai_case_probe_notes.py"
    )));
}
