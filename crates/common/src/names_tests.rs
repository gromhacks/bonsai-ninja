use std::path::Path;

use super::{callable_reference_variants, is_bonsai_case_probe_path, short_qualified_tail};

#[test]
fn qualified_tail_uses_rightmost_supported_separator() {
    assert_eq!(short_qualified_tail("a.b.c"), "c");
    assert_eq!(short_qualified_tail("std::fs::read"), "read");
    assert_eq!(short_qualified_tail("ptr->call"), "call");
    assert_eq!(short_qualified_tail("Module:function"), "function");
    assert_eq!(short_qualified_tail("plain"), "plain");
}

#[test]
fn single_colon_does_not_split_inside_double_colon_tail() {
    assert_eq!(short_qualified_tail("A::B:C"), "C");
    assert_eq!(short_qualified_tail("A::B::C"), "C");
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
