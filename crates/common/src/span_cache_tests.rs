use super::cached_span_map;
use crate::FileId;

#[test]
fn returns_same_map_for_same_file_version() {
    let first = cached_span_map(FileId::new(1), 7, "a\nb\n");
    let second = cached_span_map(FileId::new(1), 7, "a\nb\n");
    assert!(std::sync::Arc::ptr_eq(&first, &second));
}

#[test]
fn version_change_rebuilds_map() {
    let first = cached_span_map(FileId::new(2), 1, "a\n");
    let second = cached_span_map(FileId::new(2), 2, "a\n");
    assert!(!std::sync::Arc::ptr_eq(&first, &second));
}

#[test]
fn content_change_with_reused_file_version_rebuilds_map() {
    let first = cached_span_map(FileId::new(3), 1, "a\n");
    let second = cached_span_map(FileId::new(3), 1, "a\nb\n");
    assert!(!std::sync::Arc::ptr_eq(&first, &second));
}
