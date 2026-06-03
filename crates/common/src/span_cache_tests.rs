use super::{cached_span_map, cached_span_map_arc};
use crate::FileId;
use std::sync::Arc;

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

#[test]
fn same_length_content_change_with_reused_file_version_rebuilds_map() {
    let first_text = String::from("a\nb\n");
    let second_text = String::from("c\nd\n");
    let first = cached_span_map(FileId::new(4), 1, &first_text);
    let second = cached_span_map(FileId::new(4), 1, &second_text);
    assert!(!std::sync::Arc::ptr_eq(&first, &second));
}

#[test]
fn arc_snapshot_cache_keeps_same_snapshot_fast_but_distinguishes_new_snapshot() {
    let first_text: Arc<str> = Arc::from("a\nb\n");
    let first = cached_span_map_arc(FileId::new(5), 1, &first_text);
    let second = cached_span_map_arc(FileId::new(5), 1, &first_text);
    assert!(std::sync::Arc::ptr_eq(&first, &second));

    let replacement_text: Arc<str> = Arc::from("c\nd\n");
    let replacement = cached_span_map_arc(FileId::new(5), 1, &replacement_text);
    assert!(!std::sync::Arc::ptr_eq(&first, &replacement));
}
