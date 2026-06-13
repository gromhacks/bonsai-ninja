use super::SecondaryFilter;
use serde_json::json;

#[test]
fn inactive_filter_keeps_everything() {
    let f = SecondaryFilter::new(&[], &[]);
    assert!(!f.is_active());
    assert!(f.matches_text("anything"));
    assert!(f.matches_value(&json!({"file": "a.rs"})));
}

#[test]
fn contains_is_case_insensitive_substring_and() {
    let f = SecondaryFilter::new(&["EXEC".to_string(), "user".to_string()], &[]);
    assert!(f.matches_text("os.exec(user_input)"));
    // missing one of the two needles -> dropped
    assert!(!f.matches_text("os.exec(constant)"));
}

#[test]
fn not_contains_drops_on_any_match() {
    let f = SecondaryFilter::new(&[], &["test".to_string()]);
    assert!(f.matches_text("src/main.rs"));
    assert!(!f.matches_text("src/main_TEST.rs"));
}

#[test]
fn matches_value_searches_string_values_not_keys() {
    // `--contains source` must NOT match the `"source"` JSON key —
    // only string values count.
    let f = SecondaryFilter::new(&["source".to_string()], &[]);
    assert!(!f.matches_value(&json!({"source": {"file": "a.rs"}, "sink": {"file": "b.rs"}})));
    assert!(f.matches_value(&json!({"sink": {"file": "source_handler.rs"}})));
}

#[test]
fn retain_drops_non_matching_rows() {
    let f = SecondaryFilter::new(&["exec".to_string()], &[]);
    let mut rows = vec![
        json!({"code": "os.exec(x)"}),
        json!({"code": "print(y)"}),
        json!({"code": "subprocess.exec(z)"}),
    ];
    f.retain(&mut rows);
    assert_eq!(rows.len(), 2);
}

#[test]
fn needles_do_not_bridge_separate_leaves() {
    // "ab" must not match across two leaves "a" and "b".
    let f = SecondaryFilter::new(&["ab".to_string()], &[]);
    assert!(!f.matches_value(&json!(["a", "b"])));
    assert!(f.matches_value(&json!(["zab"])));
}
