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

#[test]
fn streaming_string_values_match_the_value_tree_leaves() {
    #[derive(serde::Serialize)]
    struct Row<'a> {
        name: &'a str,
        params: Vec<&'a str>,
        nested: serde_json::Value,
        count: u32,
        flag: bool,
        none: Option<&'a str>,
    }
    let row = Row {
        name: "exec \"quoted\" \\ back",
        params: vec!["a:b", "tab\tnew\nline", "ünï \u{1F600}"],
        nested: serde_json::json!({"key": "value:with:colons", "list": [1, "two", {"deep": "x"}]}),
        count: 7,
        flag: true,
        none: None,
    };
    let value = serde_json::to_value(&row).expect("value");
    let mut expected = String::new();
    super::collect_string_leaves(&value, &mut expected);
    let json = serde_json::to_vec(&row).expect("json");
    let mut streamed = String::new();
    super::collect_json_string_values(&json, &mut streamed);
    // Same leaves; a `Value` tree orders object keys, the stream keeps
    // serialization order. Leaves are matched independently, so order is
    // immaterial.
    let mut expected_lines: Vec<&str> = expected.lines().collect();
    let mut streamed_lines: Vec<&str> = streamed.lines().collect();
    expected_lines.sort_unstable();
    streamed_lines.sort_unstable();
    assert_eq!(streamed_lines, expected_lines);
    // Keys never leak into the searchable text.
    assert!(!streamed.contains("params"));
    assert!(!streamed.contains("nested"));
}

#[test]
fn matches_row_agrees_with_matches_value_and_adds_the_extra_leaf() {
    let filter = super::SecondaryFilter::new(&["value:with".to_string()], &["absent".to_string()]);
    let row = serde_json::json!({"name": "n", "nested": {"key": "VALUE:WITH:colons"}});
    assert!(filter.matches_value(&row));
    let mut scratch = super::FilterScratch::default();
    assert!(filter.matches_row(&row, &mut scratch, None));
    let location_filter = super::SecondaryFilter::new(&["client.java:12".to_string()], &[]);
    assert!(!location_filter.matches_row(&row, &mut scratch, None));
    assert!(location_filter.matches_row(&row, &mut scratch, Some("Client.java:12")));
}
