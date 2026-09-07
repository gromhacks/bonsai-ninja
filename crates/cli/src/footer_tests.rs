use super::{paging_total_label, uncapped_hint_tokens};
use crate::paging::PageInfo;

fn page() -> PageInfo {
    PageInfo {
        page_number: 1,
        total_pages: 2,
        page_size: 5,
        shown_rows: 5,
        total_rows: 10,
        budget: Some(1_024),
        tokens_used: 900,
        cursor: "P:00000000".to_string(),
        next_cursor: Some("P:00000001".to_string()),
        is_last: false,
        start_offset: 0,
        total_tokens_uncapped: 8_192,
    }
}

#[test]
fn uncapped_estimate_is_stable_across_pages_with_different_render_costs() {
    let info = page();
    assert_eq!(uncapped_hint_tokens(&info, 300), Some(8_192));
    assert_eq!(uncapped_hint_tokens(&info, 700), Some(8_192));
}

#[test]
fn complete_single_page_does_not_advertise_another_larger_artifact() {
    let mut info = page();
    info.total_pages = 1;
    info.is_last = true;
    info.next_cursor = None;
    assert_eq!(uncapped_hint_tokens(&info, 300), None);
}

#[test]
fn footer_units_describe_rows_not_unrelated_semantic_counts() {
    for (command, singular, plural) in [
        ("security <workspace> taint-analysis", "finding", "findings"),
        (
            "security <workspace> source-analysis",
            "source flow",
            "source flows",
        ),
        (
            "security <workspace> dependency-analysis",
            "dependency",
            "dependencies",
        ),
        ("security <workspace> deps", "dependency", "dependencies"),
        ("entrypoints <workspace>", "entry point", "entry points"),
        ("vars <workspace>", "write", "writes"),
        ("operations <workspace>", "operation", "operations"),
        ("classes <workspace>", "type", "types"),
        ("imports <workspace>", "import", "imports"),
    ] {
        let hint = format!("bonsai-ninja {command}");
        assert_eq!(paging_total_label(&hint, 1), singular);
        assert_eq!(paging_total_label(&hint, 2), plural);
    }
}
