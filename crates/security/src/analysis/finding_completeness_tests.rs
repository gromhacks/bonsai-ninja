use super::*;

fn span(file: u32, start: u64, end: u64) -> Span {
    Span::new(bonsai_common::FileId::new(file), start, end)
}

#[test]
fn unresolved_calls_only_mark_terminal_expression_incomplete() {
    let terminal = span(1, 100, 140);

    assert!(unresolved_call_site_is_in_terminal_expression(
        terminal,
        span(1, 112, 128)
    ));
    assert!(unresolved_call_site_is_in_terminal_expression(
        terminal,
        span(1, 100, 140)
    ));
    assert!(!unresolved_call_site_is_in_terminal_expression(
        terminal,
        span(1, 150, 170)
    ));
    assert!(!unresolved_call_site_is_in_terminal_expression(
        terminal,
        span(2, 112, 128)
    ));
    assert!(!unresolved_call_site_is_in_terminal_expression(
        terminal,
        span(1, 90, 150)
    ));
}

#[test]
fn grouped_findings_preserve_incomplete_member_reasons() {
    let mut complete = true;
    let mut reasons = Vec::new();

    merge_analysis_completeness(
        &mut complete,
        &mut reasons,
        false,
        vec!["unresolved-call:encode".to_string()],
    );

    assert!(!complete);
    assert_eq!(reasons, vec!["unresolved-call:encode"]);

    merge_analysis_completeness(
        &mut complete,
        &mut reasons,
        false,
        vec![
            "unresolved-call:encode".to_string(),
            "lineage incomplete".to_string(),
        ],
    );

    assert!(!complete);
    assert_eq!(reasons, vec!["lineage incomplete", "unresolved-call:encode"]);
}
