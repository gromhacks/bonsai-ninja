use super::*;

#[test]
fn byte_offsets_saturate_instead_of_wrapping() {
    assert_eq!(saturating_byte_offset(u64::MAX as usize), u64::MAX);
}

#[test]
fn zero_parse_timeout_disables_timeout() {
    assert_eq!(parse_timeout_millis(0), None);
    assert_eq!(parse_timeout_millis(5), Some(Duration::from_millis(5)));
}

#[test]
fn parse_timeout_diagnostic_is_file_level_warning() {
    let diagnostic = parse_timeout_diagnostic(FileId::new(1), 42, Duration::from_millis(7));
    assert_eq!(diagnostic.severity, Severity::Warning);
    assert_eq!(diagnostic.code.as_deref(), Some("parse-timeout"));
    assert_eq!(diagnostic.span, bonsai_common::Span::new(FileId::new(1), 0, 42));
    assert_eq!(diagnostic.message, "file skipped: parse timeout after 7 ms");
}

#[test]
fn parser_diagnostics_are_capped_with_suppression_count() {
    let mut diagnostics = Vec::new();
    let mut suppressed = 0usize;
    for _ in 0..(MAX_PARSE_NODE_DIAGNOSTICS + 5) {
        push_parser_diagnostic(
            &mut diagnostics,
            Diagnostic::new(
                bonsai_common::Span::new(FileId::new(1), 0, 1),
                Severity::Warning,
                "syntax error",
            )
            .with_code("syntax-error"),
            &mut suppressed,
        );
    }

    assert_eq!(diagnostics.len(), MAX_PARSE_NODE_DIAGNOSTICS);
    assert_eq!(suppressed, 5);
    let summary = suppression_summary_diagnostic(FileId::new(1), 10, suppressed);
    assert_eq!(summary.message, "5 more syntax errors suppressed");
    assert_eq!(summary.code.as_deref(), Some("syntax-error"));
}
