use super::*;
use bonsai_common::FileId;

#[test]
fn sink_accumulates_and_reports_errors() {
    let mut sink = DiagnosticSink::new();
    assert!(sink.is_empty());
    sink.push(Diagnostic::new(
        Span::new(FileId::new(0), 0, 1),
        Severity::Error,
        "boom",
    ));
    assert!(sink.has_errors());
    assert_eq!(sink.len(), 1);
}
