use super::to_text;
use crate::{
    AnalysisLimits, SourceSpan, TraceMetadata, TraceQuery, TraceResult, TraceStep, TraceStepKind,
    TraceSummary,
};

fn span() -> SourceSpan {
    SourceSpan {
        file: "app.py".to_string(),
        start_line: 1,
        start_col: 1,
        end_line: 1,
        end_col: 7,
        start_byte: 0,
        end_byte: 6,
    }
}

#[test]
fn text_renderer_reports_unresolved_calls_as_incomplete_metadata() {
    let trace = TraceResult {
        trace_id: "trace-test".to_string(),
        query: TraceQuery::default(),
        summary: TraceSummary {
            language: "python".to_string(),
            analysis_complete: false,
            analysis_incomplete_reasons: vec!["unresolved-call:missing".to_string()],
            total_steps: 1,
            total_paths: 1,
            explored_paths: 1,
            ..TraceSummary::default()
        },
        paths: vec![crate::PathSummary {
            path_id: 1,
            first_step: 0,
            last_step: 0,
            path_constraints: Vec::new(),
            terminated_by: crate::PathTermination::Unknown,
        }],
        steps: vec![TraceStep {
            id: 0,
            path_id: 1,
            order: 1,
            kind: TraceStepKind::Diagnostic,
            message: "Unresolved call missing".to_string(),
            function: "entry".to_string(),
            module: "app.py".to_string(),
            file: "app.py".to_string(),
            span: span(),
            code: String::new(),
            state_before: None,
            state_after: None,
            notes: Vec::new(),
        }],
        edges: Vec::new(),
        states: Vec::new(),
        diagnostics: Vec::new(),
        metadata: TraceMetadata {
            engine_version: "test".to_string(),
            analysis_limits: AnalysisLimits::default(),
        },
    };

    let rendered = to_text(&trace);
    assert!(
        rendered.contains("Unresolved call missing"),
        "unresolved calls should be visible as exact diagnostics:\n{rendered}"
    );
    assert!(
        !rendered.contains("[non-semantic"),
        "trace render must not expose non-semantic analysis evidence:\n{rendered}"
    );
    assert!(
        rendered.contains("Analysis incomplete: unresolved calls: 1 (missing)"),
        "semantic gap should still be surfaced in the summary:\n{rendered}"
    );
}

#[test]
fn incomplete_reason_summary_groups_exact_counts_and_samples() {
    let mut reasons = (0..20)
        .map(|index| format!("unresolved-call:callee_{index:02}"))
        .collect::<Vec<_>>();
    reasons.push("ambiguous-call:dispatch:3".to_string());
    reasons.push("max-depth:4".to_string());
    let summary = crate::summarize_incomplete_reasons(&reasons, 3);
    assert_eq!(
        summary,
        "unresolved calls: 20 (callee_00, callee_01, callee_02, … +17); \
         ambiguous calls: 1 (dispatch); other reasons: 1 (max-depth:4)"
    );
}
