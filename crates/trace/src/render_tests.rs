use super::to_text;
use crate::{
    AnalysisLimits, SourceSpan, TraceMetadata, TraceQuery, TraceResult, TraceStep, TraceStepKind,
    TraceSummary,
};
use bonsai_common::Precision;

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
            precision: Precision::Exact,
            ..TraceSummary::default()
        },
        paths: vec![crate::PathSummary {
            path_id: 1,
            first_step: 0,
            last_step: 0,
            path_constraints: Vec::new(),
            terminated_by: crate::PathTermination::Unknown,
            precision: Precision::Exact,
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
            precision: Precision::Exact,
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
        rendered.contains("Analysis incomplete: unresolved-call:missing"),
        "semantic gap should still be surfaced in the summary:\n{rendered}"
    );
}

#[test]
fn text_renderer_suppresses_diagnostic_precision_steps() {
    let trace = TraceResult {
        trace_id: "trace-test".to_string(),
        query: TraceQuery::default(),
        summary: TraceSummary {
            language: "python".to_string(),
            analysis_complete: false,
            analysis_incomplete_reasons: vec!["diagnostic-precision-step:Call".to_string()],
            total_steps: 1,
            total_paths: 1,
            explored_paths: 1,
            precision: Precision::Exact,
            ..TraceSummary::default()
        },
        paths: vec![crate::PathSummary {
            path_id: 1,
            first_step: 0,
            last_step: 0,
            path_constraints: Vec::new(),
            terminated_by: crate::PathTermination::Unknown,
            precision: Precision::Exact,
        }],
        steps: vec![TraceStep {
            id: 0,
            path_id: 1,
            order: 1,
            kind: TraceStepKind::Call,
            message: "Call dynamic_target".to_string(),
            function: "entry".to_string(),
            module: "app.py".to_string(),
            file: "app.py".to_string(),
            span: span(),
            code: String::new(),
            state_before: None,
            state_after: None,
            precision: Precision::Unknown,
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
        rendered.contains("Suppressed diagnostic-precision trace step"),
        "renderer should refuse to present diagnostic precision as evidence:\n{rendered}"
    );
    assert!(
        !rendered.contains("Call dynamic_target"),
        "renderer must not show the suppressed call as evidence:\n{rendered}"
    );
    assert!(
        !rendered.contains("[non-semantic"),
        "renderer must not expose non-semantic analysis evidence:\n{rendered}"
    );
}
