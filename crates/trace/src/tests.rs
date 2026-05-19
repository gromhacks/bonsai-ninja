use super::*;

fn source_span() -> SourceSpan {
    SourceSpan {
        file: "app.py".to_string(),
        start_line: 1,
        start_col: 1,
        end_line: 1,
        end_col: 1,
        start_byte: 0,
        end_byte: 1,
    }
}

fn step(id: u64, kind: TraceStepKind, precision: Precision) -> TraceStep {
    TraceStep {
        id,
        path_id: 1,
        order: id + 1,
        kind,
        message: format!("step {id}"),
        function: "handle".to_string(),
        module: "app.py".to_string(),
        file: "app.py".to_string(),
        span: source_span(),
        state_before: None,
        state_after: None,
        precision,
        notes: Vec::new(),
    }
}

#[test]
fn truncate_after_step_rebuilds_derived_trace_sections() {
    let mut trace = TraceResult {
        trace_id: "trace-test".to_string(),
        query: TraceQuery::default(),
        summary: TraceSummary {
            analysis_complete: true,
            total_steps: 4,
            total_paths: 1,
            explored_paths: 1,
            precision: Precision::Narrowed,
            ..TraceSummary::default()
        },
        paths: vec![PathSummary {
            path_id: 1,
            first_step: 0,
            last_step: 3,
            path_constraints: Vec::new(),
            terminated_by: PathTermination::Return,
            precision: Precision::Narrowed,
        }],
        steps: vec![
            step(0, TraceStepKind::EnterFunction, Precision::Exact),
            step(1, TraceStepKind::Call, Precision::Narrowed),
            step(2, TraceStepKind::EvalExpr, Precision::Exact),
            step(3, TraceStepKind::Return, Precision::Exact),
        ],
        edges: vec![
            TraceEdge {
                from_step: 0,
                to_step: 1,
                kind: TraceEdgeKind::Next,
            },
            TraceEdge {
                from_step: 1,
                to_step: 2,
                kind: TraceEdgeKind::CallEnter,
            },
            TraceEdge {
                from_step: 2,
                to_step: 3,
                kind: TraceEdgeKind::Next,
            },
        ],
        states: Vec::new(),
        diagnostics: Vec::new(),
        metadata: TraceMetadata::default(),
    };

    truncate_after_step(&mut trace, 1);

    assert_eq!(trace.steps.len(), 2);
    assert_eq!(trace.edges.len(), 1);
    assert_eq!(trace.edges[0].from_step, 0);
    assert_eq!(trace.edges[0].to_step, 1);
    assert_eq!(trace.summary.total_steps, 2);
    assert_eq!(trace.summary.total_paths, 1);
    assert_eq!(trace.summary.explored_paths, 1);
    assert_eq!(trace.summary.precision, Precision::Narrowed);
    assert_eq!(trace.paths.len(), 1);
    assert_eq!(trace.paths[0].last_step, 1);
    assert_eq!(trace.paths[0].precision, Precision::Narrowed);
}

#[test]
fn path_summary_marks_unresolved_call_diagnostic_termination() {
    let mut unresolved = step(1, TraceStepKind::Diagnostic, Precision::Exact);
    unresolved.message = "Unresolved call dynamic_target".to_string();
    let paths = path_summaries(
        &[
            step(0, TraceStepKind::EnterFunction, Precision::Exact),
            unresolved,
            step(2, TraceStepKind::Return, Precision::Exact),
        ],
        false,
    );

    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].terminated_by, PathTermination::UnknownCall);
    assert_eq!(paths[0].precision, Precision::Exact);
}

#[test]
fn public_semantic_step_suppresses_diagnostic_precision() {
    let raw = RawStep {
        id: bonsai_common::TraceStepId::new(0),
        path_id: 0,
        kind: StepKind::Call,
        span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 1),
        func: bonsai_common::FuncId::new(1),
        precision: Precision::Unknown,
        message: "Call dynamic_target".to_string(),
    };
    let mut reasons = Vec::new();

    let public = public_semantic_step(&raw, &mut reasons);

    assert_eq!(public.kind, TraceStepKind::Diagnostic);
    assert_eq!(public.precision, Precision::Exact);
    assert!(
        public.message.contains("Suppressed diagnostic-precision Call"),
        "diagnostic precision should be metadata, not call evidence: {}",
        public.message
    );
    assert_eq!(reasons, vec!["diagnostic-precision-step:Call"]);
}
