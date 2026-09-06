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

pub(super) fn step(id: u64, kind: TraceStepKind) -> TraceStep {
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
        code: String::new(),
        state_before: None,
        state_after: None,
        notes: Vec::new(),
    }
}

#[test]
fn trace_edges_preserve_each_path_when_steps_interleave() {
    let first = step(0, TraceStepKind::EnterFunction);
    let mut other = step(1, TraceStepKind::Assign);
    other.path_id = 2;
    let last = step(2, TraceStepKind::Assign);
    let edges = trace_edges(&[first, other, last]);
    assert_eq!(edges.len(), 1);
    assert_eq!((edges[0].from_step, edges[0].to_step), (0, 2));
}

#[test]
fn trace_edges_do_not_invent_dispatch_handlers_or_branch_verdicts() {
    let next = step(1, TraceStepKind::Assign);
    for kind in [
        TraceStepKind::Call,
        TraceStepKind::Return,
        TraceStepKind::Throw,
        TraceStepKind::BranchSplit,
    ] {
        assert_eq!(edge_kind(&step(0, kind), &next), TraceEdgeKind::Next, "{kind:?}");
    }
    assert_eq!(
        edge_kind(
            &step(0, TraceStepKind::Call),
            &step(1, TraceStepKind::EnterFunction)
        ),
        TraceEdgeKind::CallEnter
    );
    assert_eq!(
        edge_kind(&next, &step(2, TraceStepKind::Merge)),
        TraceEdgeKind::Merge
    );
}

#[test]
fn trace_source_lines_and_coordinates_share_one_immutable_snapshot() {
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("app.py"), "first\n  λ value\n");
    let span = Span::new(file, 8, 10);
    let mut cache = ahash::AHashMap::new();
    let location = span_to_source(&span, &vfs, &mut cache);
    assert_eq!((location.start_line, location.start_col), (2, 3));
    vfs.write(std::path::Path::new("app.py"), "changed and no second line");
    assert_eq!(span_line_text(&span, &vfs, &mut cache), "λ value");
    let repeated = span_to_source(&span, &vfs, &mut cache);
    assert_eq!((repeated.start_line, repeated.start_col), (2, 3));
}

#[test]
fn trace_locations_are_workspace_relative_without_rewriting_module_names() {
    assert_eq!(
        portable_trace_path("/workspace", "/workspace/src/app.rs"),
        "src/app.rs"
    );
    assert_eq!(
        portable_trace_path("/workspace", "crate.runtime.Handle"),
        "crate.runtime.Handle"
    );
    assert_eq!(portable_trace_path("", "/external/lib.rs"), "/external/lib.rs");
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
            ..TraceSummary::default()
        },
        paths: vec![PathSummary {
            path_id: 1,
            first_step: 0,
            last_step: 3,
            path_constraints: Vec::new(),
            terminated_by: PathTermination::Return,
        }],
        steps: vec![
            step(0, TraceStepKind::EnterFunction),
            step(1, TraceStepKind::Call),
            step(2, TraceStepKind::EvalExpr),
            step(3, TraceStepKind::Return),
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
    assert_eq!(trace.paths.len(), 1);
    assert_eq!(trace.paths[0].last_step, 1);
}

#[test]
fn selected_sink_marks_the_retained_path_as_an_intentional_stop() {
    let mut trace = TraceResult {
        steps: vec![
            step(0, TraceStepKind::EnterFunction),
            step(1, TraceStepKind::EnterFunction),
        ],
        paths: vec![PathSummary {
            path_id: 1,
            first_step: 0,
            last_step: 1,
            path_constraints: Vec::new(),
            terminated_by: PathTermination::Unknown,
        }],
        ..TraceResult::default()
    };

    mark_last_step_termination(&mut trace, PathTermination::ReachedTarget);

    assert_eq!(trace.paths[0].terminated_by, PathTermination::ReachedTarget);
}

#[test]
fn path_summary_marks_unresolved_call_diagnostic_termination() {
    let mut unresolved = step(1, TraceStepKind::Diagnostic);
    unresolved.message = "Unresolved call dynamic_target".to_string();
    let paths = path_summaries(
        &[
            step(0, TraceStepKind::EnterFunction),
            unresolved,
            step(2, TraceStepKind::Return),
        ],
        false,
    );

    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].terminated_by, PathTermination::UnknownCall);
}
