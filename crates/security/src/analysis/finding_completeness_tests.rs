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
fn compiler_resolution_gaps_drive_finding_completeness_without_name_guesses() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "app.py",
        Arc::<str>::from(concat!(
            "def pick(value: str):\n",
            "    return value\n\n",
            "def pick(value: bytes):\n",
            "    return value\n\n",
            "def entry(value):\n",
            "    return sink(pick(value))\n",
        )),
    );
    let _ = ws.db().decl_index(file);
    let call_graph = ws.cached_resolved_call_graph();
    let unresolved = call_graph.unresolved_workspace_call_sites().collect::<Vec<_>>();
    assert_eq!(
        unresolved.len(),
        1,
        "the compiler should report the ambiguous in-workspace overload once"
    );
    let (caller, unresolved_span) = unresolved[0];

    let coverage = ResolutionCoverage::from_graph(call_graph.as_ref(), [caller]);
    assert_eq!(
        coverage.unresolved_workspace_sites,
        AHashSet::from_iter([(caller, unresolved_span)])
    );

    let terminal_span = Span::new(
        unresolved_span.file,
        unresolved_span.start.saturating_sub(1),
        unresolved_span.end.saturating_add(1),
    );
    let graph = EntryTaintGraph {
        tainted_calls: vec![
            TaintedCall {
                parent_trace_id: None,
                caller,
                name: "pick".to_string(),
                call_span: unresolved_span,
                tainted_args: Vec::new(),
                tainted_receiver: None,
                tainted_receiver_source_names: Vec::new(),
                kind: bonsai_taint::TaintedCallKind::Call,
            },
            TaintedCall {
                parent_trace_id: None,
                caller,
                name: "sink".to_string(),
                call_span: terminal_span,
                tainted_args: Vec::new(),
                tainted_receiver: None,
                tainted_receiver_source_names: Vec::new(),
                kind: bonsai_taint::TaintedCallKind::Call,
            },
        ],
        ..EntryTaintGraph::default()
    };
    let index = GraphUnresolvedCallIndex::new(call_graph.as_ref(), &graph);
    assert_eq!(
        index.reasons_for_terminal_call(&graph.tainted_calls[1]),
        vec!["unresolved-call:pick"]
    );
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
