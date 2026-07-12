use super::*;

fn edge(
    trace_id: u64,
    parent_trace_id: Option<u64>,
    caller: u32,
    callee: u32,
    start: u64,
) -> TaintedCallEdge {
    TaintedCallEdge {
        trace_id,
        parent_trace_id,
        caller: FuncId::new(caller),
        callee: FuncId::new(callee),
        call_span: Span::new(bonsai_common::FileId::new(0), start, start + 1),
        tainted_args: Vec::new(),
        precision: Precision::Exact,
        edge_kind: bonsai_callgraph::EdgeKind::Direct,
    }
}

fn real_edge(trace_id: u64, caller: u32, callee: u32) -> TaintedCallEdge {
    let mut record = edge(trace_id, None, caller, callee, trace_id * 10);
    record.tainted_args.push(bonsai_taint::TaintedArg {
        index: 0,
        value_text: format!("v{caller}"),
        param_name: format!("p{callee}"),
    });
    record
}

#[test]
fn source_lineage_reports_truncated_and_omitted_paths() {
    let records = vec![
        edge(1, None, 1, 2, 10),
        edge(2, Some(1), 2, 3, 20),
        edge(3, Some(2), 3, 4, 30),
        edge(4, Some(3), 4, 5, 40),
        edge(5, Some(1), 2, 6, 50),
        edge(6, Some(1), 2, 7, 60),
    ];

    let (lineages, stats) = collect_tainted_source_lineages(&records, FuncId::new(1), 2, 2);

    assert_eq!(stats.emitted_paths, 2);
    assert_eq!(stats.omitted_paths, 1);
    assert_eq!(stats.truncated_paths, 1);
    assert_eq!(lineages.len(), 2);
    assert!(lineages[0].truncated_hops);
    assert_eq!(lineages[0].records.len(), 2);
    assert!(!lineages[1].truncated_hops);

    let summary = SourceLineageSummary::from_statuses(
        lineages
            .iter()
            .enumerate()
            .map(|(idx, emission)| SourceLineageStatus::from_lineage(emission, stats, idx)),
    );
    assert_eq!(summary.emitted_paths, 2);
    assert_eq!(summary.omitted_paths, 1);
    assert_eq!(summary.truncated_hop_flows, 1);
}

#[test]
fn source_lineage_unbounded_limits_emit_every_path() {
    let records = (1..=30)
        .map(|trace_id| edge(trace_id, None, 1, 100 + trace_id as u32, trace_id * 10))
        .collect::<Vec<_>>();

    let (bounded, bounded_stats) = collect_tainted_source_lineages(
        &records,
        FuncId::new(1),
        SourceLineageLimits::bounded_default().max_hops,
        SourceLineageLimits::bounded_default().max_paths,
    );
    assert_eq!(bounded.len(), SOURCE_ANALYSIS_LINEAGE_RENDER_PATHS);
    assert_eq!(bounded_stats.omitted_paths, 6);
    let bounded_summary = SourceLineageSummary::from_statuses(
        bounded
            .iter()
            .enumerate()
            .map(|(idx, emission)| SourceLineageStatus::from_lineage(emission, bounded_stats, idx)),
    );
    assert_eq!(
        bounded_summary.emitted_paths,
        SOURCE_ANALYSIS_LINEAGE_RENDER_PATHS
    );
    assert_eq!(bounded_summary.omitted_paths, 6);

    let (unbounded, unbounded_stats) = collect_tainted_source_lineages(
        &records,
        FuncId::new(1),
        SourceLineageLimits::unbounded().max_hops,
        SourceLineageLimits::unbounded().max_paths,
    );
    assert_eq!(unbounded.len(), records.len());
    assert_eq!(unbounded_stats.omitted_paths, 0);
    assert_eq!(unbounded_stats.truncated_paths, 0);
}

#[test]
fn source_lineage_summary_reports_incomplete_flows() {
    let summary = SourceLineageSummary::from_statuses([
        SourceLineageStatus::complete(),
        SourceLineageStatus {
            complete: false,
            truncated_hops: true,
            omitted_paths: 0,
            emitted_paths: 2,
            max_hops: 3,
            max_paths: 24,
        },
        SourceLineageStatus {
            complete: false,
            truncated_hops: false,
            omitted_paths: 5,
            emitted_paths: 4,
            max_hops: 6,
            max_paths: 24,
        },
    ]);

    assert!(!summary.is_complete());
    assert_eq!(summary.incomplete_flows, 2);
    assert_eq!(summary.truncated_hop_flows, 1);
    assert_eq!(summary.omitted_paths, 5);
    assert_eq!(summary.emitted_paths, 6);
    assert_eq!(summary.max_hops, SOURCE_ANALYSIS_LINEAGE_RENDER_HOPS);
    assert_eq!(summary.max_paths, SOURCE_ANALYSIS_LINEAGE_RENDER_PATHS);
}

#[test]
fn source_lineage_merge_preserves_additive_path_counts() {
    let mut merged = SourceLineageStatus {
        complete: true,
        truncated_hops: false,
        omitted_paths: 1,
        emitted_paths: 2,
        max_hops: 4,
        max_paths: 8,
    };
    merge_source_lineage_status(
        &mut merged,
        SourceLineageStatus {
            complete: false,
            truncated_hops: true,
            omitted_paths: 3,
            emitted_paths: 5,
            max_hops: 6,
            max_paths: 10,
        },
    );

    assert!(!merged.complete);
    assert!(merged.truncated_hops);
    assert_eq!(merged.omitted_paths, 4);
    assert_eq!(merged.emitted_paths, 7);
    assert_eq!(merged.max_hops, 6);
    assert_eq!(merged.max_paths, 10);
}

#[test]
fn source_lineage_omissions_attach_to_first_emitted_status() {
    let records = vec![edge(1, None, 1, 2, 10), edge(2, None, 1, 3, 20)];
    let (lineages, mut stats) = collect_tainted_source_lineages(&records, FuncId::new(1), 6, 2);
    stats.omitted_paths = 3;

    let first_rendered = SourceLineageStatus::from_lineage(&lineages[1], stats, 0);
    let later_rendered = SourceLineageStatus::from_lineage(&lineages[0], stats, 1);

    assert_eq!(first_rendered.omitted_paths, 3);
    assert_eq!(later_rendered.omitted_paths, 0);
}

#[test]
fn strict_source_text_matching_keeps_framework_get_receivers_distinct() {
    assert!(security_text_matches_source_strict("getenv", "os.getenv"));
    assert!(security_text_matches_source_strict(
        "request.headers.get",
        "request.headers.get"
    ));
    assert!(!security_text_matches_source_strict(
        "request.args.get",
        "request.headers.get"
    ));
    assert!(!security_text_matches_source_strict(
        "request.values.get",
        "request.args.get"
    ));
}

#[test]
fn canonical_chain_search_has_no_fixed_hop_limit() {
    let records: Vec<_> = (1..=24)
        .map(|caller| real_edge(u64::from(caller), caller, caller + 1))
        .collect();
    let call_graph = bonsai_callgraph::ResolvedCallGraph::from_call_graph(bonsai_callgraph::CallGraph::new());
    let index = CanonicalChainIndex::new(&records, &call_graph);

    let path =
        best_chain_through_real_edges(&index, FuncId::new(1), FuncId::new(25)).expect("long canonical path");
    assert_eq!(path.len(), 25);
    assert_eq!(path.first(), Some(&FuncId::new(1)));
    assert_eq!(path.last(), Some(&FuncId::new(25)));
}

#[test]
fn canonical_chain_reuses_one_complete_tree_for_multiple_terminals() {
    let records = vec![real_edge(1, 1, 2), real_edge(2, 2, 3), real_edge(3, 2, 4)];
    let call_graph = bonsai_callgraph::ResolvedCallGraph::from_call_graph(bonsai_callgraph::CallGraph::new());
    let index = CanonicalChainIndex::new(&records, &call_graph);

    assert_eq!(
        index.best_chain(FuncId::new(1), FuncId::new(3)),
        Some(vec![FuncId::new(1), FuncId::new(2), FuncId::new(3)])
    );
    assert_eq!(
        index.best_chain(FuncId::new(1), FuncId::new(4)),
        Some(vec![FuncId::new(1), FuncId::new(2), FuncId::new(4)])
    );
    assert_eq!(index.best_chain_trees.borrow().len(), 1);
}
