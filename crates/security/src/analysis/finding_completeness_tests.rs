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
fn dart_library_calls_do_not_become_spurious_workspace_resolution_gaps() {
    let root = tempfile::tempdir().expect("temporary Dart workspace");
    for (path, source) in [
        (
            "bin/app.dart",
            include_str!("../../../../examples/dart/language_gauntlet/bin/app.dart"),
        ),
        (
            "lib/src/http/handler.dart",
            include_str!("../../../../examples/dart/language_gauntlet/lib/src/http/handler.dart"),
        ),
        (
            "lib/src/domain/envelope.dart",
            include_str!("../../../../examples/dart/language_gauntlet/lib/src/domain/envelope.dart"),
        ),
        (
            "lib/src/pipeline/pipeline.dart",
            include_str!("../../../../examples/dart/language_gauntlet/lib/src/pipeline/pipeline.dart"),
        ),
        (
            "lib/src/routing/command_router.dart",
            include_str!("../../../../examples/dart/language_gauntlet/lib/src/routing/command_router.dart"),
        ),
        (
            "lib/src/storage/storage.dart",
            include_str!("../../../../examples/dart/language_gauntlet/lib/src/storage/storage.dart"),
        ),
        (
            "lib/src/runtime/executor.dart",
            include_str!("../../../../examples/dart/language_gauntlet/lib/src/runtime/executor.dart"),
        ),
    ] {
        let destination = root.path().join(path);
        std::fs::create_dir_all(destination.parent().expect("Dart fixture parent"))
            .expect("create Dart fixture parent");
        std::fs::write(destination, source).expect("write Dart fixture");
    }

    let ws = Workspace::open_with_options(
        root.path(),
        bonsai_adapters::all_languages_registry(),
        bonsai_workspace::WorkspaceOpenOptions::lazy_query(),
    )
    .expect("open lazy Dart fixture");

    let global = ws.compiler_linkage_index();
    let graph = ws.cached_resolved_call_graph();
    let gaps = graph
        .unresolved_workspace_site_records()
        .iter()
        .map(|site| {
            let caller = global
                .decl_of(SymbolId::new(site.caller.raw()))
                .map_or("<unknown>", |decl| decl.name.as_ref());
            let snapshot = ws.vfs().snapshot(site.span.file).expect("gap file");
            let source = snapshot.text.as_ref();
            let start = usize::try_from(site.span.start).expect("span start");
            let end = usize::try_from(site.span.end).expect("span end");
            format!(
                "{}:{caller}:{}",
                snapshot.path.display(),
                source.get(start..end).unwrap_or("<invalid span>")
            )
        })
        .collect::<Vec<_>>();
    assert!(gaps.is_empty(), "spurious Dart resolver gaps: {gaps:#?}");

    let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../security-patterns");
    let pack = crate::load_rulepack(&rules).expect("load bundled rules");
    let report =
        run_sink_analysis(&ws, &pack, SinkAnalysisOptions::default()).expect("run Dart sink analysis");
    assert!(
        report.analysis_complete,
        "Dart sink analysis must not invent workspace resolver gaps: {:#?}",
        report.analysis_incomplete_reasons
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

#[test]
fn unattributed_security_endpoints_make_the_whole_report_incomplete() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let report = finish_taint_analysis_report(
        Vec::new(),
        TaintReportCompletion {
            ws: &ws,
            scan_files: &[],
            resolution: None,
            unattributed_source_matches: 2,
            unattributed_sink_matches: 3,
            source_rule_count: 1,
            sink_rule_count: 1,
            sanitizer_rule_count: 0,
        },
    );

    assert!(!report.analysis_complete);
    assert_eq!(
        report.analysis_incomplete_reasons,
        vec!["unattributed-sink-matches:3", "unattributed-source-matches:2",]
    );
}
