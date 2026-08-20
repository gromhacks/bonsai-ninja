use super::{
    build_filter_marker, calculate_inspect_taint_flow_json_upper_bound, dedup_structural_flows,
    import_hit_text, inspect_requested_window, inspect_taint_flow_json_upper_bound,
    render_inspect_report_text, retrieval_prefilter_for_inspect_with_limit, taint_flow_contains_needle,
    taint_flow_matches_query, walk_flow_hits, FlowHitWalkContext, HitOut, InspectFilters,
    InspectFlowRendered, InspectJsonPageUnit, InspectOut, InspectRenderOptions, InspectReport,
    InspectSummary, InspectTaintFlow, InspectTaintStep, InspectTaintedArg, Matcher,
};
use crate::args::FactKindFilter;
use crate::paging::{FormatClass, PageArg, PagingConfig};
use bonsai_common::{FileId, FuncId, Span};
use bonsai_lang_api::{CallKind, DeclKind, FlowEvent, ImportScope, ImportSpec};
use bonsai_sdk::find_call_span_by_name;
use bonsai_sdk::Workspace;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn span(start: u32) -> Span {
    Span {
        file: FileId(0),
        start: u64::from(start),
        end: u64::from(start + 1),
    }
}

#[test]
fn inspect_render_caches_only_the_requested_page() {
    assert_eq!(
        inspect_requested_window(7, 100_000)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![7]
    );
    assert_eq!(
        inspect_requested_window(7, 100).into_iter().collect::<Vec<_>>(),
        vec![7]
    );
}

fn assign_event() -> FlowEvent {
    FlowEvent::Assign {
        target: "user".to_string(),
        source_name: None,
        source_names: vec!["request".to_string()],
        source_call: Some("read_user".to_string()),
        source_call_args: vec!["request".to_string()],
        span: span(10),
        declares_new_binding: false,
        value_kind: None,
    }
}

#[test]
fn walk_flow_hits_surfaces_assignment_source_calls() {
    let matcher = Matcher::build(Some("read_user"), false).expect("matcher");
    let kinds = ahash::AHashSet::from_iter(["call".to_string()]);
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut out: Vec<HitOut> = Vec::new();
    let mut push = |kind: &str,
                    text: String,
                    _span: Span,
                    _containing: Option<(FuncId, String)>,
                    _exact: bool,
                    _out: &mut Vec<HitOut>| {
        seen.push((kind.to_string(), text));
    };

    walk_flow_hits(
        &[assign_event()],
        FuncId::new(1),
        "handler",
        FlowHitWalkContext {
            workspace: None,
            matcher: &matcher,
            endpoint_kind_filter: None,
            kinds: &kinds,
        },
        &mut out,
        &mut push,
    );

    assert_eq!(seen, vec![("call".to_string(), "read_user".to_string())]);
}

#[test]
fn walk_flow_hits_surfaces_assignment_source_call_args() {
    let matcher = Matcher::build(Some("request"), false).expect("matcher");
    let kinds = ahash::AHashSet::from_iter(["arg".to_string()]);
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut out: Vec<HitOut> = Vec::new();
    let mut push = |kind: &str,
                    text: String,
                    _span: Span,
                    _containing: Option<(FuncId, String)>,
                    _exact: bool,
                    _out: &mut Vec<HitOut>| {
        seen.push((kind.to_string(), text));
    };

    walk_flow_hits(
        &[assign_event()],
        FuncId::new(1),
        "handler",
        FlowHitWalkContext {
            workspace: None,
            matcher: &matcher,
            endpoint_kind_filter: None,
            kinds: &kinds,
        },
        &mut out,
        &mut push,
    );

    assert_eq!(seen, vec![("arg".to_string(), "request".to_string())]);
}

#[test]
fn walk_flow_hits_prefers_explicit_call_over_assignment_projection() {
    let matcher = Matcher::build(Some("read_user"), false).expect("matcher");
    let kinds = ahash::AHashSet::from_iter(["call".to_string()]);
    let mut assign = assign_event();
    if let FlowEvent::Assign { span, .. } = &mut assign {
        span.start = 10;
        span.end = 80;
    }
    let call_span = Span {
        file: FileId(0),
        start: 30,
        end: 39,
    };
    let call = FlowEvent::Call {
        span: call_span,
        name: "read_user".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: Vec::new(),
    };
    let mut seen: Vec<(String, String, Span)> = Vec::new();
    let mut out: Vec<HitOut> = Vec::new();
    let mut push = |kind: &str,
                    text: String,
                    span: Span,
                    _containing: Option<(FuncId, String)>,
                    _assignment_projection: bool,
                    _out: &mut Vec<HitOut>| {
        seen.push((kind.to_string(), text, span));
    };

    walk_flow_hits(
        &[assign, call],
        FuncId::new(1),
        "handler",
        FlowHitWalkContext {
            workspace: None,
            matcher: &matcher,
            endpoint_kind_filter: None,
            kinds: &kinds,
        },
        &mut out,
        &mut push,
    );

    assert_eq!(
        seen,
        vec![("call".to_string(), "read_user".to_string(), call_span)],
        "one source call must render once from the explicit AST call event"
    );
}

#[test]
fn walk_flow_hits_honors_endpoint_kind_filter() {
    let matcher = Matcher::build(Some("read_user"), false).expect("matcher");
    let kinds = ahash::AHashSet::default();
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut out: Vec<HitOut> = Vec::new();
    let mut push = |kind: &str,
                    text: String,
                    _span: Span,
                    _containing: Option<(FuncId, String)>,
                    _exact: bool,
                    _out: &mut Vec<HitOut>| {
        seen.push((kind.to_string(), text));
    };

    walk_flow_hits(
        &[assign_event()],
        FuncId::new(1),
        "handler",
        FlowHitWalkContext {
            workspace: None,
            matcher: &matcher,
            endpoint_kind_filter: Some(bonsai_sdk::FactKindFilter::Call),
            kinds: &kinds,
        },
        &mut out,
        &mut push,
    );

    assert_eq!(seen, vec![("call".to_string(), "read_user".to_string())]);
}

#[test]
fn find_call_span_matches_assignment_source_call() {
    assert_eq!(
        find_call_span_by_name(&[assign_event()], "read_user"),
        Some(span(10))
    );
}

#[test]
fn inspect_cli_filters_map_one_to_one_to_sdk_filters() {
    let cli = InspectFilters {
        from: Some("request"),
        from_kind: Some(FactKindFilter::Read),
        to: Some("os.system"),
        to_kind: Some(FactKindFilter::Call),
        file: Some("gateway.py"),
        in_fn: Some("handle_request"),
    };
    let sdk = cli.to_sdk();
    assert_eq!(sdk.from, Some("request"));
    assert_eq!(sdk.from_kind, Some(bonsai_sdk::FactKindFilter::Read));
    assert_eq!(sdk.to, Some("os.system"));
    assert_eq!(sdk.to_kind, Some(bonsai_sdk::FactKindFilter::Call));
    assert_eq!(sdk.file, Some("gateway.py"));
    assert_eq!(sdk.in_fn, Some("handle_request"));

    let all_kinds = [
        (FactKindFilter::Decl, bonsai_sdk::FactKindFilter::Decl),
        (FactKindFilter::Call, bonsai_sdk::FactKindFilter::Call),
        (FactKindFilter::Read, bonsai_sdk::FactKindFilter::Read),
        (FactKindFilter::Write, bonsai_sdk::FactKindFilter::Write),
        (FactKindFilter::Arg, bonsai_sdk::FactKindFilter::Arg),
        (FactKindFilter::StringLit, bonsai_sdk::FactKindFilter::StringLit),
        (FactKindFilter::Import, bonsai_sdk::FactKindFilter::Import),
        (FactKindFilter::Class, bonsai_sdk::FactKindFilter::Class),
    ];
    for (cli_kind, sdk_kind) in all_kinds {
        assert_eq!(cli_kind.to_sdk(), sdk_kind);
    }
}

#[test]
fn filter_marker_matches_structured_subjects_not_raw_source_text() {
    let filters = InspectFilters {
        to: Some("pickle"),
        ..InspectFilters::default()
    };

    let raw_line_only = build_filter_marker(filters, &["call loads"], "7");
    assert_eq!(
        raw_line_only, "",
        "raw source text must not place a TO marker without a structured fact subject"
    );

    let structured_subject = build_filter_marker(filters, &["pickle.loads"], "7");
    assert_eq!(structured_subject, "[FLOW 7 TO: pickle]");
}

#[test]
fn inspect_import_hit_text_keeps_original_and_alias_visible() {
    let renamed_symbol = ImportSpec {
        span: span(1),
        module: "os".to_string(),
        alias: Some("run_command".to_string()),
        is_wildcard: false,
        original_name: Some("system".to_string()),
        scope: ImportScope::Module,
    };
    assert_eq!(import_hit_text(&renamed_symbol), "system from os as run_command");

    let renamed_module = ImportSpec {
        span: span(2),
        module: "os".to_string(),
        alias: Some("operating_system".to_string()),
        is_wildcard: false,
        original_name: None,
        scope: ImportScope::Module,
    };
    assert_eq!(import_hit_text(&renamed_module), "os as operating_system");
}

#[test]
fn inspect_retrieval_prefilter_uses_warmed_sidecar_candidate_files() {
    let root = tempdir_for_test("inspect-retrieval-prefilter");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(
        root.join("service.py"),
        "def inspect_unique_symbol():\n    return 'ok'\n",
    )
    .expect("write service");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters = retrieval_prefilter_for_inspect_with_limit(
        &root,
        Some("inspect_unique_symbol"),
        false,
        InspectFilters::default(),
        false,
        false,
        1,
    )
    .expect("prefilter")
    .expect("fresh retrieval sidecar should provide inspect candidates");

    assert_eq!(filters, vec!["service.py"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn inspect_retrieval_prefilter_keeps_files_matched_only_by_named_arg_key() {
    let root = tempdir_for_test("inspect-retrieval-prefilter-named-arg");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(
        root.join("service.py"),
        "def handler(endpoint):\n    connect(destination_kw=endpoint)\n",
    )
    .expect("write service");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters = retrieval_prefilter_for_inspect_with_limit(
        &root,
        Some("destination_kw"),
        false,
        InspectFilters::default(),
        false,
        false,
        1,
    )
    .expect("prefilter")
    .expect("fresh retrieval sidecar should provide inspect candidates for named arg keys");

    assert_eq!(filters, vec!["service.py"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn inspect_retrieval_prefilter_uses_safe_empty_scope_for_no_candidates() {
    let root = tempdir_for_test("inspect-retrieval-empty");
    std::fs::write(root.join("app.py"), "def only_symbol():\n    return 1\n").expect("write app");
    std::fs::write(root.join("other.py"), "def other_symbol():\n    return 2\n").expect("write other");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters = retrieval_prefilter_for_inspect_with_limit(
        &root,
        Some("missing_symbol"),
        false,
        InspectFilters::default(),
        false,
        false,
        1,
    )
    .expect("prefilter")
    .expect("fresh retrieval sidecar should decide no candidates");

    assert!(
        !filters.is_empty(),
        "inspect must not pass [] to filtered workspace open because [] opens every file"
    );
    assert!(!filters.iter().any(|filter| std::path::Path::new(filter)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("py"))));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn inspect_retrieval_prefilter_scopes_graph_flow_queries() {
    let root = tempdir_for_test("inspect-retrieval-graph-flow");
    std::fs::write(
        root.join("app.py"),
        "def inspect_unique_symbol():\n    return 1\n",
    )
    .expect("write app");
    std::fs::write(root.join("other.py"), "def other_symbol():\n    return 2\n").expect("write other");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters = retrieval_prefilter_for_inspect_with_limit(
        &root,
        Some("inspect_unique_symbol"),
        false,
        InspectFilters::default(),
        true,
        false,
        1,
    )
    .expect("prefilter");

    assert_eq!(filters, Some(vec!["app.py".to_string()]));
    let _ = std::fs::remove_dir_all(root);
}

fn sample_taint_flow() -> InspectTaintFlow {
    let mut flow = InspectTaintFlow {
        taint_id: "T:1234".to_string(),
        entry: "handle".to_string(),
        entry_kind: Some(DeclKind::Function),
        terminal: "os.system".to_string(),
        terminal_kind: "call".to_string(),
        precision: "narrowed".to_string(),
        func_ids: Vec::new(),
        chain_display: vec!["handle".to_string(), "sink".to_string()],
        steps: vec![InspectTaintStep {
            caller: "sink".to_string(),
            callee: "os.system".to_string(),
            file: "/tmp/call/narrowed.py".to_string(),
            line: 4,
            column: 5,
            kind: "call".to_string(),
            precision: "narrowed".to_string(),
            tainted_args: vec![InspectTaintedArg {
                index: 0,
                value_text: "cmd".to_string(),
                param_name: Some("command".to_string()),
            }],
        }],
        json_size_upper_bound: 0,
    };
    flow.json_size_upper_bound = calculate_inspect_taint_flow_json_upper_bound(&flow);
    flow
}

#[test]
fn raw_taint_page_cost_is_allocation_free_and_conservative() {
    let mut flow = sample_taint_flow();
    flow.entry = "quoted \"entry\"\nwith control \\u{0007} and unicode 盆".to_string();
    flow.steps[0].tainted_args[0].value_text = "cmd\\\"value".to_string();
    let serialized = serde_json::to_string(&flow).expect("serialize representative flow");

    assert!(
        inspect_taint_flow_json_upper_bound(&flow) >= serialized.len() as u64,
        "the paging estimator must remain conservative without serializing production rows"
    );
}

fn sample_structural_flow(number: u32) -> InspectFlowRendered {
    InspectFlowRendered {
        flow_number: number,
        flow_label: number.to_string(),
        flow_id: format!("F:{number:016x}"),
        chain: vec!["entry".to_string(), "target".to_string()],
        chain_display: "entry -> target".to_string(),
        precision: bonsai_common::Precision::Exact,
        functions: Vec::new(),
    }
}

#[test]
fn inspect_text_pages_taint_rows_and_flowless_hits_losslessly() {
    let mut taint_flows = Vec::new();
    for index in 0..4 {
        let mut flow = sample_taint_flow();
        flow.taint_id = format!("T:page{index:04}");
        flow.entry = format!("entry_{index}");
        taint_flows.push(flow);
    }
    let hits = (0..4)
        .map(|index| HitOut {
            kind: "call".to_string(),
            text: format!("page_hit_{index}"),
            file: format!("src/page_{index}.py"),
            line: index + 1,
            column: 1,
            in_function: None,
            chains_preview: Vec::new(),
            flows: Vec::new(),
            groups: Vec::new(),
            from_match: None,
            to_match: None,
        })
        .collect::<Vec<_>>();
    let report = InspectReport {
        query: "page".to_string(),
        analysis_complete: true,
        hits,
        taint_flows,
        summary: super::InspectReportSummary {
            total_hits: 4,
            total_taint_flows: 4,
            ..super::InspectReportSummary::default()
        },
        ..InspectReport::default()
    };
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    let render = InspectRenderOptions {
        compact: true,
        ..InspectRenderOptions::default()
    };

    let mut pages = Vec::new();
    let mut page_number = 1_u64;
    loop {
        let paging = PagingConfig::new(
            Some(800),
            PageArg::Number(page_number),
            None,
            false,
            FormatClass::Text,
        );
        let mut info = None;
        let output = crate::page_cache::capture(|| {
            info = Some(render_inspect_report_text(
                &workspace,
                &report,
                &render,
                &paging,
                Some("page"),
                false,
            )?);
            Ok(())
        })
        .expect("render inspect page");
        let info = info.expect("page info");
        pages.push(output);
        if info.is_last {
            break;
        }
        assert!(
            page_number < info.total_pages,
            "non-last page must leave a later numeric page"
        );
        page_number += 1;
    }

    let joined = pages.join("\n");
    for index in 0..4 {
        let taint_id = format!("T:page{index:04}");
        assert_eq!(
            joined.matches(&taint_id).count(),
            1,
            "taint row {taint_id} must appear on exactly one reachable page"
        );
        let hit = format!("page_hit_{index}");
        assert_eq!(
            joined.matches(&hit).count(),
            1,
            "flowless syntax hit {hit} must appear on exactly one reachable page"
        );
    }
}

#[test]
fn inspect_json_page_unit_serializes_one_flow_not_the_whole_declaration() {
    let hit = InspectOut {
        symbol: "target".to_string(),
        kind: "method".to_string(),
        file: "src/Target.java".to_string(),
        line: 7,
        column: 3,
        params: Vec::new(),
        direct_callers: Vec::new(),
        callees: Vec::new(),
        graph_evidence_evaluated: true,
        flows: vec![sample_structural_flow(1), sample_structural_flow(2)],
        groups: Vec::new(),
        summary: InspectSummary {
            evidence_units: 2,
            max_functions_per_unit: 2,
            unique_symbol_roots: 1,
        },
    };
    let unit = InspectJsonPageUnit::Decl {
        index: 0,
        hit: &hit,
        flow: hit.flows.first(),
    };
    let value = serde_json::to_value(unit).expect("serialize page unit");
    assert_eq!(value["section"], "decl_hits");
    assert_eq!(value["value"]["flows"].as_array().map(Vec::len), Some(1));
    assert_eq!(value["value"]["flows"][0]["flow_id"], "F:0000000000000001");
    assert_eq!(hit.flows.len(), 2, "pagination must not mutate the exact report");
}

#[test]
fn exact_duplicate_structural_flows_collapse_before_paging() {
    let first = sample_structural_flow(1);
    let mut duplicate = first.clone();
    duplicate.flow_label = "99".to_string();
    duplicate.flow_number = 99;
    let second = sample_structural_flow(2);
    let mut flows = vec![first.clone(), duplicate, second.clone()];

    dedup_structural_flows(&mut flows);

    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0].flow_id, first.flow_id);
    assert_eq!(flows[0].flow_number, first.flow_number);
    assert_eq!(flows[1].flow_id, second.flow_id);
}

fn tempdir_for_test(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!("{name}-{}-{nanos:x}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create tempdir {}: {error}", path.display()),
        }
    }
    panic!("could not allocate tempdir for {name}");
}

#[test]
fn taint_query_matching_ignores_metadata_labels() {
    let flow = sample_taint_flow();
    for query in ["call", "narrowed", "/tmp/call"] {
        let matcher = Matcher::build(Some(query), false).expect("matcher");
        assert!(
            !taint_flow_matches_query(&flow, &matcher),
            "query `{query}` matched taint metadata instead of path content"
        );
    }
}

#[test]
fn taint_query_matching_keeps_real_path_content() {
    let flow = sample_taint_flow();
    for query in ["handle", "sink", "os.system", "cmd", "command", "T:1234"] {
        let matcher = Matcher::build(Some(query), false).expect("matcher");
        assert!(
            taint_flow_matches_query(&flow, &matcher),
            "query `{query}` should match actual taint path content"
        );
    }
}

#[test]
fn taint_from_to_needles_ignore_file_paths() {
    let flow = sample_taint_flow();
    assert!(
        !taint_flow_contains_needle(&flow, "/tmp/call"),
        "from/to needle matched a file path instead of taint path content"
    );
    assert!(taint_flow_contains_needle(&flow, "cmd"));
}

#[test]
fn taint_from_to_needles_ignore_constructor_prelude_labels() {
    let mut flow = sample_taint_flow();
    flow.entry = "Gateway".to_string();
    flow.entry_kind = Some(DeclKind::Constructor);
    flow.chain_display = vec![
        "Gateway".to_string(),
        "handleRequest".to_string(),
        "updateUser".to_string(),
    ];
    flow.steps.insert(
        0,
        InspectTaintStep {
            caller: "Gateway".to_string(),
            callee: "handleRequest".to_string(),
            file: "/tmp/Gateway.java".to_string(),
            line: 16,
            column: 9,
            kind: "propagation".to_string(),
            precision: "narrowed".to_string(),
            tainted_args: Vec::new(),
        },
    );

    assert!(
        !taint_flow_contains_needle(&flow, "Gateway"),
        "constructor/prelude labels must not satisfy untyped from/to taint needles"
    );
    assert!(
        taint_flow_contains_needle(&flow, "os.system"),
        "terminal call names should remain matchable"
    );
    assert!(
        taint_flow_contains_needle(&flow, "cmd"),
        "tainted values should remain matchable"
    );
}
