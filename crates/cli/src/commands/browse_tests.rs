use super::{
    exact_identifier_regex_literal, format_flow_labels_for_cell, rendered_table_row_cost,
    retrieval_prefilter_for_browse_literal_with_limit, retrieval_prefilter_for_search_with_limit, truncate,
    FlowColumnStatus, SearchFilters,
};
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{CallKind, FlowEvent};
use bonsai_sdk::Workspace;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn span() -> Span {
    Span {
        file: FileId(0),
        start: 0,
        end: 1,
    }
}

#[test]
fn rendered_table_row_cost_tracks_physical_output_lines() {
    assert_eq!(rendered_table_row_cost(&[20, 20, 20]), 160);
    assert_eq!(rendered_table_row_cost(&[60, 60, 60]), 320);
}

#[test]
fn truncate_zero_chars_keeps_only_ellipsis() {
    assert_eq!(truncate("abcdef", 0), "…");
    assert_eq!(truncate("éclair", 0), "…");
}

#[test]
fn exact_identifier_regex_is_safe_for_literal_candidate_lookup() {
    assert_eq!(
        exact_identifier_regex_literal("^ThreadContext$"),
        Some("ThreadContext")
    );
    assert_eq!(exact_identifier_regex_literal("^_Node42$"), Some("_Node42"));
    assert_eq!(exact_identifier_regex_literal("ThreadContext"), None);
    assert_eq!(exact_identifier_regex_literal("^Thread.*$"), None);
    assert_eq!(exact_identifier_regex_literal("^pkg.Class$"), None);
}

#[test]
fn collect_callees_includes_assignment_source_calls() {
    let events = vec![
        FlowEvent::Assign {
            target: "x".to_string(),
            source_name: None,
            source_names: Vec::new(),
            source_call: Some("read_user".to_string()),
            source_call_args: vec!["request".to_string()],
            span: span(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            name: "sink".to_string(),
            receiver: None,
            args: Vec::new(),
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            span: span(),
        },
    ];
    let out = bonsai_sdk::collect_callee_names(&events);
    assert_eq!(out, vec!["read_user", "sink"]);
}

#[test]
fn flow_labels_render_with_safe_breaks_between_ids() {
    let mut status = FlowColumnStatus::default();
    assert_eq!(
        format_flow_labels_for_cell("F:1111111111111111 F:2222222222222222", &mut status),
        Some("F1\nF2".to_string())
    );
    assert_eq!(status.flow_ids, vec!["F:1111111111111111", "F:2222222222222222"]);
}

#[test]
fn flow_labels_cap_preserves_complete_ids() {
    let labels = (0..10)
        .map(|idx| format!("F:{idx:016x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut status = FlowColumnStatus::default();
    let formatted = format_flow_labels_for_cell(&labels, &mut status).expect("formatted labels");

    assert!(formatted.contains("F8"));
    assert!(!formatted.contains("F9"));
    assert!(formatted.contains("(+2 more)"));
    assert_eq!(status.flow_ids.len(), 8);
    assert_eq!(status.flow_ids[7], "F:0000000000000007");
    assert!(!status.flow_ids.iter().any(|id| id == "F:0000000000000008"));
}

#[test]
fn retrieval_search_prefilter_uses_warmed_sidecar_candidate_files() {
    let root = tempdir_for_test("bonsai-retrieval-search-prefilter");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(
        root.join("service.py"),
        "def warmed_unique_symbol():\n    return 'ok'\n",
    )
    .expect("write service");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters =
        retrieval_prefilter_for_search_with_limit(&root, "warmed_unique_symbol", SearchFilters::default(), 1)
            .expect("prefilter")
            .expect("warmed sidecar should provide candidates");

    assert_eq!(filters, vec!["service.py"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn retrieval_search_prefilter_file_filter_is_workspace_relative() {
    let outer = tempdir_for_test("bonsai-retrieval-search-prefilter-parent");
    let root = outer.join("tests/chosen-workspace");
    std::fs::create_dir_all(root.join("tests")).expect("mkdir workspace");
    std::fs::write(root.join("app.py"), "def app_marker():\n    return 1\n").expect("write app");
    std::fs::write(root.join("tests/helper.py"), "def test_marker():\n    return 2\n").expect("write helper");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters = retrieval_prefilter_for_search_with_limit(
        &root,
        "marker",
        SearchFilters {
            file: Some("tests/"),
            ..SearchFilters::default()
        },
        1,
    )
    .expect("prefilter")
    .expect("warmed sidecar should provide scoped candidates");

    assert_eq!(filters, vec!["tests/helper.py"]);
    let _ = std::fs::remove_dir_all(outer);
}

#[test]
fn retrieval_search_prefilter_uses_safe_empty_scope_for_no_candidates() {
    let root = tempdir_for_test("bonsai-retrieval-search-empty");
    std::fs::write(root.join("app.py"), "def only_symbol():\n    return 1\n").expect("write app");
    std::fs::write(root.join("other.py"), "def other_symbol():\n    return 2\n").expect("write other");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters =
        retrieval_prefilter_for_search_with_limit(&root, "missing_symbol", SearchFilters::default(), 1)
            .expect("prefilter")
            .expect("fresh retrieval sidecar should decide no candidates");

    assert!(
        !filters.is_empty(),
        "CLI must not pass [] to filtered workspace open because [] opens every file"
    );
    assert_ne!(filters, vec!["app.py"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn retrieval_search_prefilter_rejects_stale_sidecar_after_source_edit() {
    let root = tempdir_for_test("bonsai-retrieval-search-stale");
    let service = root.join("service.py");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(&service, "def stale_unique_symbol():\n    return 'old'\n").expect("write service");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    std::fs::write(&service, "def fresh_unique_symbol():\n    return 'new'\n").expect("edit service");
    let filters =
        retrieval_prefilter_for_search_with_limit(&root, "stale_unique_symbol", SearchFilters::default(), 1)
            .expect("prefilter");

    assert!(
        filters.is_none(),
        "stale retrieval sidecar must not provide candidate filters"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn retrieval_browse_prefilter_narrows_call_commands_from_warmed_sidecar() {
    let root = tempdir_for_test("bonsai-retrieval-browse-call-prefilter");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(
        root.join("service.py"),
        "def handler():\n    return run_admin_command()\n",
    )
    .expect("write service");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters = retrieval_prefilter_for_browse_literal_with_limit(
        &root,
        "run_admin_command",
        Some("call"),
        None,
        false,
        1,
    )
    .expect("prefilter")
    .expect("warmed sidecar should provide call candidates");

    assert_eq!(filters, vec!["service.py"]);
    let exact_regex_filters = retrieval_prefilter_for_browse_literal_with_limit(
        &root,
        "^run_admin_command$",
        Some("call"),
        None,
        true,
        1,
    )
    .expect("exact regex prefilter")
    .expect("an anchored identifier regex has an exact literal candidate phase");
    assert_eq!(exact_regex_filters, vec!["service.py"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn retrieval_browse_prefilter_narrows_operation_commands_from_operation_docs() {
    let root = tempdir_for_test("bonsai-retrieval-browse-operation-prefilter");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(root.join("gen.py"), "def gen(payload):\n    yield payload[0]\n").expect("write gen");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters = retrieval_prefilter_for_browse_literal_with_limit(
        &root,
        "payload[0]",
        Some("operation"),
        None,
        false,
        1,
    )
    .expect("prefilter")
    .expect("warmed sidecar should provide operation candidates");

    assert_eq!(filters, vec!["gen.py"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn retrieval_browse_prefilter_keeps_function_scoped_string_candidates() {
    let root = tempdir_for_test("bonsai-retrieval-browse-string-prefilter");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 'x'\n").expect("write app");
    std::fs::write(
        root.join("service.py"),
        "def audit_handler():\n    return 'audit literal'\n",
    )
    .expect("write service");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.ingest_dir(&root).expect("ingest");
    bonsai_retrieval::save_sidecar(&ws, &root).expect("save retrieval sidecar");

    let filters = retrieval_prefilter_for_browse_literal_with_limit(
        &root,
        "audit_handler",
        Some("string"),
        None,
        false,
        1,
    )
    .expect("prefilter")
    .expect("warmed sidecar should provide string candidates by function");

    assert_eq!(filters, vec!["service.py"]);
    let _ = std::fs::remove_dir_all(root);
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
