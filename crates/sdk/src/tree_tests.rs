use super::effective_optional_cap;

#[test]
fn navigation_propagates_scan_incompleteness_without_findings() {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("app.py", "def broken(:\n    pass\n");
    let pack = bonsai_security::Rulepack::default();
    let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("analysis");
    assert!(report.findings.is_empty());
    assert!(!report.analysis_complete, "exercise a scan-level parser gap");

    let tree = super::tree(&ws, Some(&pack), &super::TreeFilters::default()).expect("tree");
    assert!(
        !tree.analysis_complete,
        "empty finding list must not erase scan gaps"
    );
    for reason in &report.analysis_incomplete_reasons {
        assert!(tree.analysis_incomplete_reasons.contains(reason));
    }
    let file = crate::read_file::read_file(
        &ws,
        Some(&pack),
        &crate::read_file::ReadFileFilters {
            path: "app.py",
            ..Default::default()
        },
    )
    .expect("read file");
    assert!(
        !file.analysis_complete,
        "read-file must also preserve scan-level gaps"
    );
    for reason in &report.analysis_incomplete_reasons {
        assert!(file.analysis_incomplete_reasons.contains(reason));
    }
}

#[test]
fn deliberate_severity_filter_is_not_tree_truncation() {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("app.py", "value = 1\n");
    let output = super::tree(
        &ws,
        None,
        &super::TreeFilters {
            severity: Some(bonsai_security::rule::Severity::High),
            ..Default::default()
        },
    )
    .expect("filtered tree");
    assert!(output.roots.is_empty());
    assert!(
        output.analysis_complete,
        "intentional filtering is not lost evidence: {:?}",
        output.analysis_incomplete_reasons
    );
}

#[test]
fn tree_directory_locators_are_workspace_relative() {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    let root = std::env::temp_dir().join("bonsai-tree-locator-root");
    ws.db().set_workspace_root(root.clone());
    ws.vfs().write(root.join("pkg/app.py"), "value = 1\n");
    let output = super::tree(&ws, None, &super::TreeFilters::default()).expect("tree");
    assert_eq!(output.roots[0].locator.file, ".");
    assert_eq!(output.roots[0].children[0].locator.file, "pkg");
    assert_eq!(output.roots[0].children[0].children[0].locator.file, "pkg/app.py");
}

#[test]
fn pattern_only_finding_has_no_invented_flow_summary() {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    let site = serde_json::json!({
        "origin": "rulepack", "rule_id": "test.rule", "file": "app.py", "line": 1,
        "column": 1, "text": "value", "tainted_args": [], "sanitised_arg_indices": []
    });
    let finding: bonsai_security::Finding = serde_json::from_value(serde_json::json!({
        "finding_id": "S:test", "language": "python", "source": site.clone(), "sink": site,
        "analysis_complete": true, "analysis_incomplete_reasons": [], "severity": "high"
    }))
    .expect("pattern-only finding");
    let summary = serde_json::to_value(super::build_most_severe_flow(&finding, &ws)).expect("summary");
    assert!(
        summary.is_null(),
        "no route id means no flow summary, not a fake F:0000: {summary}"
    );
}

#[test]
fn cross_file_tree_links_point_at_the_call_not_the_function_declaration() {
    let workspace = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    let caller = workspace.vfs().write(
        "app.py",
        "from helper import target\n\ndef caller():\n    value = 1\n    return target(value)\n",
    );
    workspace
        .vfs()
        .write("helper.py", "def target(value):\n    return value\n");
    let graph = workspace.cached_resolved_call_graph();
    let edges = super::build_cross_edges(&graph, &workspace);
    let cross = edges
        .out_callees
        .values()
        .flatten()
        .next()
        .expect("resolved cross-file edge");
    let edge = graph
        .inner()
        .edges
        .iter()
        .find(|edge| edge.span.file == caller)
        .expect("call edge");
    let location = bonsai_browse::Locator::from_span(edge.span, &workspace);
    assert_eq!(cross.call_site.line, location.line);
    assert_eq!(cross.call_site.column, location.column);
    assert_eq!(cross.call_site.line, 5);
    assert_ne!(cross.call_site.line, cross.caller.line);
    assert!(
        cross.edge_id.is_some(),
        "cross-file evidence should be reopenable by its canonical edge id"
    );
}

#[test]
fn zero_optional_tree_cap_means_unbounded() {
    assert_eq!(effective_optional_cap(None, 5), 5);
    assert_eq!(effective_optional_cap(Some(3), 5), 3);
    assert_eq!(effective_optional_cap(Some(0), 5), usize::MAX);
}
