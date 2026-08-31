//! Public browse/inspect surfaces must consume every compiler loop phase.
//!
//! The per-language conformance crate proves that each applicable frontend
//! lowers conditions and updates. This test pins the other side of that
//! contract once, against the language-neutral consumer APIs: adding a new
//! frontend does not require duplicating the same command test, while adding
//! a body-only `FlowEvent::Loop` visitor immediately loses one of these rows.

use bonsai_browse::{
    args, calls, refs, resolution_coverage, search, vars, ArgsFilters, CallsFilters, RefsFilters,
    ResolutionCoverageFilters, SearchFilters, VarsFilters,
};
use bonsai_workspace::Workspace;

fn workspace() -> (tempfile::TempDir, Workspace) {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(
        root.path().join("phases.js"),
        r#"function phaseFacts(input) {
  for (
    let state = initialize(input);
    condition(state);
    state = update(state)
  ) {
    body(state);
  }
}
"#,
    )
    .expect("write loop-phase fixture");
    let workspace = Workspace::index(root.path(), bonsai_adapters::all_languages_registry())
        .expect("index loop-phase fixture");
    assert!(
        workspace.diagnostics().is_empty(),
        "valid loop fixture diagnostics: {:#?}",
        workspace.diagnostics()
    );
    (root, workspace)
}

#[test]
fn public_syntax_inventories_include_condition_body_and_update_facts() {
    let (_root, workspace) = workspace();
    let call_rows = calls(
        &workspace,
        &CallsFilters {
            caller: Some("phaseFacts"),
            ..CallsFilters::default()
        },
    )
    .expect("calls query");
    for callee in ["condition", "body", "update"] {
        assert!(
            call_rows.iter().any(|row| row.callee == callee),
            "calls omitted `{callee}` loop phase: {call_rows:#?}"
        );
    }

    let arg_rows = args(
        &workspace,
        &ArgsFilters {
            in_fn: Some("phaseFacts"),
            value: Some("state"),
            ..ArgsFilters::default()
        },
    )
    .expect("args query");
    for callee in ["condition", "body", "update"] {
        assert!(
            arg_rows.iter().any(|row| row.callee == callee),
            "args omitted `{callee}` loop phase: {arg_rows:#?}"
        );
    }

    let vars_rows = vars(
        &workspace,
        &VarsFilters {
            name: Some("state"),
            in_fn: Some("phaseFacts"),
            ..VarsFilters::default()
        },
    )
    .expect("vars query");
    assert!(
        vars_rows
            .iter()
            .any(|row| row.source_name.as_deref() == Some("update")),
        "vars omitted the loop update assignment: {vars_rows:#?}"
    );

    let ref_rows = refs(
        &workspace,
        "update",
        &RefsFilters {
            in_fn: Some("phaseFacts"),
            ..RefsFilters::default()
        },
    )
    .expect("refs query");
    assert!(!ref_rows.is_empty(), "refs omitted the loop update call");

    let search_rows = search(
        &workspace,
        "update",
        &SearchFilters {
            kind: Some("call"),
            ..SearchFilters::default()
        },
        usize::MAX,
    )
    .expect("search query");
    assert!(
        search_rows.iter().any(|row| row.name == "update"),
        "search omitted the loop update call: {search_rows:#?}"
    );
}

#[test]
fn semantic_resolution_and_inspection_include_condition_body_and_update_calls() {
    let (_root, workspace) = workspace();
    let coverage = resolution_coverage(&workspace, &ResolutionCoverageFilters::default());
    let phase_decl = coverage
        .iter()
        .flat_map(|row| &row.decls)
        .find(|row| row.name == "phaseFacts")
        .expect("phaseFacts resolution row");
    assert_eq!(
        phase_decl.call_sites, 4,
        "resolution must count initialize, condition, body, and update: {phase_decl:#?}"
    );

    let global = workspace.db().global_index();
    let decl = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "phaseFacts")
        .expect("phaseFacts declaration");
    for callee in ["condition", "body", "update"] {
        assert!(
            bonsai_inspect::find_call_span_by_name(&decl.flow_events, callee).is_some(),
            "inspect omitted `{callee}` loop phase"
        );
    }
}
