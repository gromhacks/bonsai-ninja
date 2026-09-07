use super::*;

fn call(callee: &str, column: u32, caller: Option<&str>, call_kind: Option<&str>) -> CallOut {
    CallOut {
        resolution_scope: CALLSITE_RESOLUTION_SCOPE.to_string(),
        callee: callee.to_string(),
        file: "fixture.py".to_string(),
        line: 7,
        column,
        caller: caller.map(str::to_string),
        call_kind: call_kind.map(str::to_string),
    }
}

#[test]
fn assignment_source_call_rows_do_not_double_count_explicit_calls() {
    let mut rows = vec![
        call("verify_token", 5, Some("get_user"), None),
        call("verify_token", 15, Some("get_user"), Some("function")),
    ];

    drop_assignment_call_rows_shadowed_by_explicit_calls(&mut rows);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].column, 15);
}

#[test]
fn assignment_source_call_rows_remain_when_no_explicit_call_exists() {
    let mut rows = vec![call("factory", 5, Some("build"), None)];

    drop_assignment_call_rows_shadowed_by_explicit_calls(&mut rows);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].callee, "factory");
}

#[test]
fn callee_regex_preserves_literal_caller_selector() {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write(
        "app.js",
        "function $scope(value) { invoke(value); invokeExtra(value); }\n\
         function scope(value) { invoke(value); }\n",
    );

    let rows = calls(
        &workspace,
        &CallsFilters {
            callee: Some("^invoke$"),
            caller: Some("$scope"),
            regex: true,
            ..Default::default()
        },
    )
    .expect("callee regex with literal caller");

    assert_eq!(rows.len(), 1, "exact callee and literal caller: {rows:?}");
    assert_eq!(rows[0].callee, "invoke");
    assert_eq!(rows[0].caller.as_deref(), Some("$scope"));
    assert_eq!(rows[0].line, 1);
}

#[test]
fn regex_validation_applies_only_to_callee() {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace
        .vfs()
        .write("app.js", "function scope(value) { invoke(value); }\n");

    let rows = calls(
        &workspace,
        &CallsFilters {
            callee: Some("^invoke$"),
            caller: Some("["),
            regex: true,
            ..Default::default()
        },
    )
    .expect("caller is a literal substring, even when it is not a valid regex");
    assert!(rows.is_empty(), "the literal caller does not match: {rows:?}");

    assert!(calls(
        &workspace,
        &CallsFilters {
            callee: Some("["),
            regex: true,
            ..Default::default()
        },
    )
    .is_err());
}
