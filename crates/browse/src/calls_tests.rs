use super::*;

fn call(callee: &str, column: u32, caller: Option<&str>, call_kind: Option<&str>) -> CallOut {
    CallOut {
        resolution_scope: CALLSITE_RESOLUTION_SCOPE,
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
