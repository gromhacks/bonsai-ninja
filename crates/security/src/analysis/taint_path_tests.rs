use super::*;

fn path_step(
    caller: &str,
    callee: &str,
    file: &str,
    line: u32,
    column: u32,
    args: Vec<(usize, &str, &str)>,
) -> TaintPropagationStep {
    TaintPropagationStep {
        caller: caller.to_string(),
        callee: callee.to_string(),
        file: file.to_string(),
        line,
        column,
        tainted_args: args
            .into_iter()
            .map(|(index, value_text, param_name)| TaintPropagationArg {
                index,
                value_text: value_text.to_string(),
                param_name: param_name.to_string(),
            })
            .collect(),
    }
}

fn sink_match(file: &str, line: u32, column: u32, text: &str, enclosing_fn: &str) -> RuleMatch {
    RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: "typescript.test.sink".to_string(),
        language: "typescript".to_string(),
        file: file.to_string(),
        line,
        column,
        span: Span::new(bonsai_common::FileId::new(0), 0, 1),
        match_text: text.to_string(),
        enclosing_fn: Some(enclosing_fn.to_string()),
    }
}

#[test]
fn normalize_taint_path_collapses_adjacent_duplicate_report_sites() {
    let normalized = normalize_taint_path(vec![
        path_step(
            "route",
            "service",
            "src/server.js",
            10,
            12,
            vec![(0, "q", "query")],
        ),
        path_step(
            "service",
            "renderResults",
            "src/server.js",
            10,
            28,
            vec![(0, "q", "")],
        ),
    ]);

    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].caller, "route");
    assert_eq!(normalized[0].callee, "renderResults");
    assert_eq!(normalized[0].file, "src/server.js");
    assert_eq!(normalized[0].line, 10);
    assert_eq!(normalized[0].tainted_args.len(), 2);
}

#[test]
fn normalize_taint_path_collapses_all_same_location_chain() {
    let normalized = normalize_taint_path(vec![
        path_step(
            "resource",
            "loader",
            "SafeYaml.java",
            11,
            4,
            vec![(0, "body", "body")],
        ),
        path_step(
            "loader",
            "YAML.load",
            "SafeYaml.java",
            11,
            14,
            vec![(0, "body", "")],
        ),
        path_step(
            "YAML.load",
            "YAML.load",
            "SafeYaml.java",
            11,
            14,
            vec![(0, "body", "")],
        ),
    ]);

    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].caller, "resource");
    assert_eq!(normalized[0].callee, "YAML.load");
    assert_eq!(normalized[0].tainted_args.len(), 2);
}

#[test]
fn normalize_taint_path_preserves_distinct_report_lines() {
    let normalized = normalize_taint_path(vec![
        path_step("route", "service", "src/server.js", 7, 18, vec![(0, "q", "q")]),
        path_step(
            "service",
            "renderResults",
            "src/render.js",
            3,
            9,
            vec![(0, "q", "")],
        ),
    ]);

    assert_eq!(normalized.len(), 2);
    assert_eq!(normalized[0].callee, "service");
    assert_eq!(normalized[1].callee, "renderResults");
}

#[test]
fn terminal_taint_step_aligns_to_selected_sink_location() {
    let aligned = align_terminal_taint_step_to_sink(
        vec![
            path_step(
                "route",
                "applyOverrides",
                "src/server.ts",
                4,
                10,
                vec![(1, "req.body", "source")],
            ),
            path_step(
                "applyOverrides",
                "key",
                "src/deep.ts",
                2,
                3,
                vec![(0, "key", ""), (1, "source", "")],
            ),
        ],
        &sink_match("src/deep.ts", 6, 7, "target.key", "applyOverrides"),
    );

    assert_eq!(aligned.len(), 2);
    let terminal = aligned.last().unwrap();
    assert_eq!(terminal.file, "src/deep.ts");
    assert_eq!(terminal.line, 6);
    assert_eq!(terminal.column, 7);
    assert_eq!(terminal.callee, "target.key");
}

#[test]
fn terminal_taint_step_does_not_align_across_functions() {
    let aligned = align_terminal_taint_step_to_sink(
        vec![path_step(
            "helper",
            "key",
            "src/deep.ts",
            2,
            3,
            vec![(0, "key", "")],
        )],
        &sink_match("src/deep.ts", 6, 7, "target.key", "applyOverrides"),
    );

    assert_eq!(aligned[0].line, 2);
    assert_eq!(aligned[0].callee, "key");
}
