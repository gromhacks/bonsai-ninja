use super::bindings::{
    extract_comprehension_for_clause_assigns, extract_foreach_binding_assigns, extract_match_binding_assigns,
};
use super::{
    annotate_tuple_call_result_bindings, apply_assign_call_result_types, apply_call_receiver_types,
    apply_call_receiver_types_with_language_syntax, apply_constructor_result_type_aliases, argument_place,
    assign_lexical_callable_parents, assignment_value_node, build_call_event, callable_reference_name,
    canonical_simple_type_name, collect_kinds, expression_flow_from_node, extend_alias_map_with_flow_events,
    extract_assignment_value_facts, extract_call_receiver_facts, extract_direct_call_info,
    extract_return_value_name, extract_rhs_expr_operands, extract_runtime_type_narrowing_facts,
    extract_string_literals, language_from_pack, lower_local_closure_captures, mark_namespace_call_receivers,
    node_text, normalize_call_name_whitespace, normalize_call_result_assignment_sources,
    package_module_segments_with_workspace_prefix, receiver_projected_alias_matches, span_of,
    walk_flow_events, GENERIC_HANDLER, SYNTHETIC_TUPLE_RESULT_PREFIX,
};
use crate::{
    AliasTarget, AssignValueKind, AssignmentValueIndex, CallArg, CallKind, CallReceiverFact,
    CallReceiverRole, Decl, DeclIndex, DeclKind, ExpressionFlow, FlowEvent, GrammarHandler, ImportIndex,
    ImportScope, ImportSpec, ModulePath, Visibility,
};
use bonsai_common::{FileId, Span, SymbolId};
use tree_sitter::Node;

fn parse_language(pack: &str, src: &[u8]) -> tree_sitter::Tree {
    let language = language_from_pack(pack).expect("language grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set language grammar");
    parser.parse(src, None).expect("parse source")
}

fn assign_facts(events: &[FlowEvent]) -> Vec<(&str, Option<&str>, Vec<&str>)> {
    events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                ..
            } => Some((
                target.as_str(),
                source_name.as_deref(),
                source_names.iter().map(String::as_str).collect(),
            )),
            _ => None,
        })
        .collect()
}

fn assignment_targets(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } => {
                if !out.contains(target) {
                    out.push(target.clone());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                assignment_targets(then_events, out);
                assignment_targets(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                assignment_targets(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                assignment_targets(body, out);
                assignment_targets(catch_events, out);
                assignment_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn runtime_type_narrowings_are_lowered_from_guard_nodes() {
    let cases = [
        (
            "python",
            "def f(value):\n    if isinstance(value, Payload):\n        sink(value)\n",
        ),
        (
            "javascript",
            "function f(value) { if (value instanceof Payload) { sink(value); } }",
        ),
        (
            "typescript",
            "function f(value: unknown) { if (typeof value === 'string') { sink(value); } }",
        ),
    ];
    for (language, source) in cases {
        let tree = parse_language(language, source.as_bytes());
        let handler = match language {
            "python" => GrammarHandler {
                runtime_type_guard_calls: &["isinstance"],
                ..GENERIC_HANDLER
            },
            "javascript" => GrammarHandler {
                runtime_type_guard_operators: &["instanceof"],
                ..GENERIC_HANDLER
            },
            "typescript" => GrammarHandler {
                runtime_typeof_operators: &["typeof"],
                runtime_type_equality_operators: &["==", "==="],
                ..GENERIC_HANDLER
            },
            _ => unreachable!(),
        };
        let facts = extract_runtime_type_narrowing_facts(&tree, FileId::new(0), &handler, source.as_bytes());
        assert_eq!(facts.len(), 1, "{language}: {facts:#?}");
        assert_eq!(facts[0].subject, "value", "{language}");
        let expected_type = if language == "typescript" {
            "string"
        } else {
            "Payload"
        };
        assert_eq!(facts[0].type_name, expected_type, "{language}");
        assert!(
            source
                .get(facts[0].guarded_span.start as usize..facts[0].guarded_span.end as usize)
                .is_some_and(|guarded| guarded.contains("sink(value)")),
            "{language}: guarded span must be the parsed then arm"
        );
    }
}

#[test]
fn python_identity_guard_is_not_a_runtime_type_narrowing() {
    let source = "def f(value, other):\n    if value is other:\n        sink(value)\n";
    let tree = parse_language("python", source.as_bytes());
    let handler = GrammarHandler {
        runtime_type_guard_calls: &["isinstance"],
        ..GENERIC_HANDLER
    };
    let facts = extract_runtime_type_narrowing_facts(&tree, FileId::new(0), &handler, source.as_bytes());
    assert!(
        facts.is_empty(),
        "identity comparison is not a type fact: {facts:#?}"
    );
}

#[test]
fn destructured_assignment_targets_follow_cst_binding_positions() {
    type DestructureCase<'a> = (&'a str, &'a [u8], &'a [&'a str], &'a [&'a str]);
    let cases: &[DestructureCase<'_>] = &[
        (
            "python",
            b"first, second = pair\n",
            &["first", "second"],
            &["pair"],
        ),
        (
            "javascript",
            b"const {key: renamed = fallback, plain} = object; const [first = backup, second] = items;",
            &["renamed", "plain", "first", "second"],
            &["key", "object", "items", "fallback", "backup"],
        ),
        (
            "go",
            b"package p\nfunc f() { first, second := pair() }",
            &["first", "second"],
            &["pair"],
        ),
        (
            "kotlin",
            b"fun f(pair: Pair<String, String>) { val (first, second) = pair }",
            &["first", "second"],
            &["pair"],
        ),
        (
            "elixir",
            b"[first | second] = items",
            &["first", "second"],
            &["items"],
        ),
        ("ruby", b"first, second = pair\n", &["first", "second"], &["pair"]),
        (
            "perl",
            b"my ($first, $second) = @items;",
            &["first", "second"],
            &["items"],
        ),
        (
            "rust",
            b"struct Boxed { value: String } fn f(args: Boxed) { let Boxed { value } = args; }",
            &["value"],
            &["Boxed", "args"],
        ),
        (
            "lua",
            b"function outer() local ok, value = pcall(function() return source() end) end",
            &["ok", "value"],
            &["pcall", "source"],
        ),
    ];

    for (pack, src, expected, non_bindings) in cases {
        let tree = parse_language(pack, src);
        let scope = collect_kinds(&tree, &["block", "statement_block", "function_body"])
            .into_iter()
            .next()
            .unwrap_or_else(|| tree.root_node());
        let elixir_handler = GrammarHandler {
            assignment_kinds: &["binary_operator"],
            ..GENERIC_HANDLER
        };
        let handler = if *pack == "elixir" {
            &elixir_handler
        } else {
            &GENERIC_HANDLER
        };
        let events = walk_flow_events(scope, FileId::new(0), src, handler, &[]);
        let mut targets = Vec::new();
        assignment_targets(&events, &mut targets);
        for expected_target in *expected {
            assert!(
                targets
                    .iter()
                    .any(|target| target.trim_start_matches(['$', '@', '%']) == *expected_target),
                "{pack}: missing {expected_target}: {events:#?}\nAST: {}",
                tree.root_node().to_sexp()
            );
        }
        for non_binding in *non_bindings {
            assert!(
                targets
                    .iter()
                    .all(|target| target.trim_start_matches(['$', '@', '%']) != *non_binding),
                "{pack}: value/key became binding {non_binding}: {events:#?}"
            );
        }
        if *pack == "kotlin" {
            for expected_target in *expected {
                assert!(
                    events.iter().any(|event| matches!(
                        event,
                        FlowEvent::Assign { target, source_names, .. }
                            if target == expected_target && source_names.iter().any(|source| source == "pair")
                    )),
                    "kotlin: destructured binding {expected_target} lost its RHS dependency: {events:#?}"
                );
            }
        }
    }
}

#[test]
fn indexed_field_assignment_does_not_rebind_its_base_object() {
    let src = b"void f(struct Envelope env) { env.cmd[sizeof(env.cmd) - 1] = '\\0'; }";
    let tree = parse_language("c", src);
    let scope = collect_kinds(&tree, &["compound_statement"])
        .into_iter()
        .next()
        .expect("C function body");
    let events = walk_flow_events(scope, FileId::new(0), src, &GENERIC_HANDLER, &[]);
    let mut targets = Vec::new();
    assignment_targets(&events, &mut targets);

    assert!(
        targets.iter().any(|target| target.starts_with("env.cmd")),
        "indexed field write must keep its parsed place: {events:#?}"
    );
    assert!(
        targets.iter().all(|target| target != "env"),
        "indexed field write must not become a whole-object assignment: {events:#?}"
    );
}

#[test]
fn indexed_assignment_is_a_typed_operation_not_a_pseudo_api_call() {
    let src = b"def set_header(response, name, value):\n    response[name] = value\n";
    let tree = parse_language("python", src);
    let scope = collect_kinds(&tree, &["block"])
        .into_iter()
        .next()
        .expect("Python function body");
    let events = walk_flow_events(scope, FileId::new(0), src, &GENERIC_HANDLER, &[]);

    assert!(
        events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                call_kind: crate::CallKind::IndexWrite,
                args,
                ..
            } if name == "response.index_write"
                && receiver == "response"
                && args.first().and_then(|arg| arg.place.as_deref()) == Some("name")
                && args.get(1).and_then(|arg| arg.place.as_deref()) == Some("value")
        )),
        "indexed assignment lost its typed index/value facts: {events:#?}"
    );
}

#[test]
fn python_match_patterns_lower_only_ast_binding_positions() {
    let src = br#"match subject:
    case {"value": value, "nested": {"item": item}, **rest} if limit:
        sink(value, item, rest)
    case Point(x=px, y=py) as point:
        sink(px, py, point)
"#;
    let tree = parse_language("python", src);
    let statement = collect_kinds(&tree, &["match_statement"])[0];
    let events = extract_match_binding_assigns(FileId::new(0), &statement, src, &GENERIC_HANDLER);
    let facts = assign_facts(&events);

    for target in ["value", "item", "rest", "px", "py", "point"] {
        assert!(
            facts
                .iter()
                .any(|(actual, source, _)| *actual == target && *source == Some("subject")),
            "missing binding {target}: {facts:?}"
        );
    }
    for non_binding in ["nested", "x", "y", "Point", "limit"] {
        assert!(
            facts.iter().all(|(actual, _, _)| *actual != non_binding),
            "syntax/value name became a binding: {non_binding}: {facts:?}"
        );
    }
}

#[test]
fn rust_pattern_and_foreach_bindings_follow_ast_fields() {
    let src = br#"fn handle(subject: Option<(String, usize)>, rows: Vec<(String, usize)>) {
    if let Some((value, index)) = subject { sink(value, index); }
    match subject { Some((part, count)) => sink(part, count), None => (), }
    for (row, offset) in rows { sink(row, offset); }
}"#;
    let tree = parse_language("rust", src);
    let if_expr = collect_kinds(&tree, &["if_expression"])[0];
    let match_expr = collect_kinds(&tree, &["match_expression"])[0];
    let for_expr = collect_kinds(&tree, &["for_expression"])[0];

    let mut events = extract_match_binding_assigns(FileId::new(0), &if_expr, src, &GENERIC_HANDLER);
    events.extend(extract_match_binding_assigns(
        FileId::new(0),
        &match_expr,
        src,
        &GENERIC_HANDLER,
    ));
    events.extend(extract_foreach_binding_assigns(
        FileId::new(0),
        &for_expr,
        src,
        &GENERIC_HANDLER,
    ));
    let facts = assign_facts(&events);

    for (target, source) in [
        ("value", "subject"),
        ("index", "subject"),
        ("part", "subject"),
        ("count", "subject"),
        ("row", "rows"),
        ("offset", "rows"),
    ] {
        assert!(
            facts
                .iter()
                .any(|(actual, actual_source, _)| *actual == target && *actual_source == Some(source)),
            "missing {target} <- {source}: {facts:?}"
        );
    }
    assert!(facts
        .iter()
        .all(|(target, _, _)| !matches!(*target, "Some" | "None")));
}

#[test]
fn ruby_and_elixir_map_patterns_do_not_bind_keys_or_atoms() {
    let ruby = br#"case subject
in {value:, nested: {item:}, **rest}
  sink(value, item, rest)
end"#;
    let ruby_tree = parse_language("ruby", ruby);
    let case_match = collect_kinds(&ruby_tree, &["case_match"])[0];
    let ruby_events = extract_match_binding_assigns(FileId::new(0), &case_match, ruby, &GENERIC_HANDLER);
    let ruby_facts = assign_facts(&ruby_events);
    for target in ["value", "item", "rest"] {
        assert!(ruby_facts.iter().any(|(actual, _, _)| *actual == target));
    }
    assert!(ruby_facts.iter().all(|(target, _, _)| *target != "nested"));

    let elixir = br#"case subject do
  %{value: value, nested: %{item: item}} -> sink(value, item)
  {:ok, result} -> sink(result)
end"#;
    let elixir_tree = parse_language("elixir", elixir);
    let case_call = collect_kinds(&elixir_tree, &["call"])
        .into_iter()
        .find(|node| {
            node.child_by_field_name("target")
                .is_some_and(|target| node_text(&target, elixir) == "case")
        })
        .expect("case call");
    let elixir_events = extract_match_binding_assigns(FileId::new(0), &case_call, elixir, &GENERIC_HANDLER);
    let elixir_facts = assign_facts(&elixir_events);
    for target in ["value", "item", "result"] {
        assert!(elixir_facts.iter().any(|(actual, _, _)| *actual == target));
    }
    assert!(elixir_facts
        .iter()
        .all(|(target, _, _)| !matches!(*target, "nested" | "ok")));
}

#[test]
fn comprehension_binding_uses_fielded_pattern_and_iterable_nodes() {
    let src = b"[(part, index) for (part, index) in rows]";
    let tree = parse_language("python", src);
    let clause = collect_kinds(&tree, &["for_in_clause"])[0];
    let events = extract_comprehension_for_clause_assigns(FileId::new(0), &clause, src, &GENERIC_HANDLER);
    let facts = assign_facts(&events);

    assert_eq!(
        facts,
        vec![
            ("part", Some("rows"), vec!["rows"]),
            ("index", Some("rows"), vec!["rows"]),
        ]
    );
}

#[test]
fn foreach_bindings_cover_fielded_and_wrapped_grammar_shapes() {
    type ForeachCase<'a> = (&'a str, &'a [u8], &'a str, &'a [&'a str], &'a str);
    let cases: &[ForeachCase<'_>] = &[
        (
            "php",
            b"<?php foreach ($rows as $key => $value) { sink($key, $value); }",
            "foreach_statement",
            &["key", "value"],
            "rows",
        ),
        (
            "go",
            b"package p\nfunc f(rows []string) { for index, row := range rows { sink(index, row) } }",
            "for_statement",
            &["index", "row"],
            "rows",
        ),
        (
            "lua",
            b"for index, row in ipairs(rows) do sink(index, row) end",
            "for_statement",
            &["index", "row"],
            "rows",
        ),
        (
            "scala",
            b"def f(rows: List[(String, Int)]) = for ((row, index) <- rows) yield sink(row, index)",
            "for_expression",
            &["row", "index"],
            "rows",
        ),
        (
            "perl",
            b"foreach my $row (@$rows) { sink($row); }",
            "for_statement",
            &["row"],
            "rows",
        ),
        (
            "swift",
            b"for (row, index) in rows { sink(row, index) }",
            "for_statement",
            &["row", "index"],
            "rows",
        ),
        (
            "cpp",
            b"void f(auto rows) { for (const auto& row : rows) { sink(row); } }",
            "for_range_loop",
            &["row"],
            "rows",
        ),
        (
            "kotlin",
            b"fun f(rows: List<Pair<String, Int>>) { for ((row, index) in rows) sink(row, index) }",
            "for_statement",
            &["row", "index"],
            "rows",
        ),
        (
            "dart",
            b"void f(List<String> rows) { for (var row in rows) sink(row); }",
            "for_statement",
            &["row"],
            "rows",
        ),
        (
            "objc",
            b"void f(NSArray *rows) { for (NSString *row in rows) { sink(row); } }",
            "for_statement",
            &["row"],
            "rows",
        ),
    ];

    for (pack, src, kind, expected_targets, expected_source) in cases {
        let tree = parse_language(pack, src);
        let loop_node = collect_kinds(&tree, &[*kind])
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing {pack} {kind}"));
        let events = extract_foreach_binding_assigns(FileId::new(0), &loop_node, src, &GENERIC_HANDLER);
        let facts = assign_facts(&events);
        let actual_targets: Vec<&str> = facts.iter().map(|(target, _, _)| *target).collect();
        assert_eq!(actual_targets, *expected_targets, "{pack}: {facts:?}");
        for (_, source_name, source_names) in &facts {
            assert!(
                source_name.is_some_and(|name| name.trim_start_matches(['$', '@', '%']) == *expected_source)
                    || source_names
                        .iter()
                        .any(|name| name.trim_start_matches(['$', '@', '%']) == *expected_source),
                "{pack}: missing source {expected_source}: {facts:?}"
            );
        }
    }
}

#[test]
fn scala_case_binding_uses_the_match_subject_node() {
    let src = b"object Demo { def f(args: String) = args match { case value => sink(value) } }";
    let tree = parse_language("scala", src);
    let match_expr = collect_kinds(&tree, &["match_expression"])[0];
    let events = extract_match_binding_assigns(FileId::new(0), &match_expr, src, &GENERIC_HANDLER);
    let facts = assign_facts(&events);

    assert!(
        facts.iter().any(|(target, source, sources)| {
            *target == "value" && (source == &Some("args") || sources.contains(&"args"))
        }),
        "{facts:?}"
    );
}

#[test]
fn local_closure_conversion_adds_only_ast_proven_free_bindings() {
    let file = FileId::new(0);
    let mut caller = m9_func_decl(
        0,
        "entry",
        None,
        vec![
            FlowEvent::Assign {
                span: Span::new(file, 10, 50),
                target: "closure".to_string(),
                source_name: None,
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: true,
                value_kind: Some(AssignValueKind::CallableReference),
            },
            FlowEvent::Call {
                span: Span::new(file, 60, 70),
                name: "closure".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: Vec::new(),
            },
        ],
    );
    caller.span = Span::new(file, 0, 100);
    caller.params = vec!["captured".to_string(), "unused".to_string()];
    let mut closure = m9_func_decl(
        1,
        "closure",
        None,
        vec![FlowEvent::Call {
            span: Span::new(file, 30, 40),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: Span::new(file, 35, 38),
                passing_mode: Default::default(),
                name: None,
                value_text: "captured".to_string(),
                place: Some("captured".to_string()),
                source_names: vec!["captured".to_string()],
            }],
        }],
    );
    closure.span = Span::new(file, 20, 50);
    let mut defs = vec![caller, closure];

    lower_local_closure_captures(&mut defs);

    assert_eq!(defs[1].params, ["captured"]);
    assert_eq!(defs[1].name, "closure");
    assert!(matches!(
        &defs[0].flow_events[1],
        FlowEvent::Call { call_kind: CallKind::Indirect, args, .. }
            if args.len() == 1 && args[0].place.as_deref() == Some("captured")
    ));
}

#[test]
fn tuple_call_result_bindings_keep_source_positions() {
    let src = "a, _b = helper(x)";
    let tree = parse_language("python", src.as_bytes());
    let span = Span::new(FileId::new(0), 0, src.len() as u64);
    let mut events = vec![
        FlowEvent::Assign {
            span,
            target: "_b".to_string(),
            source_name: None,
            source_call: Some("helper".to_string()),
            source_call_args: vec!["x".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Assign {
            span,
            target: "a".to_string(),
            source_name: None,
            source_call: Some("helper".to_string()),
            source_call_args: vec!["x".to_string()],
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
    ];

    annotate_tuple_call_result_bindings(&mut events, &tree, src.as_bytes());
    assert!(matches!(
        &events[0],
        FlowEvent::Assign { source_names, .. }
            if source_names == &[format!("{SYNTHETIC_TUPLE_RESULT_PREFIX}1")]
    ));
    assert!(matches!(
        &events[1],
        FlowEvent::Assign { source_names, .. }
            if source_names == &[format!("{SYNTHETIC_TUPLE_RESULT_PREFIX}0")]
    ));
}

#[test]
fn receiver_projected_alias_matches_tuple_field_chains_only() {
    assert!(receiver_projected_alias_matches("repo.0", "repo"));

    assert!(!receiver_projected_alias_matches("r.Header", "r"));
    assert!(!receiver_projected_alias_matches("r.Header.Get", "r"));
    assert!(!receiver_projected_alias_matches("r", "r"));
    assert!(!receiver_projected_alias_matches("other.r", "r"));
    assert!(!receiver_projected_alias_matches("r.Header()", "r"));
}

#[test]
fn call_name_normalization_compacts_multiline_dotted_chains() {
    assert_eq!(
        normalize_call_name_whitespace(
            "org.owasp\n        .esapi\n        .ESAPI\n        .encoder()\n        .encodeForHTML"
        ),
        "org.owasp.esapi.ESAPI.encoder().encodeForHTML"
    );
    assert_eq!(
        normalize_call_name_whitespace("Command::new(\"sh\")\n    .arg(\"-c\")\n    .output"),
        "Command::new(\"sh\").arg(\"-c\").output"
    );
}

#[test]
fn direct_call_extraction_only_crosses_transparent_ast_wrappers() {
    let direct = b"x = (helper(raw))\n";
    let direct_tree = parse_language("python", direct);
    let direct_assignment = collect_kinds(&direct_tree, &["assignment"])
        .into_iter()
        .next()
        .expect("direct assignment");
    let direct_target = direct_assignment
        .child_by_field_name("left")
        .expect("direct target");
    let direct_rhs = assignment_value_node(direct_assignment, Some(direct_target)).expect("direct rhs");
    assert_eq!(
        extract_direct_call_info(&direct_rhs, direct, &GENERIC_HANDLER),
        Some((Some("helper".to_string()), vec!["raw".to_string()])),
        "parentheses are transparent around a direct call"
    );

    let compound = b"payload = ({'cmd': raw} if len(raw) > 0 else None)\n";
    let compound_tree = parse_language("python", compound);
    let compound_assignment = collect_kinds(&compound_tree, &["assignment"])
        .into_iter()
        .next()
        .expect("compound assignment");
    let compound_target = compound_assignment
        .child_by_field_name("left")
        .expect("compound target");
    let compound_rhs =
        assignment_value_node(compound_assignment, Some(compound_target)).expect("compound rhs");
    assert_eq!(
        extract_direct_call_info(&compound_rhs, compound, &GENERIC_HANDLER),
        None,
        "a nested condition call is not the assignment's value-producing call"
    );
}

#[test]
fn call_result_assignment_pruning_removes_callee_and_arg_carriers() {
    let mut events = vec![assign_call(
        "z",
        "f",
        &["user.name"],
        &["f", "user.name", "user", "name"],
    )];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign {
        source_name,
        source_names,
        ..
    } = &events[0]
    else {
        panic!("expected assign event")
    };
    assert_eq!(source_name.as_deref(), None);
    assert!(source_names.is_empty());
}

#[test]
fn call_result_assignment_pruning_normalizes_identifier_sigils() {
    let mut events = vec![assign_call("z", "f", &["x"], &["$x", "$xy"])];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign event")
    };
    assert!(
        source_names == &["$xy"],
        "Perl/PHP sigils are syntax on the same argument binding, while a distinct prefixed name must remain an independent source"
    );
}

#[test]
fn call_result_assignment_pruning_preserves_method_receivers() {
    let mut events = vec![assign_call(
        "ok",
        "target.call",
        &["payload"],
        &["target.call", "target", "call", "payload"],
    )];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign event")
    };
    assert_eq!(source_names.as_slice(), ["target"]);
}

#[test]
fn call_result_assignment_pruning_preserves_static_factory_type_hints() {
    let mut events = vec![assign_call(
        "logger",
        "Logger.getLogger",
        &["name"],
        &["Logger", "Logger.getLogger", "getLogger", "name"],
    )];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign event")
    };
    assert_eq!(source_names.as_slice(), ["Logger", "getLogger"]);
}

#[test]
fn call_result_assignment_normalization_recovers_adjacent_call_args() {
    let mut events = vec![assign_call("z", "f", &[], &["f", "x"]), call("f", &["x"])];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign {
        source_call_args,
        source_names,
        ..
    } = &events[0]
    else {
        panic!("expected assign event")
    };
    assert_eq!(source_call_args.as_slice(), ["x"]);
    assert!(source_names.is_empty());
}

#[test]
fn call_result_assignment_normalization_uses_assignment_span_not_event_window() {
    let mut events = vec![assign_call("z", "f", &[], &["f", "x"])];
    events.extend((0..4).map(|_| call("unrelated", &[])));
    events.push(call("f", &["x"]));

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign {
        source_call_args,
        source_names,
        ..
    } = &events[0]
    else {
        panic!("expected assign event")
    };
    assert_eq!(source_call_args.as_slice(), ["x"]);
    assert!(source_names.is_empty());
}

#[test]
fn return_value_name_uses_structured_syntax_before_text_fallback() {
    let language = language_from_pack("python").expect("python grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set python grammar");
    let src = b"def a(token):\n    return token\n\ndef b():\n    return None\n";
    let tree = parser.parse(src, None).expect("parse python");
    let mut returns = collect_kinds(&tree, &["return_statement"]);
    returns.sort_by_key(tree_sitter::Node::start_byte);

    assert_eq!(returns.len(), 2);
    assert_eq!(
        extract_return_value_name(&returns[0], src).as_deref(),
        Some("token")
    );
    assert_eq!(
        extract_return_value_name(&returns[1], src),
        None,
        "literal return nodes must not become value-bearing identifier reads"
    );
}

#[test]
fn perl_sigiled_return_uses_the_scalar_ast_node() {
    let language = language_from_pack("perl").expect("perl grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set perl grammar");
    let src = b"sub f { my $value = 1; return $value; }\n";
    let tree = parser.parse(src, None).expect("parse perl");
    let returns = collect_kinds(&tree, &["return_expression"]);

    assert_eq!(returns.len(), 1);
    assert_eq!(
        extract_return_value_name(&returns[0], src).as_deref(),
        Some("$value")
    );
}

#[test]
fn assignment_value_fact_uses_exact_rhs_node_span() {
    let language = language_from_pack("python").expect("python grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set python grammar");
    let src = b"def f():\n    policy = \"left=right\"\n";
    let tree = parser.parse(src, None).expect("parse python");
    let assignment = collect_kinds(&tree, &["assignment"])
        .into_iter()
        .next()
        .expect("assignment node");
    let assignment_span = span_of(FileId::new(0), &assignment);

    let facts = extract_assignment_value_facts(&tree, FileId::new(0), &GENERIC_HANDLER, src);
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].assignment_span, assignment_span);
    let target_span = facts[0].target_span.expect("exact assignment target span");
    let target = &src[target_span.start as usize..target_span.end as usize];
    assert_eq!(target, b"policy");
    let value = &src[facts[0].value_span.start as usize..facts[0].value_span.end as usize];
    assert_eq!(value, b"\"left=right\"");
    let index = AssignmentValueIndex::new(&facts);
    assert_eq!(
        index.target_rendering(assignment_span, "def f():\n    policy = \"left=right\"\n"),
        Some("policy")
    );
    assert_eq!(
        index.rendering(assignment_span, "def f():\n    policy = \"left=right\"\n"),
        Some("\"left=right\"")
    );
    assert_eq!(
        crate::assignment_value_rendering(&facts, assignment_span, "def f():\n    policy = \"left=right\"\n",),
        Some("\"left=right\"")
    );
}

#[test]
fn callable_assignment_references_are_lowered_from_ast_shapes() {
    fn reference(pack: &str, source: &str, assignment_kinds: &[&str]) -> Option<String> {
        let language = language_from_pack(pack).expect("grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set grammar");
        let tree = parser.parse(source, None).expect("parse source");
        let handler = match pack {
            "java" => GrammarHandler {
                callable_reference_kinds: &["method_reference"],
                ..GENERIC_HANDLER
            },
            _ => GENERIC_HANDLER,
        };
        collect_kinds(&tree, assignment_kinds)
            .into_iter()
            .find_map(|assignment| {
                let value = assignment_value_node(assignment, None)?;
                callable_reference_name(&value, source.as_bytes(), &handler)
            })
    }

    assert_eq!(
        reference(
            "java",
            "class C { void f() { Consumer<String> cb = this::helper; } }",
            &["variable_declarator"],
        )
        .as_deref(),
        Some("helper")
    );
    assert_eq!(
        reference("python", "cb = 'helper'", &["assignment"]),
        None,
        "data literals must not be promoted to callable aliases"
    );
}

#[test]
fn literal_keywords_are_not_argument_places_or_return_value_names() {
    let swift = language_from_pack("swift").expect("swift grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&swift).expect("set swift grammar");
    let src = b"func f() -> String? { g(nil); return nil }\n";
    let tree = parser.parse(src, None).expect("parse swift");

    let returns = collect_kinds(&tree, &["control_transfer_statement"]);
    assert_eq!(returns.len(), 1);
    assert_eq!(extract_return_value_name(&returns[0], src), None);
    let nil_arg = collect_kinds(&tree, &["value_argument"])
        .into_iter()
        .find(|node| node_text(node, src).trim() == "nil")
        .expect("nil value_argument");
    assert_eq!(argument_place(&nil_arg, src), None);

    let cpp = language_from_pack("cpp").expect("cpp grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&cpp).expect("set cpp grammar");
    let src = b"void f() { g(nullptr); }\n";
    let tree = parser.parse(src, None).expect("parse cpp");
    let null_arg = collect_kinds(&tree, &["null"])
        .into_iter()
        .next()
        .expect("nullptr null node");
    assert_eq!(argument_place(&null_arg, src), None);
}

fn assign_call(target: &str, source_call: &str, args: &[&str], sources: &[&str]) -> FlowEvent {
    FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 0, 0),
        target: target.to_string(),
        source_name: Some(source_call.to_string()),
        source_call: Some(source_call.to_string()),
        source_call_args: args.iter().map(|arg| (*arg).to_string()).collect(),
        source_names: sources.iter().map(|source| (*source).to_string()).collect(),
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::CallResult),
    }
}

fn call(name: &str, args: &[&str]) -> FlowEvent {
    FlowEvent::Call {
        span: Span::new(FileId::INVALID, 0, 0),
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: args
            .iter()
            .map(|arg| CallArg {
                passing_mode: Default::default(),
                span: Span::new(FileId::INVALID, 0, 0),
                name: None,
                value_text: (*arg).to_string(),
                place: Some((*arg).to_string()),
                source_names: vec![(*arg).to_string()],
            })
            .collect(),
    }
}

// audit re-apply: H1 + H7-guard: pure-helper unit tests matching the existing

#[test]
fn compound_assignment_operators_detected() {
    use super::is_compound_assignment_operator;
    for op in [
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "**=", ".=", "||=", "&&=", "??=",
    ] {
        assert!(is_compound_assignment_operator(op), "{op} should be compound");
    }
    for op in ["=", "==", "!=", "<=", ">=", ":=", "=>"] {
        assert!(
            !is_compound_assignment_operator(op),
            "{op} should NOT be compound"
        );
    }
}

#[test]
fn receiver_projection_base_extracts_leftmost_token() {
    use super::receiver_projection_base;
    assert_eq!(receiver_projection_base("this.conn"), "this");
    assert_eq!(receiver_projection_base("self.conn"), "self");
    assert_eq!(receiver_projection_base("pool.conn"), "pool");
    assert_eq!(receiver_projection_base("a->b->c"), "a");
    assert_eq!(receiver_projection_base("Foo::bar"), "Foo");
    assert_eq!(receiver_projection_base("conn"), "conn");
}

#[test]
fn package_module_segments_keep_sibling_projects_distinct() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let vfs = Vfs::new();
    let root = std::env::temp_dir().join("bonsai-package-module-prefix");
    let first = vfs.write(root.join("flow_a/src/main/java/mega/App.java"), "");
    let second = vfs.write(root.join("flow_b/src/main/java/mega/App.java"), "");
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = crate::AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: Some(&root),
    };

    assert_eq!(
        package_module_segments_with_workspace_prefix(first, &ctx, ["mega"]),
        vec!["flow_a".to_string(), "mega".to_string()]
    );
    assert_eq!(
        package_module_segments_with_workspace_prefix(second, &ctx, ["mega"]),
        vec!["flow_b".to_string(), "mega".to_string()]
    );
}

#[test]
fn package_module_segments_preserve_plain_fixture_packages() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let vfs = Vfs::new();
    let root = std::env::temp_dir().join("bonsai-package-module-plain");
    let file = vfs.write(root.join("App.java"), "");
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = crate::AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: Some(&root),
    };

    assert_eq!(
        package_module_segments_with_workspace_prefix(file, &ctx, ["mega"]),
        vec!["mega".to_string()]
    );
}

#[test]
fn parse_with_reuses_context_canonical_tree() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;
    use std::sync::Arc;

    struct Provider(Arc<crate::SyntaxTree>);
    impl crate::TreeProvider for Provider {
        fn tree_for_snapshot(
            &self,
            pack_name: &str,
            snapshot: &bonsai_vfs::FileSnapshot,
        ) -> Option<Arc<crate::SyntaxTree>> {
            assert_eq!(pack_name, "java");
            assert_eq!(snapshot.file_id, FileId::new(0));
            Some(Arc::clone(&self.0))
        }
    }

    let vfs = Vfs::new();
    let file = vfs.write("Cached.java", "class Cached {}");
    let snapshot = vfs.snapshot(file).expect("snapshot");
    let language = language_from_pack("java").expect("java grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set language");
    let canonical = Arc::new(
        parser
            .parse(snapshot.text.as_bytes(), None)
            .expect("canonical parse"),
    );
    let provider = Provider(Arc::clone(&canonical));
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = crate::AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: Some(&provider),
        workspace_root: None,
    };

    let (_, first) = super::parse_with("java", file, &ctx).expect("first parse");
    let (_, second) = super::parse_with("java", file, &ctx).expect("second parse");
    assert!(Arc::ptr_eq(&canonical, &first));
    assert!(Arc::ptr_eq(&canonical, &second));
}

// audit M9: `apply_assign_call_result_types` must fail closed when two
// same-named functions/overloads have differing return types -- a name-only
// lookup is then unknowable and a last-writer-wins alias drives bogus
// [Type, method] matching.
#[test]
fn call_result_types_fail_closed_on_same_name_overload_conflict() {
    let mut idx = DeclIndex::default();
    idx.defs.push(m9_func_decl(0, "make", Some("Foo"), Vec::new()));
    idx.defs.push(m9_func_decl(1, "make", Some("Bar"), Vec::new()));
    idx.defs.push(m9_func_decl(2, "single", Some("Baz"), Vec::new()));
    idx.defs.push(m9_func_decl(
        3,
        "consumer",
        None,
        vec![
            assign_call("y", "make", &[], &["make"]),
            assign_call("z", "single", &[], &["single"]),
        ],
    ));

    apply_assign_call_result_types(&mut idx);

    let consumer = idx.defs.iter().find(|d| d.name == "consumer").unwrap();
    assert!(
        !consumer.type_aliases.iter().any(|a| a.name == "y"),
        "ambiguous overload `make` must not stamp an alias on `y`, got {:?}",
        consumer.type_aliases
    );
    assert!(
        consumer
            .type_aliases
            .iter()
            .any(|a| a.name == "z" && a.type_name == "Baz"),
        "unique callee `single` must still stamp z -> Baz, got {:?}",
        consumer.type_aliases
    );
}

#[test]
fn constructor_result_typing_handles_source_call_and_adjacent_new_call() {
    let file = FileId::new(0);
    let sp = |lo: u64, hi: u64| Span::new(file, lo, hi);
    let assign = |target: &str, source_call: Option<&str>, span: Span| FlowEvent::Assign {
        span,
        target: target.to_string(),
        source_name: None,
        source_call: source_call.map(str::to_string),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::Compound),
    };
    let call = |name: &str, span: Span, call_kind: CallKind| FlowEvent::Call {
        span,
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind,
        args: Vec::new(),
    };
    let qualified_constructor = |name: &str, receiver: &str, span: Span| FlowEvent::Call {
        span,
        name: name.to_string(),
        receiver: Some(receiver.to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Constructor,
        args: Vec::new(),
    };

    let mut idx = DeclIndex::default();
    for (symbol, name) in [(10, "Connection"), (11, "Util"), (12, "widget")] {
        let mut class = m9_func_decl(symbol, name, None, Vec::new());
        class.kind = DeclKind::Class;
        idx.defs.push(class);
    }
    idx.defs.push(m9_func_decl(
        0,
        "handler",
        None,
        vec![
            // `source_call` languages (Python/Java/C#/Go): `conn = Connection(...)`.
            assign("conn", Some("Connection"), sp(10, 30)),
            // Perl/Ruby-style class constructor methods should type the
            // receiver as the owner, not as the method call tail.
            assign("obj", Some("Util->new"), sp(31, 39)),
            qualified_constructor("Util->new", "Util", sp(34, 38)),
            // Declaration resolution, not casing, proves this lower-case
            // symbol is a constructed type.
            assign("lower", Some("widget"), sp(141, 150)),
            // Uppercase spelling alone is not constructor evidence.
            assign("unknown", Some("Mystery"), sp(151, 160)),
            // JS/TS shape: `const client = new ApolloClient({})` is an
            // Assign with no source_call plus a sibling constructor Call
            // whose span lies inside the assignment's RHS.
            assign("client", None, sp(40, 80)),
            call("ApolloClient", sp(56, 78), CallKind::Constructor),
            // Negative: an Assign with no source_call followed by an
            // UNRELATED constructor call outside its span must not type it.
            assign("misc", None, sp(90, 100)),
            call("Helper", sp(120, 140), CallKind::Constructor),
        ],
    ));

    apply_constructor_result_type_aliases(&mut idx);
    let decl = idx.defs.iter().find(|decl| decl.name == "handler").unwrap();
    let typed = |name: &str| {
        decl.type_aliases
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.type_name.as_str())
    };
    assert_eq!(typed("conn"), Some("Connection"), "{:?}", decl.type_aliases);
    assert_eq!(typed("obj"), Some("Util"), "{:?}", decl.type_aliases);
    assert_eq!(typed("lower"), Some("widget"), "{:?}", decl.type_aliases);
    assert_eq!(typed("unknown"), None, "{:?}", decl.type_aliases);
    assert_eq!(
        typed("client"),
        Some("ApolloClient"),
        "adjacent new-expr Call within assign span must type the receiver: {:?}",
        decl.type_aliases
    );
    assert_eq!(
        typed("misc"),
        None,
        "a constructor call outside the assign span must not type the target: {:?}",
        decl.type_aliases
    );
}

#[test]
fn constructor_result_typing_uses_span_index_without_event_window() {
    let file = FileId::new(0);
    let mut events = vec![FlowEvent::Assign {
        span: Span::new(file, 10, 1_000),
        target: "client".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::Compound),
    }];
    for index in 0..64 {
        events.push(FlowEvent::Call {
            span: Span::new(file, 20 + index * 10, 25 + index * 10),
            name: format!("helper_{index}"),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        });
    }
    events.push(FlowEvent::Call {
        span: Span::new(file, 900, 920),
        name: "ApolloClient".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Constructor,
        args: Vec::new(),
    });
    let mut idx = DeclIndex::default();
    idx.defs.push(m9_func_decl(0, "handler", None, events));

    apply_constructor_result_type_aliases(&mut idx);

    assert!(idx.defs[0]
        .type_aliases
        .iter()
        .any(|alias| alias.name == "client" && alias.type_name == "ApolloClient"));
}

#[test]
fn alias_propagation_worklist_resolves_chains_longer_than_sixteen() {
    let file = FileId::new(0);
    let mut events = Vec::new();
    for index in 0..64 {
        events.push(FlowEvent::Assign {
            span: Span::new(file, index * 10, index * 10 + 5),
            target: format!("alias_{index}"),
            source_name: Some(if index == 63 {
                "imported".to_string()
            } else {
                format!("alias_{}", index + 1)
            }),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::Unknown),
        });
    }
    let expected = AliasTarget::Member {
        module: "child_process".to_string(),
        member: "exec".to_string(),
    };
    let mut aliases = std::collections::HashMap::from([("imported".to_string(), expected.clone())]);

    extend_alias_map_with_flow_events(&mut aliases, &events);

    assert_eq!(aliases.get("alias_0"), Some(&expected));
}

#[test]
fn string_literal_extraction_preserves_large_ast_literals() {
    let content = "x".repeat(8_192);
    let source = format!("const value = \"{content}\";");
    let tree = parse_language("javascript", source.as_bytes());
    let strings = extract_string_literals(&tree, FileId::new(0), source.as_bytes());

    assert!(strings.iter().any(|literal| literal.text.contains(&content)));
}

#[test]
fn receiver_type_uses_declared_class_facts_without_factory_name_knowledge() {
    let mut idx = DeclIndex::default();
    let mut child = m9_func_decl(0, "Child", None, Vec::new());
    child.kind = DeclKind::Class;
    let arbitrary_factory_call = |receiver: &str| FlowEvent::Call {
        span: Span::new(FileId::new(0), 10, 20),
        name: format!("{receiver}.consume"),
        receiver: Some(receiver.to_string()),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: Vec::new(),
    };
    idx.defs.push(child);
    idx.defs.push(m9_func_decl(
        1,
        "entry",
        None,
        vec![
            arbitrary_factory_call("Child()"),
            arbitrary_factory_call("Child.fabricate"),
            arbitrary_factory_call("package.Child(value)"),
        ],
    ));

    apply_call_receiver_types(&mut idx);
    let entry = idx.defs.iter().find(|decl| decl.name == "entry").unwrap();
    assert!(entry.flow_events.iter().all(|event| {
        matches!(
            event,
            FlowEvent::Call { receiver_types, .. } if receiver_types == &["Child"]
        )
    }));
}

#[test]
fn receiver_type_joins_sigiled_ast_aliases_by_canonical_binding_name() {
    let mut idx = DeclIndex::default();
    let mut child = m9_func_decl(0, "Child", None, Vec::new());
    child.kind = DeclKind::Class;
    let mut entry = m9_func_decl(
        1,
        "entry",
        None,
        vec![FlowEvent::Call {
            span: Span::new(FileId::new(0), 10, 20),
            name: "obj.consume".to_string(),
            receiver: Some("obj".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        }],
    );
    entry.type_aliases.push(crate::TypeAliasBinding {
        name: "$obj".to_string(),
        type_name: "Child".to_string(),
    });
    idx.defs.extend([child, entry]);

    apply_call_receiver_types(&mut idx);

    assert!(matches!(
        &idx.defs[1].flow_events[0],
        FlowEvent::Call { receiver_types, .. } if receiver_types == &["Child"]
    ));
}

#[test]
fn implicit_receiver_typing_normalizes_adapter_declared_sigils() {
    let mut idx = DeclIndex::default();
    let mut repository = m9_func_decl(0, "Repository", None, Vec::new());
    repository.kind = DeclKind::Class;
    repository.bases = vec!["BaseRepository".to_string()];
    let mut method = m9_func_decl(
        1,
        "run",
        None,
        vec![FlowEvent::Call {
            span: Span::new(FileId::new(0), 10, 20),
            name: "$this->cmd".to_string(),
            receiver: Some("$this".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        }],
    );
    method.kind = DeclKind::Method;
    method.parent = Some(repository.symbol);
    idx.defs.extend([repository, method]);

    apply_call_receiver_types_with_language_syntax(
        &mut idx,
        &[],
        &["$this"],
        &[],
        crate::ReceiverTypeSyntax::none(),
    );

    assert!(matches!(
        &idx.defs[1].flow_events[0],
        FlowEvent::Call { receiver_types, .. }
            if receiver_types == &["Repository".to_string(), "BaseRepository".to_string()]
    ));
}

fn test_writeback_classifier(argument: Node<'_>, value: Node<'_>) -> crate::ArgumentPassingMode {
    let node_kind_proves_writeback = |node: Node<'_>| {
        matches!(
            node.kind(),
            "reference_expression" | "pointer_expression" | "unary_expression" | "ref_expression"
        ) || {
            let mut cursor = node.walk();
            let has_writeback_token = node
                .children(&mut cursor)
                .any(|child| matches!(child.kind(), "&" | "ref" | "out" | "ref_kind_keyword"));
            has_writeback_token
        }
    };
    if node_kind_proves_writeback(argument) || node_kind_proves_writeback(value) {
        crate::ArgumentPassingMode::WriteBack
    } else {
        crate::ArgumentPassingMode::Value
    }
}

#[test]
fn adapter_writeback_classifier_populates_language_neutral_call_args() {
    let handler = GrammarHandler {
        argument_passing_mode_extractor: Some(test_writeback_classifier),
        ..GENERIC_HANDLER
    };
    for (pack, source) in [
        ("c", "void f(void) { int out; helper(&out); }"),
        ("cpp", "void f() { int out; helper(&out); }"),
        (
            "csharp",
            "class C { void F() { string result; helper(out result); } }",
        ),
        ("go", "package p\nfunc f() { var out string; helper(&out) }"),
        ("objc", "void f(void) { id out; helper(&out); }"),
        (
            "rust",
            "fn f() { let mut out = String::new(); helper(&mut out); }",
        ),
    ] {
        let language = language_from_pack(pack).expect("language pack");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set language");
        let tree = parser.parse(source, None).expect("parse");
        let event = collect_kinds(&tree, &["call_expression", "invocation_expression", "call"])
            .into_iter()
            .filter_map(|node| build_call_event(node, FileId::new(0), source.as_bytes(), &handler, &[]))
            .find(|event| matches!(event, FlowEvent::Call { name, .. } if name == "helper"))
            .unwrap_or_else(|| panic!("{pack}: helper call"));
        let FlowEvent::Call { args, .. } = event else {
            unreachable!();
        };
        assert_eq!(args.len(), 1, "{pack}: {args:?}");
        assert_eq!(
            args[0].passing_mode,
            crate::ArgumentPassingMode::WriteBack,
            "{pack}: {args:?}"
        );
        let expected_place = if pack == "csharp" { "result" } else { "out" };
        assert_eq!(args[0].place.as_deref(), Some(expected_place), "{pack}: {args:?}");
    }
}

#[test]
fn rust_match_result_dependencies_come_from_arm_ast_values() {
    let source = r#"fn f(kind: Kind, joined: String) {
        let routed: String = match kind {
            Kind::Run => format!("{}", joined),
            Kind::Eval => joined.trim().to_string(),
        };
    }"#;
    let language = language_from_pack("rust").expect("Rust language pack");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set Rust language");
    let tree = parser.parse(source, None).expect("parse Rust match");
    let match_expr = collect_kinds(&tree, &["match_expression"])
        .into_iter()
        .next()
        .expect("match expression");

    let operands = extract_rhs_expr_operands(&match_expr, source.as_bytes(), &GENERIC_HANDLER);
    assert!(
        operands.iter().any(|operand| operand == "joined"),
        "both macro-token-tree and method-receiver arm values must retain the joined dependency: {operands:?}"
    );
}

#[test]
fn perl_list_expression_dependencies_come_from_scalar_ast_values() {
    let source = "sub entry { my ($a, $b) = ($args, 'ok'); }";
    let language = language_from_pack("perl").expect("Perl language pack");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set Perl language");
    let tree = parser.parse(source, None).expect("parse Perl list assignment");
    let list = collect_kinds(&tree, &["list_expression"])
        .into_iter()
        .next()
        .expect("list expression");

    let operands = extract_rhs_expr_operands(&list, source.as_bytes(), &GENERIC_HANDLER);
    assert_eq!(operands, vec!["$args".to_string(), "args".to_string()]);

    let assignment = collect_kinds(&tree, &["assignment_expression"])
        .into_iter()
        .next()
        .expect("assignment expression");
    let selected_rhs = assignment_value_node(assignment, assignment.child_by_field_name("left"))
        .expect("selected assignment RHS");
    let field_kinds = ["right", "rhs", "value", "result"]
        .into_iter()
        .map(|field| {
            (
                field,
                assignment.child_by_field_name(field).map(|node| node.kind()),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        selected_rhs.kind(),
        "list_expression",
        "assignment value fields: {field_kinds:?}"
    );
    assert_eq!(
        extract_rhs_expr_operands(&selected_rhs, source.as_bytes(), &GENERIC_HANDLER),
        vec!["$args".to_string(), "args".to_string()]
    );

    let body = collect_kinds(&tree, &["block"])
        .into_iter()
        .next()
        .expect("subroutine body");
    let events = walk_flow_events(body, FileId::new(0), source.as_bytes(), &GENERIC_HANDLER, &[]);
    assert!(
        events.iter().any(|event| {
            matches!(event, FlowEvent::Assign { span, source_names, .. }
                if span.start == 12 && source_names.iter().any(|source| source == "args"))
        }),
        "generic AST lowering must retain the tuple RHS carrier: {events:?}"
    );
}

#[test]
fn erlang_list_argument_keeps_nested_call_operand_from_ast() {
    let source = r#"-module(example).
-export([run/1]).
run(Input) -> os:cmd(["ping ", uri_string:quote(Input)]).
"#;
    let tree = parse_language("erlang", source.as_bytes());
    let outer = collect_kinds(&tree, &["call"])
        .into_iter()
        .filter_map(|node| build_call_event(node, FileId::new(0), source.as_bytes(), &GENERIC_HANDLER, &[]))
        .find(|event| matches!(event, FlowEvent::Call { name, .. } if name == "os:cmd"))
        .expect("outer os:cmd call");
    let FlowEvent::Call { args, .. } = outer else {
        unreachable!();
    };
    assert_eq!(args.len(), 1, "{args:?}");
    assert_eq!(args[0].source_names, ["Input"]);
}

#[test]
fn rust_shorthand_struct_initializer_is_an_exact_aggregate_field() {
    let source = "fn make(data: Envelope) -> Self { Self { data } }";
    let language = language_from_pack("rust").expect("Rust language pack");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set Rust language");
    let tree = parser.parse(source, None).expect("parse Rust struct expression");
    let expression = collect_kinds(&tree, &["struct_expression"])
        .into_iter()
        .next()
        .expect("struct expression");

    let flow = expression_flow_from_node(expression, FileId::new(0), source.as_bytes());
    assert_eq!(flow.aggregate_fields.len(), 1, "{flow:?}");
    assert_eq!(flow.aggregate_fields[0].name, "data");
    assert_eq!(flow.aggregate_fields[0].value.place.as_deref(), Some("data"));
}

#[test]
fn postfix_method_receiver_keeps_nested_call_arguments_structural() {
    fn postfix_receiver<'tree>(node: Node<'tree>, _src: &[u8]) -> Option<Node<'tree>> {
        (node.kind() == "field_expression")
            .then(|| node.child_by_field_name("value").or_else(|| node.named_child(0)))
            .flatten()
    }
    let handler = GrammarHandler {
        call_kinds: &["call_expression", "generic_function"],
        pseudo_call_receiver_extractor: Some(postfix_receiver),
        ..GENERIC_HANDLER
    };
    let source = r#"Seq("sh", "-c", command).!"#;
    let tree = parse_language("scala", source.as_bytes());
    let file = FileId::new(0);
    let events = collect_kinds(&tree, &["call_expression"])
        .into_iter()
        .filter_map(|node| build_call_event(node, file, source.as_bytes(), &handler, &[]))
        .collect::<Vec<_>>();
    let calls = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { span, name, args, .. } => Some((*span, name.as_str(), args)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let (constructor_span, _, constructor_args) = calls
        .iter()
        .find(|(_, name, _)| *name == "Seq")
        .expect("receiver constructor call");
    assert!(constructor_args.iter().any(|arg| {
        arg.place.as_deref() == Some("command") || arg.source_names.iter().any(|name| name == "command")
    }));

    let postfix = collect_kinds(&tree, &["field_expression"])
        .into_iter()
        .next()
        .expect("postfix field expression");
    let facts = extract_call_receiver_facts(&tree, file, &handler, source.as_bytes());
    let receiver = facts
        .iter()
        .find(|fact| fact.call_span == span_of(file, &postfix))
        .expect("postfix receiver fact");
    assert!(receiver
        .value_flow
        .call_sites
        .iter()
        .any(|span| span.start <= constructor_span.start && constructor_span.end <= span.end));
}

#[test]
fn kotlin_method_chain_receivers_join_every_semantic_call_span() {
    let source = r#"fun flow(cmd: String) = cmd.splitToSequence(" ")
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .fold("", makeJoiner(" "))"#;
    let tree = parse_language("kotlin", source.as_bytes());
    let file = FileId::new(0);
    let handler = GrammarHandler {
        call_kinds: &["call_expression"],
        member_expression_kinds: &["navigation_expression"],
        ..GENERIC_HANDLER
    };
    let facts = extract_call_receiver_facts(&tree, file, &handler, source.as_bytes());
    let mut chain_calls = collect_kinds(&tree, &["call_expression"])
        .into_iter()
        .filter_map(|call| {
            let text = node_text(&call, source.as_bytes()).trim();
            if !text.starts_with("cmd.splitToSequence") {
                return None;
            }
            let target = super::parsed_call_target(&call, source.as_bytes())?;
            Some((span_of(file, &target.node), text))
        })
        .collect::<Vec<_>>();
    chain_calls.sort_by_key(|(span, _)| span.end - span.start);
    assert_eq!(chain_calls.len(), 4, "facts={facts:#?}");
    for (index, (span, name)) in chain_calls.into_iter().enumerate() {
        let fact = facts
            .iter()
            .find(|fact| fact.call_span == span)
            .unwrap_or_else(|| panic!("missing receiver fact for {name} at {span:?}; facts={facts:#?}"));
        if index > 0 {
            assert!(
                !fact.value_flow.call_sites.is_empty(),
                "nested receiver for {name} must reference its inner call: {fact:#?}"
            );
        }
    }
}

fn m9_func_decl(raw: u32, name: &str, return_type: Option<&str>, flow_events: Vec<FlowEvent>) -> Decl {
    Decl {
        symbol: SymbolId::new(raw),
        kind: DeclKind::Function,
        name: name.to_string(),
        qualified_name: None,
        module_path: ModulePath::default(),
        span: Span::new(FileId::INVALID, 0, 0),
        name_span: Span::new(FileId::INVALID, 0, 0),
        visibility: Visibility::Public,
        parent: None,
        body_span: None,
        flow_events,
        has_implicit_returns: false,
        params: Vec::new(),
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: return_type.map(str::to_string),
        is_variadic: false,
    }
}

#[test]
fn lexical_callable_parent_stack_selects_nearest_ast_owner() {
    let file = FileId::new(0);
    let mut outer = m9_func_decl(1, "outer", None, Vec::new());
    outer.span = Span::new(file, 0, 200);
    outer.body_span = Some(Span::new(file, 10, 190));
    let mut local = m9_func_decl(2, "local", None, Vec::new());
    local.span = Span::new(file, 20, 150);
    local.body_span = Some(Span::new(file, 30, 140));
    let mut lambda = m9_func_decl(3, "<lambda>", None, Vec::new());
    lambda.span = Span::new(file, 40, 60);
    lambda.body_span = Some(Span::new(file, 45, 55));
    let mut sibling = m9_func_decl(4, "sibling", None, Vec::new());
    sibling.span = Span::new(file, 210, 260);
    sibling.body_span = Some(Span::new(file, 220, 250));
    let mut defs = vec![sibling, lambda, outer, local];

    assign_lexical_callable_parents(&mut defs);
    let parent_by_name = defs
        .iter()
        .map(|decl| (decl.name.as_str(), decl.parent))
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(parent_by_name["outer"], None);
    assert_eq!(parent_by_name["local"], Some(SymbolId::new(1)));
    assert_eq!(parent_by_name["<lambda>"], Some(SymbolId::new(2)));
    assert_eq!(parent_by_name["sibling"], None);
}

#[test]
fn imported_namespace_receiver_is_non_value_unless_locally_shadowed() {
    let file = FileId::new(0);
    let call_span = Span::new(file, 40, 52);
    let mut function = m9_func_decl(
        1,
        "restore",
        None,
        vec![FlowEvent::Call {
            span: call_span,
            name: "pickle.loads".to_string(),
            receiver: Some("pickle".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        }],
    );
    function.span = Span::new(file, 20, 80);
    function.body_span = Some(Span::new(file, 30, 80));
    let receiver = CallReceiverFact {
        call_span,
        receiver_span: Span::new(file, 40, 46),
        value_flow: ExpressionFlow::from_place("pickle"),
        role: CallReceiverRole::Value,
        static_value: None,
    };
    let imports = ImportIndex {
        file,
        imports: vec![ImportSpec {
            span: Span::new(file, 0, 13),
            module: "pickle".to_string(),
            alias: Some("pickle".to_string()),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        }],
    };
    let mut index = DeclIndex {
        file,
        defs: vec![function.clone()],
        call_receivers: vec![receiver.clone()],
        ..DeclIndex::default()
    };

    mark_namespace_call_receivers(&mut index, &imports);
    assert_eq!(index.call_receivers[0].role, CallReceiverRole::Namespace);

    function.flow_events.insert(
        0,
        FlowEvent::Assign {
            span: Span::new(file, 32, 38),
            target: "pickle".to_string(),
            source_name: Some("runtime_value".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
    );
    let mut shadowed = DeclIndex {
        file,
        defs: vec![function],
        call_receivers: vec![receiver],
        ..DeclIndex::default()
    };
    mark_namespace_call_receivers(&mut shadowed, &imports);
    assert_eq!(shadowed.call_receivers[0].role, CallReceiverRole::Value);
}

// audit L3: `canonical_simple_type_name` must strip array / nullable /
// force-unwrap / pointer / reference decorations (mirroring
// `canonical_short_type_name`) so a decorated return type resolves to the
// class indexed under its bare name for base-class expansion.
#[test]
fn canonical_simple_type_name_strips_array_nullable_pointer_suffixes() {
    // Generics + dotted prefixes (existing behavior, must stay green).
    assert_eq!(canonical_simple_type_name("java.io.IOException"), "IOException");
    assert_eq!(canonical_simple_type_name("List<Foo>"), "List");
    assert_eq!(
        canonical_simple_type_name("kotlin.collections.MutableList<E>"),
        "MutableList"
    );
    // New: array / nullable / force-unwrap / pointer / reference suffixes.
    assert_eq!(canonical_simple_type_name("User?"), "User");
    assert_eq!(canonical_simple_type_name("User!"), "User");
    assert_eq!(canonical_simple_type_name("byte[]"), "byte");
    assert_eq!(canonical_simple_type_name("com.acme.User[]"), "User");
    assert_eq!(canonical_simple_type_name("*const T"), "T");
    assert_eq!(canonical_simple_type_name("&User"), "User");
    assert_eq!(canonical_simple_type_name("Outer::Inner"), "Inner");
}
