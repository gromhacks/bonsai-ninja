use super::bindings::{
    extract_comprehension_for_clause_assigns, extract_foreach_binding_assigns, extract_match_binding_assigns,
};
use super::{
    annotate_tuple_call_result_bindings, apply_assign_call_result_types, apply_call_receiver_types,
    apply_constructor_result_type_aliases, argument_place, assignment_value_node, build_call_event,
    callable_reference_name, canonical_simple_type_name, collect_kinds, expression_flow_from_node,
    extract_assignment_value_facts, extract_return_value_name, extract_rhs_expr_operands, language_from_pack,
    node_text, normalize_call_name_whitespace, normalize_call_result_assignment_sources,
    package_module_segments_with_workspace_prefix, receiver_projected_alias_matches, span_of,
    walk_flow_events, GENERIC_HANDLER, SYNTHETIC_TUPLE_RESULT_PREFIX,
};
use crate::{
    AssignValueKind, AssignmentValueIndex, CallArg, CallKind, Decl, DeclIndex, DeclKind, FlowEvent,
    GrammarHandler, ModulePath, Visibility,
};
use bonsai_common::{FileId, Span, SymbolId};

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
fn python_match_patterns_lower_only_ast_binding_positions() {
    let src = br#"match subject:
    case {"value": value, "nested": {"item": item}, **rest} if limit:
        sink(value, item, rest)
    case Point(x=px, y=py) as point:
        sink(px, py, point)
"#;
    let tree = parse_language("python", src);
    let statement = collect_kinds(&tree, &["match_statement"])[0];
    let events = extract_match_binding_assigns(FileId::new(0), &statement, src);
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

    let mut events = extract_match_binding_assigns(FileId::new(0), &if_expr, src);
    events.extend(extract_match_binding_assigns(FileId::new(0), &match_expr, src));
    events.extend(extract_foreach_binding_assigns(FileId::new(0), &for_expr, src));
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
    let ruby_events = extract_match_binding_assigns(FileId::new(0), &case_match, ruby);
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
    let elixir_events = extract_match_binding_assigns(FileId::new(0), &case_call, elixir);
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
    let events = extract_comprehension_for_clause_assigns(FileId::new(0), &clause, src);
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
    ];

    for (pack, src, kind, expected_targets, expected_source) in cases {
        let tree = parse_language(pack, src);
        let loop_node = collect_kinds(&tree, &[*kind])
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing {pack} {kind}"));
        let events = extract_foreach_binding_assigns(FileId::new(0), &loop_node, src);
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
        collect_kinds(&tree, assignment_kinds)
            .into_iter()
            .find_map(|assignment| {
                let value = assignment_value_node(assignment, None)?;
                callable_reference_name(&value, source.as_bytes())
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
        reference("elixir", "cb = &helper/1", &["binary_operator"]).as_deref(),
        Some("helper")
    );
    assert_eq!(
        reference("ruby", "cb = method(:helper)", &["assignment"]).as_deref(),
        Some("helper")
    );
    assert_eq!(
        reference(
            "php",
            "<?php function f() { $cb = system(...); }",
            &["assignment_expression"],
        )
        .as_deref(),
        Some("system")
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
    let call = |name: &str, span: Span| FlowEvent::Call {
        span,
        name: name.to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: Vec::new(),
    };

    let mut idx = DeclIndex::default();
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
            // JS/TS shape: `const client = new ApolloClient({})` is an
            // Assign with no source_call plus a sibling constructor Call
            // whose span lies inside the assignment's RHS.
            assign("client", None, sp(40, 80)),
            call("ApolloClient", sp(56, 78)),
            // Negative: an Assign with no source_call followed by an
            // UNRELATED constructor call outside its span must not type it.
            assign("misc", None, sp(90, 100)),
            call("Helper", sp(120, 140)),
        ],
    ));

    apply_constructor_result_type_aliases(&mut idx);
    let decl = &idx.defs[0];
    let typed = |name: &str| {
        decl.type_aliases
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.type_name.as_str())
    };
    assert_eq!(typed("conn"), Some("Connection"), "{:?}", decl.type_aliases);
    assert_eq!(typed("obj"), Some("Util"), "{:?}", decl.type_aliases);
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
fn address_arguments_emit_writeback_mode_from_ast_nodes() {
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
            .filter_map(|node| {
                build_call_event(node, FileId::new(0), source.as_bytes(), &GENERIC_HANDLER, &[])
            })
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

    let operands = extract_rhs_expr_operands(&match_expr, source.as_bytes());
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

    let operands = extract_rhs_expr_operands(&list, source.as_bytes());
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
        extract_rhs_expr_operands(&selected_rhs, source.as_bytes()),
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
