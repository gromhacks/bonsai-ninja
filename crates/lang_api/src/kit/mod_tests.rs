use super::bindings::{extract_comprehension_for_clause_assigns, extract_foreach_binding_assigns};
use super::{
    annotate_tuple_call_result_bindings, apply_assign_call_result_types, apply_assignment_type_aliases,
    apply_call_receiver_types, apply_call_receiver_types_with_language_syntax,
    apply_constructor_result_type_aliases, argument_place, assign_lexical_callable_parents,
    assignment_value_node, build_call_event, call_arg_from_nodes_with_handler, callable_reference_name,
    canonical_simple_type_name, collect_kinds, complete_finite_selection_return_span,
    expression_flow_from_node, extend_alias_map_with_flow_events, extract_assignment_value_facts,
    extract_call_receiver_facts, extract_direct_call_info, extract_return_value_name,
    extract_rhs_expr_operands, extract_runtime_type_narrowing_facts, extract_string_literals,
    language_from_pack, lower_adapter_local_breaks, lower_local_closure_captures,
    mark_namespace_call_receivers, node_at_span, node_text, normalize_call_name_whitespace,
    normalize_call_result_assignment_sources, normalize_decl_event_evaluation_order,
    normalize_variadic_builtin_flow, package_module_segments_with_workspace_prefix,
    receiver_projected_alias_matches, same_identifier_name, span_of, walk_flow_events, SyntaxKindIndex,
    GENERIC_HANDLER, SYNTHETIC_TUPLE_RESULT_PREFIX,
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

#[test]
fn collect_kinds_is_true_source_order_preorder() {
    let source = b"function f() { first(); second(); third(); }";
    let tree = parse_language("javascript", source);
    let calls = collect_kinds(&tree, &["call_expression"]);
    let starts: Vec<usize> = calls.iter().map(Node::start_byte).collect();
    assert_eq!(calls.len(), 3, "fixture must expose three call expressions");
    assert!(
        starts.windows(2).all(|pair| pair[0] < pair[1]),
        "collect_kinds promises pre-order but returned reverse/non-source order: {starts:?}"
    );
}

#[test]
fn adapter_proven_local_break_truncates_only_its_structured_arm() {
    let file = FileId::new(1);
    let local_break = Span::new(file, 20, 25);
    let mut events = vec![
        FlowEvent::Branch {
            span: Span::new(file, 10, 40),
            condition: None,
            then_events: vec![
                FlowEvent::Assign {
                    span: Span::new(file, 11, 19),
                    target: "value".into(),
                    source_name: Some("input".into()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: vec!["input".into()],
                    declares_new_binding: false,
                    value_kind: Some(AssignValueKind::Compound),
                },
                FlowEvent::Break {
                    span: local_break,
                    target: None,
                },
                FlowEvent::Call {
                    span: Span::new(file, 26, 30),
                    receiver: None,
                    receiver_types: Vec::new(),
                    name: "unreachable_in_arm".into(),
                    call_kind: CallKind::Function,
                    args: Vec::new(),
                },
            ],
            else_events: vec![FlowEvent::Break {
                span: Span::new(file, 31, 35),
                target: None,
            }],
        },
        FlowEvent::Call {
            span: Span::new(file, 41, 50),
            receiver: None,
            receiver_types: Vec::new(),
            name: "after_branch".into(),
            call_kind: CallKind::Function,
            args: Vec::new(),
        },
    ];
    lower_adapter_local_breaks(&mut events, &std::collections::HashSet::from([local_break]));

    let FlowEvent::Branch {
        then_events,
        else_events,
        ..
    } = &events[0]
    else {
        panic!("expected structured branch")
    };
    assert_eq!(
        then_events.len(),
        1,
        "events after the local arm break are unreachable"
    );
    assert!(matches!(then_events[0], FlowEvent::Assign { .. }));
    assert!(
        matches!(else_events[0], FlowEvent::Break { .. }),
        "an unproved loop/function break must remain"
    );
    assert!(matches!(&events[1], FlowEvent::Call { name, .. } if name == "after_branch"));
}

#[test]
fn syntax_kind_index_matches_independent_preorder_walks() {
    let source = b"function f(a) { if (a) first(); second(); }";
    let tree = parse_language("javascript", source);
    let index = SyntaxKindIndex::new(
        &tree,
        &["function_declaration", "if_statement", "call_expression"],
    );
    for wanted in [
        &["call_expression"][..],
        &["if_statement"][..],
        &["function_declaration", "call_expression"][..],
    ] {
        let indexed = index
            .collect(wanted)
            .into_iter()
            .map(|node| (node.kind().to_string(), node.start_byte(), node.end_byte()))
            .collect::<Vec<_>>();
        let direct = collect_kinds(&tree, wanted)
            .into_iter()
            .map(|node| (node.kind().to_string(), node.start_byte(), node.end_byte()))
            .collect::<Vec<_>>();
        assert_eq!(indexed, direct, "indexed and direct CST walks must agree");
    }
}

fn legacy_node_at_span<'a>(root: Node<'a>, span: Span, expected_kinds: &[&str]) -> Option<Node<'a>> {
    let mut exact_typed = None;
    let mut exact_any = None;
    let mut tightest_container = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let node_start = u64::try_from(node.start_byte()).unwrap_or(u64::MAX);
        let node_end = u64::try_from(node.end_byte()).unwrap_or(u64::MAX);
        if node_start == span.start && node_end == span.end {
            if expected_kinds.iter().any(|kind| *kind == node.kind()) {
                exact_typed.get_or_insert(node);
            } else {
                exact_any.get_or_insert(node);
            }
        }
        if node_start <= span.start && node_end >= span.end {
            let width = node_end - node_start;
            let previous = tightest_container.map(|candidate: Node<'_>| {
                u64::try_from(candidate.end_byte() - candidate.start_byte()).unwrap_or(u64::MAX)
            });
            if previous.is_none_or(|previous| width < previous) {
                tightest_container = Some(node);
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    exact_typed.or(exact_any).or(tightest_container)
}

#[test]
fn indexed_node_at_span_preserves_exact_tree_walk_results() {
    let source = r#"
        package demo;
        final class Worker<T> {
            @Deprecated
            T run(T value) {
                try {
                    return transform(value, item -> item);
                } catch (RuntimeException error) {
                    throw error;
                }
            }
        }
    "#;
    let tree = parse_language("java", source.as_bytes());
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let span = span_of(FileId::new(0), &node);
        for expected in [&[node.kind()][..], &[][..]] {
            let legacy = legacy_node_at_span(root, span, expected).expect("legacy exact node");
            let indexed = node_at_span(root, span, expected).expect("indexed exact node");
            assert_eq!(indexed.id(), legacy.id(), "span={span:?}, expected={expected:?}");
        }

        if span.end.saturating_sub(span.start) > 2 {
            let interior = Span::new(span.file, span.start + 1, span.end - 1);
            let legacy = legacy_node_at_span(root, interior, &[]).expect("legacy enclosing node");
            let indexed = node_at_span(root, interior, &[]).expect("indexed enclosing node");
            assert_eq!(indexed.id(), legacy.id(), "interior={interior:?}");
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }

    assert!(node_at_span(root, Span::new(FileId::new(0), 0, u64::MAX), &[]).is_none());
}

fn fielded_comprehension_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    Some((
        node.child_by_field_name("left")?,
        node.child_by_field_name("right")?,
    ))
}

fn fixture_sigiled_binding_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let value = node_text(&node, src)
        .trim()
        .trim_start_matches(['$', '@', '%'])
        .trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn fixture_perl_assignment_semantics(node: Node<'_>, _src: &[u8]) -> crate::AssignmentNodeSemantics {
    if node.kind() == "variable_declaration" {
        crate::AssignmentNodeSemantics::Other
    } else {
        crate::AssignmentNodeSemantics::Assignment
    }
}

fn fixture_elixir_assignment_semantics(node: Node<'_>, _src: &[u8]) -> crate::AssignmentNodeSemantics {
    let mut cursor = node.walk();
    let is_assignment = node.children(&mut cursor).any(|child| child.kind() == "=");
    if is_assignment {
        crate::AssignmentNodeSemantics::Assignment
    } else {
        crate::AssignmentNodeSemantics::Other
    }
}

/// Test-only union used to exercise the shared foreach packager against the
/// exact CST roles supplied by adapter callbacks. Production lowering never
/// calls this function; every language crate owns its corresponding decoder.
fn fixture_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() == "for_expression" {
        let enumerators = node
            .child_by_field_name("enumerators")
            .filter(|child| matches!(child.kind(), "enumerators" | "enumerator"))
            .or_else(|| {
                let mut cursor = node.walk();
                let found = node
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "enumerators");
                found
            })
            .or_else(|| node.named_child(0))?;
        let enumerator = if enumerators.kind() == "enumerator" {
            enumerators
        } else {
            enumerators.named_child(0)?
        };
        return Some((enumerator.named_child(0)?, enumerator.named_child(1)?));
    }
    if let (Some(binding), Some(iterable)) = (
        node.child_by_field_name("item"),
        node.child_by_field_name("collection"),
    ) {
        return Some((binding, iterable));
    }
    if node.kind() == "for_statement"
        && node
            .named_child(0)
            .is_some_and(|child| child.kind() == "multi_variable_declaration")
    {
        return Some((node.named_child(0)?, node.named_child(1)?));
    }
    if node.kind() == "for_statement" {
        let child_count = u32::try_from(node.child_count()).ok()?;
        if let Some(in_index) =
            (0..child_count).find(|index| node.child(*index).is_some_and(|child| child.kind() == "in"))
        {
            let binding = (0..in_index)
                .rev()
                .filter_map(|index| node.child(index))
                .find(Node::is_named)?;
            let iterable = ((in_index + 1)..child_count)
                .filter_map(|index| node.child(index))
                .find(Node::is_named)?;
            return Some((binding, iterable));
        }
    }
    if let (Some(binding), Some(iterable)) = (
        node.child_by_field_name("variable"),
        node.child_by_field_name("list"),
    ) {
        return Some((binding, iterable));
    }
    if let (Some(binding), Some(iterable)) = (
        node.child_by_field_name("variable")
            .or_else(|| node.child_by_field_name("left"))
            .or_else(|| node.child_by_field_name("declarator")),
        node.child_by_field_name("range")
            .or_else(|| node.child_by_field_name("right"))
            .or_else(|| node.child_by_field_name("value")),
    ) {
        return Some((binding, iterable));
    }
    let mut cursor = node.walk();
    if let Some(range) = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "range_clause")
    {
        return Some((
            range
                .child_by_field_name("left")
                .or_else(|| range.named_child(0))?,
            range
                .child_by_field_name("right")
                .or_else(|| range.named_child(1))?,
        ));
    }
    let mut cursor = node.walk();
    if let Some(clause) = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "for_generic_clause")
    {
        return Some((clause.named_child(0)?, clause.named_child(1)?));
    }
    let mut cursor = node.walk();
    if let Some(parts) = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "for_loop_parts")
    {
        return Some((
            parts.child_by_field_name("name")?,
            parts.child_by_field_name("value").unwrap_or(parts),
        ));
    }
    let enumerators = node.child_by_field_name("enumerators").or_else(|| {
        let mut cursor = node.walk();
        let found = node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "enumerators");
        found
    });
    if let Some(enumerators) = enumerators {
        let mut cursor = enumerators.walk();
        let enumerator = enumerators
            .named_children(&mut cursor)
            .find(|child| child.kind() == "enumerator")?;
        return Some((enumerator.named_child(0)?, enumerator.named_child(1)?));
    }
    if node.kind() == "foreach_statement" {
        let body_id = node.child_by_field_name("body").map(|body| body.id());
        let mut cursor = node.walk();
        let mut header = node
            .named_children(&mut cursor)
            .filter(|child| Some(child.id()) != body_id);
        let iterable = header.next()?;
        let binding = header.next()?;
        return Some((binding, iterable));
    }
    None
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
            assignment_semantics_extractor: Some(fixture_elixir_assignment_semantics),
            ..GENERIC_HANDLER
        };
        let perl_handler = GrammarHandler {
            assignment_semantics_extractor: Some(fixture_perl_assignment_semantics),
            ..GENERIC_HANDLER
        };
        let handler = match *pack {
            "elixir" => &elixir_handler,
            "perl" => &perl_handler,
            _ => &GENERIC_HANDLER,
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
    let handler = GrammarHandler {
        member_expression_kinds: &["field_expression"],
        subscript_expression_kinds: &["subscript_expression"],
        member_base_field_names: &["argument"],
        member_name_field_names: &["field"],
        subscript_base_field_names: &["argument"],
        subscript_index_field_names: &["index"],
        ..GENERIC_HANDLER
    };
    let events = walk_flow_events(scope, FileId::new(0), src, &handler, &[]);
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
fn aggregate_assignment_overwrites_root_before_installing_exact_fields() {
    let src = b"function build(raw, user) { const payload = {cmd: raw, user: user}; }";
    let tree = parse_language("javascript", src);
    let scope = collect_kinds(&tree, &["statement_block"])
        .into_iter()
        .next()
        .expect("JavaScript function body");
    let handler = GrammarHandler {
        named_aggregate_kinds: &["object"],
        aggregate_pair_kinds: &["pair"],
        aggregate_key_field_names: &["key"],
        aggregate_value_field_names: &["value"],
        static_field_name_kinds: &["property_identifier"],
        assignment_target_wrapper_kinds: &["variable_declarator"],
        ..GENERIC_HANDLER
    };
    let events = walk_flow_events(scope, FileId::new(0), src, &handler, &[]);
    let root = events
        .iter()
        .position(|event| matches!(event, FlowEvent::Assign { target, .. } if target == "payload"))
        .expect("root assignment");
    let fields = events
        .iter()
        .position(|event| {
            matches!(
                event,
                FlowEvent::AggregateAssign {
                    target,
                    value_flow,
                    ..
                } if target == "payload" && value_flow.aggregate_fields.len() == 2
            )
        })
        .expect("exact aggregate assignment");
    assert!(
        root < fields,
        "root overwrite must precede its exact field writes: {events:#?}"
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
    let handler = GrammarHandler {
        subscript_expression_kinds: &["subscript"],
        subscript_base_field_names: &["value"],
        subscript_index_field_names: &["subscript"],
        ..GENERIC_HANDLER
    };
    let events = walk_flow_events(scope, FileId::new(0), src, &handler, &[]);

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
fn comprehension_binding_uses_fielded_pattern_and_iterable_nodes() {
    let src = b"[(part, index) for (part, index) in rows]";
    let tree = parse_language("python", src);
    let clause = collect_kinds(&tree, &["for_in_clause"])[0];
    let handler = GrammarHandler {
        comprehension_binding_extractor: Some(fielded_comprehension_binding),
        ..GENERIC_HANDLER
    };
    let events = extract_comprehension_for_clause_assigns(FileId::new(0), &clause, src, &handler);
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
        let handler = GrammarHandler {
            foreach_binding_extractor: Some(fixture_foreach_binding),
            binding_name_extractor: Some(fixture_sigiled_binding_name),
            ..GENERIC_HANDLER
        };
        let events = extract_foreach_binding_assigns(FileId::new(0), &loop_node, src, &handler);
        let facts = assign_facts(&events);
        let actual_targets: Vec<&str> = facts.iter().map(|(target, _, _)| *target).collect();
        assert_eq!(actual_targets, *expected_targets, "{pack}: {facts:?}");
        for event in &events {
            let FlowEvent::Assign {
                source_name,
                source_names,
                source_call_args,
                ..
            } = event
            else {
                panic!("{pack}: foreach helper emitted a non-assignment: {event:?}");
            };
            assert!(
                source_name
                    .as_deref()
                    .is_some_and(|name| name.trim_start_matches(['$', '@', '%']) == *expected_source)
                    || source_names
                        .iter()
                        .any(|name| name.trim_start_matches(['$', '@', '%']) == *expected_source)
                    || source_call_args
                        .iter()
                        .any(|name| name.trim_start_matches(['$', '@', '%']) == *expected_source),
                "{pack}: missing source {expected_source}: {facts:?}"
            );
        }
    }
}

#[test]
fn foreach_call_binding_preserves_the_exact_receiver_dependency() {
    let src =
        b"object App { def run(request: Request) = for { value <- request.read(\"key\") } yield value }";
    let tree = parse_language("scala", src);
    let loop_node = collect_kinds(&tree, &["for_expression"])
        .into_iter()
        .next()
        .expect("Scala for expression");
    let handler = GrammarHandler {
        foreach_binding_extractor: Some(fixture_foreach_binding),
        member_expression_kinds: &["field_expression"],
        member_base_field_names: &["value", "object"],
        member_name_field_names: &["field", "name"],
        ..GENERIC_HANDLER
    };
    let events = extract_foreach_binding_assigns(FileId::new(0), &loop_node, src, &handler);
    let assignment = events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_names,
                ..
            } if target == "value" => Some((source_call, source_names)),
            _ => None,
        })
        .expect("generator binding assignment");

    assert!(
        assignment.0.is_some(),
        "the generator must retain its compiler-recognized call result: {events:#?}"
    );
    assert!(
        assignment.1.iter().any(|name| name == "request"),
        "the exact receiver value must reach the generator binding: {events:#?}"
    );
    assert!(
        assignment.1.iter().all(|name| name != "read"),
        "method syntax must not become a value dependency: {events:#?}"
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
        FlowEvent::Assign { target, source_name, .. }
            if target == "closure.captured" && source_name.as_deref() == Some("captured")
    ));
    assert!(matches!(
        &defs[0].flow_events[2],
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

    annotate_tuple_call_result_bindings(&mut events, &tree, src.as_bytes(), &GENERIC_HANDLER);
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
fn compiler_identifier_equivalence_is_punctuation_vocabulary_free() {
    assert!(same_identifier_name("$value", "value"));
    assert!(same_identifier_name("&$value", "$value"));
    assert!(!same_identifier_name("left.value", "value"));
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
fn exact_projected_receiver_type_overrides_the_base_object_type() {
    let file = FileId::new(0);
    let mut repository = m9_func_decl(0, "Repository", None, Vec::new());
    repository.kind = DeclKind::Struct;
    let mut audited = m9_func_decl(1, "AuditedRepository", None, Vec::new());
    audited.kind = DeclKind::Struct;
    let mut run = m9_func_decl(
        2,
        "run",
        None,
        vec![FlowEvent::Call {
            span: Span::new(file, 10, 20),
            name: "self.0.run".to_string(),
            receiver: Some("self.0".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        }],
    );
    run.parent = Some(audited.symbol);
    run.params = vec!["self".to_string()];
    run.receiver_param_index = Some(0);
    run.type_aliases = vec![
        crate::TypeAliasBinding {
            name: "self".to_string(),
            type_name: "AuditedRepository".to_string(),
        },
        crate::TypeAliasBinding {
            name: "self.0".to_string(),
            type_name: "Repository".to_string(),
        },
    ];
    let mut idx = DeclIndex {
        file,
        defs: vec![repository, audited, run],
        ..DeclIndex::default()
    };

    apply_call_receiver_types(&mut idx);

    assert!(matches!(
        &idx.defs[2].flow_events[0],
        FlowEvent::Call { receiver_types, .. } if receiver_types == &["Repository"]
    ));
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
    let mut events = vec![
        assign_call("z", "f", &["user.name"], &["f", "user.name", "user", "name"]),
        call("f", &["user.name"]),
    ];

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
    let mut events = vec![assign_call("z", "f", &["$x"], &["$x", "$xy"]), call("f", &["$x"])];

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
    let mut events = vec![
        assign_call(
            "ok",
            "target.call",
            &["payload"],
            &["target.call", "target", "call", "payload"],
        ),
        call("target.call", &["payload"]),
    ];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign event")
    };
    assert_eq!(source_names.as_slice(), ["target"]);
}

#[test]
fn call_result_assignment_pruning_never_treats_casing_as_type_evidence() {
    let mut events = vec![
        assign_call(
            "logger",
            "Logger.getLogger",
            &["name"],
            &["Logger", "Logger.getLogger", "getLogger", "name"],
        ),
        call("Logger.getLogger", &["name"]),
    ];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign event")
    };
    assert_eq!(source_names.as_slice(), ["Logger"]);
}

#[test]
fn call_result_assignment_pruning_never_tokenizes_argument_rendering() {
    let mut events = vec![
        assign_call("z", "f", &["wrapper(user)"], &["f", "safe", "user"]),
        FlowEvent::Call {
            span: Span::new(FileId::INVALID, 0, 0),
            name: "f".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: Span::new(FileId::INVALID, 0, 0),
                name: None,
                value_text: "wrapper(user)".to_string(),
                place: Some("safe".to_string()),
                source_names: vec!["safe".to_string()],
            }],
        },
    ];

    normalize_call_result_assignment_sources(&mut events);

    let FlowEvent::Assign { source_names, .. } = &events[0] else {
        panic!("expected assign event")
    };
    assert_eq!(source_names.as_slice(), ["user"]);
}

#[test]
fn variadic_builtin_read_uses_exact_argument_place() {
    let span = Span::new(FileId::INVALID, 0, 12);
    let call_span = Span::new(FileId::INVALID, 4, 11);
    let mut events = vec![
        FlowEvent::Assign {
            span,
            target: "value".to_string(),
            source_name: None,
            source_call: Some("va_arg".to_string()),
            source_call_args: vec!["rendered_decoy".to_string()],
            source_names: vec!["rendered_decoy".to_string()],
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::CallResult),
        },
        FlowEvent::Call {
            span: call_span,
            name: "va_arg".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: call_span,
                name: None,
                value_text: "rendered_decoy".to_string(),
                place: Some("compiler_place".to_string()),
                source_names: vec!["compiler_place".to_string()],
            }],
        },
    ];

    normalize_variadic_builtin_flow(&mut events, false, &[], &["va_arg"]);

    let FlowEvent::Assign {
        source_name,
        source_call,
        source_names,
        ..
    } = &events[0]
    else {
        panic!("expected assignment")
    };
    assert_eq!(source_name.as_deref(), Some("compiler_place"));
    assert_eq!(source_call, &None);
    assert_eq!(source_names.as_slice(), ["compiler_place"]);
}

#[test]
fn variadic_builtin_read_fails_closed_without_exact_call_fact() {
    let mut events = vec![FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 0, 12),
        target: "value".to_string(),
        source_name: None,
        source_call: Some("va_arg".to_string()),
        source_call_args: vec!["rendered_decoy".to_string()],
        source_names: vec!["compiler_source".to_string()],
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::CallResult),
    }];

    normalize_variadic_builtin_flow(&mut events, false, &[], &["va_arg"]);

    let FlowEvent::Assign {
        source_name,
        source_call,
        source_names,
        ..
    } = &events[0]
    else {
        panic!("expected assignment")
    };
    assert_eq!(source_name, &None);
    assert_eq!(source_call.as_deref(), Some("va_arg"));
    assert_eq!(source_names.as_slice(), ["compiler_source"]);
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
    assert_eq!(argument_place(&nil_arg, src, &GENERIC_HANDLER), None);

    let cpp = language_from_pack("cpp").expect("cpp grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&cpp).expect("set cpp grammar");
    let src = b"void f() { g(nullptr); }\n";
    let tree = parser.parse(src, None).expect("parse cpp");
    let null_arg = collect_kinds(&tree, &["null"])
        .into_iter()
        .next()
        .expect("nullptr null node");
    assert_eq!(argument_place(&null_arg, src, &GENERIC_HANDLER), None);
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
        package_module_segments_with_workspace_prefix(first, &ctx, ["mega"], &[&["src", "main", "java"]],),
        vec!["flow_a".to_string(), "mega".to_string()]
    );
    assert_eq!(
        package_module_segments_with_workspace_prefix(second, &ctx, ["mega"], &[&["src", "main", "java"]],),
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
        package_module_segments_with_workspace_prefix(file, &ctx, ["mega"], &[]),
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

fn exact_type_alias_assign(target: &str, source: &str, offset: u64) -> FlowEvent {
    FlowEvent::Assign {
        span: Span::new(FileId::new(0), offset, offset + 1),
        target: target.to_string(),
        source_name: Some(source.to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::Compound),
    }
}

#[test]
fn exact_assignment_alias_propagates_receiver_type_without_language_names() {
    let mut repository = m9_func_decl(0, "Repository", None, Vec::new());
    repository.kind = DeclKind::Class;
    let mut handler = m9_func_decl(
        1,
        "handler",
        None,
        vec![
            exact_type_alias_assign("$alias", "$repository", 10),
            FlowEvent::Call {
                span: Span::new(FileId::new(0), 20, 30),
                name: "alias->run".to_string(),
                receiver: Some("alias".to_string()),
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            },
        ],
    );
    handler.type_aliases.push(crate::TypeAliasBinding {
        name: "$repository".to_string(),
        type_name: "Repository".to_string(),
    });
    let mut idx = DeclIndex {
        defs: vec![repository, handler],
        ..DeclIndex::default()
    };

    apply_assignment_type_aliases(&mut idx);
    apply_call_receiver_types(&mut idx);

    let handler = &idx.defs[1];
    assert!(handler
        .type_aliases
        .iter()
        .any(|alias| alias.name == "$alias" && alias.type_name == "Repository"));
    assert!(matches!(
        &handler.flow_events[1],
        FlowEvent::Call { receiver_types, .. } if receiver_types == &["Repository"]
    ));
}

#[test]
fn assignment_type_alias_inference_fails_closed_on_conflict_or_overwrite() {
    let mut conflicting = m9_func_decl(
        0,
        "conflicting",
        None,
        vec![
            exact_type_alias_assign("alias", "left", 10),
            exact_type_alias_assign("alias", "right", 20),
        ],
    );
    conflicting.type_aliases = vec![
        crate::TypeAliasBinding {
            name: "left".to_string(),
            type_name: "Left".to_string(),
        },
        crate::TypeAliasBinding {
            name: "right".to_string(),
            type_name: "Right".to_string(),
        },
    ];
    let mut overwritten = m9_func_decl(
        1,
        "overwritten",
        None,
        vec![
            exact_type_alias_assign("alias", "source", 30),
            FlowEvent::Assign {
                span: Span::new(FileId::new(0), 40, 41),
                target: "alias".to_string(),
                source_name: None,
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: Some(AssignValueKind::Literal),
            },
        ],
    );
    overwritten.type_aliases.push(crate::TypeAliasBinding {
        name: "source".to_string(),
        type_name: "Source".to_string(),
    });
    let mut idx = DeclIndex {
        defs: vec![conflicting, overwritten],
        ..DeclIndex::default()
    };

    apply_assignment_type_aliases(&mut idx);

    assert!(!idx.defs[0].type_aliases.iter().any(|alias| alias.name == "alias"));
    assert!(!idx.defs[1].type_aliases.iter().any(|alias| alias.name == "alias"));
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
            // Method-based constructor syntax must preserve the complete
            // parsed owner rather than collapsing it to the terminal type.
            // This keeps equally named types in distinct providers separate.
            assign("qualified", Some("External::Nested::Context.new"), sp(161, 200)),
            qualified_constructor(
                "External::Nested::Context.new",
                "External::Nested::Context",
                sp(173, 199),
            ),
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
    assert_eq!(
        typed("qualified"),
        Some("External::Nested::Context"),
        "qualified constructor owners must remain exact: {:?}",
        decl.type_aliases
    );
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
    let strings = extract_string_literals(&tree, FileId::new(0), source.as_bytes(), &GENERIC_HANDLER);

    assert!(strings.iter().any(|literal| literal.text.contains(&content)));
}

#[test]
fn callable_argument_does_not_treat_captures_as_host_value_operands() {
    let source = b"register(function (value) { sink(captured, value); });";
    let tree = parse_language("javascript", source);
    let callable = collect_kinds(&tree, &["function_expression"])
        .into_iter()
        .next()
        .expect("anonymous callback");
    let argument =
        call_arg_from_nodes_with_handler(callable, callable, FileId::new(0), source, None, &GENERIC_HANDLER)
            .expect("callable argument");

    assert!(argument.place.is_none());
    assert!(
        argument.source_names.is_empty(),
        "callback captures are environment reads at execution time, not scalar values delivered to register: {argument:?}"
    );
}

#[test]
fn nested_callable_scope_does_not_leak_into_parent_expression_operands() {
    let source = b"const items = values.map(value => value + captured);";
    let tree = parse_language("javascript", source);
    let declarator = collect_kinds(&tree, &["variable_declarator"])
        .into_iter()
        .next()
        .expect("variable declarator");
    let value = declarator.child_by_field_name("value").expect("initializer");

    let operands = extract_rhs_expr_operands(&value, source, &GENERIC_HANDLER);
    assert!(operands.iter().any(|operand| operand == "values"));
    assert!(
        operands
            .iter()
            .all(|operand| operand != "value" && operand != "captured"),
        "callback parameters, locals, and captures belong to the callback environment: {operands:?}"
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
fn qualified_receiverless_call_does_not_inherit_enclosing_class_type() {
    let file = FileId::new(0);
    let mut idx = DeclIndex::default();
    let mut runtime = m9_func_decl(0, "Runtime", None, Vec::new());
    runtime.kind = DeclKind::Struct;
    let mut spawn = m9_func_decl(
        1,
        "spawn",
        None,
        vec![
            FlowEvent::Call {
                span: Span::new(file, 10, 20),
                name: "SpawnMeta::new_unnamed".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            },
            FlowEvent::Call {
                span: Span::new(file, 30, 40),
                name: "poll".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            },
        ],
    );
    spawn.kind = DeclKind::Method;
    spawn.parent = Some(runtime.symbol);
    idx.defs.extend([runtime, spawn]);

    apply_call_receiver_types(&mut idx);

    let method = &idx.defs[1];
    assert!(matches!(
        &method.flow_events[0],
        FlowEvent::Call { receiver_types, .. } if receiver_types.is_empty()
    ));
    assert!(matches!(
        &method.flow_events[1],
        FlowEvent::Call { receiver_types, .. } if receiver_types == &["Runtime"]
    ));
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
fn receiver_type_retains_distinct_provider_identities_with_one_terminal_name() {
    let mut idx = DeclIndex::default();
    let mut entry = m9_func_decl(
        0,
        "entry",
        None,
        vec![FlowEvent::Call {
            span: Span::new(FileId::new(0), 10, 20),
            name: "client.consume".to_string(),
            receiver: Some("client".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        }],
    );
    entry.type_aliases = vec![
        crate::TypeAliasBinding {
            name: "client".to_string(),
            type_name: "Client".to_string(),
        },
        crate::TypeAliasBinding {
            name: "client".to_string(),
            type_name: "provider.transport.Client".to_string(),
        },
        crate::TypeAliasBinding {
            name: "client".to_string(),
            type_name: "application.transport.Client".to_string(),
        },
    ];
    idx.defs.push(entry);

    apply_call_receiver_types(&mut idx);

    assert!(matches!(
        &idx.defs[0].flow_events[0],
        FlowEvent::Call { receiver_types, .. }
            if receiver_types == &[
                "Client".to_string(),
                "provider.transport.Client".to_string(),
                "application.transport.Client".to_string(),
            ]
    ));
}

#[test]
fn receiver_type_uses_the_outer_qualified_generic_constructor() {
    let mut idx = DeclIndex::default();
    let mut entry = m9_func_decl(
        0,
        "entry",
        None,
        vec![FlowEvent::Call {
            span: Span::new(FileId::new(0), 10, 20),
            name: "values.push".to_string(),
            receiver: Some("values".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        }],
    );
    entry.type_aliases = vec![crate::TypeAliasBinding {
        name: "values".to_string(),
        type_name: "std::vector<std::string>".to_string(),
    }];
    idx.defs.push(entry);

    apply_call_receiver_types(&mut idx);

    assert!(matches!(
        &idx.defs[0].flow_events[0],
        FlowEvent::Call { receiver_types, .. }
            if receiver_types == &["std::vector".to_string()]
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
    assert_eq!(operands, vec!["args".to_string()]);

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
        vec!["args".to_string()]
    );

    let body = collect_kinds(&tree, &["block"])
        .into_iter()
        .next()
        .expect("subroutine body");
    let handler = GrammarHandler {
        assignment_semantics_extractor: Some(fixture_perl_assignment_semantics),
        ..GENERIC_HANDLER
    };
    let events = walk_flow_events(body, FileId::new(0), source.as_bytes(), &handler, &[]);
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
        param_default_calls: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        receiver_field_initializers: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: return_type.map(str::to_string),
        is_variadic: false,
    }
}

#[test]
fn evaluation_order_places_exact_binding_before_its_first_dependent_use() {
    let file = FileId::new(0);
    let source = FlowEvent::Call {
        span: Span::new(file, 20, 26),
        name: "source".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: Vec::new(),
    };
    let binding = FlowEvent::Assign {
        span: Span::new(file, 10, 30),
        target: "bound".to_string(),
        source_name: None,
        source_call: Some("source".to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::CallResult),
    };
    let use_bound = FlowEvent::Call {
        span: Span::new(file, 40, 47),
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: Span::new(file, 48, 53),
            passing_mode: crate::ArgumentPassingMode::Value,
            name: None,
            value_text: "bound".to_string(),
            place: Some("bound".to_string()),
            source_names: vec!["bound".to_string()],
        }],
    };
    let aggregate = FlowEvent::Assign {
        span: Span::new(file, 0, 60),
        target: "result".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["bound".to_string()],
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::Compound),
    };
    let mut index = DeclIndex::default();
    index.defs.push(m9_func_decl(
        1,
        "pipeline",
        None,
        vec![aggregate, source, binding, use_bound],
    ));

    normalize_decl_event_evaluation_order(&mut index);
    let events = &index.defs[0].flow_events;
    assert!(matches!(&events[0], FlowEvent::Call { name, .. } if name == "source"));
    assert!(matches!(&events[1], FlowEvent::Assign { target, .. } if target == "bound"));
    assert!(matches!(&events[2], FlowEvent::Call { name, .. } if name == "consume"));
    assert!(matches!(&events[3], FlowEvent::Assign { target, .. } if target == "result"));
}

#[test]
fn evaluation_order_places_aggregate_write_before_its_consumer_and_is_idempotent() {
    let file = FileId::new(0);
    let consumer = FlowEvent::Call {
        span: Span::new(file, 40, 58),
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: Span::new(file, 48, 57),
            passing_mode: crate::ArgumentPassingMode::Value,
            name: None,
            value_text: "envelope".to_string(),
            place: Some("envelope".to_string()),
            source_names: vec!["envelope".to_string()],
        }],
    };
    let aggregate = FlowEvent::AggregateAssign {
        span: Span::new(file, 10, 30),
        target: "envelope".to_string(),
        type_name: None,
        value_flow: ExpressionFlow {
            aggregate_fields: vec![crate::ExpressionField {
                name: "value".to_string(),
                value_span: Some(Span::new(file, 20, 23)),
                value: ExpressionFlow::from_place("raw"),
            }],
            ..ExpressionFlow::default()
        },
    };
    let mut index = DeclIndex::default();
    index
        .defs
        .push(m9_func_decl(1, "pipeline", None, vec![consumer, aggregate]));

    normalize_decl_event_evaluation_order(&mut index);
    normalize_decl_event_evaluation_order(&mut index);
    let events = &index.defs[0].flow_events;
    assert!(matches!(&events[0], FlowEvent::AggregateAssign { target, .. } if target == "envelope"));
    assert!(matches!(&events[1], FlowEvent::Call { name, .. } if name == "consume"));
}

#[test]
fn evaluation_order_self_assignment_executes_rhs_before_write_without_a_cycle() {
    let file = FileId::new(0);
    let assignment_span = Span::new(file, 10, 30);
    let rhs_call_span = Span::new(file, 14, 26);
    let assignment = FlowEvent::Assign {
        span: assignment_span,
        target: "value".to_string(),
        source_name: None,
        source_call: Some("transform".to_string()),
        source_call_args: vec!["value".to_string()],
        source_names: vec!["value".to_string()],
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::CallResult),
    };
    let rhs_call = FlowEvent::Call {
        span: rhs_call_span,
        name: "transform".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: Span::new(file, 24, 25),
            passing_mode: crate::ArgumentPassingMode::Value,
            name: None,
            value_text: "value".to_string(),
            place: Some("value".to_string()),
            source_names: vec!["value".to_string()],
        }],
    };
    let later_use = FlowEvent::Call {
        span: Span::new(file, 40, 54),
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: Span::new(file, 48, 53),
            passing_mode: crate::ArgumentPassingMode::Value,
            name: None,
            value_text: "value".to_string(),
            place: Some("value".to_string()),
            source_names: vec!["value".to_string()],
        }],
    };
    let mut index = DeclIndex::default();
    index.defs.push(m9_func_decl(
        1,
        "pipeline",
        None,
        vec![assignment, rhs_call, later_use],
    ));

    normalize_decl_event_evaluation_order(&mut index);
    let events = &index.defs[0].flow_events;
    assert!(matches!(&events[0], FlowEvent::Call { name, .. } if name == "transform"));
    assert!(matches!(&events[1], FlowEvent::Assign { target, .. } if target == "value"));
    assert!(matches!(&events[2], FlowEvent::Call { name, .. } if name == "consume"));
}

#[test]
fn evaluation_order_recovers_a_late_emitted_lexical_write_before_its_branch_use() {
    let file = FileId::new(0);
    let branch = FlowEvent::Branch {
        span: Span::new(file, 40, 80),
        condition: Some("path != empty".to_string()),
        then_events: vec![FlowEvent::Call {
            span: Span::new(file, 60, 64),
            name: "consume".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: Span::new(file, 65, 69),
                passing_mode: crate::ArgumentPassingMode::Value,
                name: None,
                value_text: "path".to_string(),
                place: Some("path".to_string()),
                source_names: vec!["path".to_string()],
            }],
        }],
        else_events: Vec::new(),
    };
    let lexical_write = FlowEvent::Assign {
        span: Span::new(file, 10, 35),
        target: "path".to_string(),
        source_name: Some("input".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["input".to_string()],
        declares_new_binding: true,
        value_kind: Some(AssignValueKind::Compound),
    };
    let mut index = DeclIndex::default();
    // Some adapters add expression facts after the primary statement walk.
    index
        .defs
        .push(m9_func_decl(1, "pipeline", None, vec![branch, lexical_write]));

    normalize_decl_event_evaluation_order(&mut index);
    let events = &index.defs[0].flow_events;
    assert!(matches!(&events[0], FlowEvent::Assign { target, .. } if target == "path"));
    assert!(matches!(&events[1], FlowEvent::Branch { .. }));
}

#[test]
fn evaluation_order_preserves_lowered_loop_body_before_textually_earlier_update() {
    let file = FileId::new(0);
    let body_call = FlowEvent::Call {
        span: Span::new(file, 50, 61),
        name: "consume".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: Span::new(file, 58, 59),
            passing_mode: crate::ArgumentPassingMode::Value,
            name: None,
            value_text: "value".to_string(),
            place: Some("value".to_string()),
            source_names: vec!["value".to_string()],
        }],
    };
    let header_update = FlowEvent::Assign {
        span: Span::new(file, 30, 45),
        target: "value".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::Literal),
    };
    let loop_event = FlowEvent::Loop {
        span: Span::new(file, 10, 65),
        loop_kind: crate::LoopKind::For,
        label: None,
        condition_events: Vec::new(),
        // The compiler lowering keeps the update phase distinct so continue
        // cannot skip it.
        update_events: vec![header_update],
        body: vec![body_call],
    };
    let mut index = DeclIndex::default();
    index
        .defs
        .push(m9_func_decl(1, "pipeline", None, vec![loop_event]));

    normalize_decl_event_evaluation_order(&mut index);
    let FlowEvent::Loop {
        body, update_events, ..
    } = &index.defs[0].flow_events[0]
    else {
        panic!("expected loop event");
    };
    assert!(matches!(&body[0], FlowEvent::Call { name, .. } if name == "consume"));
    assert!(matches!(&update_events[0], FlowEvent::Assign { target, .. } if target == "value"));
}

#[test]
fn evaluation_order_keeps_a_loop_assignment_after_its_nested_rhs_call() {
    let file = FileId::new(0);
    let assignment = FlowEvent::Assign {
        span: Span::new(file, 50, 80),
        target: "value".to_string(),
        source_name: Some("value".to_string()),
        source_call: Some("transform".to_string()),
        source_call_args: vec!["value".to_string()],
        source_names: vec!["value".to_string()],
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::CallResult),
    };
    let rhs_call = FlowEvent::Call {
        span: Span::new(file, 58, 76),
        name: "transform".to_string(),
        receiver: None,
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        args: vec![CallArg {
            span: Span::new(file, 68, 73),
            passing_mode: crate::ArgumentPassingMode::Value,
            name: None,
            value_text: "value".to_string(),
            place: Some("value".to_string()),
            source_names: vec!["value".to_string()],
        }],
    };
    let loop_event = FlowEvent::Loop {
        span: Span::new(file, 10, 90),
        loop_kind: crate::LoopKind::For,
        label: None,
        condition_events: Vec::new(),
        update_events: Vec::new(),
        // A secondary adapter pass may append the nested call after the
        // enclosing assignment. AST containment still defines evaluator
        // order inside a loop body.
        body: vec![assignment, rhs_call],
    };
    let mut index = DeclIndex::default();
    index
        .defs
        .push(m9_func_decl(1, "pipeline", None, vec![loop_event]));

    normalize_decl_event_evaluation_order(&mut index);
    let FlowEvent::Loop { body, .. } = &index.defs[0].flow_events[0] else {
        panic!("expected loop event");
    };
    assert!(matches!(&body[0], FlowEvent::Call { name, .. } if name == "transform"));
    assert!(matches!(&body[1], FlowEvent::Assign { target, .. } if target == "value"));
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

#[test]
fn finite_selection_return_proof_requires_every_returning_path() {
    let file = FileId::new(0);
    let selection = Span::new(file, 20, 30);
    let finite_return = FlowEvent::Return {
        span: Span::new(file, 10, 32),
        value_kind: None,
        value_text: None,
        value_name: None,
        value_flow: ExpressionFlow::default(),
    };
    let literal_return = FlowEvent::Return {
        span: Span::new(file, 40, 50),
        value_kind: Some(AssignValueKind::Literal),
        value_text: None,
        value_name: None,
        value_flow: ExpressionFlow::default(),
    };
    let dynamic_return = FlowEvent::Return {
        span: Span::new(file, 60, 70),
        value_kind: None,
        value_text: None,
        value_name: Some("runtime".to_string()),
        value_flow: ExpressionFlow::from_place("runtime"),
    };

    assert_eq!(
        complete_finite_selection_return_span(std::slice::from_ref(&finite_return), &[selection]),
        Some(selection)
    );
    assert_eq!(
        complete_finite_selection_return_span(
            &[FlowEvent::Branch {
                span: Span::new(file, 5, 55),
                condition: None,
                then_events: vec![finite_return.clone()],
                else_events: vec![literal_return],
            }],
            &[selection],
        ),
        Some(selection),
        "literal alternatives remain within the same finite output domain"
    );
    assert_eq!(
        complete_finite_selection_return_span(
            &[FlowEvent::Branch {
                span: Span::new(file, 5, 75),
                condition: None,
                then_events: vec![finite_return.clone()],
                else_events: vec![dynamic_return],
            }],
            &[selection],
        ),
        None,
        "one dynamic return must invalidate the whole callable summary"
    );
    assert_eq!(
        complete_finite_selection_return_span(
            &[
                FlowEvent::Branch {
                    span: Span::new(file, 5, 35),
                    condition: None,
                    then_events: vec![finite_return],
                    else_events: Vec::new(),
                },
                FlowEvent::Assign {
                    span: Span::new(file, 80, 90),
                    target: "result".to_string(),
                    source_name: None,
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: Vec::new(),
                    declares_new_binding: true,
                    value_kind: Some(AssignValueKind::Literal),
                },
            ],
            &[selection],
        ),
        None,
        "a conditional selection with a fallthrough path is not a complete return proof"
    );
}
