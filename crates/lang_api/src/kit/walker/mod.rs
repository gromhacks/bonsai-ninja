use super::{
    build_dart_cascade_events, build_dart_object_expression_call, build_dart_selector_call_event,
    call_receiver_from_name, elixir_unwrap_def, emit_elixir_control_flow_call,
    emit_erlang_functional_loop_call, emit_ruby_block_loop_call, extract_comprehension_for_clause_assigns,
    extract_foreach_binding_assigns, extract_match_binding_assigns, extract_rhs_expr_operands,
    extract_rust_let_condition_bindings, first_identifier_like_child, first_named_child,
    first_named_child_of_kind, has_direct_child_kind, is_comprehension_binding_clause, is_comprehension_kind,
    is_initializer_list_kind, is_large_data_declaration_node, is_large_literal_initializer_node,
    is_scala_operator_method_call, is_swift_defer_call, looks_like_bare_identifier,
    next_named_sibling_within, node_text, pseudo_call_event, repair_branch_events_by_else_keyword, span_of,
    swift_trailing_lambdas, walk_deep_sequence_executable_nodes, walk_lambda_body, FileId, FlowEvent,
    GrammarHandler, LoopKind, Node, SyntaxSpecialForm,
};

mod assignment;
mod call;
mod control;

use assignment::lower_assignment;
use call::lower_call;
use control::{lower_control_and_scope, lower_function_exit, lower_try};

#[derive(Clone, Copy)]
struct LoweringContext<'a> {
    file: FileId,
    src: &'a [u8],
    handler: &'a GrammarHandler,
    class_names: &'a [String],
}

pub(super) fn walk_into(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
    is_root: bool,
) {
    let kind = node.kind();
    let context = LoweringContext {
        file,
        src,
        handler,
        class_names,
    };
    if is_large_literal_initializer_node(kind, &node) {
        return;
    }
    if is_initializer_list_kind(kind) || kind == "comma_expression" {
        walk_deep_sequence_executable_nodes(node, file, src, handler, class_names, out);
        return;
    }
    if is_large_data_declaration_node(kind, &node) {
        return;
    }

    // Skip over nested function/class definitions — their flow belongs to
    // their own decls. But do walk into their *declarators* to catch inline
    // default-arg expressions (rare; best-effort).
    //
    // Elixir exception: `call` is in its FN_KINDS (Elixir function defs
    // are `def foo do ... end` parsed as a `call`), but the same `call`
    // kind also covers ordinary runtime calls. Only skip the call when
    // it's actually a def-macro; let runtime calls fall through to the
    // call handler below.
    let is_skippable_nested_fn = if !is_root && kind == "call" {
        // Only treat a nested call as a skippable function decl when
        // its target identifier is one of Elixir's def macros.
        elixir_unwrap_def(&node, src).is_some()
    } else {
        !is_root && handler.is_fn(kind)
    };
    if is_skippable_nested_fn || (!is_root && (handler.is_class(kind) || handler.is_lambda(kind))) {
        return;
    }

    if let Some(event) = pseudo_call_event(&node, file, src) {
        out.push(event);
    }

    // Comprehensions / generator expressions across Python, JS, TS.
    // Tree-sitter exposes them as `list_comprehension`,
    // `dict_comprehension`, `set_comprehension`, `generator_expression`
    // (Python), `array_comprehension` / `generator_expression` (JS/TS
    // proposals). Each one has one or more `for_in_clause` children
    // that bind a loop variable from an iterable. Without explicit
    // handling the loop-variable assignment never surfaces — taint
    // on the iterable can't reach the comprehension's body
    // expression. Synthesize an Assign per for-clause + walk the body
    // so calls inside the expression are observed in the enclosing
    // scope's flow events. Adapter-agnostic: relies only on the
    // common `for_in_clause` / `comp_for` shape that all three
    // grammars expose.
    if lower_comprehension(node, context, out) {
        return;
    }
    if lower_branch(node, context, out) {
        return;
    }
    if lower_loop(node, context, out) {
        return;
    }

    if lower_function_exit(node, context, out) {
        return;
    }
    if lower_assignment(node, context, out) {
        return;
    }
    if lower_special_form(node, context, out) {
        return;
    }
    if lower_call(node, context, out) {
        return;
    }
    if lower_try(node, context, out) {
        return;
    }
    if lower_control_and_scope(node, context, out) {
        return;
    }

    // Default: recurse into every named child.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_into(child, file, src, handler, class_names, out, false);
    }
}

fn lower_branch(node: Node<'_>, context: LoweringContext<'_>, out: &mut Vec<FlowEvent>) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    if handler.is_if(kind) {
        let then_node = node
            .child_by_field_name("consequence")
            .or_else(|| node.child_by_field_name("then"))
            .or_else(|| node.child_by_field_name("body"))
            .or_else(|| first_named_child_of_kind(&node, "statements"));
        let else_node = node
            .child_by_field_name("alternative")
            .or_else(|| node.child_by_field_name("else"))
            // Solidity's grammar exposes both if arms with the same
            // `body` field. `child_by_field_name("body")` returns the
            // first arm only, so recover the second body-like sibling
            // when no explicit alternative field exists.
            .or_else(|| then_node.and_then(|then| next_named_sibling_within(&node, then)));
        let mut then_events = Vec::new();
        if let Some(n) = then_node {
            walk_into(n, file, src, handler, class_names, &mut then_events, false);
        }
        let mut else_events = Vec::new();
        if let Some(n) = else_node {
            walk_into(n, file, src, handler, class_names, &mut else_events, false);
        }
        // Python's if/elif/elif/else lays out additional elif_clause
        // and else_clause nodes as SIBLINGS inside the if_statement
        // (not as nested alternatives), so the single `alternative`
        // field only exposes the first elif. Walk every remaining
        // elif_clause / else_clause named child so later branches'
        // calls still surface. Lua is the same shape but names the
        // siblings `elseif_statement` / `else_statement` (all carried on
        // the repeated `alternative` field, of which `child_by_field_name`
        // returns only the first) — without them, every branch after the
        // first `elseif`, plus the trailing `else`, was dropped along
        // with its calls.
        let then_id = then_node.map(|n| n.id());
        let else_id = else_node.map(|n| n.id());
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if Some(child.id()) == then_id || Some(child.id()) == else_id {
                continue;
            }
            if matches!(
                child.kind(),
                "elif_clause" | "else_clause" | "elseif_statement" | "else_statement"
            ) {
                walk_into(child, file, src, handler, class_names, &mut else_events, false);
            }
        }
        // Switch/match/when don't expose consequence/alternative fields: if
        // neither path produced any events, walk all named children so the
        // calls inside case arms still surface in the flow. Skip the
        // discriminant/condition field child — it is walked separately into
        // the OUTER flow below; walking it here too double-emits its calls
        // (`if (check(x)) {}` with empty arms emitted two `check` events).
        if then_events.is_empty() && else_events.is_empty() {
            let discriminant_ids: [Option<usize>; 4] = [
                node.child_by_field_name("condition").map(|n| n.id()),
                node.child_by_field_name("subject").map(|n| n.id()),
                node.child_by_field_name("value").map(|n| n.id()),
                node.child_by_field_name("discriminant").map(|n| n.id()),
            ];
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if discriminant_ids.iter().any(|id| *id == Some(child.id())) {
                    continue;
                }
                walk_into(child, file, src, handler, class_names, &mut then_events, false);
            }
        }
        repair_branch_events_by_else_keyword(&mut then_events, &mut else_events, &node, src);
        // Go type switch `switch t := v.(type) { ... }` binds `t` to the
        // switched value `v` inside every arm. tree-sitter-go exposes the
        // bound name as an `alias` field and the value as a `value` field,
        // with no assignment node — so without this the arms' `t` never
        // links to `v` and the switched value's taint is lost. Prepend the
        // `t <- v` binding to both arms.
        let mut type_switch_binding: Vec<FlowEvent> = Vec::new();
        if let (Some(alias), Some(value)) = (
            node.child_by_field_name("alias"),
            node.child_by_field_name("value"),
        ) {
            let alias_text = first_identifier_like_child(&alias)
                .map(|id| node_text(&id, src))
                .unwrap_or_else(|| node_text(&alias, src));
            let target = alias_text.trim().to_string();
            let value_text = node_text(&value, src).trim().to_string();
            if !target.is_empty() && !value_text.is_empty() && target != value_text {
                type_switch_binding.push(FlowEvent::Assign {
                    span: span_of(file, &node),
                    target,
                    source_name: looks_like_bare_identifier(&value_text).then(|| value_text.clone()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: extract_rhs_expr_operands(&value, src),
                    declares_new_binding: true,
                    value_kind: None,
                });
            }
        }
        if !type_switch_binding.is_empty() {
            let mut prefixed = type_switch_binding.clone();
            prefixed.extend(then_events);
            then_events = prefixed;
            let mut prefixed_else = type_switch_binding;
            prefixed_else.extend(else_events);
            else_events = prefixed_else;
        }
        let match_bindings = extract_match_binding_assigns(file, &node, src);
        if !match_bindings.is_empty() {
            let mut prefixed = match_bindings.clone();
            prefixed.extend(then_events);
            then_events = prefixed;
            if !else_events.is_empty() {
                let mut prefixed_else = match_bindings;
                prefixed_else.extend(else_events);
                else_events = prefixed_else;
            }
        }
        // Also descend into the discriminant for any nested calls.
        // Grammars name it differently:
        //   * if:    `condition`
        //   * match / switch (Python, Rust): `subject` / `value`
        //   * when-expression (Kotlin):       `subject`
        let mut condition = None;
        for field in ["condition", "subject", "value", "discriminant"] {
            if let Some(cond) = node.child_by_field_name(field) {
                condition.get_or_insert_with(|| node_text(&cond, src).trim().to_string());
                walk_into(cond, file, src, handler, class_names, out, false);
            }
        }
        out.push(FlowEvent::Branch {
            span: span_of(file, &node),
            condition,
            then_events,
            else_events,
        });
        return true;
    }

    false
}

fn lower_comprehension(node: Node<'_>, context: LoweringContext<'_>, out: &mut Vec<FlowEvent>) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    if is_comprehension_kind(kind) {
        // Emit the loop-variable bindings BEFORE the body, regardless of
        // AST order (python lays the body out first). This gives the
        // natural flow order — bindings then body — so a NESTED
        // comprehension's chained bindings resolve: `[f(t) for row in rows
        // for t in row]` emits `row<-rows` then `t<-row` then the body, so
        // taint flows rows -> row -> t into the sink. (A single-clause comp
        // worked even body-first since its binding is a direct param, but
        // the two-hop nested chain needs binding-before-body.)
        //
        // Binding clauses are found by DESCENDANT search, not direct
        // children: Python/JS expose `for_in_clause` directly, but Erlang
        // nests its `generator` under `lc_exprs > lc_or_zc_expr`
        // (`[E || X <- List]`), so a direct-children scan never saw the
        // binding and the iterable's taint could not reach the body.
        let mut clauses: Vec<Node<'_>> = Vec::new();
        let mut stack: Vec<Node<'_>> = vec![node];
        while let Some(current) = stack.pop() {
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                if is_comprehension_binding_clause(child.kind()) {
                    clauses.push(child);
                } else {
                    stack.push(child);
                }
            }
        }
        clauses.sort_by_key(|clause| clause.start_byte());
        for clause in &clauses {
            out.extend(extract_comprehension_for_clause_assigns(file, clause, src));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !is_comprehension_binding_clause(child.kind()) {
                walk_into(child, file, src, handler, class_names, out, false);
            }
        }
        return true;
    }

    false
}

fn lower_loop(node: Node<'_>, context: LoweringContext<'_>, out: &mut Vec<FlowEvent>) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    if handler.is_for(kind)
        || handler.is_foreach(kind)
        || handler.is_while(kind)
        || (handler.is_do(kind) && !has_direct_child_kind(&node, "catch_block"))
        || handler.is_loop(kind)
    {
        let body_node = node
            .child_by_field_name("body")
            .or_else(|| node.child_by_field_name("consequence"))
            .or_else(|| {
                let mut cursor = node.walk();
                let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                children.into_iter().rev().find(|child| {
                    matches!(
                        child.kind(),
                        "block" | "compound_statement" | "statement" | "expression_statement"
                    )
                })
            });
        let mut body = Vec::new();
        if let Some(n) = body_node {
            walk_into(n, file, src, handler, class_names, &mut body, false);
            let body_id = n.id();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.id() != body_id {
                    walk_into(child, file, src, handler, class_names, out, false);
                }
            }
        } else {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_into(child, file, src, handler, class_names, &mut body, false);
            }
        }
        let loop_kind = if handler.is_foreach(kind) {
            LoopKind::ForEach
        } else if handler.is_for(kind) {
            LoopKind::For
        } else if handler.is_loop(kind) {
            LoopKind::Loop
        } else if handler.is_do(kind) {
            LoopKind::DoWhile
        } else {
            LoopKind::While
        };
        if matches!(loop_kind, LoopKind::ForEach | LoopKind::For) {
            out.extend(extract_foreach_binding_assigns(file, &node, src));
        }
        out.extend(extract_rust_let_condition_bindings(file, &node, src));
        out.push(FlowEvent::Loop {
            span: span_of(file, &node),
            loop_kind,
            body,
        });
        return true;
    }

    false
}

fn lower_special_form(node: Node<'_>, context: LoweringContext<'_>, out: &mut Vec<FlowEvent>) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    // Dart-specific: tree-sitter-dart (UserNobody14) models calls as
    // `identifier` followed by a sibling `selector` (which contains
    // `argument_part > arguments > argument*`), rather than a unified
    // call node. We synthesize a Call event when we see a selector
    // whose previous named sibling is an identifier-like callee.
    // Re-run for `dotted` receivers: `receiver.method(args)` parses as
    // `identifier.identifier selector`, so the prev sibling is a `.`
    // followed by the method identifier; we walk back as needed.
    if handler.has_special_form(SyntaxSpecialForm::SplitSelectorCall) && kind == "selector" {
        if let Some(event) = build_dart_selector_call_event(node, file, src) {
            out.push(event);
            // Descend into arguments for nested calls.
            if let Some(arg_part) = first_named_child_of_kind(&node, "argument_part") {
                if let Some(args) = first_named_child_of_kind(&arg_part, "arguments") {
                    let mut cursor = args.walk();
                    for arg in args.named_children(&mut cursor) {
                        walk_into(arg, file, src, handler, class_names, out, false);
                    }
                }
            }
            return true;
        }
    }

    // Dart cascades: `w..configure(cmd)..enable()` (method form) and
    // `b..name = cmd` (field-write form). tree-sitter-dart emits each
    // `..segment` as a `cascade_section` sibling of the base expression —
    // neither a call node nor an assignment node — so without this branch
    // the idiomatic Flutter builder pattern is invisible to sink rules
    // (no Call) and cascade field writes vanish (no Assign).
    if handler.has_special_form(SyntaxSpecialForm::CascadeSection) && kind == "cascade_section" {
        if let Some(events) = build_dart_cascade_events(node, file, src) {
            out.extend(events);
            // Descend into call arguments / the written value for
            // nested calls, mirroring the selector branch above.
            if let Some(arg_part) = first_named_child_of_kind(&node, "argument_part") {
                if let Some(args) = first_named_child_of_kind(&arg_part, "arguments") {
                    let mut cursor = args.walk();
                    for arg in args.named_children(&mut cursor) {
                        walk_into(arg, file, src, handler, class_names, out, false);
                    }
                }
            } else {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() != "cascade_selector" {
                        walk_into(child, file, src, handler, class_names, out, false);
                    }
                }
            }
            return true;
        }
    }

    // Dart explicit constructor invocations: `new T(args)` /
    // `const T(args)`. These node kinds are not call-shaped (no
    // callee/arguments fields the generic builder recognises), so the
    // implicit `T(args)` form worked while the explicit forms emitted
    // nothing. Gated on `!handler.is_call(kind)` so grammars that DO
    // model `new_expression` as a call (JS/TS list it in `call_kinds`)
    // fall through to the generic call branch below — which inlines
    // closure arguments (`new Promise((r) => { sink(x) })`). Dart's
    // `call_kinds` is empty, so only Dart takes this branch.
    if handler.has_special_form(SyntaxSpecialForm::ObjectConstructionExpression)
        && (kind == "new_expression" || kind == "const_object_expression")
        && !handler.is_call(kind)
    {
        if let Some(event) = build_dart_object_expression_call(node, file, src) {
            out.push(event);
            if let Some(args) = first_named_child_of_kind(&node, "arguments") {
                let mut cursor = args.walk();
                for arg in args.named_children(&mut cursor) {
                    walk_into(arg, file, src, handler, class_names, out, false);
                }
            }
            return true;
        }
    }

    // Scala-specific: `foo.!` / `foo.bar_!` (Scala operator-method
    // postfix invocations — used by the `sys.process` "run-as-shell-
    // command" idiom). tree-sitter-scala parses these as
    // `field_expression` with an `operator_identifier` as the second
    // child, NOT as a call. Emit a Call event here so the sink
    // surfaces in the flow.
    if handler.has_special_form(SyntaxSpecialForm::PostfixOperatorCall)
        && kind == "field_expression"
        && is_scala_operator_method_call(&node)
    {
        let receiver_node = node
            .child_by_field_name("value")
            .or_else(|| first_named_child(&node));
        if let Some(receiver_node) = receiver_node {
            // Evaluate the receiver before invoking its postfix method. This
            // preserves nested calls such as `Seq(a, value).!` as ordinary
            // Call/CallArg facts instead of flattening their source text.
            walk_into(receiver_node, file, src, handler, class_names, out, false);
        }
        let name = node_text(&node, src).trim().to_string();
        if !name.is_empty() {
            out.push(FlowEvent::Call {
                span: span_of(file, &node),
                receiver: call_receiver_from_name(&name),
                receiver_types: Vec::new(),
                name,
                call_kind: crate::CallKind::Method,
                args: Vec::new(),
            });
        }
        return true;
    }

    // Swift-specific: `defer { body }` parses as a `call_expression`
    // with callee `defer` and a trailing `lambda_literal`. Convert to
    // a Defer event BEFORE the generic call handler would turn it
    // into a regular Call (which would lose the body's contents).
    if handler.has_special_form(SyntaxSpecialForm::TrailingClosureDefer)
        && kind == "call_expression"
        && is_swift_defer_call(&node, src)
    {
        let mut body = Vec::new();
        for lambda in swift_trailing_lambdas(node) {
            walk_lambda_body(lambda, file, src, handler, class_names, &mut body);
        }
        out.push(FlowEvent::Defer {
            span: span_of(file, &node),
            body,
        });
        return true;
    }

    if kind == "call"
        && ((handler.has_special_form(SyntaxSpecialForm::CallEncodedControlFlow)
            && emit_elixir_control_flow_call(&node, file, src, handler, class_names, out))
            || (handler.has_special_form(SyntaxSpecialForm::FunctionalLoopCall)
                && emit_erlang_functional_loop_call(&node, file, src, handler, class_names, out))
            || (handler.has_special_form(SyntaxSpecialForm::BlockLoopCall)
                && emit_ruby_block_loop_call(&node, file, src, handler, class_names, out)))
    {
        return true;
    }

    false
}
