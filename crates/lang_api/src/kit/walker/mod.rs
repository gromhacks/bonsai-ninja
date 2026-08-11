use super::{
    extract_comprehension_for_clause_assigns, extract_foreach_binding_assigns, extract_match_binding_assigns,
    extract_rhs_expr_operands, first_identifier_like_child, is_comprehension_binding_clause,
    is_comprehension_kind, looks_like_bare_identifier, next_named_sibling_within, node_text,
    pseudo_call_event, span_of, walk_lambda_body, FileId, FlowEvent, GrammarHandler, LoopKind, Node,
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
    // Adapter-owned syntax events are executable compiler facts. Evaluate
    // them before large-literal/declaration pruning: a grammar may represent
    // a real call as declaration syntax (C++ direct initialization is the
    // canonical case), and the structural skip must not erase that language
    // semantic. The shared walker still owns recursion and downstream IR.
    if let Some(event) = handler
        .syntax_event_extractor
        .and_then(|extract| extract(node, file, src, handler))
    {
        out.push(event);
    }
    if let Some(extract) = handler.syntax_events_extractor {
        out.extend(extract(node, file, src, handler));
    }

    // Skip over nested function/class definitions — their flow belongs to
    // their own decls. But do walk into their *declarators* to catch inline
    // default-arg expressions (rare; best-effort).
    //
    let is_skippable_nested_fn = !is_root
        && handler.is_fn(kind)
        && handler
            .function_definition_extractor
            .is_none_or(|extract| extract(node, src).is_some());
    if is_skippable_nested_fn || (!is_root && (handler.is_class(kind) || handler.is_lambda(kind))) {
        return;
    }

    if let Some(event) = pseudo_call_event(node, file, src, handler) {
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
        let then_node = handler
            .branch_then_field_names
            .iter()
            .find_map(|field| node.child_by_field_name(field))
            .or_else(|| {
                let mut cursor = node.walk();
                let selected = node
                    .named_children(&mut cursor)
                    .find(|child| handler.branch_arm_kinds.contains(&child.kind()));
                selected
            });
        let else_node = handler
            .branch_else_field_names
            .iter()
            .find_map(|field| node.child_by_field_name(field))
            // Some grammars expose both arms with the same `body` field.
            // `child_by_field_name("body")` returns the first arm only, so
            // recover the second body-like sibling when no explicit
            // alternative field exists.
            .or_else(|| then_node.and_then(|then| next_named_sibling_within(&node, then, handler)));
        let mut then_events = Vec::new();
        if let Some(n) = then_node {
            walk_into(n, file, src, handler, class_names, &mut then_events, false);
        }
        let mut else_events = Vec::new();
        if let Some(n) = else_node {
            walk_into(n, file, src, handler, class_names, &mut else_events, false);
        }
        // A branch may have more than two direct AST arms: switch/match/case
        // constructs and grammars with repeated alternative fields are the
        // common examples. Walk every remaining adapter-declared arm into
        // the joined alternative set. This is exact CST ownership, not a
        // source-text repair, and prevents third/later cases from vanishing.
        let then_id = then_node.map(|n| n.id());
        let else_id = else_node.map(|n| n.id());
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if Some(child.id()) == then_id || Some(child.id()) == else_id {
                continue;
            }
            if handler.additional_alternative_kinds.contains(&child.kind())
                || handler.branch_arm_kinds.contains(&child.kind())
            {
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
            let discriminant_ids = handler
                .branch_condition_field_names
                .iter()
                .filter_map(|field| node.child_by_field_name(field).map(|child| child.id()))
                .chain({
                    let mut cursor = node.walk();
                    node.named_children(&mut cursor)
                        .filter(|child| handler.branch_condition_kinds.contains(&child.kind()))
                        .map(|child| child.id())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if discriminant_ids.contains(&child.id()) {
                    continue;
                }
                walk_into(child, file, src, handler, class_names, &mut then_events, false);
            }
        }
        // Go type switch `switch t := v.(type) { ... }` binds `t` to the
        // switched value `v` inside every arm. tree-sitter-go exposes the
        // bound name as an `alias` field and the value as a `value` field,
        // with no assignment node — so without this the arms' `t` never
        // links to `v` and the switched value's taint is lost. Prepend the
        // `t <- v` binding to both arms.
        let mut type_switch_binding: Vec<FlowEvent> = Vec::new();
        if let Some((alias, value)) = handler.branch_alias_extractor.and_then(|extract| extract(node)) {
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
                    source_names: extract_rhs_expr_operands(&value, src, handler),
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
        let match_bindings = extract_match_binding_assigns(file, &node, src, handler);
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
        for field in handler.branch_condition_field_names {
            if let Some(cond) = node.child_by_field_name(field) {
                condition.get_or_insert_with(|| node_text(&cond, src).trim().to_string());
                walk_into(cond, file, src, handler, class_names, out, false);
            }
        }
        let field_condition_ids = handler
            .branch_condition_field_names
            .iter()
            .filter_map(|field| node.child_by_field_name(field).map(|child| child.id()))
            .collect::<Vec<_>>();
        let mut cursor = node.walk();
        for cond in node.named_children(&mut cursor) {
            if handler.branch_condition_kinds.contains(&cond.kind())
                && !field_condition_ids.contains(&cond.id())
            {
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
    if is_comprehension_kind(kind, handler) {
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
                if is_comprehension_binding_clause(child.kind(), handler) {
                    clauses.push(child);
                } else {
                    stack.push(child);
                }
            }
        }
        clauses.sort_by_key(|clause| clause.start_byte());
        for clause in &clauses {
            out.extend(extract_comprehension_for_clause_assigns(
                file, clause, src, handler,
            ));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !is_comprehension_binding_clause(child.kind(), handler) {
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
        || handler.is_do(kind)
        || handler.is_loop(kind)
    {
        let body_node = handler
            .loop_body_field_names
            .iter()
            .find_map(|field| node.child_by_field_name(field))
            .or_else(|| {
                let mut cursor = node.walk();
                let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                children
                    .into_iter()
                    .rev()
                    .find(|child| handler.loop_body_kinds.contains(&child.kind()))
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
        let has_foreach_binding = handler
            .foreach_binding_extractor
            .is_some_and(|extract| extract(node).is_some());
        let loop_kind = if handler.is_foreach(kind) || has_foreach_binding {
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
        if loop_kind == LoopKind::ForEach {
            out.extend(extract_foreach_binding_assigns(file, &node, src, handler));
        }
        out.extend(extract_match_binding_assigns(file, &node, src, handler));
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
    let deferred_bodies = handler
        .deferred_body_extractor
        .map_or_else(Vec::new, |extract| extract(node, src));
    if !deferred_bodies.is_empty() {
        let mut body = Vec::new();
        for lambda in deferred_bodies {
            walk_lambda_body(lambda, file, src, handler, class_names, &mut body);
        }
        out.push(FlowEvent::Defer {
            span: span_of(file, &node),
            body,
        });
        return true;
    }

    if handler.is_call(kind) {
        if let Some(events) = handler
            .call_encoded_control_flow_extractor
            .and_then(|extract| extract(node, file, src, handler, class_names))
        {
            out.extend(events);
            return true;
        }
    }

    false
}
