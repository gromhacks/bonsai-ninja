use super::{
    append_tail_expression_return, extract_comprehension_for_clause_assigns, extract_foreach_binding_assigns,
    extract_match_binding_assigns, extract_rhs_expr_operands, first_identifier_like_child,
    is_comprehension_binding_clause, is_comprehension_kind, looks_like_bare_identifier,
    next_named_sibling_within, node_text, pseudo_call_event, span_of, walk_lambda_body, FileId, FlowEvent,
    GrammarHandler, LoopKind, Node,
};

mod assignment;
mod call;
mod control;

use super::branch_conditions::branch_condition_nodes;
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
        let exclusive_arms = collect_exclusive_branch_arms(node, handler);
        let has_exclusive_arms = exclusive_arms.len() >= 2;
        // Projected match bindings belong to one exact case arm. Compute the
        // complete adapter-owned binding relation once, then place each write
        // only in the arm whose CST span contains its capture node. Prefixing
        // every match binding to every arm aliases sibling captures and can
        // make a later arm's write replace the value used by an earlier arm.
        // The partition is purely structural: adapters identify the capture
        // nodes and Tree-sitter supplies the arm ownership spans.
        let exclusive_match_bindings = if has_exclusive_arms {
            extract_match_binding_assigns(file, &node, src, handler)
        } else {
            Vec::new()
        };
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
        let condition_nodes = branch_condition_nodes(node, handler);
        let (mut then_events, mut else_events) = if has_exclusive_arms {
            let mut lowered = Vec::with_capacity(exclusive_arms.len());
            for arm in exclusive_arms {
                let arm_span = span_of(file, &arm);
                let mut events = Vec::new();
                walk_into(arm, file, src, handler, class_names, &mut events, false);
                let mut arm_bindings = exclusive_match_bindings
                    .iter()
                    .filter(|binding| {
                        matches!(binding, FlowEvent::Assign { span, .. }
                            if span.file == arm_span.file
                                && arm_span.start <= span.start
                                && span.end <= arm_span.end)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                arm_bindings.extend(events);
                events = arm_bindings;
                if handler.tail_expression_returns {
                    let body = handler
                        .branch_then_field_names
                        .iter()
                        .find_map(|field| arm.child_by_field_name(field))
                        .or_else(|| arm.child_by_field_name("body"))
                        .or_else(|| {
                            let mut cursor = arm.walk();
                            let body = arm.named_children(&mut cursor).find(|child| {
                                handler.loop_body_kinds.contains(&child.kind())
                                    || handler.branch_arm_kinds.contains(&child.kind())
                            });
                            body
                        })
                        .unwrap_or(arm);
                    append_tail_expression_return(&mut events, &body, file, src, handler);
                }
                lowered.push((
                    arm_span,
                    events,
                    handler.fallthrough_branch_arm_kinds.contains(&arm.kind()),
                ));
            }
            lower_exclusive_arm_chain(lowered)
        } else {
            let mut then_events = Vec::new();
            if let Some(n) = then_node {
                walk_into(n, file, src, handler, class_names, &mut then_events, false);
            }
            let mut else_events = Vec::new();
            if let Some(n) = else_node {
                walk_into(n, file, src, handler, class_names, &mut else_events, false);
            }
            (then_events, else_events)
        };
        let mut handled_alternative_ids = Vec::new();
        if !has_exclusive_arms {
            let mut alternatives = Vec::new();
            for field in handler.branch_else_field_names {
                let mut cursor = node.walk();
                alternatives.extend(node.children_by_field_name(field, &mut cursor));
            }
            alternatives.sort_by_key(|alternative| (alternative.start_byte(), alternative.end_byte()));
            alternatives.dedup_by_key(|alternative| alternative.id());
            handled_alternative_ids.extend(alternatives.iter().map(Node::id));
            for alternative in alternatives.into_iter().skip(1) {
                let mut alternative_events = Vec::new();
                walk_into(
                    alternative,
                    file,
                    src,
                    handler,
                    class_names,
                    &mut alternative_events,
                    false,
                );
                append_branch_alternative(&mut else_events, alternative_events, span_of(file, &alternative));
            }
        }
        // A branch may have more than two direct AST arms: switch/match/case
        // constructs and grammars with repeated alternative fields are the
        // common examples. Walk every remaining adapter-declared arm into
        // the joined alternative set. This is exact CST ownership, not a
        // source-text repair, and prevents third/later cases from vanishing.
        if !has_exclusive_arms {
            let then_id = then_node.map(|n| n.id());
            let else_id = else_node.map(|n| n.id());
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if Some(child.id()) == then_id || Some(child.id()) == else_id {
                    continue;
                }
                if handled_alternative_ids.contains(&child.id()) {
                    continue;
                }
                if handler.additional_alternative_kinds.contains(&child.kind())
                    || handler.branch_arm_kinds.contains(&child.kind())
                {
                    walk_into(child, file, src, handler, class_names, &mut else_events, false);
                }
            }
        }
        // Switch/match/when don't expose consequence/alternative fields: if
        // neither path produced any events, walk all named children so the
        // calls inside case arms still surface in the flow. Skip the
        // discriminant/condition field child — it is walked separately into
        // the OUTER flow below; walking it here too double-emits its calls
        // (`if (check(x)) {}` with empty arms emitted two `check` events).
        if !has_exclusive_arms && then_events.is_empty() && else_events.is_empty() {
            let discriminant_ids = condition_nodes.iter().map(Node::id).collect::<Vec<_>>();
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
        let match_bindings = if has_exclusive_arms {
            Vec::new()
        } else {
            extract_match_binding_assigns(file, &node, src, handler)
        };
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
        let condition = condition_nodes
            .first()
            .zip(condition_nodes.last())
            .map(|(first, last)| {
                std::str::from_utf8(&src[first.start_byte()..last.end_byte()])
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            });
        for condition_node in condition_nodes {
            walk_into(condition_node, file, src, handler, class_names, out, false);
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

fn append_branch_alternative(
    events: &mut Vec<FlowEvent>,
    alternative: Vec<FlowEvent>,
    span: bonsai_common::Span,
) {
    if let [FlowEvent::Branch { else_events, .. }] = events.as_mut_slice() {
        if else_events.is_empty() {
            *else_events = alternative;
        } else {
            append_branch_alternative(else_events, alternative, span);
        }
        return;
    }
    let prior = std::mem::take(events);
    events.push(FlowEvent::Branch {
        span,
        condition: None,
        then_events: prior,
        else_events: alternative,
    });
}

/// Collect the outermost adapter-declared arm nodes beneath one branch.
/// Stopping descent at a match prevents nested switches inside an arm from
/// being mistaken for siblings of the outer switch.
fn collect_exclusive_branch_arms<'tree>(branch: Node<'tree>, handler: &GrammarHandler) -> Vec<Node<'tree>> {
    if handler.exclusive_branch_arm_kinds.is_empty() {
        return Vec::new();
    }
    let mut arms = Vec::new();
    let mut stack = Vec::new();
    let mut cursor = branch.walk();
    stack.extend(branch.named_children(&mut cursor));
    while let Some(node) = stack.pop() {
        if handler.exclusive_branch_arm_kinds.contains(&node.kind()) {
            arms.push(node);
            continue;
        }
        // A nested branch owns its own arms.
        if handler.is_if(node.kind()) {
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    arms.sort_by_key(|arm| (arm.start_byte(), arm.end_byte()));
    arms.dedup_by_key(|arm| arm.id());
    arms
}

fn lower_exclusive_arm_chain(
    mut arms: Vec<(bonsai_common::Span, Vec<FlowEvent>, bool)>,
) -> (Vec<FlowEvent>, Vec<FlowEvent>) {
    for index in (0..arms.len().saturating_sub(1)).rev() {
        if arms[index].2 && flow_events_may_complete_normally(&arms[index].1) {
            let suffix = arms[index + 1].1.clone();
            append_to_normal_paths(&mut arms[index].1, &suffix);
        }
    }
    let (_, first_events, _) = arms.remove(0);
    let else_events = nest_exclusive_arm_alternatives(arms);
    (first_events, else_events)
}

fn nest_exclusive_arm_alternatives(
    mut arms: Vec<(bonsai_common::Span, Vec<FlowEvent>, bool)>,
) -> Vec<FlowEvent> {
    if arms.is_empty() {
        return Vec::new();
    }
    let (span, events, _) = arms.remove(0);
    if arms.is_empty() {
        return events;
    }
    vec![FlowEvent::Branch {
        span,
        condition: None,
        then_events: events,
        else_events: nest_exclusive_arm_alternatives(arms),
    }]
}

fn flow_events_may_complete_normally(events: &[FlowEvent]) -> bool {
    let Some(last) = events.last() else {
        return true;
    };
    match last {
        FlowEvent::Break { .. } | FlowEvent::Return { .. } | FlowEvent::Throw { .. } => false,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => flow_events_may_complete_normally(then_events) || flow_events_may_complete_normally(else_events),
        _ => true,
    }
}

fn append_to_normal_paths(events: &mut Vec<FlowEvent>, suffix: &[FlowEvent]) {
    if let Some(FlowEvent::Branch {
        then_events,
        else_events,
        ..
    }) = events.last_mut()
    {
        append_to_normal_paths(then_events, suffix);
        append_to_normal_paths(else_events, suffix);
    } else if flow_events_may_complete_normally(events) {
        events.extend_from_slice(suffix);
    }
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
            let header_node = {
                let mut cursor = node.walk();
                let found = node
                    .named_children(&mut cursor)
                    .find(|child| handler.loop_header_container_kinds.contains(&child.kind()));
                found
            };
            let phase_owner = header_node.unwrap_or(node);
            let mut update_nodes = Vec::new();
            for field in handler.loop_update_field_names {
                let mut cursor = phase_owner.walk();
                update_nodes.extend(phase_owner.children_by_field_name(field, &mut cursor));
            }
            update_nodes.sort_by_key(|update| (update.start_byte(), update.end_byte()));
            update_nodes.dedup_by_key(|update| update.id());

            // A C-style update clause executes only after the first body
            // iteration. Keep it inside the Loop body, after the parsed body,
            // rather than walking source-order header children into the
            // enclosing scope before the Loop event.
            for update in &update_nodes {
                walk_into(*update, file, src, handler, class_names, &mut body, false);
            }

            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.id() == body_id {
                    continue;
                }
                if header_node.is_some_and(|header| header.id() == child.id()) {
                    let mut header_cursor = child.walk();
                    for part in child.named_children(&mut header_cursor) {
                        if !update_nodes.iter().any(|update| update.id() == part.id()) {
                            walk_into(part, file, src, handler, class_names, out, false);
                        }
                    }
                } else if !update_nodes.iter().any(|update| update.id() == child.id()) {
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
