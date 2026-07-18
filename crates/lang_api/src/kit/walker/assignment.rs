use super::super::{
    argument_place, assignment_declared_type, assignment_is_compound, assignment_target_node,
    assignment_value_node, assignment_wrapper_has_variable_declarator, binary_operator_is_assignment,
    binary_operator_is_pipe, call_arg_from_node, callable_reference_name, expression_flow,
    extra_lhs_binding_targets, extract_dart_selector_call_info, extract_direct_call_info,
    extract_rhs_expr_operands, first_call_descendant, has_direct_large_literal_initializer_child,
    is_large_literal_initializer_node, keyed_lhs_binding_sources, looks_like_bare_identifier,
    looks_like_identifier, node_text, prepend_pipe_arg_to_call, qualified_assign_target,
    ruby_append_mutation_assignment, same_identifier_name, sanitize_assign_target, span_of,
    subscript_place_parts, type_only_declaration_without_initializer, FlowEvent, Node, COMMON_CALL_KINDS,
};
use super::{walk_into, LoweringContext};

pub(super) fn lower_assignment(
    node: Node<'_>,
    context: LoweringContext<'_>,
    out: &mut Vec<FlowEvent>,
) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    if ruby_append_mutation_assignment(&node, file, src, out) {
        return true;
    }

    if handler.is_assignment(kind) {
        if kind == "binary_operator" && !binary_operator_is_assignment(&node, src) {
            // Elixir pipe `lhs |> call(args)` desugars to `call(lhs,
            // args)` — the piped value becomes the callee's FIRST
            // argument. Without threading it in, `conn.params |>
            // System.cmd()` leaves `System.cmd` with no args and the
            // piped taint never reaches the sink (the dominant Elixir
            // dataflow idiom). Walk the RHS call, then prepend the LHS as
            // its arg 0.
            if binary_operator_is_pipe(&node, src) {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    walk_into(left, file, src, handler, class_names, out, false);
                    let before = out.len();
                    walk_into(right, file, src, handler, class_names, out, false);
                    prepend_pipe_arg_to_call(out, before, &right, &left, file, src);
                    return true;
                }
            }
            // G3 follow-up: synthesizing a Call event for every
            // binary_operator broke the C interproc-empty-seed
            // invariant (every `int x = a + b;` produced a synthetic
            // call propagation record). The Path-overload case
            // needs a more targeted approach — gated on the LHS
            // being a known constructor (Path, PurePath, etc.) so
            // we don't synthesize calls for arithmetic. Tracked as
            // task #109 for a follow-up.
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_into(child, file, src, handler, class_names, out, false);
            }
            return true;
        }
        if assignment_wrapper_has_variable_declarator(kind, &node) {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_into(child, file, src, handler, class_names, out, false);
            }
            return true;
        }
        // Target-name extraction. Grammars disagree on field names, and
        // some emit keywords (`val`, `var`, `let`, `const`, `auto`) as
        // visible named children — skip those so the real identifier
        // gets picked. Kotlin `property_declaration` is the canonical
        // offender: its first named child is the `val`/`var` keyword
        // node, which without filtering would become the target text.
        let target_node = assignment_target_node(node, src);
        // If the picked target is itself a declarator wrapper —
        // tree-sitter emits `variable_declarator` in C# /
        // JavaScript / TypeScript / Java, `init_declarator` in C /
        // C++, and similar in Solidity / Swift — descend into its
        // identifier child so the emitted `target` is the variable
        // name rather than the whole `name = rhs` expression. Also
        // the downstream walker will visit the declarator anyway
        // and emit its own clean Assign, so without this unwrap we
        // get two events per variable: one with wrapper text and one
        // with the canonical identifier.
        let raw_target = target_node
            .map(|n| node_text(&n, src).trim().to_string())
            .unwrap_or_default();
        // C# tree-sitter-c-sharp doesn't expose the binding identifier as a
        // *named* node inside `variable_declarator` — `action` in
        // `action = req.Query["action"].ToString()` is anonymous, so every
        // named-child walker picks up the RHS instead and the target
        // becomes `action = req.Query…`. Same pattern surfaces in Solidity
        // (`bytes32 t`), Perl (`my $query`), Lua (full statement), and Go
        // multi-return destructuring (`result, _`). When the picked target
        // text has shape `LHS = RHS`, keep just the LHS; when it has a
        // space, keep the last whitespace-delimited token (types on
        // Solidity / Perl stay off the target). The underlying identifier
        // is still reachable through the structured `target` field on
        // downstream analyses — we just display the clean name.
        let target = sanitize_assign_target(&raw_target);
        // RHS: most grammars expose it via `right` or `value`. Kotlin's
        // property_declaration has no field for the initializer — it's
        // just a sibling of the variable-declaration identifier. We'd
        // rather over-walk than miss calls on the RHS, so as a fallback
        // we pick the LAST named child that isn't the target node.
        let rhs = assignment_value_node(node, target_node);
        let rhs_is_callable_literal = rhs.is_some_and(|rhs_node| handler.is_lambda(rhs_node.kind()));
        let callable_source = rhs
            .filter(|_| !rhs_is_callable_literal)
            .and_then(|rhs_node| callable_reference_name(&rhs_node, src));
        let simple_place_source = rhs
            .filter(|rhs_node| looks_like_identifier(rhs_node.kind()))
            .and_then(|rhs_node| argument_place(&rhs_node, src));
        let mut assignment_value_kind = (callable_source.is_some() || rhs_is_callable_literal)
            .then_some(crate::AssignValueKind::CallableReference);
        let mut source_name = callable_source
            .clone()
            .or_else(|| simple_place_source.clone())
            .or_else(|| {
                rhs.and_then(|rhs_node| {
                    let rhs_text = node_text(&rhs_node, src).trim();
                    // Only emit `source_name` for bare-identifier RHS — compound
                    // expressions go through `source_call` / `source_names`.
                    looks_like_bare_identifier(rhs_text).then(|| rhs_text.to_string())
                })
            });
        // source_call: when the RHS is a direct call expression,
        // capture the callee name + the call's positional
        // argument identifier texts. This is what the interprocedural
        // taint pass uses to propagate return-value taint:
        //   `y = transform(x)` → source_call = Some("transform"),
        //   `y = item.get("k")` → source_call = Some("item.get"),
        //   source_call_args = ["x"]. If transform's summary says
        //   param 0 flows to the return, y inherits x's taint.
        let (mut source_call, mut source_call_args) = if callable_source.is_some() || rhs_is_callable_literal
        {
            (None, Vec::new())
        } else {
            rhs.and_then(|n| extract_direct_call_info(&n, src))
                .or_else(|| rhs.and_then(|n| extract_dart_selector_call_info(n, file, src)))
                .or_else(|| {
                    rhs.is_none()
                        .then(|| {
                            first_call_descendant(node).and_then(|call| extract_direct_call_info(&call, src))
                        })
                        .flatten()
                })
                .or_else(|| extract_dart_selector_call_info(node, file, src))
                .unwrap_or((None, Vec::new()))
        };
        // G2: when the RHS is a compound expression (template literal,
        // string concat, binary op, f-string, interpolation, member /
        // subscript access, ternary, null-coalesce), there is no
        // single call or bare identifier. Extract every bare-identifier
        // operand into `source_names` so the intra / inter passes
        // treat "any operand tainted → target tainted". This makes
        // `y = "prefix" + tainted` / `y = f"{x}"` / `` y = `${x}` `` /
        // `y = obj.field` / `y = cond ? a : b` propagate taint
        // correctly across all grammars without requiring the adapter
        // to evaluate the expression AST itself.
        let mut source_names: Vec<String> = Vec::new();
        let rhs_is_large_literal = rhs
            .as_ref()
            .is_some_and(|n| is_large_literal_initializer_node(n.kind(), n))
            || has_direct_large_literal_initializer_child(&node);
        if callable_source.is_none() && !rhs_is_callable_literal {
            if let Some(n) = rhs.filter(|n| !is_large_literal_initializer_node(n.kind(), n)) {
                source_names.extend(extract_rhs_expr_operands(&n, src));
                // Retain the exact parser-proven qualified place in addition
                // to scalar operands. This preserves language sigils on a
                // projection (`$obj->token` -> `$obj.token`) without an
                // adapter rescanning rendered expression text.
                if let Some(place) = argument_place(&n, src).filter(|place| place.contains('.')) {
                    source_names.push(place);
                }
            }
        }
        // Some grammars expose a declaration initializer as a wrapper
        // whose "rhs" fallback is only the callee/type node, while the
        // actual argument expressions are siblings inside the full
        // assignment/declaration node. Walk the full assignment as a
        // tree-sitter expression fallback and drop the target itself so
        // constructor/object-literal assignments like
        // `env = Envelope(cmd: raw)` preserve the `raw` dependency.
        if rhs.is_none() {
            source_names.extend(extract_rhs_expr_operands(&node, src));
        }
        // H1: `x OP= rhs` desugars to `x = x OP rhs`, so the LHS is always
        // read. Keep it among the sources (don't strip via same_identifier)
        // so a literal / untainted RHS can't reach the clean-overwrite kill
        // arm and drop `x`'s prior taint.
        let is_compound = assignment_is_compound(&node, kind, src);
        // Self-referential assignment: `x = x + a`, `x = x.field`,
        // `x = cond ? x : y`. When the target appears as an operand of a
        // NON-call RHS expression, it is genuinely read into the result
        // (exactly like a compound `x += a`), so it must NOT be stripped as
        // a clean overwrite — dropping it silently loses `x`'s prior taint,
        // a universal false negative. A CALL RHS (`x = sanitize(x)`) still
        // strips: there the target is a consumed argument and the result is
        // the callee's return, so clean-overwrite / call-result semantics
        // apply. `rhs` is `None` only for the full-node structural fallback
        // (where the LHS identifier can also appear among descendants), so a
        // missing RHS also strips.
        let rhs_is_noncall_expr = rhs
            .as_ref()
            .is_some_and(|n| !COMMON_CALL_KINDS.contains(&n.kind()));
        let target_self_read = is_compound || rhs_is_noncall_expr;
        if !target_self_read {
            source_names.retain(|name| !same_identifier_name(name, &target));
        }
        // Only a compound `x += a` unconditionally reads its target, so only
        // it re-adds the target when extraction missed it. A plain
        // `x = a + b` must NOT push `x` — that would fabricate a self-read
        // and keep `x`'s prior taint through a clean overwrite. The genuine
        // non-call self-read (`x = x + a`) already carries `x` in
        // `source_names` (it was never stripped), so it needs no push.
        if is_compound
            && !target.is_empty()
            && !source_names
                .iter()
                .any(|name| same_identifier_name(name, &target))
        {
            source_names.push(target.clone());
        }
        source_names.sort();
        source_names.dedup();
        // Keyed destructuring is a field projection, not a whole-container
        // read. Preserve the parser-declared selector for each binding so
        // `['cmd' => $cmd] = $envelope` lowers to
        // `cmd <- $envelope.cmd`. This keeps exact aggregate writes
        // field-sensitive across a later destructure without recovering keys
        // from rendered assignment text.
        let keyed_binding_sources = rhs
            .and_then(|rhs_node| argument_place(&rhs_node, src))
            .map(|base| keyed_lhs_binding_sources(&node, src, &base))
            .unwrap_or_default();
        // Some grammars emit a declaration-name wrapper as an
        // assignment-shaped node (`val raw` / `local raw`) in addition
        // to the real initializer assignment. A node with no RHS and
        // no surfaced source operands has no value semantics; emitting
        // it would be a fake clean overwrite that erases the real
        // source assignment immediately after it.
        let has_value_semantics =
            (rhs.is_some() || source_name.is_some() || source_call.is_some() || !source_names.is_empty())
                && !rhs_is_large_literal
                && !type_only_declaration_without_initializer(&node);
        if has_value_semantics {
            // Positional aggregate initialization is a distinct compiler
            // operation from scalar assignment. Preserve the initializer's
            // ordered tree-sitter value facts here; the workspace semantic
            // pass later resolves the declared type against its parsed field
            // layout (including layouts declared in another file).
            if let Some(rhs_node) = rhs
                .filter(|rhs_node| node.kind() == "init_declarator" && rhs_node.kind() == "initializer_list")
            {
                let value_flow = expression_flow::positional_expression_flow_from_node(rhs_node, file, src);
                if !value_flow.tuple_items.is_empty() && !target.is_empty() {
                    out.push(FlowEvent::AggregateAssign {
                        span: span_of(file, &node),
                        target: target.clone(),
                        type_name: assignment_declared_type(&node, src),
                        value_flow,
                    });
                }
            }
            // G3 + G4: when the LHS is a member / subscript expression
            // (`self.cmd = x`, `env['cmd'] = x`), also emit an Assign for
            // the FULL qualified form so reads of `self.cmd` / `env.cmd`
            // elsewhere in the function can see the write. The bare
            // `cmd` Assign below stays because many reads still come
            // through as the bare identifier (`cmd = self.cmd; use(cmd)`).
            // Both entries carry the same source_name / source_call so
            // the taint transfer sees the same RHS dependency on both
            // keys.
            let qualified_target = qualified_assign_target(target_node, src);
            if let Some(qname) = qualified_target.as_ref() {
                if qname != &target {
                    out.push(FlowEvent::Assign {
                        span: span_of(file, &node),
                        target: qname.clone(),
                        source_name: source_name.clone(),
                        source_call: source_call.clone(),
                        source_call_args: source_call_args.clone(),
                        source_names: source_names.clone(),
                        declares_new_binding: false,
                        value_kind: assignment_value_kind,
                    });
                }
            }
            // Parallel/destructured bindings are grammar-proven independently
            // of qualified-place recovery. Lua's `local ok, value = pcall(...)`
            // exposes a `variable_list`; its head is also a valid simple
            // qualified target, but that must not suppress the remaining
            // result slots. Member/subscript places cannot enter this loop
            // because `extra_lhs_binding_targets` accepts only aggregate CST
            // pattern kinds.
            for extra_target in extra_lhs_binding_targets(&node, src, &target) {
                let keyed_source = keyed_binding_sources.iter().find_map(|(binding, source)| {
                    same_identifier_name(binding, &extra_target).then_some(source)
                });
                out.push(FlowEvent::Assign {
                    span: span_of(file, &node),
                    target: extra_target,
                    source_name: keyed_source.cloned().or_else(|| source_name.clone()),
                    source_call: keyed_source.is_none().then(|| source_call.clone()).flatten(),
                    source_call_args: keyed_source.map_or_else(|| source_call_args.clone(), |_| Vec::new()),
                    source_names: keyed_source
                        .map(|source| vec![source.clone()])
                        .unwrap_or_else(|| source_names.clone()),
                    declares_new_binding: false,
                    value_kind: keyed_source
                        .map(|_| crate::AssignValueKind::Destructure)
                        .or(assignment_value_kind),
                });
            }
            // Subscript-assign `obj[key] = value` is semantically
            // `obj.__setitem__(key, value)`. Emit a synthetic Call so
            // `kind: call` rules can match the item-set with the RHS value
            // as a tainted arg (e.g. Django `response[name] = tainted`
            // header injection). Gated to a simple `<ident>[...]` LHS so it
            // never fires on member/nested-subscript shapes. Harmless for
            // languages with no `__setitem__` rule — nothing matches it.
            if let (Some(target_node), Some(value_node)) = (target_node, rhs) {
                if let Some((base_node, key_node)) = subscript_place_parts(target_node) {
                    let base = node_text(&base_node, src).trim();
                    if looks_like_bare_identifier(base) {
                        let key_arg = call_arg_from_node(key_node, file, src, None);
                        let value_arg = call_arg_from_node(value_node, file, src, None);
                        if let (Some(key_arg), Some(value_arg)) = (key_arg, value_arg) {
                            let span = span_of(file, &node);
                            out.push(FlowEvent::Call {
                                span,
                                receiver: Some(base.to_string()),
                                receiver_types: Vec::new(),
                                name: format!("{base}.__setitem__"),
                                call_kind: crate::CallKind::Method,
                                args: vec![key_arg, value_arg],
                            });
                        }
                    }
                }
            }
            // A pattern LHS whose head sanitizes to empty (extractor /
            // constructor pattern like Scala `val Envelope(kind, cmd)`,
            // where `Envelope(kind` is not a real lvalue) must not emit a
            // blank-target Assign — the real bindings are already emitted
            // as extras above.
            if !target.is_empty() {
                if let Some(keyed_source) = keyed_binding_sources
                    .iter()
                    .find_map(|(binding, source)| same_identifier_name(binding, &target).then_some(source))
                {
                    source_name = Some(keyed_source.clone());
                    source_call = None;
                    source_call_args.clear();
                    source_names = vec![keyed_source.clone()];
                    assignment_value_kind = Some(crate::AssignValueKind::Destructure);
                }
                out.push(FlowEvent::Assign {
                    span: span_of(file, &node),
                    target,
                    source_name,
                    source_call,
                    source_call_args,
                    source_names,
                    declares_new_binding: false,
                    value_kind: assignment_value_kind,
                });
            }
        }
        // Walk every named child so nested calls inside the LHS or RHS
        // surface, regardless of whether the grammar exposes
        // `right`/`value` fields. C# `variable_declaration` wraps the
        // initializer in a `variable_declarator`; Kotlin's
        // `property_declaration` has no field for the initializer at
        // all; JS's `variable_declarator` nests the initializer under
        // a `value` that we DO have but also has nothing else to skip.
        // Over-walking a rhs is fine — call events surface once.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, out, false);
        }
        return true;
    }

    false
}
