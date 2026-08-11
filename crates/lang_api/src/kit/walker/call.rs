use super::super::{
    argument_value_node, build_call_event, call_argument_containers, call_event_value_source_names,
    call_receiver_node, emit_inline_closure_param_bindings,
    emit_inline_closure_param_bindings_from_yield_call, emit_invoked_lambda_param_bindings,
    immediately_invoked_lambda_callee, is_closure_arg, is_comprehension_kind, walk_call_argument_expressions,
    walk_lambda_body, walk_method_chain_receivers, FlowEvent, Node, SyntaxSpecialForm,
};
use super::{walk_into, LoweringContext};

pub(super) fn lower_call(node: Node<'_>, context: LoweringContext<'_>, out: &mut Vec<FlowEvent>) -> bool {
    let LoweringContext {
        file,
        src,
        handler,
        class_names,
    } = context;
    let kind = node.kind();
    if handler.is_call(kind) {
        let call_event = build_call_event(node, file, src, handler, class_names);
        if let Some(lambda) = immediately_invoked_lambda_callee(&node, handler) {
            walk_call_argument_expressions(node, file, src, handler, class_names, out);
            if let Some(event) = call_event.as_ref() {
                emit_invoked_lambda_param_bindings(lambda, file, src, handler, event, out);
            }
            walk_lambda_body(lambda, file, src, handler, class_names, out);
            return true;
        }
        if let Some(event) = call_event.clone() {
            out.push(event);
        }
        let closure_source_names = call_event
            .as_ref()
            .map(call_event_value_source_names)
            .unwrap_or_default();
        // Also descend into nested calls inside arguments. For lambda
        // arguments (`xs.forEach { x -> body }`, `xs.map(x => body)`,
        // `[...].forEach(x => body)`), inline the closure body into
        // the OUTER flow — higher-order-function calls execute the
        // closure as part of the caller's behavior, so their calls
        // are flow-relevant and shouldn't be lost to the usual
        // is_lambda short-circuit.
        // Objective-C message sends carry their arguments as direct
        // children interleaved with `method:` keyword selectors, not in an
        // `arguments` container — so `call_argument_containers` finds none
        // and a call nested in an arg position (`[self run:[self wrap:s]]`,
        // `[self sink:strlen(s)]`) never surfaced its inner call. Walk each
        // non-receiver, non-method child so nested message/function calls
        // emit their own Call events.
        if handler.has_special_form(SyntaxSpecialForm::DirectCallArguments)
            && call_argument_containers(node, handler).is_empty()
        {
            let mut cur = node.walk();
            if cur.goto_first_child() {
                loop {
                    let child = cur.node();
                    if child.is_named()
                        && !cur.field_name().is_some_and(|field| {
                            handler.direct_call_argument_excluded_fields.contains(&field)
                        })
                    {
                        walk_into(child, file, src, handler, class_names, out, false);
                    }
                    if !cur.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        let arg_containers = call_argument_containers(node, handler);
        let mut walked_closures = std::collections::HashSet::new();
        for container in arg_containers {
            // `any(f(t) for t in xs)` / `list(g(t) for t in xs)`: python
            // exposes the bare generator_expression DIRECTLY as the call's
            // `arguments` field (no `argument_list` wrapper). Iterating its
            // children would walk the body call and `for_in_clause`
            // separately — losing the loop-variable binding so the sink's
            // arg stays untainted. Walk the comprehension AS a whole so the
            // COMPREHENSION_KINDS branch binds the iterator and emits the body.
            if is_comprehension_kind(container.kind(), handler) {
                walk_into(container, file, src, handler, class_names, out, false);
                continue;
            }
            // Some grammars expose a single call DIRECTLY as the
            // `arguments` field with no argument-list wrapper — Perl
            // `sink(source())` parses as `function_call_expression`
            // whose `arguments` field IS the `source()` call. Iterating
            // its children would walk `source` as a bare identifier and
            // drop the nested Call (so a source rule on `source()` never
            // matches). Walk the container whole so build_call_event
            // fires on the nested call and its own args recurse.
            if handler.is_call(container.kind()) {
                walk_into(container, file, src, handler, class_names, out, false);
                continue;
            }
            let mut cursor = container.walk();
            for arg in container.named_children(&mut cursor) {
                // Several grammars wrap each argument in a dedicated
                // node (C# `argument`, Kotlin `value_argument`, Python
                // `keyword_argument`, C# `named_argument`). A closure
                // hidden inside such a wrapper would otherwise recurse
                // into `walk_into`, hit the lambda short-circuit, and
                // vanish — while the standalone-decl pass ALSO skips it
                // (it sees a call ancestor and assumes it was inlined
                // here). Unwrap one level so wrapped closures inline
                // exactly like direct positional ones. `pair` /
                // object-literal values stay decl-owned on purpose —
                // unwrapping those would create double ownership with
                // the standalone-decl pass.
                let closure_node = if is_closure_arg(arg.kind(), handler) {
                    Some(arg)
                } else if handler.argument_wrapper_kinds.contains(&arg.kind()) {
                    let value = argument_value_node(arg, src, handler);
                    is_closure_arg(value.kind(), handler).then_some(value)
                } else {
                    None
                };
                if let Some(closure) = closure_node {
                    walked_closures.insert(arg.id());
                    walked_closures.insert(closure.id());
                    emit_inline_closure_param_bindings(
                        closure,
                        file,
                        src,
                        handler,
                        &closure_source_names,
                        out,
                    );
                    // Inline the lambda body so its calls belong to
                    // the enclosing function. Walks via a helper that
                    // bypasses the is_lambda short-circuit.
                    walk_lambda_body(closure, file, src, handler, class_names, out);
                } else {
                    walk_into(arg, file, src, handler, class_names, out, false);
                }
            }
        }
        // Some grammars attach the trailing-closure block as a direct
        // sibling of the call (Ruby `xs.each { |x| ... }` — the `block`
        // is a top-level child of the call, not inside any arguments
        // container). Kotlin and Swift place the closure one level under an
        // adapter-declared call suffix. Scan only those exact direct/wrapper
        // roles and inline their bodies too.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            let closures = if is_closure_arg(child.kind(), handler) {
                vec![child]
            } else if handler.call_argument_wrapper_kinds.contains(&child.kind()) {
                let mut wrapper_cursor = child.walk();
                child
                    .named_children(&mut wrapper_cursor)
                    .filter(|nested| is_closure_arg(nested.kind(), handler))
                    .collect()
            } else {
                Vec::new()
            };
            for closure in closures {
                if handler.has_special_form(SyntaxSpecialForm::DirectDoBlockBody)
                    && handler.lambda_body_kinds.contains(&closure.kind())
                {
                    continue;
                }
                if !walked_closures.insert(closure.id()) {
                    continue;
                }
                if handler
                    .inline_closure_yield_extractor
                    .is_some_and(|extract| extract(node, closure, src))
                {
                    emit_inline_closure_param_bindings_from_yield_call(
                        closure,
                        file,
                        src,
                        handler,
                        call_event.as_ref(),
                        out,
                    );
                } else {
                    emit_inline_closure_param_bindings(
                        closure,
                        file,
                        src,
                        handler,
                        &closure_source_names,
                        out,
                    );
                }
                walk_lambda_body(closure, file, src, handler, class_names, out);
            }
        }
        // Elixir-specific: control-flow constructs (`case`, `cond`,
        // `if`, `with`, `try`, `receive`, `for`) are all parsed as
        // `call` nodes whose body lives in a `do_block` direct child.
        // Without this descent, calls inside those bodies wouldn't
        // surface in the enclosing function's flow events.
        if handler.has_special_form(SyntaxSpecialForm::DirectDoBlockBody) {
            let do_block = {
                let mut cursor = node.walk();
                let body = node
                    .named_children(&mut cursor)
                    .find(|child| handler.lambda_body_kinds.contains(&child.kind()));
                body
            };
            if let Some(do_block) = do_block {
                let mut do_cursor = do_block.walk();
                for child in do_block.named_children(&mut do_cursor) {
                    walk_into(child, file, src, handler, class_names, out, false);
                }
            }
        }
        // Method-chain receivers. Rust / Swift / Kotlin / JS / TS
        // parse `a.b().c().d()` as a nested call_expression chain
        // where each step's `function` field wraps the previous step
        // as its receiver. Without descending into the function /
        // callee field, only the outermost call emits an event and
        // the inner calls' structured args are lost. Walk through
        // field-access wrappers (`field_expression`,
        // `member_expression`, navigation_expression, etc.) to
        // reach any nested call_expression and emit a proper event
        // per inner call.
        let receiver_node = call_receiver_node(&node, src, handler).or_else(|| {
            handler
                .call_callee_field_names
                .iter()
                .find_map(|field| node.child_by_field_name(field))
        });
        if let Some(recv) = receiver_node {
            walk_method_chain_receivers(recv, file, src, handler, class_names, out);
        }
        return true;
    }

    false
}
