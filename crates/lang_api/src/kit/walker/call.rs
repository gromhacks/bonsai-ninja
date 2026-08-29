use super::super::{
    argument_value_node, build_call_event, call_argument_containers, call_receiver_node,
    emit_invoked_lambda_param_bindings, immediately_invoked_lambda_callee, is_closure_arg,
    is_comprehension_kind, walk_call_argument_expressions, walk_lambda_body, walk_method_chain_receivers,
    FlowEvent, Node, SyntaxSpecialForm,
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
        // Evaluate a method receiver/callee before its arguments, matching the
        // source-language evaluator. Nested calls in a fluent receiver chain
        // therefore precede both argument calls and this outer Call event.
        let receiver_node = call_receiver_node(&node, src, handler).or_else(|| {
            handler
                .call_callee_field_names
                .iter()
                .find_map(|field| node.child_by_field_name(field))
        });
        if let Some(recv) = receiver_node {
            walk_method_chain_receivers(recv, file, src, handler, class_names, out);
        }

        // Descend into evaluated argument expressions, but never execute a
        // callable merely because it is passed as a value. Direct callback
        // expressions are lowered as their own declarations; execution is
        // established later by a workspace callee invoking its formal or by
        // an exact rule-declared external callback boundary.
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
                    let _ = closure;
                } else {
                    walk_into(arg, file, src, handler, class_names, out, false);
                }
            }
        }
        // Receiver and argument expressions have now been evaluated. Emit the
        // invocation itself; callback bodies remain separate callable scopes.
        if let Some(event) = call_event.clone() {
            out.push(event);
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
        return true;
    }

    false
}
