use super::super::{
    build_call_event, call_argument_containers, call_event_value_source_names,
    emit_inline_closure_param_bindings_from_yield_call,
    emit_inline_closure_param_bindings_with_extra_sources, emit_invoked_lambda_param_bindings,
    first_callee_expression_child, first_named_child_of_kind, immediately_invoked_lambda_callee,
    inline_closure_param_extra_sources, is_closure_arg, is_comprehension_kind, last_named_child,
    ruby_call_block_uses_yield_result, walk_call_argument_expressions, walk_lambda_body,
    walk_method_chain_receivers, FlowEvent, Node, SyntaxSpecialForm,
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
                emit_invoked_lambda_param_bindings(lambda, file, src, event, out);
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
            && node.child_by_field_name("receiver").is_some()
            && node.child_by_field_name("method").is_some()
        {
            let mut cur = node.walk();
            if cur.goto_first_child() {
                loop {
                    let child = cur.node();
                    if child.is_named() && !matches!(cur.field_name(), Some("receiver" | "method")) {
                        walk_into(child, file, src, handler, class_names, out, false);
                    }
                    if !cur.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        let arg_containers = call_argument_containers(node);
        let mut walked_closures = std::collections::HashSet::new();
        for container in arg_containers {
            // `any(f(t) for t in xs)` / `list(g(t) for t in xs)`: python
            // exposes the bare generator_expression DIRECTLY as the call's
            // `arguments` field (no `argument_list` wrapper). Iterating its
            // children would walk the body call and `for_in_clause`
            // separately — losing the loop-variable binding so the sink's
            // arg stays untainted. Walk the comprehension AS a whole so the
            // COMPREHENSION_KINDS branch binds the iterator and emits the body.
            if is_comprehension_kind(container.kind()) {
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
                } else if matches!(
                    arg.kind(),
                    "argument" | "keyword_argument" | "named_argument" | "value_argument"
                ) {
                    arg.child_by_field_name("value")
                        .or_else(|| arg.child_by_field_name("expression"))
                        .or_else(|| last_named_child(&arg))
                        .filter(|inner| is_closure_arg(inner.kind(), handler))
                } else {
                    None
                };
                if let Some(closure) = closure_node {
                    walked_closures.insert(arg.id());
                    walked_closures.insert(closure.id());
                    let extra_sources = inline_closure_param_extra_sources(call_event.as_ref(), closure, src);
                    emit_inline_closure_param_bindings_with_extra_sources(
                        closure,
                        file,
                        src,
                        &closure_source_names,
                        &extra_sources,
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
        // container). Scan the call's direct children for such closures
        // and inline their bodies too.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "do_block" && handler.has_special_form(SyntaxSpecialForm::DirectDoBlockBody) {
                continue;
            }
            if is_closure_arg(child.kind(), handler) {
                if !walked_closures.insert(child.id()) {
                    continue;
                }
                if ruby_call_block_uses_yield_result(&node, &child, src) {
                    emit_inline_closure_param_bindings_from_yield_call(
                        child,
                        file,
                        src,
                        call_event.as_ref(),
                        out,
                    );
                } else {
                    let extra_sources = inline_closure_param_extra_sources(call_event.as_ref(), child, src);
                    emit_inline_closure_param_bindings_with_extra_sources(
                        child,
                        file,
                        src,
                        &closure_source_names,
                        &extra_sources,
                        out,
                    );
                }
                walk_lambda_body(child, file, src, handler, class_names, out);
            }
        }
        // Elixir-specific: control-flow constructs (`case`, `cond`,
        // `if`, `with`, `try`, `receive`, `for`) are all parsed as
        // `call` nodes whose body lives in a `do_block` direct child.
        // Without this descent, calls inside those bodies wouldn't
        // surface in the enclosing function's flow events.
        if handler.has_special_form(SyntaxSpecialForm::DirectDoBlockBody) {
            if let Some(do_block) = first_named_child_of_kind(&node, "do_block") {
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
        let receiver_node = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("callee"))
            .or_else(|| node.child_by_field_name("receiver"))
            .or_else(|| node.child_by_field_name("object"))
            // Kotlin and Swift place the navigation expression as the first
            // named child without assigning a field name. This helper skips
            // argument/type lists and returns that compiler AST callee.
            .or_else(|| first_callee_expression_child(&node));
        if let Some(recv) = receiver_node {
            walk_method_chain_receivers(recv, file, src, handler, class_names, out);
        }
        return true;
    }

    false
}
