//! Elixir / Erlang / Ruby control-flow lowering into flow events.
//!
//! These grammars express `if`/`case`/`cond`/`try` and block-passing loops
//! (`Enum.each`, Erlang list-comprehension generators, Ruby `each do |x|`)
//! as ordinary macro / method calls with `do ... end` blocks rather than
//! dedicated statement nodes. This module lowers those call shapes into the
//! kit's `FlowEvent` taxonomy (`Branch`/`Loop`/`Try` + synthetic binding
//! `Assign`s) so the shared walker and taint engine treat them like native
//! control flow without per-adapter handling.

use bonsai_common::FileId;
use tree_sitter::Node;

use crate::{FlowEvent, LoopKind};

#[allow(clippy::wildcard_imports)]
use super::*;

/// Unwrap Elixir's `def foo(x, y) do ... end` macro-call into its
/// signature pieces: the real function name node, the signature-call
/// node (whose `arguments` holds the params), and the body
/// expression — either a `do_block` child of the outer call (long
/// form) OR the `value` of a `do:` keyword pair in the outer call's
/// arguments (short form `def foo, do: expr`). Returns `None` when
/// `node` is an ordinary call (e.g. `IO.puts("hi")`).
pub(super) struct ElixirDef<'tree> {
    pub(super) name: Node<'tree>,
    pub(super) signature_call: Node<'tree>,
    /// Body expression for `def foo, do: expr` short form. `None` for
    /// the long form (`do ... end`) — the kit's body fallback finds
    /// the `do_block` child of the outer call directly.
    pub(super) short_form_body: Option<Node<'tree>>,
}

pub(super) fn elixir_unwrap_def<'tree>(node: &Node<'tree>, src: &[u8]) -> Option<ElixirDef<'tree>> {
    // The outer call's target is an identifier like `def` or `defp`.
    let target = node.child_by_field_name("target")?;
    let target_text = node_text(&target, src).trim();
    if !matches!(
        target_text,
        "def" | "defp" | "defmacro" | "defmacrop" | "defguard" | "defguardp"
    ) {
        return None;
    }
    // The outer call's arguments container is a child node of kind
    // `arguments` (tree-sitter-elixir uses the kind name, not a field
    // name). Its first named child is the signature call.
    let outer_args = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "arguments"))?;
    let mut cursor = outer_args.walk();
    let sig_call = outer_args
        .named_children(&mut cursor)
        .find(|c| c.kind() == "call" || c.kind() == "identifier")?;
    let name_node = if sig_call.kind() == "identifier" {
        // Zero-arg def: `def foo do ... end` parses with the signature
        // as a bare identifier rather than a call. The identifier IS
        // the name.
        sig_call
    } else {
        sig_call.child_by_field_name("target")?
    };
    // Detect short-form body: outer_args contains a `keywords` child
    // whose first `pair` has a `do:` key. The pair's `value` field is
    // the body expression.
    let short_form_body = first_named_child_of_kind(&outer_args, "keywords")
        .and_then(|kws| first_named_child_of_kind(&kws, "pair"))
        .and_then(|pair| {
            let key = pair.child_by_field_name("key")?;
            let key_text = node_text(&key, src).trim().trim_end_matches(':');
            if key_text == "do" {
                pair.child_by_field_name("value")
            } else {
                None
            }
        });
    Some(ElixirDef {
        name: name_node,
        signature_call: sig_call,
        short_form_body,
    })
}

/// True when an Elixir `binary_operator` node's operator token equals `op`.
fn elixir_binary_operator_is(node: &Node<'_>, src: &[u8], op: &str) -> bool {
    if let Some(operator) = node.child_by_field_name("operator") {
        return node_text(&operator, src).trim() == op;
    }
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    children
        .iter()
        .any(|child| !child.is_named() && node_text(child, src).trim() == op)
}

/// Elixir `for x <- enum` (H20) and `with pat <- expr` (M14) generator
/// clauses bind a new variable to the enumerable / matched expression.
/// Each clause is a `binary_operator` arg whose operator is `<-`.
/// Synthesize an Assign per binding target so taint flows into the
/// comprehension body / with-chain. Filters and the do-block are ignored.
fn extract_elixir_generator_binding_assigns(
    file: FileId,
    node: &Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    let Some(args) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "arguments"))
    else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    let arg_nodes: Vec<Node<'_>> = args.named_children(&mut cursor).collect();
    let mut out = Vec::new();
    for arg in arg_nodes {
        if arg.kind() != "binary_operator" || !elixir_binary_operator_is(&arg, src, "<-") {
            continue;
        }
        let (Some(pattern), Some(rhs)) = (arg.child_by_field_name("left"), arg.child_by_field_name("right"))
        else {
            continue;
        };
        for target in binding_targets_from_pattern_node(&pattern, src) {
            if let Some(assign) = pattern_binding_assign(file, &pattern, &target, rhs, src, handler) {
                out.push(assign);
            }
        }
    }
    dedup_assign_events(out)
}

pub(super) fn emit_elixir_control_flow_call(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) -> bool {
    let Some(name) = elixir_call_name(node, src) else {
        return false;
    };
    match name.as_str() {
        "if" | "unless" | "case" | "cond" | "with" => {
            let mut then_events = Vec::new();
            let mut else_events = Vec::new();
            if let Some(condition) = elixir_condition_arg(node) {
                walk_into(condition, file, src, handler, class_names, out, false);
            }
            if let Some(value) = elixir_keyword_value(node, src, "do") {
                walk_into(value, file, src, handler, class_names, &mut then_events, false);
            }
            if let Some(value) = elixir_keyword_value(node, src, "else") {
                walk_into(value, file, src, handler, class_names, &mut else_events, false);
            }
            if let Some(do_block) = first_named_child_of_kind(node, "do_block") {
                walk_elixir_do_block_as_branch(
                    do_block,
                    file,
                    src,
                    handler,
                    class_names,
                    &mut then_events,
                    &mut else_events,
                );
            }
            if name == "case" {
                let match_bindings = extract_elixir_case_stab_clause_bindings(file, node, src, handler);
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
            }
            if name == "with" {
                let with_bindings = extract_elixir_generator_binding_assigns(file, node, src, handler);
                if !with_bindings.is_empty() {
                    let mut prefixed = with_bindings.clone();
                    prefixed.extend(then_events);
                    then_events = prefixed;
                    if !else_events.is_empty() {
                        let mut prefixed_else = with_bindings;
                        prefixed_else.extend(else_events);
                        else_events = prefixed_else;
                    }
                }
            }
            let condition = elixir_condition_arg(node)
                .map(|condition| node_text(&condition, src).trim().to_string())
                .filter(|condition| !condition.is_empty());
            out.push(FlowEvent::Branch {
                span: span_of(file, node),
                condition,
                then_events,
                else_events,
            });
            true
        }
        "try" => {
            let mut body = Vec::new();
            let mut catch_events = Vec::new();
            let mut finally_events = Vec::new();
            if let Some(do_block) = first_named_child_of_kind(node, "do_block") {
                let mut events = ElixirTryEventBuckets {
                    body: &mut body,
                    catch_events: &mut catch_events,
                    finally_events: &mut finally_events,
                };
                walk_elixir_do_block_as_try(do_block, file, src, handler, class_names, &mut events);
            }
            let (catch_param, catch_types) = elixir_rescue_binding(node, src);
            out.push(FlowEvent::Try {
                span: span_of(file, node),
                body,
                catch_events,
                finally_events,
                catch_param: catch_param.or_else(|| extract_catch_param(node, src)),
                catch_types,
            });
            true
        }
        "for" => emit_elixir_loop_call(node, file, src, handler, class_names, out),
        _ if matches!(
            name.as_str(),
            "Enum.each" | "Enum.map" | "Enum.flat_map" | "Enum.reduce" | "Stream.each" | "Stream.map"
        ) =>
        {
            emit_elixir_loop_call(node, file, src, handler, class_names, out)
        }
        _ => false,
    }
}

fn emit_elixir_loop_call(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) -> bool {
    let mut body = Vec::new();
    // H20: a plain `for x <- enum, do: ...` comprehension binds `x` to the
    // enumerable; the closure-param path below only covers Enum.each/map
    // closures, so synthesize the generator bindings up front.
    body.extend(extract_elixir_generator_binding_assigns(file, node, src, handler));
    let sources = non_closure_arg_source_names(node, src, &["arguments"], handler);
    if let Some(args) = first_named_child_of_kind(node, "arguments") {
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            if arg.kind() == "anonymous_function" || is_closure_arg(arg.kind(), handler) {
                emit_inline_closure_param_bindings(arg, file, src, &sources, &mut body);
                walk_lambda_body(arg, file, src, handler, class_names, &mut body);
            }
        }
    }
    if let Some(do_block) = first_named_child_of_kind(node, "do_block") {
        walk_elixir_do_block_as_branch(
            do_block,
            file,
            src,
            handler,
            class_names,
            &mut body,
            &mut Vec::new(),
        );
    }
    if body.is_empty() {
        return false;
    }
    if let Some(event) = build_call_event(*node, file, src, handler, class_names) {
        out.push(event);
    }
    out.push(FlowEvent::Loop {
        span: span_of(file, node),
        loop_kind: LoopKind::ForEach,
        body,
    });
    true
}

pub(super) fn emit_erlang_functional_loop_call(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) -> bool {
    let Some(call_event) = build_call_event(*node, file, src, handler, class_names) else {
        return false;
    };
    let FlowEvent::Call { name, .. } = &call_event else {
        return false;
    };
    if !matches!(
        name.as_str(),
        "lists:foreach" | "lists:map" | "lists:filter" | "lists:foldl" | "lists:foldr"
    ) {
        return false;
    }
    let Some(args) = node
        .child_by_field_name("args")
        .or_else(|| erlang_remote_args_node(node))
    else {
        return false;
    };
    let sources = non_closure_arg_source_names_from_container(args, src, handler);
    let mut body = Vec::new();
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if arg.kind() == "anonymous_fun" || handler.is_lambda(arg.kind()) {
            emit_inline_closure_param_bindings(arg, file, src, &sources, &mut body);
            walk_lambda_body(arg, file, src, handler, class_names, &mut body);
        }
    }
    if body.is_empty() {
        return false;
    }
    out.push(call_event);
    out.push(FlowEvent::Loop {
        span: span_of(file, node),
        loop_kind: LoopKind::ForEach,
        body,
    });
    true
}

pub(super) fn emit_ruby_block_loop_call(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) -> bool {
    let Some(call_event) = build_call_event(*node, file, src, handler, class_names) else {
        return false;
    };
    let FlowEvent::Call { name, .. } = &call_event else {
        return false;
    };
    if !matches!(
        short_name_of(name),
        "each" | "each_with_index" | "map" | "flat_map" | "collect" | "select" | "filter" | "reject"
    ) {
        return false;
    }
    let block =
        first_named_child_of_kind(node, "do_block").or_else(|| first_named_child_of_kind(node, "block"));
    let Some(block) = block else {
        return false;
    };

    let sources = call_event_value_source_names(&call_event);
    let mut body = Vec::new();
    emit_inline_closure_param_bindings(block, file, src, &sources, &mut body);
    walk_lambda_body(block, file, src, handler, class_names, &mut body);
    if body.is_empty() {
        return false;
    }

    out.push(call_event);
    out.push(FlowEvent::Loop {
        span: span_of(file, node),
        loop_kind: LoopKind::ForEach,
        body,
    });
    true
}

/// Extract the rescue/catch binding from an Elixir `try` call:
/// `rescue e -> ...` binds `e`; `rescue e in RuntimeError -> ...`
/// binds `e` and names `RuntimeError` as the caught type; Erlang-style
/// `catch :exit, reason -> ...` binds `reason` (the atom is the kind
/// tag, not a binding). The rescue arms live inside the `do_block`,
/// so the generic [`extract_catch_param`] walk over the call node's
/// direct children cannot see them.
fn elixir_rescue_binding(node: &Node<'_>, src: &[u8]) -> (Option<String>, Vec<String>) {
    let Some(do_block) = first_named_child_of_kind(node, "do_block") else {
        return (None, Vec::new());
    };
    let mut cursor = do_block.walk();
    for child in do_block.named_children(&mut cursor) {
        if !matches!(child.kind(), "rescue_block" | "catch_block") {
            continue;
        }
        let Some(stab) = first_named_child_of_kind(&child, "stab_clause") else {
            continue;
        };
        // Clause head = every named child before the `->` body.
        let mut head_cursor = stab.walk();
        let Some(head) = stab.named_children(&mut head_cursor).find(|n| n.kind() != "body") else {
            continue;
        };
        let param = first_identifier_descendant(head).map(|id| node_text(&id, src).trim().to_string());
        let mut types = Vec::new();
        collect_elixir_alias_texts(&head, src, &mut types);
        if param.is_some() || !types.is_empty() {
            return (param, types);
        }
    }
    (None, Vec::new())
}

/// Collect `alias` node texts (module names such as `RuntimeError`)
/// under an Elixir rescue clause head.
fn collect_elixir_alias_texts(node: &Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if node.kind() == "alias" {
        let text = node_text(node, src).trim().to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push(text);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_elixir_alias_texts(&child, src, out);
    }
}

pub(super) fn elixir_call_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "call" {
        return None;
    }
    let target = node.child_by_field_name("target")?;
    let name = normalize_call_name_whitespace(node_text(&target, src));
    (!name.is_empty()).then_some(name)
}

fn elixir_condition_arg<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    let args = first_named_child_of_kind(node, "arguments")?;
    let mut cursor = args.walk();
    let condition = args
        .named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "keywords" | "pair"));
    condition
}

fn elixir_keyword_value<'tree>(node: &Node<'tree>, src: &[u8], key: &str) -> Option<Node<'tree>> {
    fn visit<'tree>(node: Node<'tree>, src: &[u8], key: &str) -> Option<Node<'tree>> {
        if node.kind() == "pair" {
            let pair_key = node.child_by_field_name("key")?;
            let pair_key = node_text(&pair_key, src)
                .trim()
                .trim_end_matches(':')
                .trim()
                .to_string();
            if pair_key == key {
                return node.child_by_field_name("value");
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(found) = visit(child, src, key) {
                return Some(found);
            }
        }
        None
    }
    visit(*node, src, key)
}

fn walk_elixir_do_block_as_branch(
    do_block: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    then_events: &mut Vec<FlowEvent>,
    else_events: &mut Vec<FlowEvent>,
) {
    let mut cursor = do_block.walk();
    for child in do_block.named_children(&mut cursor) {
        match child.kind() {
            "else_block" => walk_named_children(child, file, src, handler, class_names, else_events),
            "rescue_block" | "catch_block" | "after_block" => {}
            _ => walk_into(child, file, src, handler, class_names, then_events, false),
        }
    }
}

struct ElixirTryEventBuckets<'a> {
    body: &'a mut Vec<FlowEvent>,
    catch_events: &'a mut Vec<FlowEvent>,
    finally_events: &'a mut Vec<FlowEvent>,
}

fn walk_elixir_do_block_as_try(
    do_block: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    events: &mut ElixirTryEventBuckets<'_>,
) {
    let mut cursor = do_block.walk();
    for child in do_block.named_children(&mut cursor) {
        match child.kind() {
            "rescue_block" | "catch_block" => {
                walk_named_children(child, file, src, handler, class_names, events.catch_events);
            }
            "after_block" => {
                walk_named_children(child, file, src, handler, class_names, events.finally_events);
            }
            _ => walk_into(child, file, src, handler, class_names, events.body, false),
        }
    }
}
