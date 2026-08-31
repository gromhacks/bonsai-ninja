//! Elixir language adapter.
//!
//! Elixir's `def` and `defp` are macros, not keywords — tree-sitter-elixir
//! parses them as `call` nodes whose target is the identifier `def` or
//! `defp`. We use `call` as the function-kind and filter by the target
//! identifier in the grammar handler. Constructs with `do ... end`
//! blocks (function bodies, branches, loops) all share the `do_block`
//! grammar kind.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        binding_targets_from_pattern_node, call_arg_from_node_with_handler, collect_kinds,
        dedup_assign_events, extract_catch_param, first_identifier_descendant, first_named_child,
        first_named_child_of_kind, language_from_pack, node_at_span, node_text, parse_with,
        pattern_binding_assign, populate_call_argument_static_values, span_of, walk_flow_node_into,
    },
    AdapterContext, AdapterError, AssignmentNodeSemantics, AssignmentValueFact, CallTargetExtraction,
    CompilerGuardFact, DeclIndex, ExpressionFlow, ExpressionPlaceExtraction, FunctionDefinitionExtraction,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    LoopKind, ModulePath, Ref, RefKind, StaticScalarValue, StaticStringMapEntry, StaticStringMapFact,
    StringCompositionFact, StringCompositionPart, SyntaxSpecialForm, Visibility, EMPTY_HANDLER,
};
use bonsai_lang_api::{AssignValueKind, FlowEvent};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("elixir");
const PACK_NAME: &str = "elixir";

fn direct_token(node: Node<'_>, src: &[u8], expected: &str) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() && node_text(&child, src).trim() == expected {
            return true;
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}

fn elixir_call_arguments(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let arguments = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "arguments");
    arguments
}

/// Elixir remote calls expose their complete `Module.function` expression as
/// a `dot` node in the call's `target` field. Preserve atoms (for example
/// `:gen_server.stop`) and aliases verbatim; rule data, not the adapter,
/// assigns any library meaning to the resulting syntax fact.
fn elixir_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if node.kind() != "call" {
        return None;
    }
    let target = node.child_by_field_name("target")?;
    if !matches!(
        target.kind(),
        "identifier" | "alias" | "atom" | "quoted_atom" | "dot"
    ) {
        return None;
    }
    let full_text = node_text(&target, src)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let semantic_name_node = if target.kind() == "dot" {
        target.child_by_field_name("right").unwrap_or(target)
    } else {
        target
    };
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: semantic_name_node,
        full_text,
    })
}

fn elixir_static_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    match node.kind() {
        // `%{name: value}` uses an identifier-shaped key as atom shorthand,
        // while `map[name]` evaluates `name` dynamically. The parent grammar
        // node proves which syntax owns this occurrence.
        "identifier" if node.parent().is_some_and(|parent| parent.kind() != "access_call") => {
            (!raw.is_empty()).then(|| raw.to_string())
        }
        "atom" | "keyword" => {
            let value = if node.kind() == "atom" {
                raw.strip_prefix(':')?
            } else {
                raw.strip_suffix(':')?
            };
            (!value.is_empty()
                && value
                    .chars()
                    .all(|ch| ch == '_' || ch == '@' || ch == '!' || ch == '?' || ch.is_alphanumeric()))
            .then(|| value.to_string())
        }
        "quoted_atom" => {
            let quoted = raw.strip_prefix(':')?;
            let quote = quoted.as_bytes().first().copied()?;
            if !matches!(quote, b'\'' | b'"') || quoted.as_bytes().last().copied() != Some(quote) {
                return None;
            }
            let value = quoted.get(1..quoted.len().checked_sub(1)?)?;
            (!value.is_empty() && !value.contains(['\\', '#'])).then(|| value.to_string())
        }
        _ => None,
    }
}

/// Return the direct key/value pairs owned by one Elixir aggregate.
///
/// `tree-sitter-elixir` wraps `%{key: value}` pairs in `map_content` and a
/// `keywords` node, while the same `keywords` node is itself the aggregate
/// for a standalone keyword-list argument.  The generic aggregate walker
/// deliberately stops at nested aggregates, so the adapter must identify
/// these grammar-only wrappers explicitly.  Traversal never enters a pair's
/// value, which keeps a nested map as the value of its parent field rather
/// than flattening its children into the parent aggregate.
fn elixir_aggregate_pairs(node: Node<'_>) -> Vec<(Node<'_>, Node<'_>)> {
    if !matches!(node.kind(), "map" | "map_content" | "keywords") {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    let mut pending = vec![node];
    while let Some(container) = pending.pop() {
        let mut cursor = container.walk();
        for child in container.named_children(&mut cursor) {
            if child.kind() == "pair" {
                if let (Some(key), Some(value)) = (
                    child.child_by_field_name("key"),
                    child.child_by_field_name("value"),
                ) {
                    pairs.push((key, value));
                }
            } else if matches!(child.kind(), "map_content" | "keywords") {
                pending.push(child);
            }
        }
    }
    pairs.sort_by_key(|(key, value)| (key.start_byte(), value.start_byte()));
    pairs
}

fn elixir_expression_places(node: Node<'_>, src: &[u8]) -> ExpressionPlaceExtraction {
    if node.kind() == "unary_operator" && direct_token(node, src, "@") {
        let Some(operand) = node
            .child_by_field_name("operand")
            .or_else(|| node.named_child(0))
            .filter(|operand| operand.kind() == "identifier")
        else {
            return ExpressionPlaceExtraction::default();
        };
        let place = node_text(&operand, src).trim();
        return if place.is_empty() {
            ExpressionPlaceExtraction::default()
        } else {
            ExpressionPlaceExtraction {
                places: vec![place.to_string()],
                consumed_node_ids: vec![node.id()],
            }
        };
    }
    if node.kind() != "call" || elixir_call_arguments(node).is_some() {
        return ExpressionPlaceExtraction::default();
    }
    let Some(target) = node.child_by_field_name("target") else {
        return ExpressionPlaceExtraction::default();
    };
    fn collect(node: Node<'_>, src: &[u8], parts: &mut Vec<String>) -> bool {
        if node.kind() == "dot" {
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            let Some(left) = node
                .child_by_field_name("left")
                .or_else(|| children.first().copied())
            else {
                return false;
            };
            let Some(right) = node
                .child_by_field_name("right")
                .or_else(|| children.last().copied())
            else {
                return false;
            };
            return collect(left, src, parts) && collect(right, src, parts);
        }
        if !matches!(node.kind(), "identifier" | "alias" | "atom") {
            return false;
        }
        let part = node_text(&node, src).trim();
        if part.is_empty() {
            return false;
        }
        parts.push(part.trim_start_matches(':').to_string());
        true
    }
    let mut parts = Vec::new();
    if !collect(target, src, &mut parts) || parts.len() < 2 {
        return ExpressionPlaceExtraction::default();
    }
    ExpressionPlaceExtraction {
        places: vec![parts.join(".")],
        consumed_node_ids: vec![node.id()],
    }
}

fn extract_elixir_callable_reference(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "unary_operator" || !direct_token(node, src, "&") {
        return None;
    }
    let operand = node
        .child_by_field_name("operand")
        .or_else(|| node.named_child(0))?;
    if operand.kind() != "binary_operator" || !direct_token(operand, src, "/") {
        return None;
    }
    let function = operand
        .child_by_field_name("left")
        .or_else(|| operand.named_child(0))?;
    let arity = operand.child_by_field_name("right").or_else(|| {
        u32::try_from(operand.named_child_count().saturating_sub(1))
            .ok()
            .and_then(|index| operand.named_child(index))
    })?;
    if arity.kind() != "integer" {
        return None;
    }
    let function = node_text(&function, src).trim();
    (!function.is_empty()).then(|| function.to_string())
}

fn extract_elixir_function_definition<'tree>(
    node: Node<'tree>,
    src: &[u8],
) -> Option<FunctionDefinitionExtraction<'tree>> {
    if node.kind() != "call" {
        return None;
    }
    let target = node.child_by_field_name("target")?;
    if !matches!(
        node_text(&target, src).trim(),
        "def" | "defp" | "defmacro" | "defmacrop" | "defguard" | "defguardp"
    ) {
        return None;
    }
    let outer_args = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(&node, "arguments"))?;
    let mut cursor = outer_args.walk();
    let first_arg = outer_args.named_children(&mut cursor).next()?;
    // A guarded definition is parsed as `def (head when guard)`, so the
    // function head is the left operand of the first argument rather than a
    // direct child of the outer `def` arguments.  Unwrap only the parsed
    // `when` operator; other binary expressions remain ordinary macro input
    // and must not become declarations.
    let signature = if first_arg.kind() == "binary_operator" && elixir_binary_operator_is(&first_arg, "when")
    {
        first_arg.child_by_field_name("left")?
    } else {
        first_arg
    };
    if !matches!(signature.kind(), "call" | "identifier") {
        return None;
    }
    let name = if signature.kind() == "identifier" {
        signature
    } else {
        signature.child_by_field_name("target")?
    };
    let short_form_body = first_named_child_of_kind(&outer_args, "keywords")
        .and_then(|keywords| first_named_child_of_kind(&keywords, "pair"))
        .and_then(|pair| {
            let key = pair.child_by_field_name("key")?;
            (node_text(&key, src).trim().trim_end_matches(':') == "do")
                .then(|| pair.child_by_field_name("value"))
                .flatten()
        });
    let body = short_form_body.or_else(|| first_named_child_of_kind(&node, "do_block"));
    Some(FunctionDefinitionExtraction {
        name,
        parameter_source: signature,
        body,
    })
}

fn elixir_generator_bindings(
    file: FileId,
    node: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    let Some(arguments) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(&node, "arguments"))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        if argument.kind() != "binary_operator" || !elixir_binary_operator_is(&argument, "<-") {
            continue;
        }
        let (Some(pattern), Some(value)) = (
            argument.child_by_field_name("left"),
            argument.child_by_field_name("right"),
        ) else {
            continue;
        };
        for target in binding_targets_from_pattern_node(&pattern, src, handler) {
            if let Some(assign) = pattern_binding_assign(file, &pattern, &target, value, src, handler) {
                out.push(assign);
            }
        }
    }
    dedup_assign_events(out)
}

fn elixir_call_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "call" {
        return None;
    }
    let target = node.child_by_field_name("target")?;
    let name = node_text(&target, src).split_whitespace().collect::<String>();
    (!name.is_empty()).then_some(name)
}

fn elixir_condition_arg(node: Node<'_>) -> Option<Node<'_>> {
    let arguments = first_named_child_of_kind(&node, "arguments")?;
    let mut cursor = arguments.walk();
    let condition = arguments
        .named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "keywords" | "pair"));
    condition
}

fn elixir_keyword_value<'tree>(node: Node<'tree>, src: &[u8], expected: &str) -> Option<Node<'tree>> {
    fn visit<'tree>(node: Node<'tree>, src: &[u8], expected: &str) -> Option<Node<'tree>> {
        if node.kind() == "pair" {
            let key = node.child_by_field_name("key")?;
            if node_text(&key, src).trim().trim_end_matches(':').trim() == expected {
                return node.child_by_field_name("value");
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(value) = visit(child, src, expected) {
                return Some(value);
            }
        }
        None
    }
    visit(node, src, expected)
}

fn elixir_case_bindings(
    file: FileId,
    node: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    let Some(subject) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(&node, "arguments"))
        .and_then(|arguments| first_named_child(&arguments).or(Some(arguments)))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "stab_clause" {
            if let Some(pattern) = current.child_by_field_name("left") {
                for target in binding_targets_from_pattern_node(&pattern, src, handler) {
                    if target == "_" || target.chars().next().is_some_and(char::is_uppercase) {
                        continue;
                    }
                    if let Some(assign) =
                        pattern_binding_assign(file, &pattern, &target, subject, src, handler)
                    {
                        out.push(assign);
                    }
                }
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    dedup_assign_events(out)
}

fn walk_elixir_children(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_flow_node_into(child, file, src, handler, class_names, out);
    }
}

fn walk_elixir_branch_block(
    block: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    then_events: &mut Vec<FlowEvent>,
    else_events: &mut Vec<FlowEvent>,
) {
    let mut cursor = block.walk();
    for child in block.named_children(&mut cursor) {
        match child.kind() {
            "else_block" => walk_elixir_children(child, file, src, handler, class_names, else_events),
            "rescue_block" | "catch_block" | "after_block" => {}
            _ => walk_flow_node_into(child, file, src, handler, class_names, then_events),
        }
    }
}

fn elixir_rescue_binding(node: Node<'_>, src: &[u8]) -> (Option<String>, Vec<String>) {
    let Some(block) = first_named_child_of_kind(&node, "do_block") else {
        return (None, Vec::new());
    };
    let mut cursor = block.walk();
    for child in block.named_children(&mut cursor) {
        if !matches!(child.kind(), "rescue_block" | "catch_block") {
            continue;
        }
        let Some(clause) = first_named_child_of_kind(&child, "stab_clause") else {
            continue;
        };
        let (parameter, types) = elixir_catch_clause_binding(clause, src);
        if parameter.is_some() || !types.is_empty() {
            return (parameter, types);
        }
    }
    (None, Vec::new())
}

fn elixir_catch_clause_binding(clause: Node<'_>, src: &[u8]) -> (Option<String>, Vec<String>) {
    let mut clause_cursor = clause.walk();
    let Some(head) = clause
        .named_children(&mut clause_cursor)
        .find(|candidate| candidate.kind() != "body")
    else {
        return (None, Vec::new());
    };
    let parameter = first_identifier_descendant(head)
        .map(|identifier| node_text(&identifier, src).trim().to_string())
        .filter(|parameter| !parameter.is_empty() && parameter != "_");
    let mut types = Vec::new();
    collect_elixir_aliases(head, src, &mut types);
    (parameter, types)
}

fn collect_elixir_aliases(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if node.kind() == "alias" {
        let value = node_text(&node, src).trim().to_string();
        if !value.is_empty() && !out.contains(&value) {
            out.push(value);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_elixir_aliases(child, src, out);
    }
}

fn extract_elixir_control_flow(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
) -> Option<Vec<FlowEvent>> {
    let name = elixir_call_name(node, src)?;
    match name.as_str() {
        "if" | "unless" | "case" | "cond" | "with" => {
            let mut prefix = Vec::new();
            let mut then_events = Vec::new();
            let mut else_events = Vec::new();
            if let Some(condition) = elixir_condition_arg(node) {
                walk_flow_node_into(condition, file, src, handler, class_names, &mut prefix);
            }
            if let Some(value) = elixir_keyword_value(node, src, "do") {
                walk_flow_node_into(value, file, src, handler, class_names, &mut then_events);
            }
            if let Some(value) = elixir_keyword_value(node, src, "else") {
                walk_flow_node_into(value, file, src, handler, class_names, &mut else_events);
            }
            if let Some(block) = first_named_child_of_kind(&node, "do_block") {
                walk_elixir_branch_block(
                    block,
                    file,
                    src,
                    handler,
                    class_names,
                    &mut then_events,
                    &mut else_events,
                );
            }
            let bindings = if name == "case" {
                elixir_case_bindings(file, node, src, handler)
            } else if name == "with" {
                elixir_generator_bindings(file, node, src, handler)
            } else {
                Vec::new()
            };
            if !bindings.is_empty() {
                let mut prefixed_then = bindings.clone();
                prefixed_then.extend(then_events);
                then_events = prefixed_then;
                if !else_events.is_empty() {
                    let mut prefixed_else = bindings;
                    prefixed_else.extend(else_events);
                    else_events = prefixed_else;
                }
            }
            let condition = elixir_condition_arg(node)
                .map(|condition| node_text(&condition, src).trim().to_string())
                .filter(|condition| !condition.is_empty());
            prefix.push(FlowEvent::Branch {
                span: span_of(file, &node),
                condition,
                then_events,
                else_events,
            });
            Some(prefix)
        }
        "try" => {
            let mut body = Vec::new();
            let mut catch_events = Vec::new();
            let mut finally_events = Vec::new();
            if let Some(block) = first_named_child_of_kind(&node, "do_block") {
                let mut cursor = block.walk();
                for child in block.named_children(&mut cursor) {
                    match child.kind() {
                        "rescue_block" | "catch_block" => {
                            walk_elixir_children(child, file, src, handler, class_names, &mut catch_events);
                        }
                        "after_block" => {
                            walk_elixir_children(child, file, src, handler, class_names, &mut finally_events);
                        }
                        _ => walk_flow_node_into(child, file, src, handler, class_names, &mut body),
                    }
                }
            }
            let catch_arms = elixir_catch_arm_facts(node, file, src);
            let catch_arm_spans = catch_arms.iter().map(|arm| arm.span).collect::<Vec<_>>();
            bonsai_lang_api::kit::split_flat_alternative_events(&mut catch_events, &catch_arm_spans);
            let (catch_param, catch_types) = elixir_rescue_binding(node, src);
            Some(vec![FlowEvent::Try {
                span: span_of(file, &node),
                body,
                catch_events,
                finally_events,
                catch_param: catch_param.or_else(|| extract_catch_param(&node, src)),
                catch_types,
                catch_arms,
            }])
        }
        "for" => {
            let mut body = elixir_generator_bindings(file, node, src, handler);
            if let Some(value) = elixir_keyword_value(node, src, "do") {
                walk_flow_node_into(value, file, src, handler, class_names, &mut body);
            }
            if let Some(block) = first_named_child_of_kind(&node, "do_block") {
                walk_elixir_branch_block(block, file, src, handler, class_names, &mut body, &mut Vec::new());
            }
            Some(vec![FlowEvent::Loop {
                span: span_of(file, &node),
                loop_kind: LoopKind::ForEach,
                label: None,
                condition_events: Vec::new(),
                update_events: Vec::new(),
                body,
            }])
        }
        _ => None,
    }
}

fn elixir_catch_arm_facts(node: Node<'_>, file: FileId, src: &[u8]) -> Vec<bonsai_lang_api::CatchArmFact> {
    let Some(block) = first_named_child_of_kind(&node, "do_block") else {
        return Vec::new();
    };
    let mut facts = Vec::new();
    let mut cursor = block.walk();
    for branch in block
        .named_children(&mut cursor)
        .filter(|child| matches!(child.kind(), "rescue_block" | "catch_block"))
    {
        let mut branch_cursor = branch.walk();
        for clause in branch
            .named_children(&mut branch_cursor)
            .filter(|child| child.kind() == "stab_clause")
        {
            let (parameter, types) = elixir_catch_clause_binding(clause, src);
            facts.push(bonsai_lang_api::CatchArmFact {
                span: span_of(file, &clause),
                parameter,
                types,
            });
        }
    }
    facts.sort_by_key(|fact| (fact.span.start, fact.span.end));
    facts
}
// Elixir has no direct `function_definition` grammar node. Function
// definitions come through as `call` nodes with target `def` / `defp`.
// Accepting `call` as the fn-kind means the adapter treats every call
// as a potential function body; the walker then finds the actual name
// from the child identifier. This over-captures (macro calls that aren't
// definitions also match), but that's the cost of Elixir's macro-based
// syntax — precision upgrades would require a hand-rolled handler
// filtering by target.
const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &[
        "nil",
        "boolean",
        "char",
        "float",
        "integer",
        "atom",
        "quoted_atom",
        "true",
        "false",
    ],
    string_literal_kinds: &["string", "charlist"],
    comment_kinds: &["comment"],
    parameter_container_kinds: &["arguments"],
    parameter_kinds: &["identifier"],
    binding_identifier_kinds: &["identifier"],
    identifier_kinds: &["identifier"],
    aggregate_pattern_kinds: &["tuple", "list"],
    named_aggregate_kinds: &["map", "keywords"],
    positional_aggregate_kinds: &["tuple", "list"],
    aggregate_pair_kinds: &["pair"],
    aggregate_pair_extractor: Some(elixir_aggregate_pairs),
    aggregate_key_field_names: &["key"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["atom", "identifier"],
    static_subscript_key_extractor: Some(elixir_static_key),
    expression_place_extractor: Some(elixir_expression_places),
    transparent_call_wrapper_kinds: &["dot"],
    branch_condition_is_first_named_child: false,
    branch_arm_kinds: &["do_block", "else_block"],
    condition_group_kinds: &[],
    condition_all_operators: &["and"],
    condition_any_operators: &["or"],
    condition_not_operators: &["not"],
    condition_not_operator_kinds: &[],
    exclusive_branch_arm_kinds: &["stab_clause"],
    fallthrough_branch_arm_kinds: &[],
    exclusive_catch_arm_kinds: &["stab_clause"],
    additional_alternative_kinds: &["else_block"],
    fn_kinds: &["call"],
    function_definition_extractor: Some(extract_elixir_function_definition),
    call_kinds: &["call"],
    call_encoded_control_flow_extractor: Some(extract_elixir_control_flow),
    call_callee_field_names: &["target"],
    call_target_extractor: Some(elixir_call_target),
    call_argument_container_kinds: &["arguments"],
    lambda_body_kinds: &["body", "block", "do_block"],
    argument_passing_mode_extractor: None,
    assignment_kinds: &["binary_operator"],
    assignment_semantics_extractor: Some(elixir_assignment_semantics),
    call_ref_kinds: &["call"],
    member_expression_kinds: &["dot"],
    member_base_field_names: &["left"],
    member_name_field_names: &["right"],
    subscript_expression_kinds: &["access_call"],
    subscript_base_field_names: &["target"],
    subscript_index_field_names: &["key"],
    non_call_ref_names: &[
        "def",
        "defp",
        "defmodule",
        "defmacro",
        "defmacrop",
        "defprotocol",
        "defimpl",
        "defdelegate",
        "defstruct",
        "defexception",
    ],
    callable_reference_extractor: Some(extract_elixir_callable_reference),
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    // Elixir functions return their final expression; the kit emits a
    // `Return` for the last statement of the `do` block.
    tail_expression_returns: true,
    // A `do_block` is a block argument to a macro/call, not an anonymous
    // function declaration. Treating every block as a callable fabricated
    // edges from module/definition syntax into the declared function and
    // made real unreferenced entrypoints appear called. Actual `fn ... end`
    // values use `anonymous_function`; rule data can assign external callback
    // semantics to an exact block argument without inventing a function here.
    lambda_kinds: &["anonymous_function"],
    inline_closure_kinds: &["do_block"],
    special_forms: &[SyntaxSpecialForm::DirectDoBlockBody],
    ..EMPTY_HANDLER
};

/// Tree-sitter node kinds consumed by Elixir-specific compiler passes after
/// the shared grammar-handler lowering. Keeping this inventory beside the
/// adapter makes grammar upgrades fail conformance instead of silently
/// disabling a branch.
const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[
    ("call target", "call"),
    ("call arguments", "arguments"),
    ("call target", "identifier"),
    ("call target", "alias"),
    ("call target", "atom"),
    ("call target", "quoted_atom"),
    ("member expression", "dot"),
    ("static subscript guard", "access_call"),
    ("callable capture", "unary_operator"),
    ("capture token", "&"),
    ("operator expression", "binary_operator"),
    ("arity token", "/"),
    ("guard operator", "when"),
    ("generator operator", "<-"),
    ("default argument operator", "\\\\"),
    ("assignment operator", "="),
    ("pipeline operator", "|>"),
    ("tail pattern operator", "|"),
    ("callable arity", "integer"),
    ("function body", "do_block"),
    ("keyword arguments", "keywords"),
    ("keyword pair", "pair"),
    ("keyword key", "keyword"),
    ("case arm", "stab_clause"),
    ("branch body", "body"),
    ("else branch", "else_block"),
    ("rescue branch", "rescue_block"),
    ("catch branch", "catch_block"),
    ("after branch", "after_block"),
    ("map literal", "map"),
    ("map content", "map_content"),
    ("struct pattern", "struct"),
    ("word-list literal", "sigil"),
    ("word-list literal name", "sigil_name"),
    ("word-list literal content", "quoted_content"),
    ("tuple pattern", "tuple"),
    ("list pattern", "list"),
    ("pattern literal", "float"),
    ("pattern literal", "string"),
    ("branch value filter", "comment"),
];

#[derive(Debug, Default, Copy, Clone)]
pub struct ElixirAdapter;

impl ElixirAdapter {
    /// Construct a stateless Elixir adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ElixirAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Elixir"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ex", "exs"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
            callable_declaration_family: bonsai_lang_api::CallableDeclarationFamily::FunctionClauses,
            callable_reference_syntax: bonsai_lang_api::CallableReferenceSyntax {
                prefixes: &["&"],
                numeric_arity_suffix: true,
                symbol_wrapper: None,
                trailing_invocation_punctuation: true,
            },
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        ADDITIONAL_GRAMMAR_NODE_KINDS
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        let src = snapshot.text.as_bytes();
        let mut decl_index = decl_index_from_tree_with_handler(file, src, &tree, &HANDLER);
        // Elixir privacy: `defp` is module-private, `def` is public.
        // Both lower to `call` nodes whose target identifier names
        // the macro. Walk for `defp` call spans, then mark matching
        // decls private.
        {
            decl_index
                .branch_conditions
                .extend(collect_elixir_branch_conditions(&tree, src, file));
            populate_call_argument_static_values(
                &mut decl_index,
                &tree,
                file,
                src,
                &HANDLER,
                elixir_static_scalar,
            );
            let (attribute_values, static_maps) = collect_elixir_static_module_attributes(&tree, src, file);
            decl_index.assignment_values.extend(attribute_values);
            decl_index.static_string_maps.extend(static_maps);
            decl_index
                .string_compositions
                .extend(collect_elixir_string_compositions(&decl_index, &tree, src, file));
            decl_index
                .assignment_values
                .sort_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end));
            decl_index.assignment_values.dedup();
            decl_index
                .static_string_maps
                .sort_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end));
            decl_index.static_string_maps.dedup();
            decl_index.string_compositions.sort_by_key(|fact| {
                (
                    fact.container_span.start,
                    fact.container_span.end,
                    fact.value_span.start,
                )
            });
            decl_index.string_compositions.dedup();
            decl_index.branch_conditions.sort_by_key(|fact| {
                (
                    fact.branch_span.start,
                    fact.branch_span.end,
                    fact.condition_span.start,
                    fact.condition_span.end,
                )
            });
            decl_index.branch_conditions.dedup();
            let case_arm_spans = collect_elixir_case_arm_spans(&tree, src, file);
            let map_field_assigns = collect_elixir_map_literal_field_assigns(&tree, src, file);
            let value_field_accesses = collect_elixir_value_field_accesses(&tree, src, file);
            let value_field_assignments = lower_elixir_value_field_assignment_facts(
                &mut decl_index.assignment_values,
                &value_field_accesses,
            );
            let local_callable_invocations = collect_elixir_local_callable_invocations(&tree, src, file);
            decl_index
                .refs
                .extend(synthesize_elixir_value_field_reads(&tree, src, file));
            let module_spans = collect_elixir_module_spans(&tree, src, file);
            if module_spans.is_empty() {
                bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
            } else {
                apply_elixir_module_semantics(&mut decl_index, &module_spans, &tree, src);
            }
            decl_index
                .compiler_guards
                .extend(collect_elixir_guarded_case_arm_facts(
                    &tree,
                    src,
                    file,
                    &decl_index.defs,
                    &decl_index.call_argument_values,
                ));
            for decl in &mut decl_index.defs {
                bonsai_lang_api::kit::split_match_arms_in_branch_events(
                    &mut decl.flow_events,
                    &case_arm_spans,
                );
                if let Some(param_nodes) = elixir_clause_param_nodes(&tree, src, decl.span, &decl.name) {
                    decl.params = elixir_clause_param_slots(&param_nodes, src);
                    augment_elixir_param_pattern_bindings(decl, &param_nodes, src);
                }
                inject_elixir_local_callable_invocations(decl, &local_callable_invocations);
                bonsai_lang_api::kit::insert_flow_field_assignments(
                    &mut decl.flow_events,
                    &map_field_assigns,
                );
                lower_elixir_value_field_access_events(
                    &mut decl.flow_events,
                    &value_field_accesses,
                    &value_field_assignments,
                );
                normalize_elixir_control_expression_assignments(&mut decl.flow_events, &tree, src);
                rewrite_elixir_raise_calls(&mut decl.flow_events);
                bonsai_lang_api::kit::annotate_tuple_call_result_bindings(
                    &mut decl.flow_events,
                    &tree,
                    src,
                    &HANDLER,
                );
            }
            let private_spans = collect_elixir_defp_spans(&tree, src);
            for decl in &mut decl_index.defs {
                let body_start = decl.body_span.map(|s| s.start).unwrap_or(decl.span.start);
                let body_end = decl.body_span.map(|s| s.end).unwrap_or(decl.span.end);
                // Match either by exact body-span anchor, or by an
                // enclosing span that aligns with the decl's start —
                // the walker may have anchored to either depending on
                // whether a `do` block was seen.
                if private_spans.iter().any(|(defp_start, defp_end)| {
                    *defp_start == body_start
                        || (*defp_start >= body_start
                            && *defp_end <= body_end
                            && *defp_start == decl.span.start)
                }) {
                    decl.visibility = Visibility::Module;
                }
            }
        }
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing follows adapter facts and
        // declarations; spelling alone is not constructor evidence.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Elixir exception forms are macro calls in the concrete syntax but have
/// non-returning language semantics. Lower only the exact unqualified Kernel
/// forms; receiver-qualified application functions with the same tail remain
/// ordinary calls.
fn rewrite_elixir_raise_calls(events: &mut [FlowEvent]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_elixir_raise_calls(then_events);
                rewrite_elixir_raise_calls(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_elixir_raise_calls(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_elixir_raise_calls(body);
                rewrite_elixir_raise_calls(catch_events);
                rewrite_elixir_raise_calls(finally_events);
            }
            _ => {}
        }
    }
    for event in events.iter_mut() {
        let FlowEvent::Call {
            span,
            name,
            receiver,
            args,
            ..
        } = event
        else {
            continue;
        };
        if receiver.is_some() || !matches!(name.as_str(), "raise" | "reraise" | "throw" | "exit") {
            continue;
        }
        let value_name = args.first().and_then(|argument| argument.place.clone());
        *event = FlowEvent::Throw {
            span: *span,
            value_name,
            thrown_type: None,
        };
    }
}

fn collect_elixir_branch_conditions(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<bonsai_lang_api::BranchConditionFact> {
    let mut facts = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let Some(name) = elixir_call_name(call, src) else {
            continue;
        };
        if !matches!(name.as_str(), "if" | "unless") {
            continue;
        }
        let Some(condition) = elixir_condition_arg(call) else {
            continue;
        };
        facts.push(bonsai_lang_api::BranchConditionFact {
            branch_span: span_of(file, &call),
            condition_span: span_of(file, &condition),
            polarity: if name == "unless" {
                bonsai_lang_api::BranchConditionPolarity::Negated
            } else {
                bonsai_lang_api::BranchConditionPolarity::Positive
            },
            membership: None,
            expression: Some(bonsai_lang_api::kit::lower_boolean_condition_expression(
                condition, file, &HANDLER, src,
            )),
        });
    }
    facts
}

const ELIXIR_GUARD_CASE_ARM_FINITE_PATTERN_MEMBERSHIP: &str = "case-arm.finite-pattern-membership";

/// Decode exact Elixir scalar syntax for compiler facts. Interpolated strings
/// and unknown escape forms fail closed; downstream rules decide what any
/// particular field/value means.
fn elixir_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "boolean" | "true" | "false" => match node_text(&node, src).trim() {
            "true" => Some(StaticScalarValue::Boolean(true)),
            "false" => Some(StaticScalarValue::Boolean(false)),
            _ => None,
        },
        "nil" => Some(StaticScalarValue::Null),
        "string" => elixir_static_string(node, src).map(StaticScalarValue::String),
        // Atoms are immutable scalar values in Elixir. Preserve their decoded
        // payload as compiler data so rulepack constraints can distinguish
        // exact option values without matching rendered source text. The
        // same strict decoder used for static aggregate keys rejects dynamic
        // and interpolated forms.
        "atom" | "quoted_atom" => elixir_static_key(node, src).map(StaticScalarValue::String),
        _ => None,
    }
}

fn elixir_static_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let mut cursor = node.walk();
    let named = node.named_children(&mut cursor).collect::<Vec<_>>();
    if named.iter().any(|child| child.kind() != "quoted_content") {
        return None;
    }
    let raw = node_text(&node, src).trim();
    let quote = raw.chars().next()?;
    if !matches!(quote, '\'' | '"') || !raw.ends_with(quote) || raw.len() < 2 {
        return None;
    }
    let inner = raw.get(quote.len_utf8()..raw.len().checked_sub(quote.len_utf8())?)?;
    let mut decoded = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let escaped = characters.next()?;
        decoded.push(match escaped {
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => return None,
        });
    }
    Some(decoded)
}

/// Lower uniquely defined module attributes whose complete value is either
/// an exact scalar or a spread-free string map. These are language-level
/// immutable compile-time values; no provider or security meaning is assigned
/// here. Repeated definitions fail closed because Elixir permits attributes
/// to be rebound while compiling a module.
fn collect_elixir_static_module_attributes(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> (Vec<AssignmentValueFact>, Vec<StaticStringMapFact>) {
    let mut definitions: std::collections::BTreeMap<String, Vec<(Node<'_>, Node<'_>, Node<'_>)>> =
        std::collections::BTreeMap::new();
    for attribute in collect_kinds(tree, &["unary_operator"]) {
        if !direct_token(attribute, src, "@") {
            continue;
        }
        let Some(call) = attribute
            .child_by_field_name("operand")
            .or_else(|| attribute.named_child(0))
            .filter(|node| node.kind() == "call")
        else {
            continue;
        };
        let (Some(target), Some(arguments)) = (
            call.child_by_field_name("target")
                .filter(|node| node.kind() == "identifier"),
            elixir_call_arguments(call),
        ) else {
            continue;
        };
        let mut cursor = arguments.walk();
        let values = arguments.named_children(&mut cursor).collect::<Vec<_>>();
        let [value] = values.as_slice() else {
            continue;
        };
        let name = node_text(&target, src).trim();
        if name.is_empty() {
            continue;
        }
        definitions
            .entry(name.to_string())
            .or_default()
            .push((attribute, target, *value));
    }

    let mut values = Vec::new();
    let mut maps = Vec::new();
    for (name, definitions) in definitions {
        let [(attribute, target, value)] = definitions.as_slice() else {
            continue;
        };
        if let Some(static_value) = elixir_static_scalar(*value, src) {
            values.push(AssignmentValueFact {
                assignment_span: span_of(file, attribute),
                target: Some(name.clone()),
                target_is_immutable: true,
                target_owner: None,
                target_span: Some(span_of(file, target)),
                value_span: span_of(file, value),
                call_sites: Vec::new(),
                value_flow: ExpressionFlow::default(),
                static_value: Some(static_value),
                exact_callable_return: None,
                inline_callback_static_return: None,
                inline_callback_fields: Vec::new(),
                exact_static_call_args: None,
                direct_call_name: None,
                direct_call_span: None,
                direct_call_receiver: None,
                direct_call_receiver_span: None,
                direct_call_receiver_flow: None,
            });
        }
        if let Some(entries) = elixir_exact_static_string_map(*value, src) {
            maps.push(StaticStringMapFact {
                assignment_span: span_of(file, attribute),
                target: name,
                target_is_immutable: true,
                entries,
            });
        }
    }
    (values, maps)
}

fn elixir_exact_static_string_map(node: Node<'_>, src: &[u8]) -> Option<Vec<StaticStringMapEntry>> {
    if node.kind() != "map" {
        return None;
    }
    let content = first_named_child_of_kind(&node, "map_content")?;
    let mut cursor = content.walk();
    let pairs = content.named_children(&mut cursor).collect::<Vec<_>>();
    if pairs.is_empty() {
        return None;
    }
    let mut entries = Vec::with_capacity(pairs.len());
    for pair in pairs {
        if pair.kind() != "binary_operator" || !elixir_binary_operator_is(&pair, "=>") {
            return None;
        }
        let key = elixir_static_string(pair.child_by_field_name("left")?, src)?;
        let value = elixir_static_string(pair.child_by_field_name("right")?, src)?;
        entries.push(StaticStringMapEntry { key, value });
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    entries
        .windows(2)
        .all(|pair| pair[0].key != pair[1].key)
        .then_some(entries)
}

fn collect_elixir_string_compositions(
    index: &DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<StringCompositionFact> {
    let mut facts = Vec::new();
    for expression in collect_kinds(tree, &["binary_operator"]) {
        if !elixir_binary_operator_is(&expression, "<>") {
            continue;
        }
        let mut parts = Vec::new();
        if !lower_elixir_string_composition(expression, file, src, &mut parts) || parts.len() < 2 {
            continue;
        }
        let value_span = span_of(file, &expression);
        let assignment = index
            .assignment_values
            .iter()
            .filter(|fact| fact.value_span.start <= value_span.start && value_span.end <= fact.value_span.end)
            .min_by_key(|fact| fact.value_span.len());
        facts.push(StringCompositionFact {
            container_span: assignment.map_or(value_span, |fact| fact.assignment_span),
            value_span,
            target: assignment.and_then(|fact| fact.target.clone()),
            dynamic_anchor_span: None,
            parts,
        });
    }
    facts
}

fn lower_elixir_string_composition(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<StringCompositionPart>,
) -> bool {
    if let Some(value) = elixir_static_string(node, src) {
        out.push(StringCompositionPart::Literal { value });
        return true;
    }
    if node.kind() == "identifier" {
        let place = node_text(&node, src).trim();
        if place.is_empty() {
            return false;
        }
        out.push(StringCompositionPart::Place {
            place: place.to_string(),
        });
        return true;
    }
    if node.kind() == "unary_operator" && direct_token(node, src, "@") {
        let Some(operand) = node
            .child_by_field_name("operand")
            .or_else(|| node.named_child(0))
            .filter(|operand| operand.kind() == "identifier")
        else {
            return false;
        };
        let place = node_text(&operand, src).trim();
        if place.is_empty() {
            return false;
        }
        out.push(StringCompositionPart::Place {
            place: place.to_string(),
        });
        return true;
    }
    if node.kind() == "call" {
        let Some(target) = node.child_by_field_name("target") else {
            return false;
        };
        out.push(StringCompositionPart::Call {
            span: span_of(file, &target),
        });
        return true;
    }
    if node.kind() != "binary_operator" || !elixir_binary_operator_is(&node, "<>") {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    lower_elixir_string_composition(left, file, src, out)
        && lower_elixir_string_composition(right, file, src, out)
}

fn elixir_static_word_attributes(tree: &Tree, src: &[u8]) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut candidates: std::collections::BTreeMap<String, Option<Vec<String>>> =
        std::collections::BTreeMap::new();
    for attribute in collect_kinds(tree, &["unary_operator"]) {
        if !direct_token(attribute, src, "@") {
            continue;
        }
        let Some(call) = attribute
            .child_by_field_name("operand")
            .or_else(|| attribute.named_child(0))
            .filter(|node| node.kind() == "call")
        else {
            continue;
        };
        let Some(target) = call.child_by_field_name("target") else {
            continue;
        };
        let name = node_text(&target, src).trim();
        if name.is_empty() {
            continue;
        }
        let Some(arguments) = elixir_call_arguments(call) else {
            continue;
        };
        let mut argument_cursor = arguments.walk();
        let argument_nodes = arguments.named_children(&mut argument_cursor).collect::<Vec<_>>();
        let [sigil] = argument_nodes.as_slice() else {
            continue;
        };
        if sigil.kind() != "sigil" {
            continue;
        }
        let mut sigil_cursor = sigil.walk();
        let sigil_children = sigil.named_children(&mut sigil_cursor).collect::<Vec<_>>();
        if sigil_children
            .iter()
            .any(|child| !matches!(child.kind(), "sigil_name" | "quoted_content"))
        {
            continue;
        }
        let Some(sigil_name) = sigil_children.iter().find(|child| child.kind() == "sigil_name") else {
            continue;
        };
        if node_text(sigil_name, src).trim() != "w" {
            continue;
        }
        let Some(content) = sigil_children
            .iter()
            .find(|child| child.kind() == "quoted_content")
        else {
            continue;
        };
        let words = node_text(content, src)
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if words.is_empty() {
            continue;
        }
        match candidates.entry(name.to_string()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(words));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }
    candidates
        .into_iter()
        .filter_map(|(name, values)| values.map(|values| (name, values)))
        .collect()
}

fn elixir_single_named_child(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "arguments" {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        let [child] = children.as_slice() else {
            return None;
        };
        node = *child;
    }
    Some(node)
}

fn elixir_call_arguments_as_args(call: Node<'_>, file: FileId, src: &[u8]) -> Vec<bonsai_lang_api::CallArg> {
    let Some(arguments) = elixir_call_arguments(call) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        if let Some(argument) = call_arg_from_node_with_handler(argument, file, src, None, &HANDLER) {
            out.push(argument);
        }
    }
    out
}

fn elixir_case_pattern_evidence(
    mut pattern: Node<'_>,
    src: &[u8],
) -> Option<(String, Vec<String>, std::collections::BTreeMap<String, String>)> {
    pattern = elixir_single_named_child(pattern)?;
    if pattern.kind() != "map" {
        return None;
    }
    let structure = first_named_child_of_kind(&pattern, "struct")?;
    let type_node = first_named_child(&structure)?;
    let type_name = node_text(&type_node, src).trim().to_string();
    if type_name.is_empty() {
        return None;
    }
    let content = first_named_child_of_kind(&pattern, "map_content")?;
    let keywords = first_named_child_of_kind(&content, "keywords")?;
    let mut static_fields = Vec::new();
    let mut bindings = std::collections::BTreeMap::new();
    let mut cursor = keywords.walk();
    for pair in keywords.named_children(&mut cursor) {
        if pair.kind() != "pair" {
            return None;
        }
        let field = elixir_static_key(pair.child_by_field_name("key")?, src)?;
        let value = pair.child_by_field_name("value")?;
        if let Some(value) = elixir_static_scalar(value, src) {
            static_fields.push(format!(
                "static-field:{field}={}",
                compiler_guard_static_scalar(&value)
            ));
        } else if value.kind() == "identifier" {
            let binding = node_text(&value, src).trim();
            if binding.is_empty() || bindings.insert(binding.to_string(), field).is_some() {
                return None;
            }
        }
    }
    static_fields.sort();
    Some((type_name, static_fields, bindings))
}

fn compiler_guard_static_scalar(value: &StaticScalarValue) -> String {
    match value {
        StaticScalarValue::String(value) => format!("string:{value}"),
        StaticScalarValue::Boolean(value) => format!("boolean:{value}"),
        StaticScalarValue::Integer(value) => format!("integer:{value}"),
        StaticScalarValue::Null => "null".to_string(),
    }
}

fn elixir_exact_membership_guard(
    guard: Node<'_>,
    src: &[u8],
    static_attributes: &std::collections::BTreeMap<String, Vec<String>>,
) -> Option<(String, String)> {
    if guard.kind() != "binary_operator" || !elixir_binary_operator_is(&guard, "in") {
        return None;
    }
    let subject = guard.child_by_field_name("left")?;
    let collection = guard.child_by_field_name("right")?;
    if subject.kind() != "identifier" || collection.kind() != "unary_operator" {
        return None;
    }
    let subject = node_text(&subject, src).trim().to_string();
    let collection = collection
        .child_by_field_name("operand")
        .or_else(|| collection.named_child(0))?;
    if collection.kind() != "identifier" || !direct_token(collection.parent()?, src, "@") {
        return None;
    }
    let collection = node_text(&collection, src).trim().to_string();
    static_attributes
        .get(&collection)
        .filter(|values| !values.is_empty() && values.iter().all(|value| !value.is_empty()))?;
    Some((subject, collection))
}

fn compiler_guard_call_arg_relation(
    guarded_args: &[bonsai_lang_api::CallArg],
    scrutinee_args: &[bonsai_lang_api::CallArg],
) -> Vec<String> {
    let mut evidence = Vec::new();
    for (guarded_index, guarded) in guarded_args.iter().enumerate() {
        let guarded_place = guarded
            .place
            .as_deref()
            .map(str::trim)
            .filter(|place| !place.is_empty());
        let Some(guarded_place) = guarded_place else {
            continue;
        };
        for (scrutinee_index, scrutinee) in scrutinee_args.iter().enumerate() {
            if scrutinee.place.as_deref().map(str::trim) == Some(guarded_place) {
                evidence.push(format!(
                    "guarded-argument:{guarded_index}=scrutinee-argument:{scrutinee_index}"
                ));
            }
        }
    }
    evidence
}

fn collect_elixir_guarded_case_arm_facts(
    tree: &Tree,
    src: &[u8],
    file: FileId,
    defs: &[bonsai_lang_api::Decl],
    argument_values: &[bonsai_lang_api::CallArgumentValueFact],
) -> Vec<CompilerGuardFact> {
    let static_attributes = elixir_static_word_attributes(tree, src);
    let local_module_roots = defs
        .iter()
        .filter(|decl| decl.kind == bonsai_lang_api::DeclKind::Module)
        .filter_map(|decl| {
            decl.qualified_name
                .as_deref()
                .unwrap_or(&decl.name)
                .split('.')
                .next()
                .map(str::to_string)
        })
        .collect::<std::collections::BTreeSet<_>>();
    let import_alias_roots = parse_imports(tree, src, file)
        .into_iter()
        .filter_map(|import| import.alias)
        .collect::<std::collections::BTreeSet<_>>();
    let mut facts = Vec::new();
    for case_call in collect_kinds(tree, &["call"]) {
        if elixir_call_name(case_call, src).as_deref() != Some("case") {
            continue;
        }
        let Some(scrutinee) = elixir_condition_arg(case_call).filter(|node| node.kind() == "call") else {
            continue;
        };
        let Some(scrutinee_target) = elixir_call_target(scrutinee, src) else {
            continue;
        };
        let scrutinee_root = scrutinee_target.full_text.split('.').next().unwrap_or_default();
        let scrutinee_args = elixir_call_arguments_as_args(scrutinee, file, src);
        if scrutinee_args.is_empty() {
            continue;
        }
        let root_unshadowed = !scrutinee_root.is_empty()
            && !local_module_roots.contains(scrutinee_root)
            && !import_alias_roots.contains(scrutinee_root);
        let Some(block) = first_named_child_of_kind(&case_call, "do_block") else {
            continue;
        };
        let mut stack = vec![block];
        while let Some(node) = stack.pop() {
            if node.kind() != "stab_clause" {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
                continue;
            }
            let Some(head) = node.child_by_field_name("left") else {
                continue;
            };
            if head.kind() != "binary_operator" || !elixir_binary_operator_is(&head, "when") {
                continue;
            }
            let (Some(pattern), Some(guard), Some(body)) = (
                head.child_by_field_name("left"),
                head.child_by_field_name("right"),
                node.child_by_field_name("right"),
            ) else {
                continue;
            };
            let Some((pattern_type, static_fields, bindings)) = elixir_case_pattern_evidence(pattern, src)
            else {
                continue;
            };
            let Some((membership_subject, _membership_collection)) =
                elixir_exact_membership_guard(guard, src, &static_attributes)
            else {
                continue;
            };
            let Some(membership_field) = bindings.get(&membership_subject) else {
                continue;
            };
            let pattern_matches_root = pattern_type == scrutinee_root;
            for guarded_call in collect_kinds_from_node(body, &["call"]) {
                let Some(guarded_target) = elixir_call_target(guarded_call, src) else {
                    continue;
                };
                let guarded_call_span = span_of(file, &guarded_target.node);
                let Some(function_span) = defs
                    .iter()
                    .filter(|decl| {
                        let owner = decl.body_span.unwrap_or(decl.span);
                        owner.start <= guarded_call_span.start && guarded_call_span.end <= owner.end
                    })
                    .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
                    .map(|decl| decl.span)
                else {
                    continue;
                };
                let guarded_args = elixir_call_arguments_as_args(guarded_call, file, src);
                let mut evidence = vec![
                    format!("scrutinee-call:{}", scrutinee_target.full_text),
                    format!("pattern-type:{pattern_type}"),
                    format!("finite-string-membership-field:{membership_field}"),
                ];
                evidence.extend(static_fields.iter().cloned());
                evidence.extend(compiler_guard_call_arg_relation(&guarded_args, &scrutinee_args));
                if root_unshadowed {
                    evidence.push("scrutinee-root-unshadowed".to_string());
                }
                if pattern_matches_root {
                    evidence.push("pattern-type=scrutinee-root".to_string());
                }
                for argument in argument_values
                    .iter()
                    .filter(|fact| fact.call_span == guarded_call_span)
                {
                    for field in &argument.exact_static_aggregate_fields {
                        evidence.push(format!(
                            "guarded-static-field:{}.{path}={value}",
                            argument.argument_index,
                            path = field.path.join("."),
                            value = compiler_guard_static_scalar(&field.value),
                        ));
                    }
                }
                evidence.sort();
                evidence.dedup();
                facts.push(CompilerGuardFact {
                    function_span,
                    guarded_call_span,
                    proof_span: span_of(file, &head),
                    capability: ELIXIR_GUARD_CASE_ARM_FINITE_PATTERN_MEMBERSHIP.to_string(),
                    evidence,
                });
            }
        }
    }
    facts.sort_by_key(|fact| {
        (
            fact.function_span.start,
            fact.guarded_call_span.start,
            fact.guarded_call_span.end,
        )
    });
    facts.dedup();
    facts
}

fn collect_kinds_from_node<'tree>(root: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if kinds.contains(&node.kind()) {
            out.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    out.sort_by_key(Node::start_byte);
    out
}

fn collect_elixir_case_arm_spans(tree: &Tree, src: &[u8], file: FileId) -> Vec<Vec<bonsai_common::Span>> {
    let mut per_case = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        if elixir_call_name(call, src).as_deref() != Some("case") {
            continue;
        }
        let Some(block) = first_named_child_of_kind(&call, "do_block") else {
            continue;
        };
        let mut arm_spans = Vec::new();
        let mut stack = vec![block];
        while let Some(node) = stack.pop() {
            if node.kind() == "stab_clause" {
                if let Some(body) = node.child_by_field_name("right") {
                    arm_spans.push(span_of(file, &body));
                }
                continue;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        arm_spans.sort_by_key(|span| (span.start, span.end));
        if arm_spans.len() >= 2 {
            per_case.push(arm_spans);
        }
    }
    per_case
}

/// Elixir invokes a function value as `binding.()`. Tree-sitter represents
/// the callee as a `dot` node with only a left operand, so the generic call
/// extractor (which expects a named member on the right) correctly refuses
/// to invent a method name. Lower that exact CST shape to an ordinary local
/// call fact here; the callgraph/IDG then resolves `binding` through its
/// assignment to the nested function declaration.
fn collect_elixir_local_callable_invocations(tree: &Tree, src: &[u8], file: FileId) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let Some(arguments) = call
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call, "arguments"))
        else {
            continue;
        };
        let Some(target) = call.child_by_field_name("target").or_else(|| call.named_child(0)) else {
            continue;
        };
        if target.kind() != "dot" || target.child_by_field_name("right").is_some() {
            continue;
        }
        let Some(left) = target
            .child_by_field_name("left")
            .or_else(|| target.named_child(0))
        else {
            continue;
        };
        if left.kind() != "identifier" || target.named_child_count() != 1 {
            continue;
        }
        let name = node_text(&left, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let mut args = Vec::new();
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            if let Some(argument) = call_arg_from_node_with_handler(argument, file, src, None, &HANDLER) {
                args.push(argument);
            }
        }
        out.push(FlowEvent::Call {
            span: span_of(file, &target),
            name,
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args,
        });
    }
    out.sort_by_key(|event| (event.span().start, event.span().end));
    out.dedup_by_key(|event| event.span());
    out
}

fn inject_elixir_local_callable_invocations(decl: &mut bonsai_lang_api::Decl, invocations: &[FlowEvent]) {
    let owner = decl.body_span.unwrap_or(decl.span);
    for invocation in invocations {
        let span = invocation.span();
        if span.file != owner.file || span.start < owner.start || span.end > owner.end {
            continue;
        }
        let FlowEvent::Call {
            name,
            receiver,
            receiver_types,
            call_kind,
            args,
            ..
        } = invocation
        else {
            continue;
        };
        if normalize_elixir_local_callable_call(
            &mut decl.flow_events,
            span,
            name,
            receiver.as_deref(),
            receiver_types,
            *call_kind,
            args,
        ) {
            continue;
        }
        if flow_events_contain_call_span(&decl.flow_events, span) {
            continue;
        }
        decl.flow_events.push(invocation.clone());
    }
    decl.flow_events
        .sort_by_key(|event| (event.span().start, event.span().end));
}

#[allow(clippy::too_many_arguments)]
fn normalize_elixir_local_callable_call(
    events: &mut [FlowEvent],
    target: bonsai_common::Span,
    name: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: bonsai_lang_api::CallKind,
    args: &[bonsai_lang_api::CallArg],
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name: event_name,
                receiver: event_receiver,
                receiver_types: event_receiver_types,
                call_kind: event_call_kind,
                args: event_args,
            } if *span == target => {
                event_name.clear();
                event_name.push_str(name);
                *event_receiver = receiver.map(str::to_string);
                event_receiver_types.clear();
                event_receiver_types.extend_from_slice(receiver_types);
                *event_call_kind = call_kind;
                event_args.clear();
                event_args.extend_from_slice(args);
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if normalize_elixir_local_callable_call(
                    then_events,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) || normalize_elixir_local_callable_call(
                    else_events,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if normalize_elixir_local_callable_call(
                    body,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if normalize_elixir_local_callable_call(
                    body,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) || normalize_elixir_local_callable_call(
                    catch_events,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) || normalize_elixir_local_callable_call(
                    finally_events,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn flow_events_contain_call_span(events: &[FlowEvent], target: bonsai_common::Span) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Call { span, .. } => *span == target,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            flow_events_contain_call_span(then_events, target)
                || flow_events_contain_call_span(else_events, target)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            flow_events_contain_call_span(body, target)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            flow_events_contain_call_span(body, target)
                || flow_events_contain_call_span(catch_events, target)
                || flow_events_contain_call_span(finally_events, target)
        }
        _ => false,
    })
}

type ElixirMapFieldAssigns = bonsai_lang_api::kit::FlowFieldAssignInsertion;

fn collect_elixir_map_literal_field_assigns(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<ElixirMapFieldAssigns> {
    let mut out = Vec::new();
    for assignment in collect_kinds(tree, &["binary_operator"]) {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        let target = node_text(&left, src).trim().to_string();
        if target.is_empty() {
            continue;
        }
        let result_nodes = elixir_assignment_result_nodes(right, src);
        let mut joined_fields: Vec<(String, Vec<String>)> = Vec::new();
        for map in result_nodes.into_iter().filter(|node| node.kind() == "map") {
            for pair in elixir_direct_map_pairs(map) {
                let Some(key_node) = pair.child_by_field_name("key") else {
                    continue;
                };
                let Some(value_node) = pair.child_by_field_name("value") else {
                    continue;
                };
                let Some(key) = elixir_map_key(key_node, src) else {
                    continue;
                };
                let sources = elixir_value_source_names(value_node, file, src);
                let field_index =
                    if let Some(index) = joined_fields.iter().position(|(existing, _)| existing == &key) {
                        index
                    } else {
                        joined_fields.push((key.clone(), Vec::new()));
                        joined_fields.len() - 1
                    };
                let joined = &mut joined_fields[field_index].1;
                for source in sources {
                    if !joined.contains(&source) {
                        joined.push(source);
                    }
                }
            }
        }
        joined_fields.sort_by(|left, right| left.0.cmp(&right.0));
        let assign_span = span_of(file, &assignment);
        let fields = joined_fields
            .into_iter()
            .map(|(key, mut sources)| {
                sources.sort();
                sources.dedup();
                FlowEvent::Assign {
                    span: assign_span,
                    target: format!("{target}.{key}"),
                    source_name: (sources.len() == 1).then(|| sources[0].clone()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    value_kind: Some(if sources.is_empty() {
                        AssignValueKind::Literal
                    } else {
                        AssignValueKind::Compound
                    }),
                    source_names: sources,
                    declares_new_binding: false,
                }
            })
            .collect::<Vec<_>>();
        if !fields.is_empty() {
            out.push(ElixirMapFieldAssigns {
                assign_span,
                target,
                fields,
            });
        }
    }
    out
}

fn elixir_assignment_result_nodes<'tree>(right: Node<'tree>, src: &[u8]) -> Vec<Node<'tree>> {
    if right.kind() == "map" {
        return vec![right];
    }
    if right.kind() != "call" {
        return Vec::new();
    }
    let Some(macro_name) = right
        .child_by_field_name("target")
        .map(|target| node_text(&target, src).trim())
        .filter(|name| elixir_control_expression_macro(name))
    else {
        return Vec::new();
    };
    elixir_control_expression_value_nodes(&right, macro_name, src)
}

fn elixir_direct_map_pairs(map: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut pending = vec![map];
    while let Some(node) = pending.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "pair" {
                out.push(child);
            } else if matches!(child.kind(), "map_content" | "keywords" | "binary_operator") {
                pending.push(child);
            }
        }
    }
    out.sort_by_key(|pair| pair.start_byte());
    out
}

fn elixir_map_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let key = raw
        .trim_end_matches(':')
        .trim()
        .trim_start_matches(':')
        .trim_matches(['"', '\'']);
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch == '_' || ch == '@' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(key.to_string())
}

fn elixir_value_source_names(node: Node<'_>, file: FileId, src: &[u8]) -> Vec<String> {
    let flow = bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER);
    let mut out = Vec::new();
    if let Some(place) = flow.place {
        out.push(place);
    }
    out.extend(flow.source_names);
    out.sort();
    out.dedup();
    out
}

#[derive(Clone, Debug)]
struct ElixirModuleSpan {
    span: bonsai_common::Span,
    name_span: bonsai_common::Span,
    module: String,
}

fn collect_elixir_module_spans(tree: &Tree, src: &[u8], file: FileId) -> Vec<ElixirModuleSpan> {
    let mut raw = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        if call_target_text(&call_node, src).as_deref() != Some("defmodule") {
            continue;
        }
        let Some(args_node) = call_node
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call_node, "arguments"))
        else {
            continue;
        };
        let mut args_cursor = args_node.walk();
        let Some(module_node) = args_node
            .named_children(&mut args_cursor)
            .find(|child| child.kind() == "alias")
        else {
            continue;
        };
        let module = node_text(&module_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        raw.push((span_of(file, &call_node), span_of(file, &module_node), module));
    }

    raw.sort_by_key(|(span, _, _)| (span.start, std::cmp::Reverse(span.end)));
    let mut resolved = Vec::new();
    for (idx, (span, name_span, module)) in raw.iter().enumerate() {
        let parent = raw
            .iter()
            .enumerate()
            .filter(|(parent_idx, (parent_span, _, _))| {
                *parent_idx != idx
                    && parent_span.start <= span.start
                    && parent_span.end >= span.end
                    && (parent_span.start, parent_span.end) != (span.start, span.end)
            })
            .min_by_key(|(_, (parent_span, _, _))| parent_span.end.saturating_sub(parent_span.start))
            .and_then(|(parent_idx, _)| resolved_module_for_raw_index(parent_idx, &raw, &resolved));
        let full_module = if module.contains('.') {
            module.clone()
        } else if let Some(parent) = parent {
            format!("{parent}.{module}")
        } else {
            module.clone()
        };
        resolved.push(ElixirModuleSpan {
            span: *span,
            name_span: *name_span,
            module: full_module,
        });
    }
    resolved
}

fn resolved_module_for_raw_index(
    raw_idx: usize,
    raw: &[(bonsai_common::Span, bonsai_common::Span, String)],
    resolved: &[ElixirModuleSpan],
) -> Option<String> {
    let (span, _, module) = raw.get(raw_idx)?;
    resolved
        .iter()
        .find(|entry| entry.span.start == span.start && entry.span.end == span.end)
        .map(|entry| entry.module.clone())
        .or_else(|| module.contains('.').then(|| module.clone()))
}

/// Attach callable declarations to their exact `defmodule` owner and retain
/// parsed `use Module, atom` arguments as generic owner-base facts. The
/// adapter assigns no framework meaning to either the used module or the atom;
/// rule data decides whether a particular `use_arg_*` marker creates an input
/// boundary.
fn apply_elixir_module_semantics(idx: &mut DeclIndex, modules: &[ElixirModuleSpan], tree: &Tree, src: &[u8]) {
    let mut next_symbol = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let module_symbols = modules
        .iter()
        .map(|module| {
            let symbol = bonsai_common::SymbolId::new(next_symbol);
            next_symbol = next_symbol.saturating_add(1);
            (module.span, symbol)
        })
        .collect::<Vec<_>>();

    for decl in &mut idx.defs {
        let Some(module) = innermost_module_for_span(modules, decl.span) else {
            continue;
        };
        let segments: Vec<String> = module.split('.').map(str::to_string).collect();
        decl.module_path = ModulePath::from_segments(segments);
        decl.qualified_name = Some(format!("{module}.{}", decl.name));
        if decl.parent.is_none() && decl.name != bonsai_lang_api::MODULE_DECL_NAME {
            decl.parent = modules
                .iter()
                .filter(|candidate| {
                    candidate.module == module
                        && candidate.span.start <= decl.span.start
                        && candidate.span.end >= decl.span.end
                })
                .min_by_key(|candidate| candidate.span.end.saturating_sub(candidate.span.start))
                .and_then(|candidate| {
                    module_symbols
                        .iter()
                        .find_map(|(span, symbol)| (*span == candidate.span).then_some(*symbol))
                });
        }
    }

    for module in modules {
        let Some(symbol) = module_symbols
            .iter()
            .find_map(|(span, symbol)| (*span == module.span).then_some(*symbol))
        else {
            continue;
        };
        let parent = modules
            .iter()
            .filter(|candidate| {
                candidate.span != module.span
                    && candidate.span.start <= module.span.start
                    && candidate.span.end >= module.span.end
            })
            .min_by_key(|candidate| candidate.span.end.saturating_sub(candidate.span.start))
            .and_then(|candidate| {
                module_symbols
                    .iter()
                    .find_map(|(span, symbol)| (*span == candidate.span).then_some(*symbol))
            });
        let mut bases = collect_elixir_use_argument_facts(tree, src, module.span, modules);
        bases.sort();
        bases.dedup();
        idx.defs.push(bonsai_lang_api::Decl {
            symbol,
            kind: bonsai_lang_api::DeclKind::Module,
            name: module
                .module
                .rsplit('.')
                .next()
                .unwrap_or(module.module.as_str())
                .to_string(),
            qualified_name: Some(module.module.clone()),
            module_path: ModulePath::from_segments(module.module.split('.').map(str::to_string)),
            span: module.span,
            name_span: module.name_span,
            visibility: Visibility::Public,
            parent,
            body_span: Some(module.span),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases: Vec::new(),
            bases,
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            receiver_field_initializers: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
    }
}

fn collect_elixir_use_argument_facts(
    tree: &Tree,
    src: &[u8],
    owner: bonsai_common::Span,
    modules: &[ElixirModuleSpan],
) -> Vec<String> {
    let mut facts = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let span = span_of(owner.file, &call);
        if span.start < owner.start || span.end > owner.end {
            continue;
        }
        if modules.iter().any(|nested| {
            nested.span != owner
                && nested.span.start <= span.start
                && nested.span.end >= span.end
                && nested.span.start >= owner.start
                && nested.span.end <= owner.end
        }) {
            continue;
        }
        if call_target_text(&call, src).as_deref() != Some("use") {
            continue;
        }
        let Some(arguments) = elixir_call_arguments(call) else {
            continue;
        };
        let mut cursor = arguments.walk();
        let args = arguments.named_children(&mut cursor).collect::<Vec<_>>();
        for arg in args.into_iter().skip(1) {
            let Some(value) = elixir_static_key(arg, src) else {
                continue;
            };
            facts.push(format!("use_arg_{value}"));
        }
    }
    facts
}

fn innermost_module_for_span(modules: &[ElixirModuleSpan], span: bonsai_common::Span) -> Option<&str> {
    modules
        .iter()
        .filter(|module| module.span.start <= span.start && module.span.end >= span.end)
        .min_by_key(|module| module.span.end.saturating_sub(module.span.start))
        .map(|module| module.module.as_str())
}

/// Recover a function clause's positional parameter nodes from the parsed
/// `def`/`defp` macro shape. A guarded head is a `when` binary operator whose
/// left operand is the actual head call; inline `do:` pairs and block bodies
/// remain outside that call's `arguments` node.
fn elixir_clause_param_nodes<'tree>(
    tree: &'tree Tree,
    src: &[u8],
    span: bonsai_common::Span,
    name: &str,
) -> Option<Vec<Node<'tree>>> {
    let definition = node_at_span(tree.root_node(), span, &["call"])?;
    let macro_name = definition
        .child_by_field_name("target")
        .map(|target| node_text(&target, src).trim())?;
    if !matches!(macro_name, "def" | "defp") {
        return None;
    }
    let definition_args = definition
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(&definition, "arguments"))?;
    let mut definition_cursor = definition_args.walk();
    let first_arg = definition_args.named_children(&mut definition_cursor).next()?;
    let head = if first_arg.kind() == "binary_operator" && elixir_binary_operator_is(&first_arg, "when") {
        first_arg.child_by_field_name("left")?
    } else {
        first_arg
    };
    if head.kind() == "identifier" {
        return (node_text(&head, src).trim() == name).then(Vec::new);
    }
    if head.kind() != "call" {
        return None;
    }
    let head_name = head
        .child_by_field_name("target")
        .map(|target| node_text(&target, src).trim())?;
    if head_name != name {
        return None;
    }
    let Some(arguments) = head
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(&head, "arguments"))
    else {
        return Some(Vec::new());
    };
    let mut cursor = arguments.walk();
    Some(arguments.named_children(&mut cursor).collect())
}

fn elixir_clause_param_slots(params: &[Node<'_>], src: &[u8]) -> Vec<String> {
    params
        .iter()
        .enumerate()
        .map(|(idx, param)| elixir_pattern_param_name(param, src).unwrap_or_else(|| format!("_arg{idx}")))
        .collect()
}

fn elixir_pattern_param_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        let name = node_text(node, src).trim();
        return elixir_variable_name(name).then(|| name.to_string());
    }
    if node.kind() == "pair" {
        return node
            .child_by_field_name("value")
            .and_then(|value| elixir_pattern_param_name(&value, src));
    }
    if node.kind() == "keywords" && node.named_child_count() == 1 {
        return node
            .named_child(0)
            .and_then(|pair| elixir_pattern_param_name(&pair, src));
    }
    if node.kind() != "binary_operator" {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    if elixir_binary_operator_is(node, "\\\\") {
        return elixir_pattern_param_name(&left, src);
    }
    if elixir_binary_operator_is(node, "=") {
        return elixir_pattern_param_name(&left, src).or_else(|| elixir_pattern_param_name(&right, src));
    }
    None
}

fn elixir_binary_operator_is(node: &Node<'_>, expected: &str) -> bool {
    if node
        .child_by_field_name("operator")
        .is_some_and(|operator| operator.kind() == expected)
    {
        return true;
    }
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() && child.kind() == expected {
            return true;
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}

fn elixir_assignment_semantics(node: Node<'_>, _src: &[u8]) -> AssignmentNodeSemantics {
    if elixir_binary_operator_is(&node, "=") {
        AssignmentNodeSemantics::Assignment
    } else if elixir_binary_operator_is(&node, "|>") {
        AssignmentNodeSemantics::Pipe
    } else {
        AssignmentNodeSemantics::Other
    }
}

/// Lower destructured function-head parameters into explicit storage reads.
/// A head such as `%Envelope{cmd: cmd}` has one argument slot (`_arg0`) and
/// one AST-proven binding (`cmd = _arg0.cmd`). Keeping the slot distinct from
/// the binding prevents interprocedural field forwarding from inventing
/// `cmd.cmd` when the body reads the scalar `cmd`.
fn augment_elixir_param_pattern_bindings(decl: &mut bonsai_lang_api::Decl, params: &[Node<'_>], src: &[u8]) {
    let mut bindings = Vec::new();
    for (idx, param) in params.iter().enumerate() {
        let Some(slot) = decl.params.get(idx).cloned() else {
            continue;
        };
        for (projection, target) in elixir_param_pattern_bindings(param, src) {
            let source = if projection.is_empty() {
                slot.clone()
            } else {
                format!("{slot}.{}", projection.join("."))
            };
            if source == target {
                continue;
            }
            bindings.push(FlowEvent::Assign {
                span: decl.name_span,
                target,
                source_name: Some(source.clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: vec![source],
                declares_new_binding: false,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Destructure),
            });
        }
    }
    if !bindings.is_empty() {
        bindings.append(&mut decl.flow_events);
        decl.flow_events = bindings;
    }
}

/// Return every compiler-proven binding created by an Elixir parameter
/// pattern together with its projection from that parameter's call slot.
/// Maps/structs retain field paths, tuples/lists retain element positions,
/// and a cons tail uses `*` to denote the remaining descendants.  Alias and
/// default wrappers are unwrapped from the CST rather than parsed from text.
fn elixir_param_pattern_bindings(node: &Node<'_>, src: &[u8]) -> Vec<(Vec<String>, String)> {
    let mut out = Vec::new();
    collect_elixir_param_pattern_bindings(*node, src, &mut Vec::new(), &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_elixir_param_pattern_bindings(
    node: Node<'_>,
    src: &[u8],
    prefix: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, String)>,
) {
    if node.kind() == "identifier" {
        let name = node_text(&node, src).trim();
        if elixir_variable_name(name) && name != "_" {
            out.push((prefix.clone(), name.to_string()));
        }
        return;
    }

    if node.kind() == "binary_operator" {
        let left = node.child_by_field_name("left").or_else(|| node.named_child(0));
        let right = node.child_by_field_name("right").or_else(|| node.named_child(1));
        if elixir_binary_operator_is(&node, "\\\\") {
            if let Some(left) = left {
                collect_elixir_param_pattern_bindings(left, src, prefix, out);
            }
            return;
        }
        if elixir_binary_operator_is(&node, "=") {
            let (Some(left), Some(right)) = (left, right) else {
                return;
            };
            let left_is_alias = left.kind() == "identifier";
            let right_is_alias = right.kind() == "identifier";
            match (left_is_alias, right_is_alias) {
                (true, false) => collect_elixir_param_pattern_bindings(right, src, prefix, out),
                (false, true) => collect_elixir_param_pattern_bindings(left, src, prefix, out),
                _ => {
                    collect_elixir_param_pattern_bindings(left, src, prefix, out);
                    collect_elixir_param_pattern_bindings(right, src, prefix, out);
                }
            }
            return;
        }
        if elixir_binary_operator_is(&node, "|") {
            if let Some(left) = left {
                prefix.push("0".to_string());
                collect_elixir_param_pattern_bindings(left, src, prefix, out);
                prefix.pop();
            }
            if let Some(right) = right {
                prefix.push("*".to_string());
                collect_elixir_param_pattern_bindings(right, src, prefix, out);
                prefix.pop();
            }
            return;
        }
    }

    if node.kind() == "pair" {
        let Some(key_node) = node.child_by_field_name("key") else {
            return;
        };
        let Some(value_node) = node.child_by_field_name("value") else {
            return;
        };
        let key = node_text(&key_node, src).trim().trim_end_matches(':').trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|ch| ch == '_' || ch == '@' || ch.is_ascii_alphanumeric())
        {
            return;
        }
        prefix.push(key.to_string());
        collect_elixir_param_pattern_bindings(value_node, src, prefix, out);
        prefix.pop();
        return;
    }

    if matches!(node.kind(), "tuple" | "list") {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        if children.len() == 1
            && children[0].kind() == "binary_operator"
            && elixir_binary_operator_is(&children[0], "|")
        {
            collect_elixir_param_pattern_bindings(children[0], src, prefix, out);
            return;
        }
        for (index, child) in children.into_iter().enumerate() {
            prefix.push(index.to_string());
            collect_elixir_param_pattern_bindings(child, src, prefix, out);
            prefix.pop();
        }
        return;
    }

    // Struct patterns wrap their map in a dedicated node. Maps and the
    // remaining grammar wrappers are structural containers; recurse only
    // through named children, with pair nodes responsible for selecting
    // field keys. Module aliases and literal nodes never produce bindings.
    if matches!(
        node.kind(),
        "alias" | "atom" | "quoted_atom" | "integer" | "float" | "string"
    ) {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_elixir_param_pattern_bindings(child, src, prefix, out);
    }
}

fn elixir_variable_name(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_lowercase())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !matches!(text, "do" | "end" | "fn" | "true" | "false" | "nil")
}

fn normalize_elixir_control_expression_assignments(events: &mut [FlowEvent], tree: &Tree, src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } if source_call
                .as_deref()
                .is_some_and(elixir_control_expression_macro) =>
            {
                if let Some(branch_sources) = elixir_control_expression_value_sources(tree, src, *span) {
                    *source_call = None;
                    source_call_args.clear();
                    *source_names = branch_sources;
                    *value_kind = Some(if source_names.is_empty() {
                        AssignValueKind::Literal
                    } else {
                        AssignValueKind::Compound
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_elixir_control_expression_assignments(then_events, tree, src);
                normalize_elixir_control_expression_assignments(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_elixir_control_expression_assignments(body, tree, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_elixir_control_expression_assignments(body, tree, src);
                normalize_elixir_control_expression_assignments(catch_events, tree, src);
                normalize_elixir_control_expression_assignments(finally_events, tree, src);
            }
            _ => {}
        }
    }
}

fn elixir_control_expression_macro(name: &str) -> bool {
    matches!(name, "if" | "unless" | "case" | "cond" | "try")
}

fn elixir_control_expression_value_sources(
    tree: &Tree,
    src: &[u8],
    span: bonsai_common::Span,
) -> Option<Vec<String>> {
    let assignment = node_at_span(tree.root_node(), span, &["binary_operator"])?;
    if !elixir_binary_operator_is(&assignment, "=") {
        return None;
    }
    let conditional = assignment.child_by_field_name("right")?;
    if conditional.kind() != "call" {
        return None;
    }
    let macro_name = conditional
        .child_by_field_name("target")
        .map(|target| node_text(&target, src).trim())?;
    if !elixir_control_expression_macro(macro_name) {
        return None;
    }
    let mut out = Vec::new();
    for value in elixir_control_expression_value_nodes(&conditional, macro_name, src) {
        let flow =
            bonsai_lang_api::kit::expression_flow_from_node_with_handler(value, span.file, src, &HANDLER);
        if let Some(place) = flow.place {
            push_elixir_value_source(&mut out, place);
        }
        for source in flow.source_names {
            push_elixir_value_source(&mut out, source);
        }
        collect_elixir_value_call_names(value, src, &mut out);
    }
    out.sort();
    out.dedup();
    Some(out)
}

fn elixir_control_expression_value_nodes<'tree>(
    conditional: &Node<'tree>,
    macro_name: &str,
    src: &[u8],
) -> Vec<Node<'tree>> {
    let mut values = Vec::new();
    if let Some(arguments) = conditional
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(conditional, "arguments"))
    {
        let mut cursor = arguments.walk();
        for child in arguments.named_children(&mut cursor) {
            if child.kind() != "keywords" {
                continue;
            }
            let mut keywords_cursor = child.walk();
            for pair in child.named_children(&mut keywords_cursor) {
                if pair.kind() != "pair" {
                    continue;
                }
                let Some(key) = pair.child_by_field_name("key") else {
                    continue;
                };
                let key = node_text(&key, src).trim().trim_end_matches(':').trim();
                if matches!(key, "do" | "else") {
                    if let Some(value) = pair.child_by_field_name("value") {
                        values.push(value);
                    }
                }
            }
        }
    }
    if let Some(block) = first_named_child_of_kind(conditional, "do_block") {
        if matches!(macro_name, "case" | "cond") {
            let mut cursor = block.walk();
            for clause in block
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "stab_clause")
            {
                let Some(body) = clause.child_by_field_name("right") else {
                    continue;
                };
                let mut body_cursor = body.walk();
                let value = body
                    .named_children(&mut body_cursor)
                    .filter(|child| child.kind() != "comment")
                    .last()
                    .unwrap_or(body);
                values.push(value);
            }
            return values;
        }
        if macro_name == "try" {
            let mut cursor = block.walk();
            let children = block
                .named_children(&mut cursor)
                .filter(|child| child.kind() != "comment")
                .collect::<Vec<_>>();
            let branch_block = |node: &Node<'_>| {
                matches!(
                    node.kind(),
                    "rescue_block" | "catch_block" | "else_block" | "after_block"
                )
            };
            let body_end = children.iter().position(branch_block).unwrap_or(children.len());
            if let Some(value) = children[..body_end].last().copied() {
                values.push(value);
            }
            for branch in children
                .iter()
                .copied()
                .filter(|child| matches!(child.kind(), "rescue_block" | "catch_block" | "else_block"))
            {
                let mut branch_cursor = branch.walk();
                for clause in branch
                    .named_children(&mut branch_cursor)
                    .filter(|child| child.kind() == "stab_clause")
                {
                    let Some(body) = clause.child_by_field_name("right") else {
                        continue;
                    };
                    let mut body_cursor = body.walk();
                    let value = body
                        .named_children(&mut body_cursor)
                        .filter(|child| child.kind() != "comment")
                        .last()
                        .unwrap_or(body);
                    values.push(value);
                }
            }
            return values;
        }
        let mut cursor = block.walk();
        let children = block
            .named_children(&mut cursor)
            .filter(|child| child.kind() != "comment")
            .collect::<Vec<_>>();
        let else_position = children.iter().position(|child| child.kind() == "else_block");
        let then_end = else_position.unwrap_or(children.len());
        if let Some(value) = children[..then_end].last().copied() {
            values.push(value);
        }
        if let Some(else_block) = else_position.and_then(|position| children.get(position)).copied() {
            let mut else_cursor = else_block.walk();
            if let Some(value) = else_block
                .named_children(&mut else_cursor)
                .filter(|child| child.kind() != "comment")
                .last()
            {
                values.push(value);
            }
        }
    }
    values
}

fn collect_elixir_value_call_names(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "call" {
            if let Some(target) = current.child_by_field_name("target") {
                let name = node_text(&target, src).trim();
                if !name.is_empty() {
                    push_elixir_value_source(out, name.to_string());
                }
            }
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
}

fn push_elixir_value_source(out: &mut Vec<String>, source: String) {
    if !source.is_empty() && !out.iter().any(|existing| existing == &source) {
        out.push(source);
    }
}

/// Extract `alias`, `import`, `require`, `use` directives from an Elixir
/// tree into the canonical `ImportSpec` shape.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Elixir's `alias`, `import`, `require`, `use` are all macro calls —
    // `call` nodes whose target is the corresponding identifier and whose
    // first argument is the module alias. `alias MyApp.Foo, as: F` adds
    // the alias-rename via a keywords-pair child.
    for call_node in collect_kinds(tree, &["call"]) {
        let Some(target_node) = call_node.child_by_field_name("target") else {
            continue;
        };
        let target_text = node_text(&target_node, src);
        // Filter to the four directive macros — every other call slips
        // through unchanged.
        if !matches!(target_text, "alias" | "import" | "require" | "use") {
            continue;
        }
        let Some(args_node) = call_node
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call_node, "arguments"))
        else {
            continue;
        };
        // The first positional argument is normally one `alias` node.  The
        // Elixir parser represents `alias MyApp.{Foo, Bar}` structurally as
        // a `dot` whose right operand is a tuple; expand that form into the
        // two exact module bindings.  Other expression shapes (including
        // atom-form Erlang modules) do not establish an Elixir alias.
        let mut args_cursor = args_node.walk();
        let mut named_args = args_node.named_children(&mut args_cursor);
        let Some(module_node) = named_args.next() else {
            continue;
        };
        let modules = if target_text == "alias" {
            elixir_alias_directive_modules(module_node, src)
        } else if module_node.kind() == "alias" {
            vec![node_text(&module_node, src).to_string()]
        } else {
            Vec::new()
        };
        if modules.is_empty() {
            continue;
        }
        // `as: F` is a keyword pair. Select it by its parsed key rather than
        // assuming it is the first option (`warn: false, as: F` is valid).
        let explicit_alias = elixir_directive_keyword_value(args_node, src, "as")
            .map(|value_node| node_text(&value_node, src).to_string());
        // Elixir's `alias MyApp.AuthService` (no `as:` rename) binds
        // the leaf segment as the local name — `AuthService` becomes
        // a path head usable as `AuthService.run(x)`. When no
        // explicit `as:` is provided, mirror Elixir's binding rule
        // so the resolver knows `AuthService` resolves into the
        // workspace's `MyApp.AuthService` module.
        for module in &modules {
            // An explicit `as:` belongs to the single-module form. Grouped
            // aliases cannot legally share one rename, so retain only their
            // parser-proven leaf bindings.
            let alias = (modules.len() == 1)
                .then(|| explicit_alias.clone())
                .flatten()
                .or_else(|| match target_text {
                    "alias" => module
                        .rsplit('.')
                        .next()
                        .map(str::trim)
                        .filter(|leaf| !leaf.is_empty())
                        .map(str::to_string),
                    _ => None,
                });
            imports.push(ImportSpec {
                span: span_of(file, &call_node),
                module: module.clone(),
                alias,
                is_wildcard: false,
                original_name: None,
                scope: ImportScope::Module,
            });
        }
        if target_text == "import" {
            let module = modules[0].clone();
            if let Some(members) = elixir_import_only_members(args_node, src) {
                for member in members {
                    imports.push(ImportSpec {
                        span: span_of(file, &call_node),
                        module: module.clone(),
                        alias: None,
                        is_wildcard: false,
                        original_name: Some(member),
                        scope: ImportScope::Local,
                    });
                }
            } else {
                imports.push(ImportSpec {
                    span: span_of(file, &call_node),
                    module,
                    alias: None,
                    is_wildcard: true,
                    original_name: None,
                    scope: ImportScope::Local,
                });
            }
        }
    }
    imports
}

fn elixir_directive_keyword_value<'tree>(
    args: Node<'tree>,
    src: &[u8],
    expected: &str,
) -> Option<Node<'tree>> {
    let keywords = first_named_child_of_kind(&args, "keywords")?;
    let mut cursor = keywords.walk();
    for pair in keywords
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "pair")
    {
        let Some(key) = pair.child_by_field_name("key") else {
            continue;
        };
        if node_text(&key, src).trim().trim_end_matches(':') == expected {
            return pair.child_by_field_name("value");
        }
    }
    None
}

/// `import Module, only: [read: 1, fetch!: 2]` creates exact local member
/// bindings.  Function names come from the keyword-list keys; arities are
/// intentionally not collapsed into the binding identity, matching Elixir's
/// local call syntax while leaving overload/arity checks to call facts.
fn elixir_import_only_members(args: Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let only = elixir_directive_keyword_value(args, src, "only")?;
    if only.kind() != "list" {
        return Some(Vec::new());
    }
    let mut members = Vec::new();
    let mut stack = vec![only];
    while let Some(node) = stack.pop() {
        if node.kind() == "pair" {
            let Some(key) = node.child_by_field_name("key") else {
                continue;
            };
            let member = node_text(&key, src).trim().trim_end_matches(':').trim();
            if !member.is_empty()
                && !member.chars().any(char::is_whitespace)
                && !members.iter().any(|existing| existing == member)
            {
                members.push(member.to_string());
            }
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    members.sort();
    Some(members)
}

/// Expand the two compiler-valid module shapes accepted by `alias`: one
/// module alias, or a brace group rooted at one module prefix.  The result is
/// derived entirely from Tree-sitter nodes; no module or framework spelling
/// is known to the adapter.
fn elixir_alias_directive_modules(node: Node<'_>, src: &[u8]) -> Vec<String> {
    if node.kind() == "alias" {
        let module = node_text(&node, src).trim();
        return (!module.is_empty())
            .then(|| module.to_string())
            .into_iter()
            .collect();
    }
    if node.kind() != "dot" {
        return Vec::new();
    }
    let Some(prefix_node) = node
        .child_by_field_name("left")
        .or_else(|| node.named_child(0))
        .filter(|left| left.kind() == "alias")
    else {
        return Vec::new();
    };
    let Some(group) = node
        .child_by_field_name("right")
        .or_else(|| node.named_child(1))
        .filter(|right| right.kind() == "tuple")
    else {
        return Vec::new();
    };
    let prefix = node_text(&prefix_node, src).trim();
    if prefix.is_empty() {
        return Vec::new();
    }
    let mut cursor = group.walk();
    group
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "alias")
        .filter_map(|child| {
            let suffix = node_text(&child, src).trim();
            (!suffix.is_empty()).then(|| format!("{prefix}.{suffix}"))
        })
        .collect()
}

/// Elixir parses value-field syntax (`map.field`, with no argument list) as
/// a `call` node whose target is `dot`. Classify it from the CST shape so the
/// IDG sees a field projection rather than an unresolved receiver method.
fn elixir_value_field_nodes<'tree>(call_node: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    if call_node.kind() != "call"
        || call_node.child_by_field_name("arguments").is_some()
        || first_named_child_of_kind(&call_node, "arguments").is_some()
    {
        return None;
    }
    let target = call_node.child_by_field_name("target")?;
    if target.kind() != "dot" {
        return None;
    }
    let mut cursor = target.walk();
    let children = target.named_children(&mut cursor).collect::<Vec<_>>();
    let receiver = target
        .child_by_field_name("left")
        .or_else(|| children.first().copied())?;
    let field = target
        .child_by_field_name("right")
        .or_else(|| children.last().copied())?;
    let receiver_is_value = receiver.kind() == "identifier"
        || (receiver.kind() == "call" && elixir_value_field_nodes(receiver).is_some());
    (receiver_is_value && field.kind() == "identifier").then_some((receiver, field))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ElixirValueFieldAccess {
    span: Span,
    place: String,
}

fn elixir_value_field_place(call_node: Node<'_>, src: &[u8]) -> Option<String> {
    let (receiver, field) = elixir_value_field_nodes(call_node)?;
    let receiver = if receiver.kind() == "identifier" {
        let receiver = node_text(&receiver, src).trim();
        (!receiver.is_empty()).then(|| receiver.to_string())?
    } else {
        elixir_value_field_place(receiver, src)?
    };
    let field = node_text(&field, src).trim();
    (!field.is_empty()).then(|| format!("{receiver}.{field}"))
}

fn collect_elixir_value_field_accesses(tree: &Tree, src: &[u8], file: FileId) -> Vec<ElixirValueFieldAccess> {
    collect_kinds(tree, &["call"])
        .into_iter()
        .filter_map(|call| {
            elixir_value_field_place(call, src).map(|place| ElixirValueFieldAccess {
                span: span_of(file, &call),
                place,
            })
        })
        .collect()
}

/// Replace an exact `target = value.field` pseudo-call with the compiler IR
/// for a field projection. The grammar relationship is recovered from the
/// assignment fact's exact RHS span; rendered assignment text and field-name
/// inventories are deliberately not consulted.
fn lower_elixir_value_field_assignment_facts(
    facts: &mut [AssignmentValueFact],
    accesses: &[ElixirValueFieldAccess],
) -> Vec<(Span, String)> {
    let mut assignments = Vec::new();
    for fact in facts {
        let Some(access) = accesses.iter().find(|access| access.span == fact.value_span) else {
            continue;
        };
        fact.call_sites.clear();
        fact.value_flow = ExpressionFlow::from_place(access.place.clone());
        fact.direct_call_name = None;
        fact.direct_call_receiver = None;
        assignments.push((fact.assignment_span, access.place.clone()));
    }
    assignments
}

/// Surface every syntax-proven value-field access as a read reference. Rule
/// matching decides which field names matter; the adapter does not carry a
/// framework-specific field-name table.
fn synthesize_elixir_value_field_reads(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    let mut refs = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        let Some((_, field_node)) = elixir_value_field_nodes(call_node) else {
            continue;
        };
        let name = node_text(&field_node, src).trim();
        if name.is_empty() {
            continue;
        }
        refs.push(Ref {
            span: span_of(file, &field_node),
            name: name.to_string(),
            kind: RefKind::Read,
            scope: None,
            resolved: None,
        });
    }
    refs
}

fn lower_elixir_value_field_access_events(
    events: &mut Vec<FlowEvent>,
    field_accesses: &[ElixirValueFieldAccess],
    assignments: &[(Span, String)],
) {
    let original = std::mem::take(events);
    for mut event in original {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                lower_elixir_value_field_access_events(then_events, field_accesses, assignments);
                lower_elixir_value_field_access_events(else_events, field_accesses, assignments);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                lower_elixir_value_field_access_events(body, field_accesses, assignments);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                lower_elixir_value_field_access_events(body, field_accesses, assignments);
                lower_elixir_value_field_access_events(catch_events, field_accesses, assignments);
                lower_elixir_value_field_access_events(finally_events, field_accesses, assignments);
            }
            _ => {}
        }
        if let FlowEvent::Assign {
            span,
            source_name,
            source_call,
            source_call_args,
            source_names,
            value_kind,
            ..
        } = &mut event
        {
            if let Some((_, place)) = assignments
                .iter()
                .find(|(assignment_span, _)| assignment_span == span)
            {
                *source_name = Some(place.clone());
                *source_call = None;
                source_call_args.clear();
                source_names.clear();
                *value_kind = Some(AssignValueKind::Compound);
            }
        }
        let is_value_field_call = matches!(
            &event,
            FlowEvent::Call { span, args, .. }
                if args.is_empty()
                    && field_accesses.iter().any(|field_access| {
                        field_access.span.file == span.file
                            && field_access.span.start < span.end
                            && span.start < field_access.span.end
                    })
        );
        if !is_value_field_call {
            events.push(event);
        }
    }
}

fn call_target_text(call_node: &Node<'_>, src: &[u8]) -> Option<String> {
    call_node
        .child_by_field_name("target")
        .or_else(|| {
            let mut cursor = call_node.walk();
            let first = call_node.named_children(&mut cursor).next();
            first
        })
        .map(|target| node_text(&target, src).trim().to_string())
}

/// Find every `defp` call site in the tree and return its byte span.
/// Adapter uses these to mark matching decls as Visibility::Module
/// (Elixir's module-private visibility).
fn collect_elixir_defp_spans(tree: &tree_sitter::Tree, src: &[u8]) -> Vec<(u64, u64)> {
    let mut defp_spans = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        let field_target = call_node.child_by_field_name("target");
        // Prefer the `target:` field; older grammar revisions don't expose
        // it, so fall back to the first named child.
        let target_node = match field_target {
            Some(target) => target,
            None => {
                let mut call_cursor = call_node.walk();
                let first_named = call_node.named_children(&mut call_cursor).next();
                match first_named {
                    Some(first_child) => first_child,
                    None => continue,
                }
            }
        };
        let target_text = node_text(&target_node, src).trim();
        if target_text == "defp" {
            defp_spans.push((
                u64::try_from(call_node.start_byte()).unwrap_or(u64::MAX),
                u64::try_from(call_node.end_byte()).unwrap_or(u64::MAX),
            ));
        }
    }
    defp_spans
}

#[cfg(test)]
mod tests;
