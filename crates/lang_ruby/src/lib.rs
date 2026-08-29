//! Ruby language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, collect_kinds, extract_param_names, first_named_child_of_kind,
        language_from_pack, named_child_call_args_with_handler, node_at_span, node_text, parse_with,
        pattern_binding_sites_from_arms, populate_call_argument_static_values, span_of,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, AssignmentValueFact, CallArg, CallArgumentValueFact,
    CallKind, CallTargetExtraction, CompilerGuardFact, Decl, DeclIndex, DeclKind, FlowEvent, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath,
    ParseRecoveryEdit, PatternBindingSite, Ref, RefKind, StaticScalarValue, StaticStringMapEntry,
    StaticStringMapFact, StringCompositionFact, StringCompositionPart, Visibility, EMPTY_HANDLER,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("ruby");
const PACK_NAME: &str = "ruby";

fn ruby_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if node.kind() != "call" {
        return None;
    }
    let target = node.child_by_field_name("method")?;
    let member = node_text(&target, src).trim();
    if member.is_empty() {
        return None;
    }
    let full_text = node.child_by_field_name("receiver").map_or_else(
        || member.to_string(),
        |receiver| format!("{}.{}", node_text(&receiver, src).trim(), member),
    );
    Some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

/// Ruby keyword arguments are `pair` nodes in the argument list. Preserve
/// their grammar-declared key/value roles so generic constraints can address
/// the named argument without parsing Ruby source text.
fn ruby_named_argument<'tree>(node: Node<'tree>, src: &[u8]) -> Option<(String, Node<'tree>)> {
    if node.kind() != "pair" {
        return None;
    }
    let key = node.child_by_field_name("key")?;
    let value = node.child_by_field_name("value")?;
    let name = node_text(&key, src)
        .trim()
        .trim_start_matches(':')
        .trim_end_matches(':')
        .trim();
    (!name.is_empty()).then(|| (name.to_string(), value))
}

fn ruby_pattern_bindings(node: Node<'_>) -> Vec<PatternBindingSite<'_>> {
    if node.kind() != "case_match" {
        return Vec::new();
    }
    pattern_binding_sites_from_arms(node, &["value"], &["in_clause"], &["pattern"], &[])
}

fn extract_ruby_callable_reference(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "call" {
        return None;
    }
    let callee = node
        .child_by_field_name("method")
        .or_else(|| node.child_by_field_name("function"))
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.child_by_field_name("target"))?;
    if node_text(&callee, src).trim() != "method" {
        return None;
    }
    let arguments = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument_list"))?;
    if arguments.named_child_count() != 1 {
        return None;
    }
    let symbol = arguments.named_child(0)?;
    if symbol.kind() != "simple_symbol" {
        return None;
    }
    let name = node_text(&symbol, src).trim().trim_start_matches(':');
    (!name.is_empty()
        && name
            .chars()
            .enumerate()
            .all(|(index, ch)| ch == '_' || ch.is_alphanumeric() && (index > 0 || !ch.is_numeric())))
    .then(|| name.to_string())
}

fn ruby_inline_closure_uses_yield(call: Node<'_>, block: Node<'_>, _src: &[u8]) -> bool {
    call.kind() == "call" && matches!(block.kind(), "block" | "do_block")
}
const BASE_HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &["nil", "integer", "float", "true", "false"],
    string_literal_kinds: &["string", "chained_string", "heredoc_body"],
    comment_kinds: &["comment"],
    parameter_container_kinds: &["method_parameters"],
    parameter_kinds: &[
        "identifier",
        "optional_parameter",
        "keyword_parameter",
        "splat_parameter",
        "hash_splat_parameter",
        "block_parameter",
    ],
    variadic_parameter_kinds: &["splat_parameter"],
    binding_identifier_kinds: &[
        "identifier",
        "constant",
        "instance_variable",
        "class_variable",
        "global_variable",
    ],
    non_binding_pattern_kinds: &["variable_reference_pattern", "expression_reference_pattern"],
    non_binding_pattern_field_names: &["key", "class", "guard"],
    binding_name_extractor: Some(ruby_binding_name),
    pattern_binding_extractor: Some(ruby_pattern_bindings),
    // A trailing block can destructure one yielded value recursively:
    // `do |(left, (right, rest))|`. The grammar owns this wrapper, while
    // only its identifier leaves are runtime bindings.
    destructured_parameter_kinds: &["destructured_parameter"],
    identifier_kinds: &[
        "identifier",
        "constant",
        "instance_variable",
        "class_variable",
        "global_variable",
    ],
    aggregate_pattern_kinds: &["left_assignment_list", "array_pattern"],
    named_aggregate_kinds: &["hash"],
    positional_aggregate_kinds: &["array"],
    aggregate_pair_kinds: &["pair", "keyword_pattern"],
    aggregate_key_field_names: &["key"],
    aggregate_value_field_names: &["value"],
    shorthand_field_kinds: &["keyword_pattern"],
    static_field_name_kinds: &["identifier", "constant"],
    spread_kinds: &["splat_argument", "hash_splat_argument"],
    spread_value_field_names: &["value"],
    lambda_value_container_kinds: &["hash", "pair", "array"],
    transparent_call_wrapper_kinds: &["call", "parenthesized_statements"],
    single_expression_group_kinds: &[],
    inline_closure_kinds: &["block", "do_block"],
    inline_closure_yield_extractor: Some(ruby_inline_closure_uses_yield),
    fn_kinds: &["method", "singleton_method"],
    class_kinds: &["class", "module"],
    class_decl_kinds: &[("class", DeclKind::Class), ("module", DeclKind::Module)],
    method_context_kinds: &["class", "module"],
    if_kinds: &[
        "if",
        "if_modifier",
        "unless",
        "unless_modifier",
        "case",
        "case_match",
    ],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &["parenthesized_statements"],
    condition_all_operators: &["&&", "and"],
    condition_any_operators: &["||", "or"],
    condition_not_operators: &["!", "not"],
    condition_not_operator_kinds: &[],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["body_statement", "then"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &[],
    branch_arm_kinds: &["then", "else", "body_statement", "when"],
    exclusive_branch_arm_kinds: &["when", "else"],
    fallthrough_branch_arm_kinds: &[],
    additional_alternative_kinds: &["elsif", "else"],
    for_kinds: &[],
    foreach_kinds: &["for"],
    foreach_binding_extractor: Some(ruby_foreach_binding),
    while_kinds: &["while", "until"],
    return_kinds: &["return"],
    // In tree-sitter-ruby, both `do ... end` and `{ ... }` call-attached
    // blocks are anonymous callable syntax. They are never ordinary compound
    // statement nodes, so each owns a compiler declaration and its yield /
    // return facts independently of the enclosing method.
    lambda_kinds: &["lambda", "block", "do_block"],
    try_kinds: &["begin", "begin_block"],
    catch_kinds: &["rescue"],
    exclusive_catch_arm_kinds: &["rescue"],
    finally_kinds: &["ensure"],
    break_kinds: &["break"],
    // `next` advances to the next iteration; `redo` restarts the current
    // iteration without reevaluating its condition. Both map to the shared
    // loop-continue edge. Ruby's rescue-only `retry` has no equivalent in the
    // current neutral IR and is intentionally not mislabeled as loop control.
    continue_kinds: &["next", "redo"],
    control_label_field_names: &[],
    yield_kinds: &["yield"],
    yield_value_field_names: &["arguments"],
    try_body_field_names: &["body"],
    implicit_receiver_names: &["self", "super"],
    implicit_receiver_prefixes: &["@"],
    ..EMPTY_HANDLER
};
const HANDLER: GrammarHandler = GrammarHandler {
    // Ruby methods return their final expression when there is no
    // explicit `return`. Surface that terminal expression as a normal
    // Return event so the shared semantic taint summaries can model
    // wrapper methods such as `def wrap(data); new(data); end`.
    constructor_names: &["initialize", "new"],
    tail_expression_returns: true,
    void_return_type_names: &[],
    // tree-sitter-ruby parses `buf += data`, `x ||= y`, `arr <<= e`
    // as `operator_assignment`. Both assignment forms are declared here;
    // shared lowering has no cross-language fallback. The compound arm in
    // the kit then re-adds the LHS as a source operand (read-modify-write).
    assignment_kinds: &["assignment", "operator_assignment"],
    assignment_place_extractor: Some(ruby_assignment_place),
    compound_assignment_kinds: &["operator_assignment"],
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%=", "**=", "&&=", "||="],
    call_kinds: &["call"],
    call_callee_field_names: &["method"],
    call_receiver_field_names: &["receiver"],
    call_member_field_names: &["method"],
    call_target_extractor: Some(ruby_call_target),
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list"],
    named_argument_extractor: Some(ruby_named_argument),
    lambda_body_field_names: &["body"],
    lambda_body_kinds: &["block", "do_block"],
    pseudo_call_extractor: Some(extract_ruby_pseudo_call),
    syntax_event_extractor: Some(extract_ruby_syntax_event),
    argument_passing_mode_extractor: None,
    call_ref_kinds: &["call"],
    subscript_expression_kinds: &["element_reference"],
    subscript_base_field_names: &["object"],
    subscript_index_field_names: &[],
    static_subscript_key_extractor: Some(ruby_static_subscript_key),
    computed_subscript_extractor: Some(ruby_element_subscript),
    global_variable_kinds: &["global_variable"],
    reference_name_extractor: Some(ruby_reference_name),
    subscript_base_call_refs: true,
    callable_reference_extractor: Some(extract_ruby_callable_reference),
    special_forms: &[],
    ..BASE_HANDLER
};

/// Ruby-specific compiler passes consume these node kinds outside the shared
/// grammar-handler walker. Conformance checks this inventory against the
/// active Tree-sitter grammar on every adapter run.
const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[
    ("call expression", "call"),
    ("named argument", "pair"),
    ("pattern match", "case_match"),
    ("pattern arm", "in_clause"),
    ("callable symbol", "simple_symbol"),
    ("closure body", "block"),
    ("closure body", "do_block"),
    ("bare send", "identifier"),
    ("append expression", "binary"),
    ("statement scope", "program"),
    ("statement scope", "body_statement"),
    ("statement scope", "do"),
    ("statement scope", "begin"),
    ("statement scope", "ensure"),
    ("statement scope", "else"),
    ("statement scope", "elsif"),
    ("statement scope", "when"),
    ("statement scope", "rescue"),
    ("condition scope", "if"),
    ("condition scope", "unless"),
    ("condition scope", "while"),
    ("condition scope", "until"),
    ("element access", "element_reference"),
    ("static element key", "string"),
    ("static element content", "string_content"),
    ("runtime value", "constant"),
    ("runtime value", "self"),
    ("runtime value", "instance_variable"),
    ("runtime value", "class_variable"),
    ("runtime value", "global_variable"),
    ("foreach binding", "for"),
    ("shell expression", "subshell"),
    ("class scope", "class"),
    ("module scope", "module"),
    ("singleton scope", "singleton_class"),
    ("method scope", "method"),
    ("singleton method scope", "singleton_method"),
    ("assignment", "assignment"),
    ("compound assignment", "operator_assignment"),
    ("hash literal", "hash"),
    ("call arguments", "argument_list"),
    ("static hash key", "hash_key_symbol"),
    ("ignored literal", "integer"),
    ("ignored literal", "float"),
    ("block parameters", "block_parameters"),
    ("lambda parameters", "lambda_parameters"),
    ("qualified constant", "scope_resolution"),
];

fn extract_ruby_syntax_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() == "identifier" && ruby_bare_identifier_is_executable(node) {
        let name = node_text(&node, src).trim();
        if ruby_bare_method_candidate(name) {
            return Some(FlowEvent::Call {
                span: span_of(file, &node),
                receiver: None,
                receiver_types: Vec::new(),
                name: name.to_string(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            });
        }
    }
    if node.kind() != "binary" {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let operator = std::str::from_utf8(&src[left.end_byte()..right.start_byte()])
        .ok()?
        .trim();
    if operator != "<<" {
        return None;
    }
    let target = call_arg_from_node_with_handler(left, file, src, None, handler)?.place?;
    let source = call_arg_from_node_with_handler(right, file, src, None, handler)?;
    let mut source_names = source.source_names;
    if let Some(place) = source.place.as_ref() {
        if !source_names.iter().any(|existing| existing == place) {
            source_names.push(place.clone());
        }
    }
    source_names.retain(|name| name != &target);
    source_names.push(target.clone());
    source_names.sort();
    source_names.dedup();
    Some(FlowEvent::Assign {
        span: span_of(file, &node),
        target,
        source_name: source.place,
        source_call: None,
        source_call_args: Vec::new(),
        source_names,
        declares_new_binding: false,
        value_kind: None,
    })
}

/// Ruby's CST leaves a receiver-less, argument-less send as an `identifier`.
/// Its lexical role distinguishes an executable statement/condition from a
/// declaration name or other identifier syntax; binding resolution below
/// then distinguishes a local read from an implicit-self method send.
fn ruby_bare_identifier_is_executable(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if matches!(
        parent.kind(),
        "program" | "body_statement" | "do" | "begin" | "ensure" | "else" | "elsif" | "when" | "rescue"
    ) {
        return true;
    }
    matches!(parent.kind(), "if" | "unless" | "while" | "until")
        && parent
            .child_by_field_name("condition")
            .is_some_and(|condition| condition.id() == node.id())
}

fn ruby_element_subscript(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "element_reference" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let mut cursor = node.walk();
    let key = node
        .named_children(&mut cursor)
        .find(|child| child.id() != object.id())?;
    Some((object, key))
}

fn ruby_static_subscript_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "string" {
        let mut cursor = node.walk();
        let parts: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let [content] = parts.as_slice() else {
            return None;
        };
        if content.kind() != "string_content" {
            return None;
        }
        let key = node_text(content, src).trim();
        return (!key.is_empty()).then(|| key.to_string());
    }
    if node.kind() == "simple_symbol" {
        let key = node_text(&node, src).trim().trim_start_matches(':');
        return (!key.is_empty()).then(|| key.to_string());
    }
    None
}

fn ruby_reference_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    if raw.is_empty() {
        return None;
    }
    if node.kind() == "instance_variable" {
        return Some(normalize_ruby_instance_variable_text(raw));
    }
    Some(raw.to_string())
}

fn ruby_binding_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    if raw.is_empty() {
        return None;
    }
    if node.kind() == "instance_variable" {
        return Some(normalize_ruby_instance_variable_text(raw));
    }
    Some(raw.to_string())
}

/// Ruby represents a writable property target (`object.property = value`)
/// with the same `call` node used for a zero-argument reader. The enclosing
/// assignment is the syntax proof that this particular node denotes a place,
/// so expose it only through the assignment-scoped adapter capability.
fn ruby_assignment_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    fn base_place(node: Node<'_>, src: &[u8]) -> Option<String> {
        if matches!(
            node.kind(),
            "identifier" | "constant" | "instance_variable" | "class_variable" | "global_variable"
        ) {
            return ruby_reference_name(node, src);
        }
        ruby_assignment_place(node, src)
    }

    if node.kind() != "call" || node.child_by_field_name("arguments").is_some() {
        return None;
    }
    let receiver = node.child_by_field_name("receiver")?;
    let method = node.child_by_field_name("method")?;
    if method.kind() != "identifier" {
        return None;
    }
    let receiver = base_place(receiver, src)?;
    let method = node_text(&method, src).trim();
    (!receiver.is_empty() && !method.is_empty()).then(|| format!("{receiver}.{method}"))
}

fn ruby_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "for" {
        return None;
    }
    let binding = node
        .child_by_field_name("pattern")
        .or_else(|| node.child_by_field_name("left"))
        .or_else(|| node.named_child(0))?;
    let iterable = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("right"))
        .or_else(|| node.named_child(1))?;
    Some((binding, iterable))
}

fn extract_ruby_pseudo_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "subshell" {
        return None;
    }
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: None,
        receiver_types: Vec::new(),
        name: "`".to_string(),
        call_kind: CallKind::Operator,
        args: named_child_call_args_with_handler(&node, file, src, handler),
    })
}

/// Ruby class and module bodies are executable scopes. The shared declaration
/// lowering correctly excludes nested class syntax from the file initializer,
/// but Ruby also permits registration calls directly in a class body. Preserve
/// those calls in a synthetic compiler-owned scope parented to the exact class;
/// downstream rule data can then assign meaning to the call without teaching
/// the engine any framework names.
fn inject_ruby_class_body_declarations(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let class_owners = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.symbol))
        .collect::<Vec<_>>();
    let mut next_symbol = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let class_names = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| decl.name.clone())
        .collect::<Vec<_>>();
    let mut synthetic = Vec::new();
    for class_node in collect_kinds(tree, &["class", "module"]) {
        let class_span = span_of(file, &class_node);
        let Some((_, owner)) = class_owners.iter().find(|(span, _)| *span == class_span) else {
            continue;
        };
        let Some(body) = class_node
            .child_by_field_name("body")
            .or_else(|| first_named_child_of_kind(&class_node, "body_statement"))
        else {
            continue;
        };
        let flow_events = bonsai_lang_api::kit::walk_flow_events(body, file, src, &HANDLER, &class_names);
        if flow_events.is_empty() {
            continue;
        }
        let body_span = span_of(file, &body);
        synthetic.push(Decl {
            symbol: SymbolId::new(next_symbol),
            kind: DeclKind::Function,
            name: format!(
                "<class-body@{}:{}>",
                body.start_position().row + 1,
                body.start_position().column + 1
            ),
            qualified_name: None,
            module_path: ModulePath::default(),
            span: body_span,
            name_span: body_span,
            visibility: Visibility::Module,
            parent: Some(*owner),
            body_span: Some(body_span),
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
            return_type: None,
            is_variadic: false,
        });
        next_symbol = next_symbol.saturating_add(1);
    }
    idx.defs.extend(synthetic);
}

#[derive(Clone)]
struct RubyTrailingBlockFact {
    call_span: Span,
    block_span: Span,
    params: Vec<String>,
    text: String,
}

/// Lower Ruby's trailing block (`call(...) do |value| ... end` and the brace
/// form) as the final inline-callback argument. The CST represents this
/// callback beside the ordinary argument list, so this adapter pass bridges
/// that language syntax into the same generic call/callback facts used by
/// every other frontend.
fn inject_ruby_trailing_block_arguments(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut blocks = Vec::new();
    for block in collect_kinds(tree, HANDLER.inline_closure_kinds) {
        let mut owner = block.parent();
        let call = loop {
            let Some(candidate) = owner else {
                break None;
            };
            if HANDLER.call_kinds.contains(&candidate.kind()) {
                break Some(candidate);
            }
            if matches!(
                candidate.kind(),
                "method" | "singleton_method" | "class" | "module"
            ) {
                break None;
            }
            owner = candidate.parent();
        };
        let Some(call) = call else { continue };
        let Some(target) = ruby_call_target(call, src) else {
            continue;
        };
        blocks.push(RubyTrailingBlockFact {
            call_span: span_of(file, &target.node),
            block_span: span_of(file, &block),
            params: extract_param_names(&block, src, &HANDLER),
            text: node_text(&block, src).to_string(),
        });
    }
    if blocks.is_empty() {
        return;
    }

    fn inject_into_events(
        events: &mut [FlowEvent],
        blocks: &[RubyTrailingBlockFact],
        facts: &mut Vec<CallArgumentValueFact>,
    ) {
        for event in events {
            match event {
                FlowEvent::Call { span, args, .. } => {
                    let Some(block) = blocks.iter().find(|block| block.call_span == *span) else {
                        continue;
                    };
                    // The shared handler may already have retained the
                    // trailing block as an ordinary argument. Preserve that
                    // exact argument index, but always publish the separate
                    // compiler callback fact: argument presence alone does
                    // not prove callback parameters to the matcher.
                    let argument_index = args
                        .iter()
                        .position(|argument| argument.span == block.block_span)
                        .unwrap_or_else(|| {
                            let argument_index = args.len();
                            args.push(CallArg {
                                span: block.block_span,
                                passing_mode: bonsai_lang_api::ArgumentPassingMode::Value,
                                name: None,
                                value_text: block.text.clone(),
                                place: None,
                                source_names: Vec::new(),
                            });
                            argument_index
                        });
                    if let Some(fact) = facts.iter_mut().find(|fact| {
                        fact.call_span == block.call_span
                            && fact.argument_index == argument_index
                            && fact.argument_span == block.block_span
                    }) {
                        // Generic argument lowering already sees brace blocks
                        // in current tree-sitter-ruby grammars. Enrich that
                        // exact fact instead of publishing a second,
                        // value-flow-poorer copy. Older grammar shapes still
                        // take the insertion path below.
                        fact.inline_callback_params.clone_from(&block.params);
                        fact.inline_callback_span = Some(block.block_span);
                    } else {
                        facts.push(CallArgumentValueFact {
                            call_span: block.call_span,
                            argument_index,
                            argument_span: block.block_span,
                            direct_call_span: None,
                            value_kind: None,
                            inline_callback_params: block.params.clone(),
                            inline_callback_span: Some(block.block_span),
                            inline_callback_static_return: None,
                            inline_callback_fields: Vec::new(),
                            value_flow: Default::default(),
                            static_value: None,
                            exact_static_aggregate_fields: Vec::new(),
                            exact_static_sequence_values: None,
                        });
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    inject_into_events(then_events, blocks, facts);
                    inject_into_events(else_events, blocks, facts);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => inject_into_events(body, blocks, facts),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    inject_into_events(body, blocks, facts);
                    inject_into_events(catch_events, blocks, facts);
                    inject_into_events(finally_events, blocks, facts);
                }
                _ => {}
            }
        }
    }

    let mut facts = std::mem::take(&mut idx.call_argument_values);
    for decl in &mut idx.defs {
        inject_into_events(&mut decl.flow_events, &blocks, &mut facts);
    }
    idx.call_argument_values = facts;
    idx.call_argument_values.sort_by_key(|fact| {
        (
            fact.call_span.file.raw(),
            fact.call_span.start,
            fact.call_span.end,
            fact.argument_index,
        )
    });
    idx.call_argument_values.dedup();
}

/// Remove the CST body wrapper that tree-sitter-ruby nests inside `->`.
///
/// Ruby's arrow lambda has both a `lambda` node and a `block`/`do_block`
/// child. The child is the body of the arrow lambda, not a second runtime
/// callback. Both node kinds are otherwise valid standalone closures (a
/// trailing call block has no `lambda` parent), so this adapter-owned AST
/// relation is the exact discriminator.
fn remove_ruby_arrow_lambda_body_duplicates(idx: &mut DeclIndex, tree: &Tree, file: FileId) {
    let lambda_body_spans = collect_kinds(tree, &["lambda"])
        .into_iter()
        .filter_map(|lambda| {
            lambda
                .child_by_field_name("body")
                .filter(|body| matches!(body.kind(), "block" | "do_block"))
                .map(|body| (span_of(file, &lambda), span_of(file, &body)))
        })
        .collect::<Vec<_>>();
    if lambda_body_spans.is_empty() {
        return;
    }
    let mut duplicate_spans = std::collections::BTreeSet::new();
    let mut reparents = Vec::new();
    for (lambda_span, body_span) in lambda_body_spans {
        let outer = idx
            .defs
            .iter()
            .find(|decl| decl.span == lambda_span)
            .map(|decl| decl.symbol);
        let duplicate = idx
            .defs
            .iter()
            .find(|decl| decl.span == body_span)
            .map(|decl| decl.symbol);
        if let (Some(outer), Some(duplicate)) = (outer, duplicate) {
            duplicate_spans.insert(body_span);
            reparents.push((duplicate, outer));
        }
    }
    for decl in &mut idx.defs {
        if let Some(parent) = decl.parent {
            if let Some((_, replacement)) = reparents.iter().find(|(duplicate, _)| *duplicate == parent) {
                decl.parent = Some(*replacement);
            }
        }
    }
    idx.defs.retain(|decl| !duplicate_spans.contains(&decl.span));
}

const RUBY_IMPLICIT_BLOCK_PARAM: &str = "<ruby-yield-block>";

fn ruby_explicit_block_parameters(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for method in collect_kinds(tree, HANDLER.fn_kinds) {
        let Some(parameters) = method
            .child_by_field_name("parameters")
            .or_else(|| first_named_child_of_kind(&method, "method_parameters"))
        else {
            continue;
        };
        let Some(block) = first_named_child_of_kind(&parameters, "block_parameter") else {
            continue;
        };
        let Some(name) = extract_param_names(&block, src, &HANDLER).into_iter().next() else {
            continue;
        };
        out.push((span_of(file, &method), name));
    }
    out
}

fn events_contain_ruby_yield(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Yield { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => events_contain_ruby_yield(then_events) || events_contain_ruby_yield(else_events),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            events_contain_ruby_yield(body)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            events_contain_ruby_yield(body)
                || events_contain_ruby_yield(catch_events)
                || events_contain_ruby_yield(finally_events)
        }
        _ => false,
    })
}

fn lower_ruby_yield_invocations(
    events: &mut Vec<FlowEvent>,
    block_param: &str,
    facts: &mut Vec<CallArgumentValueFact>,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                lower_ruby_yield_invocations(then_events, block_param, facts);
                lower_ruby_yield_invocations(else_events, block_param, facts);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                lower_ruby_yield_invocations(body, block_param, facts);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                lower_ruby_yield_invocations(body, block_param, facts);
                lower_ruby_yield_invocations(catch_events, block_param, facts);
                lower_ruby_yield_invocations(finally_events, block_param, facts);
            }
            _ => {}
        }
    }

    let mut lowered = Vec::with_capacity(events.len() + 1);
    for event in events.drain(..) {
        let invocation = match &event {
            FlowEvent::Yield {
                span,
                value_text,
                value_flow,
            } => {
                let args = value_text.as_ref().map_or_else(Vec::new, |value_text| {
                    facts.push(CallArgumentValueFact {
                        call_span: *span,
                        argument_index: 0,
                        argument_span: *span,
                        direct_call_span: None,
                        value_kind: None,
                        inline_callback_params: Vec::new(),
                        inline_callback_span: None,
                        inline_callback_static_return: None,
                        inline_callback_fields: Vec::new(),
                        value_flow: value_flow.clone(),
                        static_value: None,
                        exact_static_aggregate_fields: Vec::new(),
                        exact_static_sequence_values: None,
                    });
                    vec![CallArg {
                        span: *span,
                        passing_mode: ArgumentPassingMode::Value,
                        name: None,
                        value_text: value_text.clone(),
                        place: value_flow.place.clone(),
                        source_names: value_flow.source_names.clone(),
                    }]
                });
                Some(FlowEvent::Call {
                    span: *span,
                    name: block_param.to_string(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args,
                })
            }
            _ => None,
        };
        lowered.push(event);
        if let Some(invocation) = invocation {
            lowered.push(invocation);
        }
    }
    *events = lowered;
}

/// Lower Ruby's implicit block into an ordinary hidden callback formal.
///
/// A resolved call with a trailing block already carries that block as its
/// final compiler argument. A method-owned yield is exact proof that the
/// corresponding callback executes. This representation lets the shared
/// callback fixed point join the declarations without external API guesses.
fn lower_ruby_yield_callbacks(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let explicit_blocks = ruby_explicit_block_parameters(tree, file, src);
    let mut facts = std::mem::take(&mut idx.call_argument_values);
    for decl in &mut idx.defs {
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) || !events_contain_ruby_yield(&decl.flow_events)
        {
            continue;
        }
        let block_param = explicit_blocks
            .iter()
            .find_map(|(span, name)| (*span == decl.span).then_some(name.clone()))
            .unwrap_or_else(|| {
                if !decl.params.iter().any(|param| param == RUBY_IMPLICIT_BLOCK_PARAM) {
                    decl.params.push(RUBY_IMPLICIT_BLOCK_PARAM.to_string());
                    if !decl.param_annotations.is_empty() {
                        decl.param_annotations.push(Vec::new());
                    }
                    if !decl.param_default_calls.is_empty() {
                        decl.param_default_calls.push(Vec::new());
                    }
                }
                RUBY_IMPLICIT_BLOCK_PARAM.to_string()
            });
        lower_ruby_yield_invocations(&mut decl.flow_events, &block_param, &mut facts);
    }
    facts.sort_by_key(|fact| {
        (
            fact.call_span.file.raw(),
            fact.call_span.start,
            fact.call_span.end,
            fact.argument_index,
        )
    });
    facts.dedup();
    idx.call_argument_values = facts;
}

fn collect_ruby_lambda_assignment_spans(
    events: &[FlowEvent],
    lambda_spans: &[Span],
    out: &mut std::collections::BTreeMap<(u64, u64), String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign { span, target, .. }
                if lambda_spans.iter().any(|lambda| {
                    span.file == lambda.file && span.start <= lambda.start && lambda.end <= span.end
                }) =>
            {
                out.insert((span.start, span.end), target.clone());
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_ruby_lambda_assignment_spans(then_events, lambda_spans, out);
                collect_ruby_lambda_assignment_spans(else_events, lambda_spans, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_ruby_lambda_assignment_spans(body, lambda_spans, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_ruby_lambda_assignment_spans(body, lambda_spans, out);
                collect_ruby_lambda_assignment_spans(catch_events, lambda_spans, out);
                collect_ruby_lambda_assignment_spans(finally_events, lambda_spans, out);
            }
            _ => {}
        }
    }
}

fn normalize_ruby_lambda_calls_in_events(
    events: &mut [FlowEvent],
    lambda_assignments: &std::collections::BTreeMap<(u64, u64), String>,
    active: &mut std::collections::BTreeSet<String>,
    normalized_spans: &mut std::collections::BTreeSet<Span>,
) {
    for event in events {
        match event {
            FlowEvent::Assign { span, target, .. } => {
                if lambda_assignments
                    .get(&(span.start, span.end))
                    .is_some_and(|binding| binding == target)
                {
                    active.insert(target.clone());
                } else {
                    active.remove(target);
                }
            }
            FlowEvent::Call {
                span,
                name,
                receiver,
                call_kind,
                ..
            } => {
                let Some(binding) = receiver.as_deref().filter(|binding| active.contains(*binding)) else {
                    continue;
                };
                if name == &format!("{binding}.call") {
                    *name = binding.to_string();
                    *receiver = None;
                    *call_kind = CallKind::Function;
                    normalized_spans.insert(*span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let mut then_active = active.clone();
                let mut else_active = active.clone();
                normalize_ruby_lambda_calls_in_events(
                    then_events,
                    lambda_assignments,
                    &mut then_active,
                    normalized_spans,
                );
                normalize_ruby_lambda_calls_in_events(
                    else_events,
                    lambda_assignments,
                    &mut else_active,
                    normalized_spans,
                );
                active.retain(|binding| then_active.contains(binding) && else_active.contains(binding));
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                let mut nested = active.clone();
                normalize_ruby_lambda_calls_in_events(
                    body,
                    lambda_assignments,
                    &mut nested,
                    normalized_spans,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                let mut body_active = active.clone();
                let mut catch_active = active.clone();
                normalize_ruby_lambda_calls_in_events(
                    body,
                    lambda_assignments,
                    &mut body_active,
                    normalized_spans,
                );
                normalize_ruby_lambda_calls_in_events(
                    catch_events,
                    lambda_assignments,
                    &mut catch_active,
                    normalized_spans,
                );
                active.retain(|binding| body_active.contains(binding) && catch_active.contains(binding));
                normalize_ruby_lambda_calls_in_events(
                    finally_events,
                    lambda_assignments,
                    active,
                    normalized_spans,
                );
            }
            _ => {}
        }
    }
}

/// Normalize Proc.call only when lexical assignment structure proves that
/// the receiver is the locally-bound lambda being invoked. Dynamic receivers
/// and parameters retain ordinary method-call facts.
fn normalize_ruby_local_lambda_calls(idx: &mut DeclIndex) {
    let mut normalized_spans = std::collections::BTreeSet::new();
    for owner_index in 0..idx.defs.len() {
        if !matches!(
            idx.defs[owner_index].kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let owner_symbol = idx.defs[owner_index].symbol;
        let owner_span = idx.defs[owner_index]
            .body_span
            .unwrap_or(idx.defs[owner_index].span);
        let lambda_spans = idx
            .defs
            .iter()
            .filter(|candidate| {
                candidate.symbol != owner_symbol
                    && candidate.kind == DeclKind::Function
                    && candidate.parent == Some(owner_symbol)
                    && owner_span.file == candidate.span.file
                    && owner_span.start <= candidate.span.start
                    && candidate.span.end <= owner_span.end
            })
            .map(|candidate| candidate.span)
            .collect::<Vec<_>>();
        if lambda_spans.is_empty() {
            continue;
        }
        let mut assignments = std::collections::BTreeMap::new();
        collect_ruby_lambda_assignment_spans(
            &idx.defs[owner_index].flow_events,
            &lambda_spans,
            &mut assignments,
        );
        if assignments.is_empty() {
            continue;
        }
        normalize_ruby_lambda_calls_in_events(
            &mut idx.defs[owner_index].flow_events,
            &assignments,
            &mut std::collections::BTreeSet::new(),
            &mut normalized_spans,
        );
    }
    idx.call_receivers
        .retain(|fact| !normalized_spans.contains(&fact.call_span));
}

#[derive(Debug, Default, Copy, Clone)]
pub struct RubyAdapter;

impl RubyAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for RubyAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Ruby"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.erb` (HTML/Ruby template blend) and `.rhtml` (legacy
        // Rails) are claimed alongside `.rb`. tree-sitter-ruby cannot
        // parse the HTML wrapper as Ruby — extract_declarations
        // pre-processes ERB files to mask HTML with whitespace
        // (preserving line numbers) and expose only the embedded
        // `<%= expr %>` / `<% stmt %>` Ruby blocks to the parser.
        &["rb", "erb", "rhtml"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn parse_normalization_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        _vfs: &bonsai_lang_api::Vfs,
    ) -> Vec<ParseRecoveryEdit> {
        let is_erb = snapshot
            .path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension == "erb" || extension == "rhtml");
        if !is_erb {
            return Vec::new();
        }
        erb_parser_mask_edits(snapshot.text.as_ref()).unwrap_or_default()
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_method_names: &["initialize", "new"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["self"],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax {
                wrapper_calls: &[],
                class_object_suffixes: &[".class"],
            },
            callable_reference_syntax: bonsai_lang_api::CallableReferenceSyntax {
                prefixes: &[],
                numeric_arity_suffix: false,
                symbol_wrapper: Some("method"),
                trailing_invocation_punctuation: false,
            },
            workspace_manifest_context_extensions: &["erb", "rhtml", "haml", "slim"],
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
        // Pure Ruby files take the standard pipeline.
        let path = ctx.vfs.path(file).ok();
        let is_erb = path
            .as_ref()
            .and_then(|p| p.extension())
            .is_some_and(|ext| ext == "erb" || ext == "rhtml");
        // Both pure Ruby and the same-width ERB compiler view lower from one
        // adapter-owned syntax tree. Every Ruby-specific projection below
        // consumes this snapshot; no post-processing pass reparses the file.
        let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        let src = snapshot.text.as_bytes();
        let mut idx = decl_index_from_tree_with_handler(file, src, &tree, &HANDLER);
        if !is_erb {
            {
                idx.refs
                    .extend(extract_ruby_static_element_key_refs(&tree, src, file));
                // Apply Ruby's scope-marker visibility: `private`,
                // `protected`, `public` keywords inside a class body
                // change the default visibility of subsequent method
                // definitions. See `apply_ruby_scope_visibility` for
                // the exact contract this implements.
                apply_ruby_scope_visibility(&mut idx, &tree, src, file);
                for decl in &mut idx.defs {
                    inject_ruby_raise_throw_events(&mut decl.flow_events);
                    inject_ruby_super_call_events(&mut decl.flow_events, &decl.name);
                    normalize_ruby_subshell_events(&mut decl.flow_events, src);
                    normalize_ruby_instance_variable_events(decl);
                }
            }
            // Per-class `bases`: `class Echo < Base` → ["Base"], while a
            // qualified base retains both `Framework::Base` and the short
            // resolver key `Base`.
            // Ruby has only single-inheritance; mixins via `include`
            // are call statements (handled by the matcher's existing
            // include path), not parent-clauses.
            let block_param_names = collect_ruby_block_param_names(&tree, src);
            let bare_identifier_calls = collect_ruby_bare_identifier_calls(&tree, file, src);
            {
                let bases_by_span = collect_ruby_class_bases(&tree, file, src);
                for decl in &mut idx.defs {
                    if !is_class_like(decl.kind) {
                        continue;
                    }
                    if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                        (*span == decl.span || name == &decl.name).then_some(bases)
                    }) {
                        decl.bases = bases.clone();
                    }
                }
                inject_ruby_hash_field_assigns(&mut idx, &tree, file, src);
                inject_ruby_bare_method_arg_calls(&mut idx, &tree, file, src);
                inject_ruby_class_body_declarations(&mut idx, &tree, file, src);
            }
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
            apply_ruby_class_semantic_identity(&mut idx);
            for decl in &mut idx.defs {
                remove_bound_ruby_bare_identifier_calls(
                    &mut decl.flow_events,
                    &decl.params,
                    &block_param_names,
                    &bare_identifier_calls,
                );
                // Paren-less method calls in value position (`cmd =
                // get_input`, `v = gets`) parse as bare identifier
                // reads; promote the ones that name a method (not a
                // local or block variable) into the call-result shape so
                // taint crosses the call edge. Runs before the call-result
                // normalizer so the promoted assign is normalized too.
                rewrite_ruby_bareword_call_result_assigns(decl, &block_param_names);
                // Same promotion for tail position: `def get_input; gets;
                // end` is a call to `gets`, not an identifier read.
                inject_ruby_bare_tail_return_calls(decl, &block_param_names);
                bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            }
            inject_ruby_unbound_receiver_calls(&mut idx, &tree, file, src, &block_param_names);
            inject_ruby_trailing_block_arguments(&mut idx, &tree, file, src);
            remove_ruby_arrow_lambda_body_duplicates(&mut idx, &tree, file);
            lower_ruby_yield_callbacks(&mut idx, &tree, file, src);
            normalize_ruby_local_lambda_calls(&mut idx);
            populate_ruby_static_value_facts(&mut idx, &tree, file, src);
            idx.compiler_guards
                .extend(ruby_compound_static_allowlist_guards(&tree, file, src));
            populate_ruby_unless_condition_facts(&mut idx.branch_conditions, &tree, file);
            // Lift `@field = ParamType` writes captured during decl
            // collection into per-method `type_aliases`, so the
            // resolver's `type_alias_for_receiver(method, "self.field")`
            // returns the constructor-supplied type without re-walking
            // sibling decls per call site.
            // Local constructor-result receiver typing (`c = Foo.new` →
            // `c: Foo`) so `c.method(...)` carries a resolved receiver
            // type for `receiver_type_in` / `[Type, method]` rules. Ruby
            // class names are CamelCase and the constructor is the `.new`
            // method, which `constructor_call_type_name` resolves to the
            // class qualifier.
            bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
            bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
            return idx;
        }
        // ERB uses the same-width parser normalization declared above. The
        // canonical lowerer already owns module-scope declaration creation,
        // syntax diagnostics, refs, literals, arguments, and branch facts;
        // this adapter pass adds only Ruby's semantic projections.
        // Rails/ERB instance variables are values supplied to the template's
        // execution context. Model the exact Tree-sitter instance-variable
        // nodes as implicit inputs of the synthetic module declaration so
        // ordinary compiler dataflow can prove `@value -> helper(@value)`.
        // Assignments inside the template remain normal FlowEvents and can
        // still overwrite an input before a sink.
        let erb_implicit_inputs = collect_ruby_erb_implicit_inputs(&tree, src);
        let block_param_names = collect_ruby_block_param_names(&tree, src);
        let bare_identifier_calls = collect_ruby_bare_identifier_calls(&tree, file, src);
        for decl in &mut idx.defs {
            inject_ruby_raise_throw_events(&mut decl.flow_events);
            normalize_ruby_subshell_events(&mut decl.flow_events, src);
            normalize_ruby_instance_variable_events(decl);
            if decl.name == bonsai_lang_api::MODULE_DECL_NAME {
                decl.has_implicit_returns = true;
                decl.params.clone_from(&erb_implicit_inputs);
                decl.param_annotations = vec![Vec::new(); erb_implicit_inputs.len()];
            }
            remove_bound_ruby_bare_identifier_calls(
                &mut decl.flow_events,
                &decl.params,
                &block_param_names,
                &bare_identifier_calls,
            );
            rewrite_ruby_bareword_call_result_assigns(decl, &block_param_names);
            inject_ruby_bare_tail_return_calls(decl, &block_param_names);
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        idx.refs
            .extend(extract_ruby_static_element_key_refs(&tree, src, file));
        inject_ruby_unbound_receiver_calls(&mut idx, &tree, file, src, &block_param_names);
        inject_ruby_trailing_block_arguments(&mut idx, &tree, file, src);
        remove_ruby_arrow_lambda_body_duplicates(&mut idx, &tree, file);
        lower_ruby_yield_callbacks(&mut idx, &tree, file, src);
        normalize_ruby_local_lambda_calls(&mut idx);
        populate_ruby_static_value_facts(&mut idx, &tree, file, src);
        idx.compiler_guards
            .extend(ruby_compound_static_allowlist_guards(&tree, file, src));
        populate_ruby_unless_condition_facts(&mut idx.branch_conditions, &tree, file);
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        apply_ruby_class_semantic_identity(&mut idx);
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

fn populate_ruby_unless_condition_facts(
    facts: &mut [bonsai_lang_api::BranchConditionFact],
    tree: &Tree,
    file: FileId,
) {
    for fact in facts {
        let Some(condition) = node_at_span(tree.root_node(), fact.condition_span, &[]) else {
            continue;
        };
        let mut ancestor = condition.parent();
        let mut is_unless = false;
        while let Some(parent) = ancestor {
            if matches!(parent.kind(), "unless" | "unless_modifier") {
                is_unless = true;
                break;
            }
            if matches!(parent.kind(), "method" | "singleton_method" | "class" | "module") {
                break;
            }
            ancestor = parent.parent();
        }
        if !is_unless {
            continue;
        }
        let atom = bonsai_lang_api::ConditionExpressionFact::Atom {
            span: span_of(file, &condition),
        };
        fact.polarity = bonsai_lang_api::BranchConditionPolarity::Negated;
        fact.expression = Some(bonsai_lang_api::ConditionExpressionFact::Not {
            span: fact.condition_span,
            operand: Box::new(atom),
        });
    }
}

/// Publish exact literal values and complete local string maps. This pass is
/// deliberately syntax-only: method names and any security interpretation of
/// a later map operation remain rulepack data.
fn populate_ruby_static_value_facts(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    populate_call_argument_static_values(idx, tree, file, src, &HANDLER, ruby_static_scalar);
    for receiver in &mut idx.call_receivers {
        let Some(node) = tree.root_node().descendant_for_byte_range(
            receiver.receiver_span.start as usize,
            receiver.receiver_span.end as usize,
        ) else {
            continue;
        };
        receiver.static_value = ruby_static_scalar(node, src);
    }
    for fact in &mut idx.assignment_values {
        fact.target_is_immutable = fact.target_span.is_some_and(|span| {
            tree.root_node()
                .descendant_for_byte_range(span.start as usize, span.end as usize)
                .is_some_and(|node| node.kind() == "constant")
        });
        if fact.target_is_immutable {
            fact.target_owner = idx
                .defs
                .iter()
                .filter(|decl| {
                    is_class_like(decl.kind)
                        && decl.span.file == fact.assignment_span.file
                        && decl.span.start <= fact.assignment_span.start
                        && fact.assignment_span.end <= decl.span.end
                })
                .min_by_key(|decl| decl.span.len())
                .map(|decl| decl.symbol);
        }
    }
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "assignment" {
            let target = node.child_by_field_name("left");
            let value = node.child_by_field_name("right");
            if let (Some(target), Some(value)) = (target, value) {
                let frozen_literal = (target.kind() == "constant" && value.kind() == "call")
                    .then(|| {
                        let method = value.child_by_field_name("method")?;
                        (node_text(&method, src).trim() == "freeze").then_some(())?;
                        let receiver = value.child_by_field_name("receiver")?;
                        ruby_static_scalar(receiver, src)
                    })
                    .flatten();
                if let Some(static_value) = frozen_literal {
                    let assignment_span = span_of(file, &node);
                    if let Some(fact) = idx
                        .assignment_values
                        .iter_mut()
                        .find(|fact| fact.assignment_span == assignment_span)
                    {
                        fact.target_is_immutable = true;
                        fact.static_value = Some(static_value);
                    } else {
                        idx.assignment_values.push(AssignmentValueFact {
                            assignment_span,
                            target: Some(node_text(&target, src).trim().to_string()),
                            target_is_immutable: true,
                            target_owner: idx
                                .defs
                                .iter()
                                .filter(|decl| {
                                    is_class_like(decl.kind)
                                        && decl.span.file == assignment_span.file
                                        && decl.span.start <= assignment_span.start
                                        && assignment_span.end <= decl.span.end
                                })
                                .min_by_key(|decl| decl.span.len())
                                .map(|decl| decl.symbol),
                            target_span: Some(span_of(file, &target)),
                            value_span: span_of(file, &value),
                            call_sites: vec![span_of(file, &value)],
                            value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                                value, file, src, &HANDLER,
                            ),
                            static_value: Some(static_value),
                            exact_callable_return: None,
                            inline_callback_static_return: None,
                            inline_callback_fields: Vec::new(),
                            exact_static_call_args: None,
                            direct_call_name: ruby_call_target(value, src).map(|target| target.full_text),
                            direct_call_span: None,
                            direct_call_receiver: None,
                            direct_call_receiver_span: None,
                            direct_call_receiver_flow: None,
                        });
                    }
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    idx.assignment_values.sort_by_key(|fact| {
        (
            fact.assignment_span.start,
            fact.assignment_span.end,
            fact.value_span.start,
            fact.value_span.end,
        )
    });
    idx.assignment_values.dedup();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "string" {
            let mut cursor = node.walk();
            let parts = node.named_children(&mut cursor).collect::<Vec<_>>();
            if let [interpolation, literal] = parts.as_slice() {
                if interpolation.kind() == "interpolation" && literal.kind() == "string_content" {
                    let mut inner_cursor = interpolation.walk();
                    let inner = interpolation
                        .named_children(&mut inner_cursor)
                        .collect::<Vec<_>>();
                    if let [value] = inner.as_slice() {
                        let flow = bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                            *value, file, src, &HANDLER,
                        );
                        if let Some(place) = flow
                            .projection
                            .as_ref()
                            .map(bonsai_lang_api::ExpressionProjection::canonical_place)
                            .or(flow.place)
                        {
                            let span = span_of(file, &node);
                            idx.string_compositions.push(StringCompositionFact {
                                container_span: span,
                                value_span: span,
                                target: None,
                                dynamic_anchor_span: None,
                                parts: vec![
                                    StringCompositionPart::Place { place },
                                    StringCompositionPart::Literal {
                                        value: node_text(literal, src).to_string(),
                                    },
                                ],
                            });
                        }
                    }
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    idx.string_compositions
        .sort_by_key(|fact| (fact.value_span.start, fact.value_span.end));
    idx.string_compositions.dedup();
    idx.static_string_maps = ruby_static_string_maps(tree, file, src);
}

fn ruby_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "nil" => Some(StaticScalarValue::Null),
        "string" => ruby_static_string_literal(node, src).map(StaticScalarValue::String),
        "simple_symbol" => ruby_static_symbol(node, src).map(StaticScalarValue::String),
        _ => None,
    }
}

/// Decode the conservative Ruby string subset represented by one complete
/// quoted literal and zero or one `string_content` children. Interpolation,
/// concatenation, escapes, heredocs, and percent literals fail closed.
fn ruby_static_string_literal(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = node_text(&node, src);
    let quote = raw.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || raw.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let mut cursor = node.walk();
    let parts = node.named_children(&mut cursor).collect::<Vec<_>>();
    match parts.as_slice() {
        [] => Some(String::new()),
        [content] if content.kind() == "string_content" => {
            let value = node_text(content, src);
            (!value.contains('\\')).then(|| value.to_string())
        }
        _ => None,
    }
}

fn ruby_static_string_maps(tree: &Tree, file: FileId, src: &[u8]) -> Vec<StaticStringMapFact> {
    let mut maps = Vec::new();
    for assignment in collect_kinds(tree, &["assignment"]) {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        let (map, target_is_immutable) = match target.kind() {
            "identifier" if ruby_inside_method(assignment) && value.kind() == "hash" => (value, false),
            "constant" => {
                let Some(map) = ruby_frozen_hash_receiver(value, src) else {
                    continue;
                };
                (map, true)
            }
            _ => continue,
        };
        let name = node_text(&target, src).trim();
        if !ruby_simple_local_name(name) {
            continue;
        }
        let Some(entries) = ruby_exact_static_string_map_entries(map, src) else {
            continue;
        };
        maps.push(StaticStringMapFact {
            assignment_span: span_of(file, &assignment),
            target: name.to_string(),
            target_is_immutable,
            entries,
        });
    }
    maps.sort_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end));
    maps.dedup();
    maps
}

const RUBY_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST: &str = "terminal-predicate.compound-static-allowlist";

/// Emit API-neutral evidence for `return unless predicate && membership`
/// when the membership receiver is a frozen finite string collection and a
/// later call consumes the same parsed component. The frontend records exact
/// call/component/value identities; rule data alone assigns URL/security
/// meaning to those syntax facts.
fn ruby_compound_static_allowlist_guards(tree: &Tree, file: FileId, src: &[u8]) -> Vec<CompilerGuardFact> {
    let static_collections = ruby_frozen_static_string_collections(tree, src);
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["method", "singleton_method"]) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let calls = ruby_collect_kinds_below(body, &["call"]);
        for branch in ruby_collect_kinds_below(body, &["unless_modifier"]) {
            if branch
                .child_by_field_name("body")
                .is_none_or(|body| body.kind() != "return")
            {
                continue;
            }
            let Some(predicate) = branch.child_by_field_name("condition").and_then(|condition| {
                ruby_compound_acceptance_predicate(condition, src, &static_collections)
            }) else {
                continue;
            };
            let Some(parser) = ruby_collect_kinds_below(body, &["assignment"])
                .into_iter()
                .filter(|assignment| assignment.end_byte() <= branch.start_byte())
                .filter_map(|assignment| ruby_parser_assignment(assignment, src))
                .filter(|assignment| assignment.output == predicate.parsed_place)
                .max_by_key(|assignment| assignment.start)
            else {
                continue;
            };
            for guarded_call in calls
                .iter()
                .copied()
                .filter(|call| call.start_byte() > branch.end_byte())
            {
                let guarded_args = ruby_direct_call_arguments(guarded_call);
                let component_relations = guarded_args
                    .iter()
                    .enumerate()
                    .filter_map(|(index, argument)| {
                        let (receiver, component, _) = ruby_accessor_call(*argument, src)?;
                        (receiver == predicate.parsed_place && component == predicate.component)
                            .then(|| format!("guarded-argument:{index}=predicate-component:{component}"))
                    })
                    .collect::<Vec<_>>();
                if component_relations.is_empty() {
                    continue;
                }
                let Some(target) = ruby_call_target(guarded_call, src) else {
                    continue;
                };
                let mut evidence = vec![
                    "predicate-complete:true".to_string(),
                    "finite-static-string-membership:true".to_string(),
                    format!("parser-call:{}", parser.call_name),
                    format!("type-predicate-call:{}", predicate.type_predicate_call),
                    format!("type-predicate-value:place:{}", predicate.type_value),
                    format!("membership-call:{}", predicate.membership_call),
                    format!("membership-component:{}", predicate.component),
                ];
                evidence.extend(component_relations);
                for (index, argument) in guarded_args.iter().enumerate() {
                    if let Some((name, value)) = ruby_named_argument(*argument, src) {
                        if let Some(value) = ruby_compiler_evidence_operand(value, src) {
                            evidence.push(format!("guarded-named-argument:{index}:{name}={value}"));
                        }
                    }
                }
                evidence.sort();
                evidence.dedup();
                facts.push(CompilerGuardFact {
                    function_span: span_of(file, &function),
                    guarded_call_span: span_of(file, &target.node),
                    proof_span: span_of(file, &branch),
                    capability: RUBY_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST.to_string(),
                    evidence,
                });
            }
        }
    }
    facts.sort_by(|left, right| {
        (
            left.function_span.start,
            left.guarded_call_span.start,
            left.proof_span.start,
            &left.evidence,
        )
            .cmp(&(
                right.function_span.start,
                right.guarded_call_span.start,
                right.proof_span.start,
                &right.evidence,
            ))
    });
    facts.dedup();
    facts
}

struct RubyParserAssignment {
    start: usize,
    output: String,
    call_name: String,
}

struct RubyCompoundPredicate {
    parsed_place: String,
    type_predicate_call: String,
    type_value: String,
    membership_call: String,
    component: String,
}

fn ruby_parser_assignment(assignment: Node<'_>, src: &[u8]) -> Option<RubyParserAssignment> {
    let output = ruby_exact_place(assignment.child_by_field_name("left")?, src)?;
    let mut value = assignment.child_by_field_name("right")?;
    if value.kind() == "rescue_modifier" {
        value = value.child_by_field_name("body")?;
    }
    let target = ruby_call_target(value, src)?;
    let arguments = ruby_direct_call_arguments(value);
    let [argument] = arguments.as_slice() else {
        return None;
    };
    ruby_exact_place(*argument, src)?;
    Some(RubyParserAssignment {
        start: assignment.start_byte(),
        output,
        call_name: target.full_text,
    })
}

fn ruby_compound_acceptance_predicate(
    condition: Node<'_>,
    src: &[u8],
    static_collections: &std::collections::HashMap<String, Vec<String>>,
) -> Option<RubyCompoundPredicate> {
    if condition.kind() != "binary" {
        return None;
    }
    let (left, right) = (
        condition.child_by_field_name("left")?,
        condition.child_by_field_name("right")?,
    );
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())?
        .trim();
    if operator != "&&" {
        return None;
    }
    let type_target = ruby_call_target(left, src)?;
    let parsed_place = left
        .child_by_field_name("receiver")
        .and_then(|receiver| ruby_exact_place(receiver, src))?;
    let type_args = ruby_direct_call_arguments(left);
    let [type_arg] = type_args.as_slice() else {
        return None;
    };
    let type_value = ruby_exact_place(*type_arg, src)?;

    let membership_target = ruby_call_target(right, src)?;
    let collection = right
        .child_by_field_name("receiver")
        .and_then(|receiver| ruby_exact_place(receiver, src))?;
    if !static_collections.contains_key(&collection) {
        return None;
    }
    let membership_args = ruby_direct_call_arguments(right);
    let [membership_arg] = membership_args.as_slice() else {
        return None;
    };
    let (component_receiver, component, _) = ruby_accessor_call(*membership_arg, src)?;
    if component_receiver != parsed_place {
        return None;
    }
    Some(RubyCompoundPredicate {
        parsed_place,
        type_predicate_call: node_text(&type_target.node, src).trim().to_string(),
        type_value,
        membership_call: node_text(&membership_target.node, src).trim().to_string(),
        component,
    })
}

fn ruby_frozen_static_string_collections(
    tree: &Tree,
    src: &[u8],
) -> std::collections::HashMap<String, Vec<String>> {
    let mut collections = std::collections::HashMap::new();
    for assignment in collect_kinds(tree, &["assignment"]) {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "constant" || value.kind() != "call" {
            continue;
        }
        let Some(method) = value.child_by_field_name("method") else {
            continue;
        };
        let Some(array) = value.child_by_field_name("receiver") else {
            continue;
        };
        if node_text(&method, src).trim() != "freeze" || array.kind() != "string_array" {
            continue;
        }
        let mut values = Vec::new();
        let mut cursor = array.walk();
        let mut complete = true;
        for item in array.named_children(&mut cursor) {
            let Some(content) = item
                .named_child(0)
                .filter(|child| child.kind() == "string_content")
            else {
                complete = false;
                break;
            };
            let value = node_text(&content, src);
            if value.is_empty() || value.contains('\\') {
                complete = false;
                break;
            }
            values.push(value.to_string());
        }
        if complete && !values.is_empty() {
            collections.insert(node_text(&target, src).trim().to_string(), values);
        }
    }
    collections
}

fn ruby_exact_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "constant" | "instance_variable" | "class_variable" | "global_variable" => {
            let value = node_text(&node, src).trim();
            (!value.is_empty()).then(|| value.to_string())
        }
        "scope_resolution" => {
            let value = node_text(&node, src)
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            (!value.is_empty()).then_some(value)
        }
        _ => None,
    }
}

fn ruby_accessor_call<'tree>(node: Node<'tree>, src: &[u8]) -> Option<(String, String, Node<'tree>)> {
    if node.kind() != "call" || !ruby_direct_call_arguments(node).is_empty() {
        return None;
    }
    let receiver = ruby_exact_place(node.child_by_field_name("receiver")?, src)?;
    let method = node.child_by_field_name("method")?;
    let component = node_text(&method, src).trim();
    (!component.is_empty()).then(|| (receiver, component.to_string(), method))
}

fn ruby_direct_call_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).collect()
}

fn ruby_compiler_evidence_operand(node: Node<'_>, src: &[u8]) -> Option<String> {
    match ruby_static_scalar(node, src) {
        Some(StaticScalarValue::String(value)) => Some(format!("string:{value}")),
        Some(StaticScalarValue::Boolean(value)) => Some(format!("boolean:{value}")),
        Some(StaticScalarValue::Null) => Some("null".to_string()),
        Some(StaticScalarValue::Integer(value)) => Some(format!("number:{value}")),
        None => ruby_exact_place(node, src).map(|value| format!("place:{value}")),
    }
}

fn ruby_collect_kinds_below<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut result = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.id() != node.id() && kinds.contains(&current.kind()) {
            result.push(current);
        }
        let mut cursor = current.walk();
        let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }
    result
}

/// Return the literal hash receiver of an exact `hash.freeze` expression.
/// Ruby constants are reassignable, so a class/module binding is only exposed
/// as immutable compiler evidence when the selected container is frozen.
fn ruby_frozen_hash_receiver<'tree>(value: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    if value.kind() != "call"
        || value
            .child_by_field_name("method")
            .is_none_or(|method| node_text(&method, src).trim() != "freeze")
    {
        return None;
    }
    let receiver = value.child_by_field_name("receiver")?;
    (receiver.kind() == "hash").then_some(receiver)
}

fn ruby_inside_method(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "method" | "singleton_method" => return true,
            "class" | "module" | "singleton_class" => return false,
            _ => node = parent,
        }
    }
    false
}

fn ruby_simple_local_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .enumerate()
            .all(|(index, ch)| ch == '_' || ch.is_alphabetic() || index > 0 && ch.is_numeric())
}

fn ruby_exact_static_string_map_entries(node: Node<'_>, src: &[u8]) -> Option<Vec<StaticStringMapEntry>> {
    let mut entries = Vec::new();
    let mut cursor = node.walk();
    for pair in node.named_children(&mut cursor) {
        if pair.kind() != "pair" {
            return None;
        }
        let key = ruby_static_map_key(pair.child_by_field_name("key")?, src)?;
        let value = ruby_static_map_value(pair.child_by_field_name("value")?, src)?;
        if entries
            .iter()
            .any(|entry: &StaticStringMapEntry| entry.key == key)
        {
            return None;
        }
        entries.push(StaticStringMapEntry { key, value });
    }
    Some(entries)
}

fn ruby_static_map_value(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "string" => ruby_static_string_literal(node, src),
        "simple_symbol" => ruby_static_symbol(node, src),
        _ => None,
    }
}

fn ruby_static_symbol(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "simple_symbol" {
        return None;
    }
    let raw = node_text(&node, src).trim();
    let value = raw.strip_prefix(':')?;
    ruby_simple_local_name(value).then(|| value.to_string())
}

fn ruby_static_map_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "string" => ruby_static_string_literal(node, src),
        "simple_symbol" => ruby_static_symbol(node, src),
        "hash_key_symbol" => {
            let raw = node_text(&node, src).trim();
            // The active Ruby grammar excludes the trailing colon from this
            // node's byte range; older compatible grammars included it.
            let value = raw.strip_suffix(':').unwrap_or(raw);
            ruby_simple_local_name(value).then(|| value.to_string())
        }
        _ => None,
    }
}

fn collect_ruby_bare_identifier_calls(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::BTreeSet<(u64, u64, String)> {
    collect_kinds(tree, &["identifier"])
        .into_iter()
        .filter(|node| ruby_bare_identifier_is_executable(*node))
        .filter_map(|node| {
            let name = node_text(&node, src).trim();
            ruby_bare_method_candidate(name).then(|| {
                let span = span_of(file, &node);
                (span.start, span.end, name.to_string())
            })
        })
        .collect()
}

fn remove_bound_ruby_bare_identifier_calls(
    events: &mut Vec<FlowEvent>,
    params: &[String],
    block_params: &std::collections::BTreeSet<String>,
    candidates: &std::collections::BTreeSet<(u64, u64, String)>,
) {
    let mut locals = params
        .iter()
        .filter_map(|param| ruby_bare_binding_name(param))
        .collect::<std::collections::BTreeSet<_>>();
    collect_ruby_local_bindings(events, &mut locals);
    locals.extend(block_params.iter().cloned());

    fn retain(
        events: &mut Vec<FlowEvent>,
        locals: &std::collections::BTreeSet<String>,
        candidates: &std::collections::BTreeSet<(u64, u64, String)>,
    ) {
        for event in events.iter_mut() {
            match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    retain(then_events, locals, candidates);
                    retain(else_events, locals, candidates);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => retain(body, locals, candidates),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    retain(body, locals, candidates);
                    retain(catch_events, locals, candidates);
                    retain(finally_events, locals, candidates);
                }
                _ => {}
            }
        }
        events.retain(|event| {
            let FlowEvent::Call { span, name, .. } = event else {
                return true;
            };
            !(locals.contains(name) && candidates.contains(&(span.start, span.end, name.clone())))
        });
    }

    retain(events, &locals, candidates);
}

fn inject_ruby_raise_throw_events(events: &mut Vec<FlowEvent>) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_ruby_raise_throw_events(then_events);
                inject_ruby_raise_throw_events(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_ruby_raise_throw_events(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_ruby_raise_throw_events(body);
                inject_ruby_raise_throw_events(catch_events);
                inject_ruby_raise_throw_events(finally_events);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let synthetic_throw = ruby_raise_throw_event(&event);
        rewritten.push(event);
        if let Some(throw_event) = synthetic_throw {
            rewritten.push(throw_event);
        }
    }
    *events = rewritten;
}

fn inject_ruby_super_call_events(events: &mut Vec<FlowEvent>, method_name: &str) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_ruby_super_call_events(then_events, method_name);
                inject_ruby_super_call_events(else_events, method_name);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_ruby_super_call_events(body, method_name);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_ruby_super_call_events(body, method_name);
                inject_ruby_super_call_events(catch_events, method_name);
                inject_ruby_super_call_events(finally_events, method_name);
            }
            _ => {}
        }
    }

    if method_name.trim().is_empty() {
        return;
    }
    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        if ruby_return_is_bare_super(&event) {
            let span = match &event {
                FlowEvent::Return { span, .. } => *span,
                _ => unreachable!("guarded by ruby_return_is_bare_super"),
            };
            rewritten.push(FlowEvent::Call {
                span,
                name: format!("super.{method_name}"),
                receiver: Some("super".to_string()),
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            });
        }
        rewritten.push(event);
    }
    *events = rewritten;
}

fn ruby_return_is_bare_super(event: &FlowEvent) -> bool {
    let FlowEvent::Return {
        value_name,
        value_text,
        value_flow,
        ..
    } = event
    else {
        return false;
    };
    value_flow.place.as_deref() == Some("super")
        || (value_name.as_deref() == Some("super")
            && value_text.as_deref().is_some_and(|text| text.trim() == "super")
            && value_flow.call_sites.is_empty())
}

fn ruby_raise_throw_event(event: &FlowEvent) -> Option<FlowEvent> {
    let FlowEvent::Call { name, args, span, .. } = event else {
        return None;
    };
    if name != "raise" {
        return None;
    }
    // `raise ExceptionClass, message` (M17): arg0 is the exception
    // class, so the thrown *value* is the message in arg1. Recognize
    // the class form by a Capitalized constant or `Foo::Bar` scope.
    let thrown_arg = match args.first() {
        Some(first) if args.len() >= 2 && ruby_is_exception_class(&first.value_text) => args.get(1),
        other => other,
    };
    // value_name is contractually a bare identifier (M18): take it
    // only from `place`, leaving compound throws such as
    // `StandardError.new(msg)` as None so the engine routes them
    // through its conservative inter-procedural branch.
    Some(FlowEvent::Throw {
        span: *span,
        value_name: thrown_arg.and_then(|arg| arg.place.clone()),
        thrown_type: None,
    })
}

/// True when an argument's text names a Ruby exception class -- a
/// Capitalized constant (`ArgumentError`) or a scope-resolved constant
/// (`Net::HTTPError`). Used to detect the two-argument
/// `raise ExceptionClass, message` form (audit M17).
fn ruby_is_exception_class(text: &str) -> bool {
    let head = text.trim().rsplit("::").next().unwrap_or("").trim();
    head.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && head.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn normalize_ruby_subshell_events(events: &mut [FlowEvent], src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                args,
                span,
                call_kind,
                ..
            } if name == "`" => {
                let source_names = ruby_subshell_arg_source_names(args);
                let value_text = ruby_span_text(src, *span)
                    .filter(|text| !text.trim().is_empty())
                    .map(|text| text.trim().to_string())
                    .unwrap_or_else(|| {
                        args.iter()
                            .map(|arg| arg.value_text.trim())
                            .filter(|text| !text.is_empty())
                            .collect::<Vec<_>>()
                            .join(" ")
                    });
                *call_kind = CallKind::Function;
                *args = vec![CallArg {
                    passing_mode: Default::default(),
                    span: *span,
                    name: None,
                    value_text,
                    place: None,
                    source_names,
                }];
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_ruby_subshell_events(then_events, src);
                normalize_ruby_subshell_events(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_ruby_subshell_events(body, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_ruby_subshell_events(body, src);
                normalize_ruby_subshell_events(catch_events, src);
                normalize_ruby_subshell_events(finally_events, src);
            }
            _ => {}
        }
    }
}

fn ruby_subshell_arg_source_names(args: &[CallArg]) -> Vec<String> {
    let mut source_names = Vec::new();
    for arg in args {
        for name in &arg.source_names {
            if name.is_empty() || source_names.iter().any(|seen| seen == name) {
                continue;
            }
            source_names.push(name.clone());
        }
    }
    source_names
}

fn normalize_ruby_instance_variable_events(decl: &mut bonsai_lang_api::Decl) {
    for write in &mut decl.receiver_field_writes {
        write.target = normalize_ruby_instance_variable_text(&write.target);
    }
    for source in &mut decl.receiver_state_sources {
        *source = normalize_ruby_instance_variable_text(source);
    }
    normalize_ruby_instance_variable_flow_events(&mut decl.flow_events);
}

fn normalize_ruby_instance_variable_flow_events(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                *target = normalize_ruby_instance_variable_text(target);
                normalize_optional_ruby_instance_variable_text(source_name);
                normalize_optional_ruby_instance_variable_text(source_call);
                normalize_ruby_instance_variable_texts(source_call_args);
                normalize_ruby_instance_variable_texts(source_names);
            }
            FlowEvent::AggregateAssign {
                target, value_flow, ..
            } => {
                *target = normalize_ruby_instance_variable_text(target);
                normalize_ruby_instance_variable_expression_flow(value_flow);
            }
            FlowEvent::Call {
                name, receiver, args, ..
            } => {
                *name = normalize_ruby_instance_variable_text(name);
                normalize_optional_ruby_instance_variable_text(receiver);
                for arg in args {
                    arg.value_text = normalize_ruby_instance_variable_text(&arg.value_text);
                    normalize_optional_ruby_instance_variable_text(&mut arg.place);
                    normalize_ruby_instance_variable_texts(&mut arg.source_names);
                    enrich_ruby_instance_variable_call_arg(arg);
                }
            }
            FlowEvent::Return {
                value_name,
                value_text,
                value_flow,
                ..
            } => {
                normalize_optional_ruby_instance_variable_text(value_name);
                normalize_optional_ruby_instance_variable_text(value_text);
                normalize_ruby_instance_variable_expression_flow(value_flow);
            }
            FlowEvent::Throw { value_name, .. } => {
                normalize_optional_ruby_instance_variable_text(value_name);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                normalize_optional_ruby_instance_variable_text(catch_param);
                normalize_ruby_instance_variable_flow_events(body);
                normalize_ruby_instance_variable_flow_events(catch_events);
                normalize_ruby_instance_variable_flow_events(finally_events);
            }
            FlowEvent::Branch {
                condition,
                then_events,
                else_events,
                ..
            } => {
                normalize_optional_ruby_instance_variable_text(condition);
                normalize_ruby_instance_variable_flow_events(then_events);
                normalize_ruby_instance_variable_flow_events(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_ruby_instance_variable_flow_events(body);
            }
            FlowEvent::Yield {
                value_text,
                value_flow,
                ..
            } => {
                normalize_optional_ruby_instance_variable_text(value_text);
                normalize_ruby_instance_variable_expression_flow(value_flow);
            }
            FlowEvent::Await { value_name, .. } => {
                normalize_optional_ruby_instance_variable_text(value_name);
            }
            FlowEvent::Lifecycle { name, .. } => {
                *name = normalize_ruby_instance_variable_text(name);
            }
            FlowEvent::Break { .. } | FlowEvent::Continue { .. } => {}
        }
    }
}

fn normalize_ruby_instance_variable_expression_flow(flow: &mut bonsai_lang_api::ExpressionFlow) {
    normalize_optional_ruby_instance_variable_text(&mut flow.place);
    normalize_ruby_instance_variable_texts(&mut flow.source_names);
    if let Some(projection) = &mut flow.projection {
        projection.base = normalize_ruby_instance_variable_text(&projection.base);
        normalize_ruby_instance_variable_texts(&mut projection.path);
    }
    for field in &mut flow.aggregate_fields {
        field.name = normalize_ruby_instance_variable_text(&field.name);
        normalize_ruby_instance_variable_expression_flow(&mut field.value);
    }
    for item in &mut flow.tuple_items {
        normalize_ruby_instance_variable_expression_flow(item);
    }
    for spread in &mut flow.spreads {
        normalize_ruby_instance_variable_expression_flow(spread);
    }
}

fn normalize_optional_ruby_instance_variable_text(value: &mut Option<String>) {
    if let Some(text) = value {
        *text = normalize_ruby_instance_variable_text(text);
    }
}

fn normalize_ruby_instance_variable_texts(values: &mut [String]) {
    for value in values {
        *value = normalize_ruby_instance_variable_text(value);
    }
}

fn enrich_ruby_instance_variable_call_arg(arg: &mut CallArg) {
    let Some(place) = ruby_normalized_instance_variable_place(&arg.value_text) else {
        return;
    };
    if arg.place.as_deref().is_none_or(str::is_empty) {
        arg.place = Some(place.clone());
    }
    if !arg.source_names.iter().any(|source| source == &place) {
        arg.source_names.push(place);
    }
    arg.source_names.sort();
    arg.source_names.dedup();
}

fn ruby_normalized_instance_variable_place(text: &str) -> Option<String> {
    let text = text.trim();
    let rest = text.strip_prefix("self.")?;
    if rest.is_empty() {
        return None;
    }
    if rest.split('.').all(ruby_identifier_part) {
        Some(text.to_string())
    } else {
        None
    }
}

fn ruby_identifier_part(part: &str) -> bool {
    let mut chars = part.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn normalize_ruby_instance_variable_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if let Some(active_quote) = quote {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }

        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            out.push(ch);
            continue;
        }

        if ch != '@' {
            out.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('@') => {
                out.push(ch);
                out.push('@');
                chars.next();
            }
            Some(next) if next == '_' || next.is_ascii_alphabetic() => {
                out.push_str("self.");
                while let Some(part) = chars.peek().copied() {
                    if part == '_' || part.is_ascii_alphanumeric() {
                        out.push(part);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

fn inject_ruby_hash_field_assigns(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut synthesized = Vec::new();
    for assignment in collect_kinds(tree, &["assignment"]) {
        let (Some(left), Some(right)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        let target = normalize_ruby_instance_variable_text(node_text(&left, src).trim());
        if target.is_empty() || !ruby_field_target_base_is_supported(&target) {
            continue;
        }
        collect_ruby_hash_field_assigns_for_target(&target, right, file, src, &mut synthesized);
    }
    if synthesized.is_empty() {
        return;
    }

    for event in synthesized {
        let span = event.span();
        let Some(decl) = idx
            .defs
            .iter_mut()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && decl_span_contains(decl, span)
            })
            .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
        else {
            continue;
        };
        if !decl.flow_events.iter().any(|existing| existing == &event) {
            decl.flow_events.push(event);
            decl.flow_events
                .sort_by_key(|event| (event.span().start, event.span().end));
        }
    }
}

fn ruby_field_target_base_is_supported(target: &str) -> bool {
    target
        .split('.')
        .all(|part| !part.is_empty() && part.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()))
}

fn decl_span_contains(decl: &bonsai_lang_api::Decl, span: Span) -> bool {
    let container = decl.body_span.unwrap_or(decl.span);
    container.file == span.file && container.start <= span.start && span.end <= container.end
}

fn collect_ruby_hash_field_assigns_for_target(
    target: &str,
    node: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<FlowEvent>,
) {
    if node.kind() == "hash" {
        collect_ruby_hash_pair_assigns(target, node, file, src, out);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_ruby_hash_field_assigns_for_target(target, child, file, src, out);
    }
}

fn collect_ruby_hash_pair_assigns(
    target: &str,
    hash: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<FlowEvent>,
) {
    let mut cursor = hash.walk();
    for child in hash.named_children(&mut cursor) {
        if child.kind() != "pair" {
            continue;
        }
        let Some(key) = child
            .child_by_field_name("key")
            .and_then(|key| ruby_hash_key_name(key, src))
        else {
            continue;
        };
        let Some(value) = child.child_by_field_name("value") else {
            continue;
        };
        let mut source_names = ruby_value_source_names(value, src);
        if source_names.is_empty() {
            continue;
        }
        source_names.sort();
        source_names.dedup();
        out.push(FlowEvent::Assign {
            span: span_of(file, &child),
            target: format!("{target}.{key}"),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names,
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        });
    }
}

fn ruby_hash_key_name(key: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&key, src)
        .trim()
        .trim_start_matches(':')
        .trim_matches('"')
        .trim_matches('\'')
        .trim();
    if raw.is_empty() || !raw.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(raw.to_string())
}

fn ruby_value_source_names(node: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    collect_ruby_value_source_names(node, src, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_ruby_value_source_names(node: tree_sitter::Node<'_>, src: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "identifier" | "constant" | "self" => {
            push_ruby_source_name(out, node_text(&node, src));
        }
        "instance_variable" => {
            push_ruby_source_name(out, &normalize_ruby_instance_variable_text(node_text(&node, src)));
        }
        "call" => {
            push_ruby_source_name(
                out,
                &normalize_ruby_instance_variable_text(node_text(&node, src).trim()),
            );
            if let Some(receiver) = node.child_by_field_name("receiver") {
                collect_ruby_value_source_names(receiver, src, out);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "argument_list" {
                    collect_ruby_value_source_names(child, src, out);
                }
            }
            return;
        }
        "element_reference" => {
            if let Some(access) = ruby_element_reference_name(node, src) {
                push_ruby_source_name(out, &access);
            }
        }
        "hash_key_symbol" | "simple_symbol" | "integer" | "float" | "string_content" => {}
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_ruby_value_source_names(child, src, out);
    }
}

fn ruby_element_reference_name(node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let object = node
        .child_by_field_name("object")
        .map(|object| normalize_ruby_instance_variable_text(node_text(&object, src).trim()))?;
    let mut cursor = node.walk();
    let key = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "simple_symbol" || child.kind() == "string")
        .and_then(|key| ruby_hash_key_name(key, src))?;
    (!object.is_empty()).then(|| format!("{object}.{key}"))
}

fn push_ruby_source_name(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with(':')
        || value.starts_with('"')
        || value.starts_with('\'')
        || value.chars().all(|ch| ch.is_ascii_digit())
    {
        return;
    }
    if !out.iter().any(|existing| existing == value) {
        out.push(value.to_string());
    }
}

fn inject_ruby_bare_method_arg_calls(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut candidates = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        for arg in arguments.named_children(&mut cursor) {
            if arg.kind() != "identifier" {
                continue;
            }
            let name = node_text(&arg, src).trim();
            if !ruby_bare_method_candidate(name) {
                continue;
            }
            candidates.push((span_of(file, &arg), name.to_string()));
        }
    }
    if candidates.is_empty() {
        return;
    }

    for (span, name) in candidates {
        let Some(decl) = idx
            .defs
            .iter_mut()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && decl_span_contains(decl, span)
            })
            .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
        else {
            continue;
        };
        let locals = ruby_local_bindings_for_decl(decl);
        if locals.contains(name.as_str()) {
            continue;
        }
        let event = FlowEvent::Call {
            span,
            name,
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        };
        if !decl.flow_events.iter().any(|existing| existing == &event) {
            decl.flow_events.push(event);
            decl.flow_events
                .sort_by_key(|event| (event.span().start, event.span().end));
        }
    }
}

fn ruby_bare_method_candidate(name: &str) -> bool {
    !name.is_empty()
        && !matches!(
            name,
            "nil" | "true" | "false" | "self" | "super" | "yield" | "return" | "break" | "next"
        )
        && name
            .chars()
            .all(|ch| ch == '_' || ch == '!' || ch == '?' || ch.is_ascii_alphanumeric())
        && name
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
}

fn ruby_local_bindings_for_decl(decl: &bonsai_lang_api::Decl) -> std::collections::BTreeSet<String> {
    let mut locals: std::collections::BTreeSet<String> = decl
        .params
        .iter()
        .filter_map(|param| ruby_bare_binding_name(param))
        .collect();
    collect_ruby_local_bindings(&decl.flow_events, &mut locals);
    locals
}

fn collect_ruby_local_bindings(events: &[FlowEvent], locals: &mut std::collections::BTreeSet<String>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } => {
                if let Some(name) = ruby_bare_binding_name(target) {
                    locals.insert(name);
                }
            }
            FlowEvent::AggregateAssign { target, .. } => {
                if let Some(name) = ruby_bare_binding_name(target) {
                    locals.insert(name);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                if let Some(param) = catch_param.as_deref().and_then(ruby_bare_binding_name) {
                    locals.insert(param);
                }
                collect_ruby_local_bindings(body, locals);
                collect_ruby_local_bindings(catch_events, locals);
                collect_ruby_local_bindings(finally_events, locals);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_ruby_local_bindings(then_events, locals);
                collect_ruby_local_bindings(else_events, locals);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_ruby_local_bindings(body, locals);
            }
            FlowEvent::Call { .. }
            | FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Yield { .. }
            | FlowEvent::Await { .. }
            | FlowEvent::Lifecycle { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. } => {}
        }
    }
}

fn ruby_bare_binding_name(value: &str) -> Option<String> {
    let name = value.trim();
    if name.is_empty() || name.contains('.') || name.contains('[') || name.starts_with('@') {
        return None;
    }
    ruby_bare_method_candidate(name).then(|| name.to_string())
}

/// Promote paren-less method calls that sit in an assignment's value
/// position into call-result assignments.
///
/// tree-sitter-ruby parses a receiver-less, argument-less method call
/// in value position (`cmd = get_input`, `v = gets`) as a bare
/// `identifier`, syntactically identical to a local-variable read. The
/// flow walker therefore emits `cmd = get_input` as a simple-rename
/// `Assign { source_name: Some("get_input"), value_kind: Compound }`
/// with no `Call` sibling — so the IDG stitches no call edge and the
/// callee's tainted return never reaches the target. The paren form
/// (`get_input()`) instead yields `Assign { source_call: "get_input",
/// value_kind: CallResult }` plus a sibling `Call`, which taints
/// correctly.
///
/// Ruby's own disambiguation rule (the same one its parser uses): a
/// bareword is a local-variable reference iff a local of that name is
/// bound in the enclosing scope; otherwise a receiver-less bareword
/// naming a method is a method call. We apply exactly that rule —
/// rewriting a simple-rename `Assign` into the call-result shape only
/// when the RHS bareword is NOT bound as a local/param anywhere in the
/// method — and emit the sibling arg-less `Call` so the paren-less
/// form produces the identical shape to the working paren form.
///
/// FP-safety: taint reaches the target via the pre-existing
/// simple-rename path only when the RHS names a *tainted local*, which
/// must have been bound earlier and is therefore excluded by the local
/// guard (locals/params always stay reads). When the bareword is never
/// bound in the method it can carry no variable-level taint today, so
/// the rewrite is purely additive: it can introduce the (correct)
/// callee-return edge but never remove a working one. An unresolved
/// callee yields no return summary, so the engine leaves the target
/// clean — the same behaviour the paren form already exhibits.
fn rewrite_ruby_bareword_call_result_assigns(
    decl: &mut bonsai_lang_api::Decl,
    block_param_names: &std::collections::BTreeSet<String>,
) {
    // Method-wide local set (params + every assignment target). Block and
    // lambda parameters (`each do |x|`, `->(x){}`) do NOT surface as Assign
    // targets — a block variable is bound by the loop, not written — so they
    // are folded in from `block_param_names` (collected from the tree by the
    // caller). Without this, a block variable that shares a method name
    // (`each do |line| ...`, with a `def line`) is wrongly promoted to a call
    // (a false positive). Collecting method-wide rather than
    // lexically-before-use is strictly conservative: it can only keep more
    // barewords as reads, never fewer.
    let mut locals = ruby_local_bindings_for_decl(decl);
    locals.extend(block_param_names.iter().cloned());
    rewrite_ruby_bareword_assigns_in_events(&mut decl.flow_events, &locals);
}

/// Paren-less method calls in TAIL position: `def get_input; gets; end`
/// parses the bare `gets` as an identifier, so the tail-return synthesis
/// records `Return { value_name: "gets" }` and NO Call event exists — the
/// source matcher never sees a `gets` call and the wrapper's taint is
/// silently lost. Mirror of [`inject_ruby_bare_method_arg_calls`] for the
/// return position: when a Return's value is a bare word that is not a
/// local, param, or block variable, it IS a method call under Ruby
/// semantics — synthesize the Call event at the tail span so matching and
/// the call-ret→Return stitch both see it.
fn inject_ruby_bare_tail_return_calls(
    decl: &mut bonsai_lang_api::Decl,
    block_param_names: &std::collections::BTreeSet<String>,
) {
    let mut locals = ruby_local_bindings_for_decl(decl);
    locals.extend(block_param_names.iter().cloned());
    let mut sites = Vec::new();
    collect_ruby_bare_tail_call_sites(&decl.flow_events, &locals, &mut sites);
    if sites.is_empty() {
        return;
    }
    let mut changed = false;
    for (span, name) in sites {
        let event = FlowEvent::Call {
            span,
            name,
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        };
        if !decl.flow_events.iter().any(|existing| existing == &event) {
            decl.flow_events.push(event);
            changed = true;
        }
    }
    if changed {
        decl.flow_events
            .sort_by_key(|event| (event.span().start, event.span().end));
    }
}

fn collect_ruby_bare_tail_call_sites(
    events: &[FlowEvent],
    locals: &std::collections::BTreeSet<String>,
    out: &mut Vec<(Span, String)>,
) {
    for event in events {
        match event {
            FlowEvent::Return {
                span,
                value_name: Some(name),
                value_flow,
                ..
            } => {
                // Only the exact bare-word shape: the whole return value
                // is the identifier itself. Compound returns
                // (`gets.chomp`, `a + b`) already carry real Call events
                // or operand reads.
                if value_flow.place.as_deref() == Some(name.as_str())
                    && ruby_bare_method_candidate(name)
                    && !locals.contains(name.as_str())
                {
                    out.push((*span, name.clone()));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_ruby_bare_tail_call_sites(then_events, locals, out);
                collect_ruby_bare_tail_call_sites(else_events, locals, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_ruby_bare_tail_call_sites(body, locals, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_ruby_bare_tail_call_sites(body, locals, out);
                collect_ruby_bare_tail_call_sites(catch_events, locals, out);
                collect_ruby_bare_tail_call_sites(finally_events, locals, out);
            }
            _ => {}
        }
    }
}

/// Names bound as block / lambda parameters anywhere in the file
/// (`xs.each do |item|`, `xs.map { |x| }`, `->(y){}`). These shadow method
/// names inside their block, so a value-position bareword naming one must
/// stay a variable read, never be promoted to a method call. Collected
/// file-wide (a conservative over-set) so the promotion never mistakes a
/// block variable for a paren-less call.
fn collect_ruby_block_param_names(tree: &Tree, src: &[u8]) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for params in collect_kinds(tree, &["block_parameters", "lambda_parameters"]) {
        collect_ruby_param_identifiers(params, src, &mut names);
    }
    names
}

/// Ruby's parser represents `read_input.to_s` with `read_input` as an
/// identifier receiver. Ruby itself resolves that identifier as a local only
/// when the enclosing scope binds it; otherwise it is an implicit-receiver,
/// zero-argument method call whose result becomes the receiver of `to_s`.
/// Materialize that compiler relation as `CallRet(read_input) -> read_input`
/// so nested source calls and ordinary user methods are visible without
/// guessing names in shared analysis.
fn inject_ruby_unbound_receiver_calls(
    index: &mut DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
    block_param_names: &std::collections::BTreeSet<String>,
) {
    let mut candidates = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let Some(receiver) = call.child_by_field_name("receiver") else {
            continue;
        };
        if receiver.kind() != "identifier" || call.child_by_field_name("method").is_none() {
            continue;
        }
        let name = node_text(&receiver, src).trim();
        if ruby_bare_method_candidate(name) {
            candidates.push((span_of(file, &receiver), name.to_string()));
        }
    }

    for (span, name) in candidates {
        let Some(decl) = index
            .defs
            .iter_mut()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && decl_span_contains(decl, span)
            })
            .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
        else {
            continue;
        };
        let mut locals = ruby_local_bindings_for_decl(decl);
        locals.extend(block_param_names.iter().cloned());
        if locals.contains(name.as_str()) {
            continue;
        }

        let call = FlowEvent::Call {
            span,
            name: name.clone(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        };
        let result = FlowEvent::Assign {
            span,
            target: name.clone(),
            source_name: None,
            source_call: Some(name),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
        };
        if !decl.flow_events.iter().any(|event| event == &call) {
            decl.flow_events.push(call);
            decl.flow_events.push(result);
            decl.flow_events
                .sort_by_key(|event| (event.span().start, event.span().end));
        }
    }
}

fn collect_ruby_param_identifiers(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    out: &mut std::collections::BTreeSet<String>,
) {
    if node.kind() == "identifier" {
        if let Some(name) = ruby_bare_binding_name(node_text(&node, src).trim()) {
            out.insert(name);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_ruby_param_identifiers(child, src, out);
    }
}

fn rewrite_ruby_bareword_assigns_in_events(
    events: &mut Vec<FlowEvent>,
    locals: &std::collections::BTreeSet<String>,
) {
    // Recurse into nested regions with the same method-wide local set.
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_ruby_bareword_assigns_in_events(then_events, locals);
                rewrite_ruby_bareword_assigns_in_events(else_events, locals);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_ruby_bareword_assigns_in_events(body, locals);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_ruby_bareword_assigns_in_events(body, locals);
                rewrite_ruby_bareword_assigns_in_events(catch_events, locals);
                rewrite_ruby_bareword_assigns_in_events(finally_events, locals);
            }
            _ => {}
        }
    }

    if !events
        .iter()
        .any(|event| ruby_bareword_call_result_name(event, locals).is_some())
    {
        return;
    }
    // Preserve source order and insert each synthetic arg-less Call
    // immediately after the promoted Assign, mirroring the paren form's
    // `Assign{CallResult}` + `Call` pairing. Order-preserving, so the
    // pass is deterministic.
    let mut rewritten = Vec::with_capacity(events.len() + 1);
    for event in events.drain(..) {
        match ruby_bareword_call_result_name(&event, locals) {
            Some(call_name) => {
                let span = event.span();
                rewritten.push(promote_ruby_bareword_assign_to_call_result(event, &call_name));
                rewritten.push(FlowEvent::Call {
                    span,
                    name: call_name,
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args: Vec::new(),
                });
            }
            None => rewritten.push(event),
        }
    }
    *events = rewritten;
}

/// If `event` is a simple-rename assignment (`target = bareword`) whose
/// RHS bareword names a method rather than a bound local, return the
/// method name. `None` for anything else — the guard that keeps locals,
/// params, literals, compound RHS, and already-a-call assigns as reads.
fn ruby_bareword_call_result_name(
    event: &FlowEvent,
    locals: &std::collections::BTreeSet<String>,
) -> Option<String> {
    let FlowEvent::Assign {
        source_name: Some(name),
        source_call: None,
        source_names,
        value_kind,
        ..
    } = event
    else {
        return None;
    };
    // Simple-name RHS only: `source_name` is contractually a single bare
    // identifier and `source_names` must carry nothing beyond it (a
    // compound RHS leaves `source_name` empty). Anything else is not a
    // bare paren-less-call candidate.
    if !source_names.iter().all(|carrier| carrier == name) {
        return None;
    }
    // Never reclassify a literal, an already-resolved call, or a yield
    // RHS. A bare identifier read is Compound / Unknown / unset.
    if matches!(
        value_kind,
        Some(
            bonsai_lang_api::AssignValueKind::Literal
                | bonsai_lang_api::AssignValueKind::CallResult
                | bonsai_lang_api::AssignValueKind::YieldResult
                | bonsai_lang_api::AssignValueKind::CallableReference
        )
    ) {
        return None;
    }
    // Ruby's rule: a bareword bound as a local/param is a variable read.
    if locals.contains(name.as_str()) {
        return None;
    }
    // The bareword must have the lexical shape of a Ruby method name.
    ruby_bare_method_candidate(name).then(|| name.clone())
}

/// Rewrite a qualifying simple-rename `Assign` into the call-result
/// shape: drop the read-style `source_name` / `source_names`, set
/// `source_call` to the callee, and mark the RHS `CallResult`.
fn promote_ruby_bareword_assign_to_call_result(event: FlowEvent, call_name: &str) -> FlowEvent {
    let FlowEvent::Assign {
        span,
        target,
        declares_new_binding,
        ..
    } = event
    else {
        return event;
    };
    FlowEvent::Assign {
        span,
        target,
        source_name: None,
        source_call: Some(call_name.to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding,
        value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
    }
}

fn ruby_span_text(src: &[u8], span: Span) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    let bytes = src.get(start..end)?;
    std::str::from_utf8(bytes).ok()
}

fn apply_ruby_class_semantic_identity(idx: &mut DeclIndex) {
    // Ruby modules are lexical namespace owners, not just display wrappers.
    // The generic declaration pass records that ownership in `Decl.parent`;
    // materialize it into `module_path` so a constant-qualified call such as
    // `Tokenizer.each_token` resolves against the exact AST-declared module.
    // Without this step every module method retained only the file module
    // (`pipeline`) even though its qualified name correctly included the
    // lexical owner (`pipeline::Tokenizer::each_token`).
    let owners = idx
        .defs
        .iter()
        .map(|decl| (decl.symbol, (decl.parent, decl.kind, decl.name.clone())))
        .collect::<std::collections::HashMap<_, _>>();
    for decl in &mut idx.defs {
        let mut owner = if decl.kind == DeclKind::Module {
            Some(decl.symbol)
        } else {
            decl.parent
        };
        let mut module_names = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while let Some(symbol) = owner {
            if !seen.insert(symbol) {
                break;
            }
            let Some((parent, kind, name)) = owners.get(&symbol) else {
                break;
            };
            if *kind == DeclKind::Module {
                module_names.push(name.clone());
            }
            owner = *parent;
        }
        module_names.reverse();
        for module_name in module_names {
            if decl.module_path.segments.last() != Some(&module_name) {
                decl.module_path.segments.push(module_name);
            }
        }
    }

    let mut classes: Vec<(Span, String, bonsai_common::SymbolId)> = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.name.clone(), decl.symbol))
        .collect();
    classes.sort_by_key(|(span, _, _)| span.end.saturating_sub(span.start));
    if classes.is_empty() {
        return;
    }
    for decl in &mut idx.defs {
        if is_class_like(decl.kind) {
            let mut segments = decl.module_path.segments.clone();
            segments.push(decl.name.clone());
            decl.module_path = ModulePath::from_segments(segments.iter().cloned());
            decl.qualified_name = Some(segments.join("."));
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some((_, class_name, class_symbol)) = classes
            .iter()
            .filter(|(span, _, _)| span.start <= decl.span.start && span.end >= decl.span.end)
            .min_by_key(|(span, _, _)| span.end.saturating_sub(span.start))
        else {
            continue;
        };
        decl.parent = Some(*class_symbol);
        let mut segments = decl.module_path.segments.clone();
        segments.push(class_name.clone());
        decl.module_path = ModulePath::from_segments(segments.iter().cloned());
        decl.qualified_name = Some(format!("{}.{}", segments.join("."), decl.name));
    }
}

/// Apply Ruby's scope-marker visibility to method decls. Ruby's
/// `private` / `protected` / `public` keywords (used as bare
/// statements inside a class / module body) change the default
/// visibility of subsequent `def` definitions until another marker
/// flips the scope. The keyword form `private :foo, :bar` flips a
/// specific list of names rather than a scope.
///
/// Visibility comes from real syntax. The kit's modifier-vocabulary
/// path doesn't model line-scoped visibility, so this adapter walks
/// the parsed tree directly.
fn apply_ruby_scope_visibility(idx: &mut DeclIndex, tree: &Tree, src: &[u8], file: FileId) {
    // Map (start_byte, end_byte) of each method decl in the index to
    // the span we'll patch when we find the matching tree node.
    let mut visibility_overrides: std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility> =
        std::collections::HashMap::new();
    walk_class_bodies(
        tree.root_node(),
        src,
        file,
        bonsai_lang_api::Visibility::Public,
        &mut visibility_overrides,
    );
    for decl in &mut idx.defs {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        if let Some(visibility) = visibility_overrides.get(&(decl.span.start, decl.span.end)) {
            decl.visibility = *visibility;
        }
    }
}

/// Walk the tree, find each `class` / `module` / `singleton_class`,
/// and run the scope-tracking pass over its body. Each body resets to
/// `Public` — Ruby scope markers don't bleed between sibling classes.
fn walk_class_bodies(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    file: FileId,
    inherited_scope: bonsai_lang_api::Visibility,
    out: &mut std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility>,
) {
    // Ruby tree-sitter exposes class / module / singleton bodies as
    // `body_statement` children of `class` / `module` / `singleton_class`.
    // Inside those bodies we track the current scope marker.
    match node.kind() {
        "class" | "module" | "singleton_class" => {
            let mut scope = bonsai_lang_api::Visibility::Public;
            if let Some(body) = node.child_by_field_name("body") {
                walk_body_statements(body, src, file, &mut scope, out);
            } else {
                // Fall back to scanning all named children — ts-ruby
                // grammar uses `body_statement` as a named child.
                let mut child_cursor = node.walk();
                for child in node.named_children(&mut child_cursor) {
                    if child.kind() == "body_statement" {
                        walk_body_statements(child, src, file, &mut scope, out);
                    }
                }
            }
        }
        _ => {}
    }
    // Recurse: nested classes and modules need their own scope tracking.
    let mut child_cursor = node.walk();
    for child in node.named_children(&mut child_cursor) {
        walk_class_bodies(child, src, file, inherited_scope, out);
    }
}

/// Iterate one class / module body in source order, mutating
/// `current_scope` as scope markers appear and tagging each `def` /
/// `singleton_method` with the active scope. The scope is line-relative
/// — markers only affect defs that follow them inside the same body.
fn walk_body_statements(
    body: tree_sitter::Node<'_>,
    src: &[u8],
    file: FileId,
    current_scope: &mut bonsai_lang_api::Visibility,
    out: &mut std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility>,
) {
    let mut body_cursor = body.walk();
    for stmt in body.named_children(&mut body_cursor) {
        match stmt.kind() {
            // Bare scope marker: `private` / `protected` / `public` /
            // `module_function` alone on a line flips the default for
            // subsequent defs. tree-sitter-ruby parses arg-less calls
            // to those methods as bare identifiers, not `call` nodes.
            "identifier" => {
                let text = std::str::from_utf8(&src[stmt.byte_range()]).unwrap_or("");
                match text {
                    "private" => *current_scope = bonsai_lang_api::Visibility::Private,
                    "protected" => *current_scope = bonsai_lang_api::Visibility::Protected,
                    "public" => *current_scope = bonsai_lang_api::Visibility::Public,
                    // `module_function` flips the dual-mode (private
                    // instance, public module-level). The
                    // resolver-relevant half is the public surface;
                    // model as Public.
                    "module_function" => *current_scope = bonsai_lang_api::Visibility::Public,
                    _ => {}
                }
            }
            // Modifier with arg list: `private :foo, :bar`. Tags the
            // listed methods only — does NOT flip the scope. Also
            // covers `module_function :name` (Ruby's "make `name` both
            // private instance and public module-level"), which we
            // model as a Public override on the named method, plus the
            // `attr_reader` / `attr_writer` / `attr_accessor` forms
            // which declare *new* synthetic methods that don't exist
            // as `def` decls — but if the declaration sits inside a
            // public scope region, we keep the default scope, and if
            // it sits inside a private region the kit's scope-marker
            // path already handles the surrounding visibility.
            "call" => {
                let method_node = stmt.child_by_field_name("method");
                let method_text = method_node
                    .map(|method| std::str::from_utf8(&src[method.byte_range()]).unwrap_or(""))
                    .unwrap_or("");
                let target_visibility = match method_text {
                    "private" => Some(bonsai_lang_api::Visibility::Private),
                    "protected" => Some(bonsai_lang_api::Visibility::Protected),
                    "public" => Some(bonsai_lang_api::Visibility::Public),
                    // `module_function :name` — exposes `name` as a
                    // public module-level method while keeping it
                    // private as an instance method. We tag the
                    // matching `def` Public so cross-module callers
                    // can resolve it.
                    "module_function" => Some(bonsai_lang_api::Visibility::Public),
                    _ => None,
                };
                if let Some(visibility) = target_visibility {
                    if let Some(args) = stmt.child_by_field_name("arguments") {
                        let mut arg_cursor = args.walk();
                        for arg in args.named_children(&mut arg_cursor) {
                            // Only `:name` symbols name a target; bare
                            // identifiers in the arg list are treated
                            // as locals by Ruby and ignored here.
                            if arg.kind() != "simple_symbol" {
                                continue;
                            }
                            let raw_symbol = std::str::from_utf8(&src[arg.byte_range()]).unwrap_or("");
                            let target_name = raw_symbol.trim_start_matches(':');
                            if target_name.is_empty() {
                                continue;
                            }
                            // Find a method def in this body with the
                            // same name and tag it.
                            let mut sibling_cursor = body.walk();
                            for sibling in body.named_children(&mut sibling_cursor) {
                                if sibling.kind() != "method" && sibling.kind() != "singleton_method" {
                                    continue;
                                }
                                let name_node = sibling.child_by_field_name("name");
                                let sibling_name = name_node
                                    .map(|name| std::str::from_utf8(&src[name.byte_range()]).unwrap_or(""))
                                    .unwrap_or("");
                                if sibling_name == target_name {
                                    let span = span_of(file, &sibling);
                                    out.insert((span.start, span.end), visibility);
                                }
                            }
                        }
                    }
                }
                // `module_function` with no args (bare keyword form)
                // flips the scope for subsequent defs to the dual
                // private-instance/public-module mode. From the
                // resolver's perspective the public module-level half
                // is what matters, so we treat it as a Public scope
                // flip for the rest of the body.
                if method_text == "module_function" {
                    let no_args = match stmt.child_by_field_name("arguments") {
                        None => true,
                        Some(args) => args.named_child_count() == 0,
                    };
                    if no_args {
                        *current_scope = bonsai_lang_api::Visibility::Public;
                    }
                }
            }
            "method" | "singleton_method" => {
                let span = span_of(file, &stmt);
                // Don't overwrite an explicit `private :foo` tag.
                out.entry((span.start, span.end)).or_insert(*current_scope);
            }
            _ => {}
        }
    }
}

/// True for any `DeclKind` that can carry a `bases` list. Ruby only
/// has `Class` itself, but the predicate is shared with the
/// post-processing loop and matches the shape used by the other adapters.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Ruby `class` declarations and collect the single optional
/// superclass from the `superclass:` field. Grammar shape (verified):
///
///   `class Echo < Base; … end` →
///     (class name: (constant) superclass: (superclass (constant)) body: …)
///
/// Ruby has no interfaces and no multiple class inheritance. `include` and
/// `prepend` are executable class-body syntax that add modules to the
/// instance ancestor chain, so retain their parser-proven constant arguments
/// beside the superclass. API meaning remains in rule data.
fn collect_ruby_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_table = Vec::new();
    for class_node in collect_kinds(tree, &["class"]) {
        let class_name = class_node
            .child_by_field_name("name")
            .map(|node| node_text(&node, src).to_string())
            .unwrap_or_default();
        let mut bases: Vec<String> = Vec::new();
        if let Some(superclass_node) = class_node.child_by_field_name("superclass") {
            // `superclass` wrapper has one named child — the constant
            // / scope_resolution naming the parent.
            let mut sc_cursor = superclass_node.walk();
            for child in superclass_node.named_children(&mut sc_cursor) {
                for name in canonical_ruby_base_names(node_text(&child, src)) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if let Some(body) = class_node.child_by_field_name("body") {
            let mut body_cursor = body.walk();
            for statement in body.named_children(&mut body_cursor) {
                if statement.kind() != "call" {
                    continue;
                }
                let Some(method) = statement.child_by_field_name("method") else {
                    continue;
                };
                if !matches!(node_text(&method, src).trim(), "include" | "prepend") {
                    continue;
                }
                let Some(arguments) = statement.child_by_field_name("arguments") else {
                    continue;
                };
                let mut argument_cursor = arguments.walk();
                for argument in arguments.named_children(&mut argument_cursor) {
                    if !matches!(argument.kind(), "constant" | "scope_resolution") {
                        continue;
                    }
                    for name in canonical_ruby_base_names(node_text(&argument, src)) {
                        if !bases.iter().any(|existing| existing == &name) {
                            bases.push(name);
                        }
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_table.push((span_of(file, &class_node), class_name, bases));
        }
    }
    bases_table
}

/// Preserve an exact qualified Ruby superclass plus its bare resolver key.
///
/// `Foo::Bar::Baz` is a real semantic identity used by class-constrained
/// rules and must not collapse to every unrelated `Baz`. Existing inherited
/// method resolution keys on the unqualified tail, so both facts are emitted.
fn canonical_ruby_base_names(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let qualified = trimmed.trim_start_matches("::").trim();
    if qualified.is_empty() {
        return Vec::new();
    }
    let bare = qualified.rsplit("::").next().unwrap_or(qualified).trim();
    if bare == qualified {
        vec![qualified.to_string()]
    } else {
        vec![qualified.to_string(), bare.to_string()]
    }
}

/// Lower Ruby's static string-key element reads into field-like compiler
/// facts. `env["QUERY_STRING"]` becomes `env.QUERY_STRING`; comments,
/// unrelated string literals, interpolated keys, and element writes do not
/// create reads. Security policy remains in the rulepack rather than in this
/// adapter.
fn extract_ruby_static_element_key_refs(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    let mut refs = Vec::new();
    for element in collect_kinds(tree, &["element_reference"]) {
        if ruby_element_reference_is_write(&element) {
            continue;
        }
        let Some(object) = element.child_by_field_name("object") else {
            continue;
        };
        let object_name = node_text(&object, src).trim();
        if object_name.is_empty() {
            continue;
        }
        let mut cursor = element.walk();
        for argument in element.named_children(&mut cursor) {
            if argument.id() == object.id() || argument.kind() != "string" {
                continue;
            }
            let mut string_cursor = argument.walk();
            let parts = argument.named_children(&mut string_cursor).collect::<Vec<_>>();
            let [content] = parts.as_slice() else {
                continue;
            };
            if content.kind() != "string_content" {
                continue;
            }
            let key = node_text(content, src).trim();
            if key.is_empty() {
                continue;
            }
            refs.push(Ref {
                span: span_of(file, content),
                name: format!("{object_name}.{key}"),
                kind: RefKind::Read,
                scope: None,
                resolved: None,
            });
        }
    }
    refs
}

fn ruby_element_reference_is_write(node: &tree_sitter::Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !matches!(parent.kind(), "assignment" | "operator_assignment") {
        return false;
    }
    parent
        .child_by_field_name("left")
        .is_some_and(|left| left.id() == node.id())
}

fn collect_ruby_erb_implicit_inputs(tree: &Tree, src: &[u8]) -> Vec<String> {
    let mut inputs = collect_kinds(tree, &["instance_variable"])
        .into_iter()
        .map(|node| normalize_ruby_instance_variable_text(node_text(&node, src).trim()))
        .filter(|input| ruby_normalized_instance_variable_place(input).is_some())
        .collect::<Vec<_>>();
    inputs.sort();
    inputs.dedup();
    inputs
}

/// Build the exact same-width masks that project an ERB/RHTML host document
/// into its embedded Ruby program. HTML, delimiters, and ERB comments are
/// masked; statement and expression bodies remain unchanged.
///
/// Line breaks are preserved — every replacement is whitespace of
/// the same byte length, so column / line positions in the resulting
/// tree-sitter node match the original `.erb` source.
fn erb_parser_mask_edits(input: &str) -> Option<Vec<ParseRecoveryEdit>> {
    let bytes = input.as_bytes();
    let mut ruby_ranges = Vec::<std::ops::Range<usize>>::new();
    let mut separators = Vec::<usize>::new();
    let mut cursor = 0;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] == b'<' && bytes[cursor + 1] == b'%' {
            // Skip optional `=` / `-` / `#` (ERB comment / silent / value).
            let tag_start = cursor;
            let escaped_tag = bytes.get(tag_start + 2).copied() == Some(b'%');
            let mut content_start = cursor + 2;
            while content_start < bytes.len() && matches!(bytes[content_start], b'=' | b'-' | b'#') {
                content_start += 1;
            }
            // Find closing `%>`.
            let mut close_start = content_start;
            while close_start + 1 < bytes.len() {
                if bytes[close_start] == b'%' && bytes[close_start + 1] == b'>' {
                    break;
                }
                close_start += 1;
            }
            if close_start + 1 >= bytes.len() {
                // An unclosed ERB tag is a real template syntax error. Leave
                // the raw source untouched so the diagnostic remains visible.
                return None;
            }
            let content_end = close_start
                .checked_sub(1)
                .filter(|index| bytes.get(*index).copied() == Some(b'-'))
                .unwrap_or(close_start);
            // Retain Ruby content [content_start..content_end]. A semicolon at
            // the close delimiter models the statement boundary ERB inserts;
            // plain whitespace would accidentally concatenate adjacent output
            // expressions that share one HTML line.
            // ERB comments (`<%# ... %>`) — masked, not surfaced as
            // Ruby. Escaped `<%%` tags are host text, not Ruby either.
            let is_comment = bytes.get(tag_start + 2).copied() == Some(b'#');
            if !is_comment && !escaped_tag && content_start < content_end {
                ruby_ranges.push(content_start..content_end);
                separators.push(close_start);
            }
            // Skip past `%>` (and an optional trailing `-` for trim form).
            cursor = close_start + 2;
            if cursor < bytes.len() && bytes[cursor] == b'-' {
                cursor += 1;
            }
            continue;
        }
        cursor += 1;
    }

    let mut retained = ruby_ranges;
    retained.extend(separators.iter().map(|offset| *offset..offset.saturating_add(1)));
    retained.sort_by_key(|range| (range.start, range.end));

    let mut edits = Vec::with_capacity(retained.len().saturating_add(separators.len() + 1));
    let mut masked_from = 0usize;
    for range in retained {
        if masked_from < range.start {
            edits.push(ParseRecoveryEdit::new(masked_from, range.start));
        }
        masked_from = range.end;
    }
    if masked_from < bytes.len() {
        edits.push(ParseRecoveryEdit::new(masked_from, bytes.len()));
    }
    edits.extend(
        separators
            .into_iter()
            .map(|offset| ParseRecoveryEdit::replace_ascii(offset, offset + 1, b";")),
    );
    Some(edits)
}

/// Lift every `require` / `require_relative` / `load` / `autoload`
/// call into an `ImportSpec`. Ruby has no native import keyword; these
/// method calls are the convention and the only handle the resolver has.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // tree-sitter-ruby parses each loader call as a `call` node whose
    // `method:` is the function name and whose `arguments:` carries
    // the module string.
    for call_node in collect_kinds(tree, &["call"]) {
        let Some(method_node) = call_node.child_by_field_name("method") else {
            continue;
        };
        let method = node_text(&method_node, src);
        if !matches!(method, "require" | "require_relative" | "load" | "autoload") {
            continue;
        }
        let Some(args) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        let module = first_named_child_of_kind(&args, "string")
            .and_then(|string_node| first_named_child_of_kind(&string_node, "string_content"))
            .map(|content| node_text(&content, src).to_string())
            .unwrap_or_default();
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &call_node),
            module: module.clone(),
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if matches!(method, "require" | "require_relative" | "load") {
            imports.push(ImportSpec {
                span: span_of(file, &call_node),
                module: module.clone(),
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Local,
            });
            if let Some(stem) = module.rsplit(['/', '\\']).next() {
                let constant = ruby_constant_name_from_snake_case(stem);
                if !constant.is_empty() && constant != module {
                    imports.push(ImportSpec {
                        span: span_of(file, &call_node),
                        module,
                        alias: Some(constant),
                        is_wildcard: true,
                        original_name: None,
                        // Resolver-only constant binding inferred
                        // from the loader target (`user_service` ->
                        // `UserService`). The visible import row is
                        // still the require/load statement itself.
                        scope: ImportScope::Local,
                    });
                }
            }
        }
    }
    for assignment in collect_kinds(tree, &["assignment"]) {
        if inside_ruby_executable_scope(assignment) {
            continue;
        }
        let (Some(left), Some(right)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if left.kind() != "constant" || right.kind() != "constant" {
            continue;
        }
        let alias = node_text(&left, src).trim();
        let module = node_text(&right, src).trim();
        if alias.is_empty() || module.is_empty() || alias == module {
            continue;
        }
        if imports.iter().any(|import| {
            import.alias.as_deref() == Some(alias)
                && import.module == module
                && import.original_name.is_none()
        }) {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &assignment),
            module: module.to_string(),
            alias: Some(alias.to_string()),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn ruby_constant_name_from_snake_case(stem: &str) -> String {
    stem.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            let Some(first) = chars.next() else {
                return String::new();
            };
            let mut out = String::new();
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
            out
        })
        .collect::<String>()
}

fn inside_ruby_executable_scope(node: tree_sitter::Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "method" | "singleton_method" | "block" | "do_block"
        ) {
            return true;
        }
        parent = current.parent();
    }
    false
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
