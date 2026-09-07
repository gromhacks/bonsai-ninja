//! Swift language adapter.
mod parse_recovery;

use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_modifier_visibility, collect_param_type_aliases, decl_index_from_tree_with_handler,
    extract_imports_via,
    kit::{
        collect_kinds, collect_receiver_field_writes, collect_receiver_state_sources,
        expression_flow_from_node_with_handler, first_identifier_like_child, first_named_child_of_kind,
        language_from_pack, node_at_span, node_text, parse_with, span_of, walk_flow_events,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, AssignValueKind, AssignmentNodeSemantics, CallKind,
    CallReceiverRole, CallTargetExtraction, Decl, DeclIndex, DeclKind, ExpressionPlaceExtraction,
    FiniteLiteralSelectionFact, FlowEvent, GrammarHandler, ImplicitMemberReadCall, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModifierVocabulary,
    PatternSourceProjection, ProjectedPatternBindingSite, StaticScalarValue, StringCompositionFact,
    StringCompositionPart, TypeAliasBinding, TypeAliasVocabulary, Visibility, EMPTY_HANDLER,
};
use tree_sitter::Node;

const SWIFT_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_declaration", "init_declaration"],
    // `property_declaration` captures typed locals (`let c: Foo = make()`,
    // `let c = x as Foo`) so cast / factory-typed receivers resolve
    // `receiver_type_in`; the name is recovered outside the type span.
    param_kinds: &["parameter", "property_declaration"],
    name_field: "name",
    type_field: "type",
};

const SWIFT_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "function_declaration",
        "class_declaration",
        "protocol_declaration",
        "init_declaration",
        "deinit_declaration",
        "property_declaration",
    ],
    modifier_container_kinds: &["modifiers", "visibility_modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("fileprivate", Visibility::Private),
        ("internal", Visibility::Module),
        ("public", Visibility::Public),
        ("open", Visibility::Public),
    ],
    // Swift's true default is `internal`: visible across the same
    // module, not across unrelated modules.
    default_visibility: Visibility::Module,
};

fn swift_pattern_bindings<'tree>(node: Node<'tree>, _src: &[u8]) -> Vec<ProjectedPatternBindingSite<'tree>> {
    fn bound_identifier(node: Node<'_>) -> Option<Node<'_>> {
        if let Some(binding) = node.child_by_field_name("bound_identifier") {
            return Some(binding);
        }
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if let Some(binding) = current.child_by_field_name("bound_identifier") {
                return Some(binding);
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
        None
    }

    if node.kind() != "switch_statement" {
        return Vec::new();
    }
    let Some(source) = node.child_by_field_name("expr") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "switch_entry" {
            let mut cursor = current.walk();
            let Some(wrapper) = current
                .named_children(&mut cursor)
                .find(|child| child.kind() == "switch_pattern")
            else {
                continue;
            };
            let mut wrapper_cursor = wrapper.walk();
            let Some(pattern) = wrapper
                .named_children(&mut wrapper_cursor)
                .find(|child| child.kind() == "pattern")
            else {
                continue;
            };
            let mut pattern_cursor = pattern.walk();
            let payloads = pattern
                .named_children(&mut pattern_cursor)
                .filter(|child| child.kind() == "pattern")
                .collect::<Vec<_>>();
            if payloads.is_empty() {
                if let Some(target) = bound_identifier(pattern) {
                    out.push(ProjectedPatternBindingSite {
                        span_node: current,
                        target,
                        source,
                        projection: Vec::new(),
                    });
                }
            } else {
                for (index, payload) in payloads.into_iter().enumerate() {
                    if let Some(target) = bound_identifier(payload) {
                        out.push(ProjectedPatternBindingSite {
                            span_node: current,
                            target,
                            source,
                            projection: vec![PatternSourceProjection::Field(format!("value{index}"))],
                        });
                    }
                }
            }
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    out
}
use parse_recovery::swift_parse_recovery_edits;
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("swift");
const PACK_NAME: &str = "swift";

fn swift_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "for_statement")
        .then(|| {
            Some((
                node.child_by_field_name("item")?,
                node.child_by_field_name("collection")?,
            ))
        })
        .flatten()
}

/// Extract the optional target label from Swift's shared
/// `control_transfer_statement` node. The same CST bucket also represents
/// return/throw, so the generic walker calls this only after it has proven the
/// leading control keyword is `break` or `continue`.
fn swift_control_target(node: Node<'_>, src: &[u8]) -> Option<bonsai_lang_api::LoopControlTarget> {
    let label = node
        .child_by_field_name("result")
        .or_else(|| node.named_child(0))?;
    let text = node_text(&label, src).trim();
    (!text.is_empty()).then(|| bonsai_lang_api::LoopControlTarget::Label(text.to_string()))
}

/// Swift labels are statement siblings (`outer: while ...`) rather than
/// children of the loop node. Preserve that exact parser relationship in the
/// adapter and expose only the normalized label to shared CFG/IDG lowering.
fn swift_loop_label(node: Node<'_>, src: &[u8]) -> Option<String> {
    let label = node
        .prev_named_sibling()
        .filter(|sibling| sibling.kind() == "statement_label")?;
    let text = node_text(&label, src).trim().trim_end_matches(':').trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Swift call targets are complete first-child navigation expressions.
/// Reading that grammar node directly avoids reconstructing its `target` and
/// `navigation_suffix` fields as `receiver..member` in shared lowering.
fn swift_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if node.kind() != "call_expression" {
        return None;
    }
    let target = node.named_child(0)?;
    if !matches!(
        target.kind(),
        "simple_identifier" | "navigation_expression" | "postfix_expression"
    ) {
        return None;
    }
    let full_text = node_text(&target, src).trim();
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text: full_text.to_string(),
    })
}

/// Swift computed-property access uses the same navigation syntax as a
/// member reference and executes an implicit getter. Preserve that exact
/// zero-argument call shape unless the navigation is already the callee of an
/// explicit `call_expression`; rule data decides whether a particular getter
/// has security meaning.
fn swift_property_getter_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    _handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "navigation_expression"
        || node.parent().is_some_and(|parent| {
            parent.kind() == "call_expression"
                && parent
                    .named_child(0)
                    .is_some_and(|callee| callee.id() == node.id())
        })
    {
        return None;
    }
    let receiver = node
        .child_by_field_name("target")
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.named_child(0))?;
    let name = node_text(&node, src).trim().to_string();
    let receiver = swift_expression_places(receiver, src)
        .places
        .into_iter()
        .next()
        .or_else(|| {
            let text = node_text(&receiver, src).trim();
            (!text.is_empty()).then(|| text.to_string())
        })?;
    (!name.is_empty()).then(|| FlowEvent::Call {
        span: span_of(file, &node),
        name,
        receiver: Some(receiver),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args: Vec::new(),
    })
}

fn swift_property_getter_receiver<'tree>(node: Node<'tree>, _src: &[u8]) -> Option<Node<'tree>> {
    (node.kind() == "navigation_expression")
        .then(|| {
            node.child_by_field_name("target")
                .or_else(|| node.child_by_field_name("expression"))
                .or_else(|| node.named_child(0))
        })
        .flatten()
}

/// Classify Swift navigation expressions as property reads when they are
/// evaluated as complete values.
///
/// The Swift grammar uses the same `navigation_expression` node for stored
/// and computed properties.  The adapter already emits an exact pseudo-call
/// for the potential getter; retaining `PropertyRead` here tells shared IDG
/// lowering that the projected storage value is also a producer.  This is a
/// syntax fact only: receiver typing and rule data decide whether a
/// particular property is security-sensitive.
fn swift_expression_value_kind(node: Node<'_>, _src: &[u8]) -> Option<AssignValueKind> {
    (node.kind() == "navigation_expression").then_some(AssignValueKind::PropertyRead)
}

/// Decode Swift lvalue/member wrappers from their Tree-sitter structure.
/// `directly_assignable_expression` is the grammar's write-side wrapper, and
/// `navigation_suffix` includes the leading dot in its rendered text. Keeping
/// this in the adapter gives shared lowering one canonical place without
/// teaching it Swift punctuation.
fn swift_expression_places(node: Node<'_>, src: &[u8]) -> ExpressionPlaceExtraction {
    fn identifier_text(node: Node<'_>, src: &[u8]) -> Option<String> {
        let text = node_text(&node, src).trim();
        (!text.is_empty()).then(|| text.to_string())
    }

    fn first_simple_identifier(node: Node<'_>, src: &[u8]) -> Option<String> {
        if node.kind() == "simple_identifier" {
            return identifier_text(node, src);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(identifier) = first_simple_identifier(child, src) {
                return Some(identifier);
            }
        }
        None
    }

    fn place(node: Node<'_>, src: &[u8]) -> Option<String> {
        match node.kind() {
            "simple_identifier" | "self_expression" => identifier_text(node, src),
            "directly_assignable_expression" | "postfix_expression" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let child = children.next()?;
                children.next().is_none().then(|| place(child, src)).flatten()
            }
            "navigation_expression" => {
                let base = node
                    .child_by_field_name("target")
                    .or_else(|| node.child_by_field_name("expression"))
                    .or_else(|| node.child_by_field_name("receiver"))
                    .or_else(|| node.named_child(0))?;
                let suffix = node
                    .child_by_field_name("suffix")
                    .or_else(|| node.child_by_field_name("name"))
                    .or_else(|| {
                        let mut cursor = node.walk();
                        node.named_children(&mut cursor).last()
                    })?;
                if suffix.id() == base.id() {
                    return None;
                }
                let base = place(base, src)?;
                let member = first_simple_identifier(suffix, src)?;
                Some(format!("{base}.{member}"))
            }
            _ => None,
        }
    }

    place(node, src).map_or_else(ExpressionPlaceExtraction::default, |place| {
        ExpressionPlaceExtraction {
            places: vec![place],
            consumed_node_ids: vec![node.id()],
        }
    })
}

/// Return the declaration keyword represented by Swift's unified
/// `class_declaration` node. The grammar preserves the keyword as an exact
/// anonymous child; no source-token or naming heuristic is needed.
fn swift_type_declaration_keyword(node: Node<'_>) -> Option<&str> {
    if node.kind() != "class_declaration" {
        return None;
    }
    let mut cursor = node.walk();
    let keyword = node
        .children(&mut cursor)
        .find(|child| matches!(child.kind(), "class" | "struct" | "enum" | "extension" | "actor"))
        .map(|child| child.kind());
    keyword
}

fn reclassify_swift_type_declarations(index: &mut DeclIndex, tree: &Tree, file: FileId) {
    for node in collect_kinds(tree, &["class_declaration"]) {
        let Some(keyword) = swift_type_declaration_keyword(node) else {
            continue;
        };
        let decl_kind = match keyword {
            "struct" => DeclKind::Struct,
            "enum" => DeclKind::Enum,
            // Extensions are partial declarations of the extended nominal
            // type. Keeping them class-like preserves parent/receiver
            // linkage while their exact keyword remains a compiler fact.
            "class" | "actor" | "extension" => DeclKind::Class,
            _ => continue,
        };
        let span = span_of(file, &node);
        if let Some(decl) = index.defs.iter_mut().find(|decl| decl.span == span) {
            decl.kind = decl_kind;
        }
    }
}

/// Swift uses `property_declaration` for both stored/type-only declarations
/// and initialized bindings. The grammar exposes initialized forms through an
/// exact `value` field, so the adapter can classify them without source-text
/// inference.
fn swift_assignment_semantics(node: Node<'_>, _src: &[u8]) -> AssignmentNodeSemantics {
    if node.kind() != "property_declaration" || node.child_by_field_name("value").is_some() {
        AssignmentNodeSemantics::Assignment
    } else {
        AssignmentNodeSemantics::Other
    }
}

/// Lower Swift optional bindings in `guard` conditions as ordinary compiler
/// assignments plus the initializer's call facts. Tree-sitter represents
///
/// `guard let value = make(input) else { ... }`
///
/// as one `guard_statement` whose named-child sequence is the binding marker,
/// bound pattern, and initializer expression. The shared branch walker
/// intentionally does not reinterpret language-specific condition syntax, so
/// the adapter preserves the binding here from that exact grammar sequence.
/// This is syntax lowering only: external constructor/call meaning remains
/// rulepack-owned.
fn collect_swift_guard_binding_events(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    class_names: &[String],
) -> Vec<(Span, Vec<FlowEvent>)> {
    let mut out = Vec::new();
    for guard in collect_kinds(tree, &["guard_statement"]) {
        let mut awaiting_target = false;
        let mut pending_target = None;
        let mut prelude = Vec::new();
        let mut cursor = guard.walk();
        for child in guard.named_children(&mut cursor) {
            if child.kind() == "value_binding_pattern" {
                awaiting_target = true;
                pending_target = None;
                continue;
            }
            if awaiting_target {
                let target = node_text(&child, src).trim();
                pending_target = (!target.is_empty()).then(|| target.to_string());
                awaiting_target = false;
                continue;
            }
            let Some(target) = pending_target.take() else {
                continue;
            };
            prelude.extend(swift_guard_binding_value_events(
                target,
                child,
                file,
                src,
                class_names,
            ));
        }
        if !prelude.is_empty() {
            out.push((span_of(file, &guard), prelude));
        }
    }
    out
}

fn swift_guard_binding_value_events(
    target: String,
    value: Node<'_>,
    file: FileId,
    src: &[u8],
    class_names: &[String],
) -> Vec<FlowEvent> {
    let value_events = walk_flow_events(value, file, src, &HANDLER, class_names);
    let direct_call = value_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, args, .. } => Some((name.clone(), args.clone())),
        _ => None,
    });
    let direct_place = swift_expression_places(value, src).places.into_iter().next();
    let simple_value = (value.kind() == "simple_identifier")
        .then(|| node_text(&value, src).trim().to_string())
        .filter(|name| !name.is_empty());
    let (source_call, source_call_args, value_kind) = direct_call.map_or_else(
        || (None, Vec::new(), Some(AssignValueKind::Compound)),
        |(name, args)| {
            (
                Some(name),
                args.into_iter().map(|arg| arg.value_text).collect(),
                Some(AssignValueKind::CallResult),
            )
        },
    );
    let source_names = if source_call.is_none() && simple_value.is_none() {
        direct_place.into_iter().collect()
    } else {
        Vec::new()
    };
    let mut events = vec![FlowEvent::Assign {
        span: span_of(file, &value),
        target,
        source_name: simple_value,
        source_call,
        source_call_args,
        source_names,
        declares_new_binding: true,
        value_kind,
    }];
    events.extend(value_events);
    events
}

fn apply_swift_guard_binding_events(events: &mut Vec<FlowEvent>, bindings: &[(Span, Vec<FlowEvent>)]) {
    let original = std::mem::take(events);
    for mut event in original {
        match &mut event {
            FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } => {
                if let Some((_, prelude)) = bindings.iter().find(|(guard_span, _)| guard_span == span) {
                    events.extend(prelude.iter().cloned());
                }
                apply_swift_guard_binding_events(then_events, bindings);
                apply_swift_guard_binding_events(else_events, bindings);
            }
            FlowEvent::Loop { body, .. } => apply_swift_guard_binding_events(body, bindings),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_swift_guard_binding_events(body, bindings);
                apply_swift_guard_binding_events(catch_events, bindings);
                apply_swift_guard_binding_events(finally_events, bindings);
            }
            _ => {}
        }
        events.push(event);
    }
}

fn swift_deferred_bodies<'tree>(node: Node<'tree>, src: &[u8]) -> Vec<Node<'tree>> {
    if node.kind() != "call_expression" {
        return Vec::new();
    }
    let Some(callee) = node
        .child_by_field_name("function")
        .or_else(|| first_identifier_like_child(&node))
    else {
        return Vec::new();
    };
    if node_text(&callee, src).trim() != "defer" {
        return Vec::new();
    }
    let mut bodies = Vec::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            if child.kind() == "lambda_literal" {
                bodies.push(child);
            } else if child.kind() == "call_suffix" {
                pending.push(child);
            }
        }
    }
    bodies.sort_by_key(Node::start_byte);
    bodies
}

fn swift_static_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "simple_identifier" {
        let key = node_text(&node, src).trim();
        return (!key.is_empty()).then(|| key.to_string());
    }
    if !matches!(
        node.kind(),
        "line_string_literal" | "multi_line_string_literal" | "raw_string_literal"
    ) {
        return None;
    }
    let raw = node_text(&node, src).trim();
    let quoted = raw
        .strip_prefix("\"\"\"")
        .and_then(|value| value.strip_suffix("\"\"\""))
        .or_else(|| raw.strip_prefix('"').and_then(|value| value.strip_suffix('"')))?;
    (!quoted.contains('\\') && !quoted.contains('#') && !quoted.is_empty()).then(|| quoted.to_string())
}
mod lexical_content;

const HANDLER: GrammarHandler = GrammarHandler {
    string_content_len: Some(lexical_content::string_content_len),
    comment_content_len: Some(lexical_content::comment_content_len),
    expression_value_kind_extractor: Some(swift_expression_value_kind),
    literal_value_kinds: &[
        "nil_literal",
        "boolean_literal",
        "integer_literal",
        "real_literal",
        "bin_literal",
        "hex_literal",
        "oct_literal",
        "true",
        "false",
    ],
    string_literal_kinds: &[
        "line_string_literal",
        "multi_line_string_literal",
        "raw_string_literal",
    ],
    comment_kinds: &["comment", "multiline_comment"],
    doc_comment_prefixes: &["///", "/**"],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["lambda_function_type_parameters"],
    parameter_kinds: &["parameter", "lambda_parameter"],
    parameter_annotation_kinds: &["attribute"],
    anonymous_variadic_token: Some("..."),
    variadic_parameter_kinds: &[],
    binding_identifier_kinds: &["simple_identifier"],
    non_binding_pattern_field_names: &["name"],
    pattern_binding_extractor: None,
    projected_pattern_binding_extractor: Some(swift_pattern_bindings),
    identifier_kinds: &["simple_identifier"],
    multi_child_aggregate_pattern_kinds: &["pattern"],
    aggregate_pattern_kinds: &[],
    named_aggregate_kinds: &["dictionary_literal"],
    positional_aggregate_kinds: &["array_literal", "tuple_expression"],
    aggregate_pair_kinds: &["dictionary_literal"],
    aggregate_key_field_names: &["key"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["simple_identifier"],
    aggregate_syntax_only_kinds: &[],
    transparent_call_wrapper_kinds: &[
        "navigation_expression",
        "postfix_expression",
        "await_expression",
        "try_expression",
    ],
    assignment_target_wrapper_kinds: &["value_binding_pattern", "pattern"],
    binding_declaration_keyword_spellings: &["let", "var"],
    fn_kinds: &["function_declaration"],
    call_kinds: &["call_expression"],
    call_argument_container_kinds: &["value_arguments"],
    call_argument_wrapper_kinds: &["call_suffix"],
    call_callee_is_first_named_child: true,
    call_target_extractor: Some(swift_call_target),
    pseudo_call_extractor: Some(swift_property_getter_call),
    pseudo_call_receiver_extractor: Some(swift_property_getter_receiver),
    pseudo_call_receiver_role: CallReceiverRole::Projection,
    argument_wrapper_kinds: &["tuple_expression", "value_argument"],
    argument_name_field_names: &["name"],
    argument_value_field_names: &["value"],
    // `try? value` and `try! value` are value-preserving expression wrappers;
    // the punctuation is anonymous and Tree-sitter exposes exactly one named
    // child. Keeping this adapter-owned grammar fact lets assignment and
    // argument lowering retain the wrapped call identity without treating a
    // `do` statement (also present in `try_kinds`) as an expression.
    transparent_expression_wrapper_kinds: &["try_expression"],
    lambda_body_field_names: &["body"],
    lambda_body_kinds: &["lambda_literal"],
    argument_passing_mode_extractor: Some(swift_argument_passing_mode),
    constructor_names: &["init"],
    runtime_type_guard_operators: &["is"],
    runtime_type_wrapper_kinds: &[],
    call_ref_kinds: &["call_expression"],
    member_expression_kinds: &["navigation_expression"],
    subscript_expression_kinds: &["subscript"],
    member_base_field_names: &["target"],
    member_name_field_names: &["name", "suffix"],
    subscript_base_field_names: &["target"],
    subscript_index_field_names: &[],
    static_subscript_key_extractor: Some(swift_static_key),
    expression_place_extractor: Some(swift_expression_places),
    class_kinds: &["class_declaration", "protocol_declaration"],
    class_decl_kinds: &[
        ("class_declaration", DeclKind::Class),
        ("protocol_declaration", DeclKind::Interface),
    ],
    method_context_kinds: &["class_declaration", "protocol_declaration"],
    constructor_method_kinds: &["init_declaration"],
    if_kinds: &["if_statement", "switch_statement", "guard_statement"],
    branch_then_field_names: &[],
    branch_else_field_names: &[],
    branch_condition_field_names: &["condition"],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &[],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    condition_not_operator_kinds: &["bang"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["statements"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &[],
    loop_condition_field_names: &["condition"],
    loop_condition_extractor: None,
    branch_arm_kinds: &["statements", "switch_entry"],
    exclusive_branch_arm_kinds: &["switch_entry"],
    fallthrough_branch_arm_kinds: &[],
    for_kinds: &[],
    foreach_kinds: &["for_statement"],
    foreach_binding_extractor: Some(swift_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["repeat_while_statement"],
    assignment_kinds: &["assignment", "property_declaration"],
    assignment_semantics_extractor: Some(swift_assignment_semantics),
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="],
    type_only_declaration_kinds: &[],
    return_kinds: &["control_transfer_statement"],
    control_target_extractor: Some(swift_control_target),
    loop_label_extractor: Some(swift_loop_label),
    lambda_kinds: &["lambda_literal"],
    try_kinds: &["try_expression", "do_statement"],
    try_body_field_names: &["body"],
    catch_kinds: &["catch_block"],
    exclusive_catch_arm_kinds: &["catch_block"],
    await_kinds: &["await_expression"],
    deferred_body_extractor: Some(swift_deferred_bodies),
    special_forms: &[],
    implicit_receiver_names: &["self", "super"],
    ..EMPTY_HANDLER
};

fn swift_argument_passing_mode(argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
    if [argument, value].into_iter().any(|node| {
        node.kind() == "prefix_expression" && {
            let mut cursor = node.walk();
            let has_address_of = node.children(&mut cursor).any(|child| child.kind() == "&");
            has_address_of
        }
    }) {
        ArgumentPassingMode::WriteBack
    } else {
        ArgumentPassingMode::Value
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct SwiftAdapter;

impl SwiftAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for SwiftAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Swift"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["swift"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        _vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        swift_parse_recovery_edits(snapshot, tree)
    }
    fn parse_recovery_edit_batches(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        _vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<Vec<bonsai_lang_api::ParseRecoveryEdit>> {
        parse_recovery::swift_parse_recovery_edit_batches(snapshot, tree)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Pattern matching: the adapter post-processes flat `Branch`
        // events emitted for `switch_statement`s into nested `Branch`
        // chains so the engine forks state per arm. Same approach as
        // the Scala adapter.
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["Any", "AnyObject"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            pattern_matching: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: &["init"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["self"],
            same_directory_unqualified_calls: true,
            // Swift construction has no `new` token. A bare call is treated
            // as construction only after exact workspace class identity is
            // available; the shared resolver never uses type-name casing.
            bare_call_constructor_syntax: true,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("custom lowering", "&"),
            ("custom lowering", "="),
            ("custom lowering", "actor"),
            ("custom lowering", "as_expression"),
            ("custom lowering", "as_operator"),
            ("custom lowering", "bang"),
            ("custom lowering", "call_expression"),
            ("custom lowering", "call_suffix"),
            ("custom lowering", "class_body"),
            ("custom lowering", "class_declaration"),
            ("custom lowering", "class"),
            ("custom lowering", "computed_property"),
            ("custom lowering", "deinit_declaration"),
            ("custom lowering", "directly_assignable_expression"),
            ("custom lowering", "enum"),
            ("custom lowering", "enum_class_body"),
            ("custom lowering", "enum_entry"),
            ("custom lowering", "enum_type_parameters"),
            ("custom lowering", "extension"),
            ("custom lowering", "for_statement"),
            ("custom lowering", "function_body"),
            ("custom lowering", "function_declaration"),
            ("custom lowering", "identifier"),
            ("custom lowering", "import_declaration"),
            ("custom lowering", "infix_expression"),
            ("custom lowering", "inheritance_specifier"),
            ("custom lowering", "init_declaration"),
            ("custom lowering", "lambda_literal"),
            ("custom lowering", "line_string_literal"),
            ("custom lowering", "multi_line_string_literal"),
            ("custom lowering", "navigation_expression"),
            ("custom lowering", "parameter"),
            ("custom lowering", "parameter_modifier"),
            ("custom lowering", "parameter_modifiers"),
            ("custom lowering", "pattern"),
            ("custom lowering", "postfix_expression"),
            ("custom lowering", "prefix_expression"),
            ("custom lowering", "property_declaration"),
            ("custom lowering", "property_modifier"),
            ("custom lowering", "protocol_declaration"),
            ("custom lowering", "raw_string_literal"),
            ("custom lowering", "self_expression"),
            ("custom lowering", "simple_identifier"),
            ("loop-control-label", "statement_label"),
            ("custom lowering", "statements"),
            ("custom lowering", "struct"),
            ("custom lowering", "switch_entry"),
            ("custom lowering", "switch_statement"),
            ("custom lowering", "tuple_expression"),
            ("custom lowering", "type_annotation"),
            ("custom lowering", "type_identifier"),
            ("custom lowering", "typealias_declaration"),
            ("custom lowering", "user_type"),
        ]
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let parsed = parse_with(PACK_NAME, file, ctx);
        let mut idx = parsed.as_ref().map_or_else(
            || DeclIndex {
                file,
                ..DeclIndex::default()
            },
            |(snapshot, tree)| {
                decl_index_from_tree_with_handler(file, snapshot.text.as_bytes(), tree, &HANDLER)
            },
        );
        if let Some((_, tree)) = parsed.as_ref() {
            reclassify_swift_type_declarations(&mut idx, tree, file);
        }
        apply_swift_semantic_identity(&mut idx, ctx);
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `func f() -> T {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, tree, src, &HANDLER);
            let arm_spans = collect_swift_switch_arm_spans(tree, src, file);
            for decl in &mut idx.defs {
                bonsai_lang_api::kit::split_match_arms_in_branch_events(&mut decl.flow_events, &arm_spans);
            }
        }
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_modifier_visibility(tree.root_node(), file, src, &SWIFT_VOCAB);
            let alias_map = collect_param_type_aliases(tree, file, src, &SWIFT_TYPE_ALIASES);
            let param_annotations = collect_swift_param_annotations(tree, file, src);
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                if let Some(annotations) = param_annotations.get(&decl.span) {
                    decl.param_annotations.clone_from(annotations);
                }
            }
            // Constructor synthesis needs inheritance before it decides
            // whether a class receives a local implicit initializer or
            // inherits its superclass initializers. Populate this exact CST
            // fact before synthesizing constructors; doing it afterwards can
            // fabricate `Child.init()` and shadow `Base.init(_:)`.
            let bases_by_span = collect_swift_class_bases(tree, file, src);
            for decl in &mut idx.defs {
                if !is_class_like(decl.kind) {
                    continue;
                }
                if let Some(bases) = bases_by_span
                    .iter()
                    .find_map(|(span, bases)| (*span == decl.span).then_some(bases))
                {
                    decl.bases = bases.clone();
                }
            }
            // Class-level property type bindings — `let
            // authService = AuthService()` makes `authService :
            // AuthService` available inside every method of the
            // enclosing class so receiver dispatch reaches the real
            // method decl.
            let declared_type_names = idx
                .defs
                .iter()
                .filter(|decl| is_class_like(decl.kind))
                .flat_map(|decl| std::iter::once(decl.name.clone()).chain(decl.qualified_name.clone()))
                .filter_map(|name| swift_canonical_type(&name))
                .collect::<std::collections::HashSet<_>>();
            let class_field_aliases =
                collect_swift_class_field_aliases(tree, file, src, &declared_type_names);
            let function_param_names = collect_swift_function_param_names(file, tree, src);
            let class_names = idx
                .defs
                .iter()
                .filter(|decl| is_class_like(decl.kind))
                .map(|decl| decl.name.clone())
                .collect::<Vec<_>>();
            let guard_bindings = collect_swift_guard_binding_events(tree, file, src, &class_names);
            for decl in &mut idx.defs {
                apply_swift_guard_binding_events(&mut decl.flow_events, &guard_bindings);
            }
            synthesize_swift_constructor_decls(&mut idx, file, tree, src);
            // Swift structs (`struct Envelope { var kind, var cmd, ... }`)
            // get a compiler-synthesized **memberwise init** — no
            // explicit `init` block, but `Envelope(kind:, cmd:, ...)`
            // is callable. Without surfacing this as a Constructor
            // decl with `receiver_field_writes` for each stored
            // property, `new Envelope(...)` never field-projects
            // `envelope.cmd ← arg` onto the caller's allocation and
            // interprocedural member flow stalls at the constructor caller.
            synthesize_swift_memberwise_struct_inits(&mut idx, file, tree, src);
            // Associated-value enum cases are compiler-generated constructor
            // boundaries.  Lower their positional payloads generically so
            // ordinary constructor/return and switch-pattern flow can carry
            // values through an enum without assigning any framework or
            // security meaning in the adapter.
            synthesize_swift_enum_case_constructors(&mut idx, file, tree, src);
            // Swift computed properties (`var cmd: String { data.cmd }`)
            // are wrapped in `property_declaration` with a
            // `computed_value: computed_property` child rather than a
            // function_declaration — the kit's fn-kind extraction
            // misses them entirely. Synthesize a zero-arg Method per
            // computed property so `let c = cmd` (resolved via the
            // qualify pass below) finds a callable getter.
            synthesize_swift_computed_property_decls(&mut idx, file, tree, src);
            // Stored properties also execute through a compiler-generated
            // getter. The syntax walker emits the same receiver pseudo-call
            // for `self.field` as it does for a computed property, so surface
            // the exact stored-member getter for classes/actors as well as
            // the struct accessors synthesized above.
            synthesize_swift_stored_property_accessors(&mut idx, file, tree, src);
            apply_swift_semantic_identity(&mut idx, ctx);
            let class_span_for_parent: std::collections::HashMap<bonsai_common::SymbolId, Span> = idx
                .defs
                .iter()
                .filter(|candidate| is_class_like(candidate.kind))
                .map(|candidate| (candidate.symbol, candidate.span))
                .collect();
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                let mut aliases = alias_map.get(&decl.span).cloned().unwrap_or_default();
                if matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    if let Some(class_span) = decl
                        .parent
                        .and_then(|parent_sym| class_span_for_parent.get(&parent_sym).copied())
                    {
                        if let Some(field_aliases) = class_field_aliases
                            .iter()
                            .find_map(|(span, list)| (*span == class_span).then_some(list))
                        {
                            for alias in field_aliases {
                                if !aliases.contains(alias) {
                                    aliases.push(alias.clone());
                                }
                            }
                        }
                    }
                }
                if !aliases.is_empty() {
                    decl.type_aliases = aliases;
                }
                if matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
                    if let Some(params) = function_param_names
                        .iter()
                        .find_map(|(span, params)| (*span == decl.span).then_some(params))
                    {
                        decl.params = params.clone();
                    }
                }
                normalize_swift_parameter_names(decl);
            }
        }
        let constructor_field_params = swift_constructor_field_params(&idx);
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            if !constructor_field_params.is_empty() {
                synthesize_swift_constructor_field_assignments(
                    &mut decl.flow_events,
                    &constructor_field_params,
                );
            }
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`let c = Foo()` →
        // `c: Foo`) requires exact declaration/CST evidence. Swift naming
        // conventions are not part of the language's type system.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let declared_aliases = collect_swift_declared_type_aliases(tree, snapshot.text.as_bytes());
            apply_swift_declared_type_aliases(&mut idx, &declared_aliases);
        }
        // Swift stored-property aliases are attached after the shared syntax
        // lowering pass. Re-run the generic receiver-type join once those
        // exact CST-derived bindings exist so calls through a typed property
        // (`store.read(...)`) carry the same evidence as typed locals and
        // parameters.
        bonsai_lang_api::apply_call_receiver_types(&mut idx);
        if let Some((snapshot, tree)) = parsed.as_ref() {
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut idx,
                tree,
                file,
                snapshot.text.as_bytes(),
                &HANDLER,
                swift_static_scalar,
            );
            normalize_swift_property_call_assignments(&mut idx);
            populate_swift_string_compositions(&mut idx, tree, file, snapshot.text.as_bytes());
            populate_swift_guard_condition_facts(&mut idx.branch_conditions, tree, file);
            idx.finite_literal_selections
                .extend(collect_swift_finite_literal_selections(
                    &idx,
                    tree,
                    file,
                    snapshot.text.as_bytes(),
                ));
            bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut idx.finite_literal_selections);
        }
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Swift `guard condition else { exit }` executes its rejection body when the
/// source condition is false. Preserve that language-level polarity in the
/// compiler condition fact rather than making consumers interpret keywords.
fn populate_swift_guard_condition_facts(
    facts: &mut [bonsai_lang_api::BranchConditionFact],
    tree: &tree_sitter::Tree,
    file: FileId,
) {
    for fact in facts {
        let Some(condition) = node_at_span(tree.root_node(), fact.condition_span, &[]) else {
            continue;
        };
        let mut ancestor = condition.parent();
        let mut is_guard = false;
        while let Some(parent) = ancestor {
            if parent.kind() == "guard_statement" {
                is_guard = true;
                break;
            }
            if matches!(
                parent.kind(),
                "function_declaration" | "class_declaration" | "struct_declaration"
            ) {
                break;
            }
            ancestor = parent.parent();
        }
        if !is_guard {
            continue;
        }
        let expression = fact
            .expression
            .take()
            .unwrap_or(bonsai_lang_api::ConditionExpressionFact::Atom {
                span: span_of(file, &condition),
            });
        fact.polarity = bonsai_lang_api::BranchConditionPolarity::Negated;
        fact.expression = Some(bonsai_lang_api::ConditionExpressionFact::Not {
            span: fact.condition_span,
            operand: Box::new(expression),
        });
    }
}

/// Lower exact Swift string addition into the shared composition IR. This is
/// syntax-only: consumers decide whether a particular boundary literal has
/// security meaning.
fn populate_swift_string_compositions(
    idx: &mut DeclIndex,
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
) {
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "additive_expression" {
            let lhs = node.child_by_field_name("lhs");
            let rhs = node.child_by_field_name("rhs");
            if let (Some(lhs), Some(_rhs), Some(StaticScalarValue::String(value))) =
                (lhs, rhs, rhs.and_then(|rhs| swift_static_scalar(rhs, src)))
            {
                let flow =
                    bonsai_lang_api::kit::expression_flow_from_node_with_handler(lhs, file, src, &HANDLER);
                let place = flow
                    .projection
                    .as_ref()
                    .map(bonsai_lang_api::ExpressionProjection::canonical_place)
                    .or(flow.place);
                if let Some(place) = place {
                    let span = span_of(file, &node);
                    idx.string_compositions.push(StringCompositionFact {
                        container_span: span,
                        value_span: span,
                        target: None,
                        dynamic_anchor_span: None,
                        parts: vec![
                            StringCompositionPart::Place { place },
                            StringCompositionPart::Literal { value },
                        ],
                    });
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    idx.string_compositions
        .sort_by_key(|fact| (fact.value_span.start, fact.value_span.end));
    idx.string_compositions.dedup();
}

/// Swift getter syntax is an exact call-like value operation even without
/// parentheses. Re-anchor assignments to the outermost adapter-emitted call so
/// downstream compiler consumers see the actual produced value rather than an
/// arbitrary nested call.
fn normalize_swift_property_call_assignments(idx: &mut DeclIndex) {
    let summaries = idx
        .defs
        .iter()
        .flat_map(|decl| swift_call_summaries(&decl.flow_events))
        .collect::<Vec<_>>();
    let mut overrides = Vec::new();
    for fact in &mut idx.assignment_values {
        // Ordinary call syntax already identifies its outer value producer
        // directly from the RHS CST. A nested call beneath a terminal Swift
        // property getter is not the complete RHS producer, however: its
        // exact callee span is strictly smaller than the value span and the
        // adapter-emitted getter fact below must own the assignment instead.
        if fact.direct_call_name.is_some() && fact.direct_call_span == Some(fact.value_span) {
            continue;
        }
        // Only the parsed RHS value can produce the assignment. The complete
        // assignment span also contains target-side navigation and, for
        // pattern bindings, the entire guarded arm/body. Searching that span
        // can therefore select an unrelated getter or later call.
        let outer = summaries.iter().find(|call| call.span == fact.value_span);
        let Some(call) = outer else { continue };
        fact.direct_call_name = Some(call.name.clone());
        let receiver = idx
            .call_receivers
            .iter()
            .find(|receiver| receiver.call_span == call.span)
            .cloned();
        fact.direct_call_span = Some(call.span);
        fact.direct_call_receiver = call.receiver.clone().or_else(|| {
            receiver.as_ref().and_then(|receiver| {
                receiver
                    .value_flow
                    .projection
                    .as_ref()
                    .map(bonsai_lang_api::ExpressionProjection::canonical_place)
                    .or_else(|| receiver.value_flow.place.clone())
            })
        });
        fact.direct_call_receiver_span = receiver.as_ref().map(|receiver| receiver.receiver_span);
        fact.direct_call_receiver_flow = receiver.map(|receiver| receiver.value_flow);
        if !fact.call_sites.contains(&call.span) {
            fact.call_sites.push(call.span);
            fact.call_sites.sort_unstable();
            fact.call_sites.dedup();
        }
        overrides.push((fact.assignment_span, call.clone()));
    }
    for decl in &mut idx.defs {
        normalize_swift_property_call_assignments_in_events(&mut decl.flow_events, &overrides);
    }
}

#[derive(Clone)]
struct SwiftCallSummary {
    span: Span,
    name: String,
    receiver: Option<String>,
    args: Vec<String>,
}

fn swift_call_summaries(events: &[FlowEvent]) -> Vec<SwiftCallSummary> {
    let mut calls = Vec::new();
    fn visit(events: &[FlowEvent], calls: &mut Vec<SwiftCallSummary>) {
        for event in events {
            match event {
                FlowEvent::Call {
                    span,
                    name,
                    receiver,
                    args,
                    ..
                } => calls.push(SwiftCallSummary {
                    span: *span,
                    name: name.clone(),
                    receiver: receiver.clone(),
                    args: args.iter().map(|arg| arg.value_text.clone()).collect(),
                }),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    visit(then_events, calls);
                    visit(else_events, calls);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => visit(body, calls),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    visit(body, calls);
                    visit(catch_events, calls);
                    visit(finally_events, calls);
                }
                _ => {}
            }
        }
    }
    visit(events, &mut calls);
    calls
}

fn normalize_swift_property_call_assignments_in_events(
    events: &mut [FlowEvent],
    overrides: &[(Span, SwiftCallSummary)],
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                value_kind,
                ..
            } => {
                if let Some(call) = overrides
                    .iter()
                    .find_map(|(assignment_span, call)| (*assignment_span == *span).then_some(call))
                {
                    *source_name = None;
                    *source_call = Some(call.name.clone());
                    source_call_args.clone_from(&call.args);
                    *value_kind = Some(bonsai_lang_api::AssignValueKind::CallResult);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_swift_property_call_assignments_in_events(then_events, overrides);
                normalize_swift_property_call_assignments_in_events(else_events, overrides);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_swift_property_call_assignments_in_events(body, overrides);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_swift_property_call_assignments_in_events(body, overrides);
                normalize_swift_property_call_assignments_in_events(catch_events, overrides);
                normalize_swift_property_call_assignments_in_events(finally_events, overrides);
            }
            _ => {}
        }
    }
}

/// Decode Swift scalar literals from exact grammar nodes. Runtime/API meaning
/// remains downstream; this adapter fact is used by generic state and guard
/// constraints. Interpolated and raw-delimiter strings fail closed here.
fn swift_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "nil_literal" => Some(StaticScalarValue::Null),
        "boolean_literal" => match node_text(&node, src).trim() {
            "true" => Some(StaticScalarValue::Boolean(true)),
            "false" => Some(StaticScalarValue::Boolean(false)),
            _ => None,
        },
        "line_string_literal" => {
            let text = node_text(&node, src).trim();
            let value = text.strip_prefix('"')?.strip_suffix('"')?;
            (!value.contains(['\\', '#'])).then(|| StaticScalarValue::String(value.to_string()))
        }
        _ => None,
    }
}

/// Lower complete Swift `switch` expressions whose every result arm is a
/// compiler literal.  The selected key remains dynamic, but it cannot become
/// part of the selected value.  Exhaustiveness is proven conservatively by an
/// explicit `default` arm; enum exhaustiveness without a default is left to a
/// future type-aware frontend proof.
fn collect_swift_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<FiniteLiteralSelectionFact> {
    let mut facts = Vec::new();
    for selection in collect_kinds(tree, &["switch_statement"]) {
        if !swift_switch_has_complete_literal_results(selection, src) {
            continue;
        }
        let selection_span = span_of(file, &selection);
        if let Some(fact) = bonsai_lang_api::kit::finite_literal_selection_fact_for_span(
            index,
            tree,
            selection_span,
            |value| value.id() == selection.id(),
        ) {
            facts.push(fact);
            continue;
        }
        if index.defs.iter().any(|decl| {
            decl.span.start <= selection_span.start
                && selection_span.end <= decl.span.end
                && swift_events_have_return_containing(&decl.flow_events, selection_span)
        }) {
            facts.push(FiniteLiteralSelectionFact {
                selection_span,
                assignment_span: None,
                target: None,
                call_span: None,
                argument_index: None,
            });
        }
    }
    let dictionaries = collect_swift_finite_dictionary_bindings(tree, src);
    for selection in collect_kinds(tree, &["nil_coalescing_expression"]) {
        let Some((lookup, lookup_name, type_member)) = swift_finite_dictionary_lookup(selection, src) else {
            continue;
        };
        let mut matching = dictionaries.iter().filter(|binding| {
            binding.name == lookup_name
                && binding.type_member == type_member
                && binding.initializer.end_byte() <= lookup.start_byte()
                && binding.scope.start_byte() <= lookup.start_byte()
                && lookup.end_byte() <= binding.scope.end_byte()
                && swift_enclosing_finite_dictionary_scope(lookup, type_member)
                    .is_some_and(|scope| scope.id() == binding.scope.id())
        });
        if matching.next().is_none() || matching.next().is_some() {
            continue;
        }
        let selection_span = span_of(file, &selection);
        if let Some(fact) = bonsai_lang_api::kit::finite_literal_selection_fact_for_span(
            index,
            tree,
            selection_span,
            |value| value.id() == selection.id(),
        ) {
            facts.push(fact);
        }
    }
    facts
}

#[derive(Copy, Clone)]
struct SwiftFiniteDictionaryBinding<'tree> {
    name: &'tree str,
    initializer: Node<'tree>,
    scope: Node<'tree>,
    type_member: bool,
}

fn collect_swift_finite_dictionary_bindings<'tree>(
    tree: &'tree Tree,
    src: &'tree [u8],
) -> Vec<SwiftFiniteDictionaryBinding<'tree>> {
    let mut bindings = Vec::new();
    for property in collect_kinds(tree, &["property_declaration"]) {
        let Some(initializer) = property.child_by_field_name("value") else {
            continue;
        };
        if initializer.kind() != "dictionary_literal"
            || !swift_property_is_let(property, src)
            || !swift_dictionary_has_only_static_entries(initializer, src)
        {
            continue;
        }
        let type_member = swift_property_is_type_member(property, src);
        let Some(scope) = swift_enclosing_finite_dictionary_scope(property, type_member) else {
            continue;
        };
        let Some(name_node) = property
            .child_by_field_name("name")
            .and_then(|pattern| first_named_child_of_kind(&pattern, "simple_identifier"))
        else {
            continue;
        };
        let name = node_text(&name_node, src).trim();
        if name.is_empty() {
            continue;
        }
        if type_member != (scope.kind() == "class_declaration") {
            continue;
        }
        bindings.push(SwiftFiniteDictionaryBinding {
            name,
            initializer,
            scope,
            type_member,
        });
    }
    bindings
}

fn swift_property_is_let(property: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = property.walk();
    let is_let = property
        .named_children(&mut cursor)
        .find(|child| child.kind() == "value_binding_pattern")
        .is_some_and(|binding| node_text(&binding, src).trim() == "let");
    is_let
}

fn swift_dictionary_has_only_static_entries(dictionary: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = dictionary.walk();
    let entries = dictionary.named_children(&mut cursor).collect::<Vec<_>>();
    !entries.is_empty()
        && entries.len().is_multiple_of(2)
        && entries.chunks_exact(2).all(|entry| {
            swift_static_scalar(entry[0], src).is_some() && swift_static_scalar(entry[1], src).is_some()
        })
}

fn swift_enclosing_finite_dictionary_scope(mut node: Node<'_>, type_member: bool) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if (type_member && parent.kind() == "class_declaration")
            || (!type_member && parent.kind() == "function_declaration")
        {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn swift_finite_dictionary_lookup<'tree>(
    selection: Node<'tree>,
    src: &'tree [u8],
) -> Option<(Node<'tree>, &'tree str, bool)> {
    let lookup = selection.child_by_field_name("value")?;
    let fallback = selection.child_by_field_name("if_nil")?;
    if lookup.kind() != "call_expression" || swift_static_scalar(fallback, src).is_none() {
        return None;
    }
    let target = lookup.named_child(0)?;
    let suffix = lookup.named_child(1)?;
    if suffix.kind() != "call_suffix" {
        return None;
    }
    let arguments = first_named_child_of_kind(&suffix, "value_arguments")?;
    if !swift_value_arguments_are_subscript(arguments) {
        return None;
    }
    let mut cursor = arguments.walk();
    let values = arguments
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "value_argument")
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return None;
    }
    match target.kind() {
        "simple_identifier" => {
            let name = node_text(&target, src).trim();
            (!name.is_empty()).then_some((lookup, name, false))
        }
        "navigation_expression" => {
            let base = target.child_by_field_name("target")?;
            let member = target.child_by_field_name("suffix")?;
            if node_text(&base, src).trim() != "Self" {
                return None;
            }
            let name_node = first_named_child_of_kind(&member, "simple_identifier")?;
            let name = node_text(&name_node, src).trim();
            (!name.is_empty()).then_some((lookup, name, true))
        }
        _ => None,
    }
}

fn swift_value_arguments_are_subscript(arguments: Node<'_>) -> bool {
    let mut cursor = arguments.walk();
    let kinds = arguments
        .children(&mut cursor)
        .map(|child| child.kind())
        .collect::<Vec<_>>();
    kinds.first() == Some(&"[") && kinds.last() == Some(&"]")
}

fn swift_switch_has_complete_literal_results(selection: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = selection.walk();
    let entries = selection
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "switch_entry")
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return false;
    }
    let mut has_default = false;
    for entry in entries {
        let mut child_cursor = entry.walk();
        has_default |= entry
            .children(&mut child_cursor)
            .any(|child| matches!(child.kind(), "default" | "default_keyword"));
        if !has_default {
            let mut named_cursor = entry.walk();
            has_default |= entry
                .named_children(&mut named_cursor)
                .find(|child| child.kind() == "switch_pattern")
                .is_some_and(|pattern| node_text(&pattern, src).trim() == "default");
        }
        let mut named_cursor = entry.walk();
        let Some(statements) = entry
            .named_children(&mut named_cursor)
            .find(|child| child.kind() == "statements")
        else {
            return false;
        };
        let mut statement_cursor = statements.walk();
        let values = statements
            .named_children(&mut statement_cursor)
            .collect::<Vec<_>>();
        let [value] = values.as_slice() else {
            return false;
        };
        if HANDLER.expression_value_kind(*value, src) != Some(AssignValueKind::Literal) {
            return false;
        }
    }
    has_default
}

fn swift_events_have_return_containing(events: &[FlowEvent], selection: Span) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return { span, .. } => {
            span.file == selection.file && span.start <= selection.start && selection.end <= span.end
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            swift_events_have_return_containing(then_events, selection)
                || swift_events_have_return_containing(else_events, selection)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            swift_events_have_return_containing(body, selection)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            swift_events_have_return_containing(body, selection)
                || swift_events_have_return_containing(catch_events, selection)
                || swift_events_have_return_containing(finally_events, selection)
        }
        _ => false,
    })
}

/// Lower Swift parameter attributes such as `@escaping` from the exact
/// `parameter_modifiers > parameter_modifier` CST shape. Tree-sitter Swift
/// places parameters directly under the callable declaration rather than in a
/// shared list node, so this stays in the owning adapter instead of teaching
/// the language-neutral extractor a Swift node inventory.
fn collect_swift_param_annotations(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Vec<Vec<String>>> {
    let mut by_decl = std::collections::HashMap::new();
    for callable in collect_kinds(
        tree,
        &["function_declaration", "init_declaration", "deinit_declaration"],
    ) {
        let mut per_param = Vec::new();
        let mut cursor = callable.walk();
        for parameter in callable
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "parameter")
        {
            let mut annotations = Vec::new();
            let mut parameter_cursor = parameter.walk();
            for modifiers in parameter
                .named_children(&mut parameter_cursor)
                .filter(|child| child.kind() == "parameter_modifiers")
            {
                let mut modifier_cursor = modifiers.walk();
                for modifier in modifiers
                    .named_children(&mut modifier_cursor)
                    .filter(|child| child.kind() == "parameter_modifier")
                {
                    let name = node_text(&modifier, src).trim().trim_start_matches('@');
                    if !name.is_empty() && !annotations.iter().any(|existing| existing == name) {
                        annotations.push(name.to_string());
                    }
                }
            }
            per_param.push(annotations);
        }
        if per_param.iter().any(|annotations| !annotations.is_empty()) {
            by_decl.insert(span_of(file, &callable), per_param);
        }
    }
    by_decl
}

fn apply_swift_semantic_identity(idx: &mut DeclIndex, ctx: &AdapterContext<'_>) {
    let module_segments = swift_module_segments(idx.file, ctx);
    let module_path = bonsai_lang_api::ModulePath::from_segments(module_segments.iter().cloned());
    let qualified_prefix =
        swift_qualified_prefix(idx.file, ctx).unwrap_or_else(|| module_segments.join("::"));
    for decl in &mut idx.defs {
        if decl.qualified_name.is_none() {
            decl.qualified_name = Some(if qualified_prefix.is_empty() {
                decl.name.clone()
            } else {
                format!("{qualified_prefix}::{}", decl.name)
            });
        }
        decl.module_path = module_path.clone();
    }
}

fn swift_module_segments(file: FileId, ctx: &AdapterContext<'_>) -> Vec<String> {
    if let Some(relative) = ctx.workspace_relative_path(file) {
        let components = swift_path_components(&relative);
        for marker in ["Sources", "Tests"] {
            if let Some(index) = components.iter().position(|part| part == marker) {
                if let Some(target) = components.get(index + 1) {
                    let mut segments = components[..index]
                        .iter()
                        .map(|part| sanitize_swift_module_segment(part))
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>();
                    segments.push(sanitize_swift_module_segment(target));
                    return segments;
                }
            }
        }
    }
    if let Some(root_path) = ctx.workspace_root {
        let mut segments = root_path
            .file_name()
            .map(|name| vec![sanitize_swift_module_segment(&name.to_string_lossy())])
            .unwrap_or_default();
        if let Some(relative) = ctx.workspace_relative_path(file) {
            if let Some(parent) = relative.parent() {
                segments.extend(
                    swift_path_components(parent)
                        .into_iter()
                        .map(|part| sanitize_swift_module_segment(&part))
                        .filter(|part| !part.is_empty()),
                );
            }
        }
        if !segments.is_empty() {
            return segments;
        }
    }
    vec!["swift".to_string()]
}

fn swift_qualified_prefix(file: FileId, ctx: &AdapterContext<'_>) -> Option<String> {
    let path = ctx
        .workspace_relative_path(file)
        .or_else(|| ctx.vfs.path(file).ok().map(|p| (*p).clone()))?;
    let mut segments = swift_path_components(&path);
    let last = segments.last_mut()?;
    if let Some((stem, _)) = last.rsplit_once('.') {
        *last = stem.to_string();
    }
    segments.retain(|segment| !segment.is_empty());
    (!segments.is_empty()).then(|| segments.join("::"))
}

fn swift_path_components(path: &std::path::Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => {
                let text = part.to_string_lossy();
                (!text.is_empty()).then(|| text.into_owned())
            }
            _ => None,
        })
        .collect()
}

fn sanitize_swift_module_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "swift".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_swift_parameter_names(decl: &mut bonsai_lang_api::Decl) {
    if !matches!(
        decl.kind,
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
    ) || decl.type_aliases.is_empty()
    {
        return;
    }
    let type_names = decl
        .type_aliases
        .iter()
        .map(|alias| alias.type_name.clone())
        .collect::<std::collections::HashSet<_>>();
    let alias_names = decl
        .type_aliases
        .iter()
        .map(|alias| alias.name.clone())
        .collect::<std::collections::HashSet<_>>();
    decl.params
        .retain(|param| !type_names.contains(param) || alias_names.contains(param));
}

fn collect_swift_declared_type_aliases(tree: &Tree, src: &[u8]) -> std::collections::HashMap<String, String> {
    let mut aliases = std::collections::HashMap::new();
    for declaration in collect_kinds(tree, &["typealias_declaration"]) {
        // Tree-sitter preserves source order here: the first named child is
        // the alias declaration name and the second is its target type. Do
        // not use the generic stack collector, whose LIFO traversal reverses
        // siblings and would invert `Alias = Target`.
        let mut cursor = declaration.walk();
        let mut children = declaration.named_children(&mut cursor);
        let Some(alias_node) = children.next() else {
            continue;
        };
        let Some(target_node) = children.next() else {
            continue;
        };
        let alias = node_text(&alias_node, src).trim();
        let target = node_text(&target_node, src).trim();
        if !alias.is_empty() && !target.is_empty() && alias != target {
            aliases.insert(alias.to_string(), target.to_string());
        }
    }
    aliases
}

fn apply_swift_declared_type_aliases(
    index: &mut DeclIndex,
    aliases: &std::collections::HashMap<String, String>,
) {
    if aliases.is_empty() {
        return;
    }
    for decl in &mut index.defs {
        for binding in &mut decl.type_aliases {
            binding.type_name = resolve_swift_declared_type_alias(&binding.type_name, aliases);
        }
        if let Some(return_type) = &mut decl.return_type {
            *return_type = resolve_swift_declared_type_alias(return_type, aliases);
        }
        rewrite_swift_event_receiver_type_aliases(&mut decl.flow_events, aliases);
    }
}

fn resolve_swift_declared_type_alias(
    type_name: &str,
    aliases: &std::collections::HashMap<String, String>,
) -> String {
    let mut current = type_name.trim();
    let mut seen = std::collections::HashSet::new();
    while seen.insert(current.to_string()) {
        let Some(next) = aliases.get(current).map(String::as_str) else {
            break;
        };
        current = next.trim();
    }
    current.to_string()
}

fn rewrite_swift_event_receiver_type_aliases(
    events: &mut [FlowEvent],
    aliases: &std::collections::HashMap<String, String>,
) {
    for event in events {
        match event {
            FlowEvent::Call { receiver_types, .. } => {
                for receiver_type in receiver_types {
                    *receiver_type = resolve_swift_declared_type_alias(receiver_type, aliases);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_swift_event_receiver_type_aliases(then_events, aliases);
                rewrite_swift_event_receiver_type_aliases(else_events, aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_swift_event_receiver_type_aliases(body, aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_swift_event_receiver_type_aliases(body, aliases);
                rewrite_swift_event_receiver_type_aliases(catch_events, aliases);
                rewrite_swift_event_receiver_type_aliases(finally_events, aliases);
            }
            _ => {}
        }
    }
}

fn collect_swift_function_param_names(file: FileId, tree: &Tree, src: &[u8]) -> Vec<(Span, Vec<String>)> {
    collect_kinds(tree, &["function_declaration"])
        .into_iter()
        .map(|function| {
            let mut params = Vec::new();
            let mut cursor = function.walk();
            for child in function.named_children(&mut cursor) {
                if child.kind() != "parameter" {
                    continue;
                }
                if let Some(name) = parameter_binding_name(child, src) {
                    params.push(name);
                }
            }
            (span_of(file, &function), params)
        })
        .collect()
}

fn synthesize_swift_constructor_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let class_names = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| decl.name.clone())
        .collect::<Vec<_>>();
    let classes = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| {
            let has_possible_superclass = decl.bases.first().is_some_and(|base| {
                idx.defs
                    .iter()
                    .find(|candidate| is_class_like(candidate.kind) && candidate.name == *base)
                    .is_none_or(|candidate| candidate.kind != DeclKind::Interface)
            });
            (
                decl.span,
                decl.symbol,
                decl.kind,
                decl.name.clone(),
                decl.name_span,
                has_possible_superclass,
            )
        })
        .collect::<Vec<_>>();
    let mut next = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    for init in collect_kinds(tree, &["init_declaration"]) {
        let Some(class_node) = nearest_swift_class_node(init) else {
            continue;
        };
        let class_span = span_of(file, &class_node);
        let Some((_, class_symbol, _, class_name, class_name_span, _)) =
            classes.iter().find(|(span, _, _, _, _, _)| *span == class_span)
        else {
            continue;
        };
        let body = first_named_child_of_kind(&init, "function_body").unwrap_or(init);
        // Stored-property initializers execute before every designated
        // initializer body. Lower only direct property declarations from the
        // class body, then the selected `init` body; never walk sibling
        // methods as constructor work.
        let mut flow_events = swift_stored_property_initializer_events(class_node, file, src, &class_names);
        flow_events.extend(walk_flow_events(body, file, src, &HANDLER, &class_names));
        idx.defs.push(swift_constructor_decl(
            bonsai_common::SymbolId::new(next),
            *class_symbol,
            class_name,
            SwiftConstructorSpans {
                name: *class_name_span,
                decl: span_of(file, &init),
                body: span_of(file, &body),
            },
            constructor_param_names(init, src),
            flow_events,
        ));
        next = next.saturating_add(1);
    }

    // A Swift class whose stored properties all have initial values receives
    // an implicit zero-argument initializer even when no `init` declaration
    // appears. Lower that compiler-synthesized constructor so property
    // initializer calls remain available to cross-file receiver resolution.
    for class_node in collect_kinds(tree, &["class_declaration"]) {
        let class_span = span_of(file, &class_node);
        let Some((_, class_symbol, class_kind, class_name, class_name_span, has_possible_superclass)) =
            classes.iter().find(|(span, _, _, _, _, _)| *span == class_span)
        else {
            continue;
        };
        if *class_kind != DeclKind::Class
            || !swift_node_declares_reference_class(class_node)
            // A subclass with no designated initializer inherits the
            // superclass's designated initializers; it does not acquire an
            // unrelated zero-argument initializer. Preserve that exact
            // language rule so `Child(value)` resolves to the inherited
            // constructor rather than a fabricated local overload.
            || *has_possible_superclass
            || !swift_class_stored_properties_have_defaults(class_node, src)
            || idx
                .defs
                .iter()
                .any(|decl| decl.kind == DeclKind::Constructor && decl.parent == Some(*class_symbol))
        {
            continue;
        }
        let Some(body) = first_named_child_of_kind(&class_node, "class_body") else {
            continue;
        };
        let flow_events = swift_stored_property_initializer_events(class_node, file, src, &class_names);
        idx.defs.push(swift_constructor_decl(
            bonsai_common::SymbolId::new(next),
            *class_symbol,
            class_name,
            SwiftConstructorSpans {
                name: *class_name_span,
                decl: class_span,
                body: span_of(file, &body),
            },
            Vec::new(),
            flow_events,
        ));
        next = next.saturating_add(1);
    }
}

/// Lower the instance stored-property initializers that Swift executes as the
/// prefix of every designated class initializer. The class body is not itself
/// executable: walking it wholesale would incorrectly pull method/getter
/// bodies into construction. Direct property CST nodes are the exact boundary.
fn swift_stored_property_initializer_events(
    class_node: Node<'_>,
    file: FileId,
    src: &[u8],
    class_names: &[String],
) -> Vec<bonsai_lang_api::FlowEvent> {
    let Some(body) = first_named_child_of_kind(&class_node, "class_body") else {
        return Vec::new();
    };
    let mut events = Vec::new();
    let mut cursor = body.walk();
    for property in body.named_children(&mut cursor) {
        if property.kind() != "property_declaration"
            || swift_property_is_computed(property)
            || swift_property_is_type_member(property, src)
            || !swift_property_has_initializer(property)
        {
            continue;
        }
        events.extend(walk_flow_events(property, file, src, &HANDLER, class_names));
    }
    qualify_swift_constructor_property_assignments(&mut events, class_node, file, src);
    events
}

fn swift_property_is_computed(property: Node<'_>) -> bool {
    let mut cursor = property.walk();
    let computed = property
        .named_children(&mut cursor)
        .any(|node| node.kind() == "computed_property");
    computed
}

fn swift_class_stored_properties_have_defaults(class_node: Node<'_>, src: &[u8]) -> bool {
    let Some(body) = first_named_child_of_kind(&class_node, "class_body") else {
        return true;
    };
    let mut cursor = body.walk();
    for property in body.named_children(&mut cursor) {
        if property.kind() != "property_declaration" {
            continue;
        }
        if swift_property_is_computed(property) || swift_property_is_type_member(property, src) {
            continue;
        }
        if !swift_property_has_initializer(property) {
            return false;
        }
    }
    true
}

fn swift_property_is_type_member(property: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = property.walk();
    let is_type_member = property
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "modifiers")
        .any(|modifiers| {
            let mut modifier_cursor = modifiers.walk();
            let has_type_modifier = modifiers
                .named_children(&mut modifier_cursor)
                .filter(|child| child.kind() == "property_modifier")
                .any(|modifier| matches!(node_text(&modifier, src).trim(), "static" | "class"));
            has_type_modifier
        });
    is_type_member
}

fn swift_property_has_initializer(property: Node<'_>) -> bool {
    if property.child_by_field_name("value").is_some() {
        return true;
    }

    fn contains_initializer_token(node: Node<'_>) -> bool {
        let mut cursor = node.walk();
        if !cursor.goto_first_child() {
            return false;
        }
        loop {
            let child = cursor.node();
            if !child.is_named() && child.kind() == "=" {
                return true;
            }
            if !cursor.goto_next_sibling() {
                return false;
            }
        }
    }

    if contains_initializer_token(property) {
        return true;
    }
    let mut cursor = property.walk();
    let has_initializer = property
        .named_children(&mut cursor)
        .any(contains_initializer_token);
    has_initializer
}

fn swift_node_declares_reference_class(node: Node<'_>) -> bool {
    matches!(swift_type_declaration_keyword(node), Some("class" | "actor"))
}

fn qualify_swift_constructor_property_assignments(
    events: &mut [bonsai_lang_api::FlowEvent],
    class_node: Node<'_>,
    file: FileId,
    src: &[u8],
) {
    let Some(body) = first_named_child_of_kind(&class_node, "class_body") else {
        return;
    };
    let mut properties = std::collections::HashMap::new();
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if child.kind() != "property_declaration" {
            continue;
        }
        if swift_property_is_computed(child) || swift_property_is_type_member(child, src) {
            continue;
        }
        let Some(name) = swift_property_name(child, src) else {
            continue;
        };
        properties.insert(span_of(file, &child), name);
    }

    fn qualify(
        events: &mut [bonsai_lang_api::FlowEvent],
        properties: &std::collections::HashMap<Span, String>,
    ) {
        for event in events {
            match event {
                bonsai_lang_api::FlowEvent::Assign { span, target, .. } => {
                    let Some(name) = properties.get(span) else {
                        continue;
                    };
                    if target == name {
                        *target = format!("self.{name}");
                    }
                }
                bonsai_lang_api::FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    qualify(then_events, properties);
                    qualify(else_events, properties);
                }
                bonsai_lang_api::FlowEvent::Loop { body, .. }
                | bonsai_lang_api::FlowEvent::Defer { body, .. }
                | bonsai_lang_api::FlowEvent::Using { body, .. } => qualify(body, properties),
                bonsai_lang_api::FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    qualify(body, properties);
                    qualify(catch_events, properties);
                    qualify(finally_events, properties);
                }
                _ => {}
            }
        }
    }

    qualify(events, &properties);
}

fn nearest_swift_class_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "class_declaration" | "protocol_declaration") {
            return Some(parent);
        }
        node = parent;
    }
    None
}

struct SwiftConstructorSpans {
    name: Span,
    decl: Span,
    body: Span,
}

fn swift_constructor_decl(
    symbol: bonsai_common::SymbolId,
    parent: bonsai_common::SymbolId,
    class_name: &str,
    spans: SwiftConstructorSpans,
    params: Vec<String>,
    flow_events: Vec<bonsai_lang_api::FlowEvent>,
) -> Decl {
    let receiver_field_writes =
        collect_receiver_field_writes(&flow_events, &params, None, &["self", "super"], &[]);
    let receiver_field_initializers =
        bonsai_lang_api::collect_receiver_field_initializers(&flow_events, &["self"]);
    Decl {
        symbol,
        kind: DeclKind::Constructor,
        name: class_name.to_string(),
        qualified_name: None,
        module_path: bonsai_lang_api::ModulePath::default(),
        span: spans.decl,
        name_span: spans.name,
        visibility: Visibility::Module,
        parent: Some(parent),
        body_span: Some(spans.body),
        flow_events,
        has_implicit_returns: false,
        params,
        param_annotations: Vec::new(),
        param_default_calls: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes,
        receiver_field_initializers,
        implicit_receiver_names: vec!["self".to_string(), "super".to_string()],
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn constructor_param_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    collect_descendant_kinds(node, &["parameter"])
        .into_iter()
        .filter_map(|param| parameter_binding_name(param, src))
        .collect()
}

fn parameter_binding_name(param: Node<'_>, src: &[u8]) -> Option<String> {
    let mut names = Vec::new();
    collect_binding_identifiers(param, src, &mut names);
    names.into_iter().rev().find(|name| name != "_")
}

fn collect_binding_identifiers(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if matches!(node.kind(), "simple_identifier" | "identifier") {
        let name = node_text(&node, src).trim();
        if !name.is_empty() {
            out.push(name.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "user_type" | "type_identifier") {
            continue;
        }
        collect_binding_identifiers(child, src, out);
    }
}

fn collect_descendant_kinds<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if kinds.contains(&current.kind()) {
            out.push(current);
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Walk every Swift class-like declaration and pull `(name, type)`
/// bindings from its `property_declaration` children. Returns
/// `(class_span, [TypeAliasBinding])` so the per-method merge can
/// attach a class's bindings to every method nested inside it.
fn collect_swift_class_field_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Vec<(Span, Vec<TypeAliasBinding>)> {
    let class_kinds = &["class_declaration", "protocol_declaration"];
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![class_node];
        while let Some(node) = work.pop() {
            if node != class_node && class_kinds.contains(&node.kind()) {
                continue;
            }
            // Don't descend into method bodies — that scope is owned
            // by the per-method param-alias pass.
            if node != class_node
                && matches!(
                    node.kind(),
                    "function_declaration" | "init_declaration" | "deinit_declaration"
                )
            {
                continue;
            }
            if node.kind() == "property_declaration" {
                if let Some(binding) = swift_property_alias(node, src, declared_type_names) {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                work.push(child);
            }
        }
        if !aliases.is_empty() {
            out.push((span_of(file, &class_node), aliases));
        }
    }
    out
}

/// Extract a `name: Type` binding from a Swift `property_declaration`.
/// Handles both `let x: T = ...` (explicit type) and `let x = T()` when
/// `T` resolves to an exact declaration in this compiler object.
fn swift_property_alias(
    node: Node<'_>,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Option<TypeAliasBinding> {
    let pattern = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.named_children(&mut cursor) {
            if matches!(child.kind(), "pattern" | "simple_identifier" | "identifier") {
                found = Some(child);
                break;
            }
        }
        found
    })?;
    let name = node_text(&pattern, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let type_short = swift_property_declared_type(node)
        .map(|t| node_text(&t, src).to_string())
        .and_then(|t| swift_canonical_type(&t))
        .or_else(|| swift_property_constructor_type(node, src, declared_type_names))?;
    if name == type_short {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: type_short,
    })
}

/// Return the exact stored-property type node. Tree-sitter Swift wraps an
/// explicit `name: Type` in `type_annotation` and fields the nested type as
/// `name`; older grammar revisions fielded the type directly. Both are CST
/// schemas owned by this adapter, not source-text inference.
fn swift_property_declared_type(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("type").or_else(|| {
        let mut cursor = node.walk();
        let annotation = node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "type_annotation");
        annotation.and_then(|annotation| {
            annotation.child_by_field_name("name").or_else(|| {
                let mut annotation_cursor = annotation.walk();
                let child = annotation.named_children(&mut annotation_cursor).next();
                child
            })
        })
    })
}

/// Find a constructor-shaped initializer (`= Foo()` / `= Foo.bar()`)
/// inside a Swift property_declaration whose static type is
/// `Foo`. Returns the canonical short type, or `None` when the
/// initializer's callee is not a declared type.
fn swift_property_constructor_type(
    node: Node<'_>,
    src: &[u8],
    declared_type_names: &std::collections::HashSet<String>,
) -> Option<String> {
    let call = node.child_by_field_name("value")?;
    if call.kind() != "call_expression" {
        return None;
    }
    let callee = call.child_by_field_name("function").or_else(|| {
        let mut inner = call.walk();
        let mut found = None;
        for child in call.named_children(&mut inner) {
            if matches!(
                child.kind(),
                "simple_identifier" | "identifier" | "navigation_expression" | "type_identifier"
            ) {
                found = Some(child);
                break;
            }
        }
        found
    })?;
    let canonical = swift_canonical_type(node_text(&callee, src))?;
    declared_type_names.contains(&canonical).then_some(canonical)
}

fn swift_canonical_type(raw: &str) -> Option<String> {
    let no_generics = raw.split('<').next().unwrap_or(raw);
    let trimmed = no_generics.trim().trim_end_matches('?').trim_end_matches('!');
    let short = trimmed.rsplit('.').next().unwrap_or(trimmed).trim();
    if short.is_empty()
        || !short
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return None;
    }
    Some(short.to_string())
}

/// True when the decl is a type-defining container that can carry `bases`.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Per-arm body spans for every `switch_statement` in the file.
///
/// Swift shape: `switch_statement > switch_entry+ > statements (the arm
/// body)`. Each `switch_entry` is one arm — `case` or `default`. We pass
/// these spans to the kit's `split_match_arms_in_branch_events` to peel
/// the kit-emitted flat Branch into per-arm forks.
fn collect_swift_switch_arm_spans(tree: &Tree, _src: &[u8], file: FileId) -> Vec<Vec<bonsai_common::Span>> {
    let mut spans_per_switch: Vec<Vec<bonsai_common::Span>> = Vec::new();
    for switch_node in collect_kinds(tree, &["switch_statement"]) {
        let mut arm_body_spans: Vec<bonsai_common::Span> = Vec::new();
        let mut switch_cursor = switch_node.walk();
        for entry in switch_node.named_children(&mut switch_cursor) {
            if entry.kind() != "switch_entry" {
                continue;
            }
            // Each `switch_entry` (case or default) has a `statements` child holding the arm body.
            let mut entry_cursor = entry.walk();
            for entry_child in entry.named_children(&mut entry_cursor) {
                if entry_child.kind() == "statements" {
                    arm_body_spans.push(span_of(file, &entry_child));
                }
            }
        }
        if !arm_body_spans.is_empty() {
            spans_per_switch.push(arm_body_spans);
        }
    }
    spans_per_switch
}

/// Walk Swift class / struct / protocol / enum / extension declarations and
/// collect bare base type names from `inheritance_specifier` children.
///
/// Grammar shape (verified):
///
///   `class Echo: WebSocketHandler, Mixin { ... }` →
///     (class_declaration name: (type_identifier)
///        (inheritance_specifier inherits_from: (user_type (type_identifier)))
///        (inheritance_specifier inherits_from: (user_type (type_identifier))))
///
/// Each `inheritance_specifier` carries one parent under the `inherits_from`
/// field. Swift doesn't distinguish super-class from protocol conformance
/// syntactically; both surface here.
fn collect_swift_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_declaration", "protocol_declaration"];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut child_cursor = class_node.walk();
        for child in class_node.named_children(&mut child_cursor) {
            if child.kind() != "inheritance_specifier" {
                continue;
            }
            // Older grammars don't expose `inherits_from:` as a field — fall back
            // to the first user_type / type_identifier child.
            let mut fallback_cursor = child.walk();
            let fallback_child = child
                .named_children(&mut fallback_cursor)
                .find(|sub| matches!(sub.kind(), "user_type" | "type_identifier"));
            let target = child.child_by_field_name("inherits_from").or(fallback_child);
            if let Some(target_node) = target {
                if let Some(name) = canonical_swift_base_name(node_text(&target_node, src)) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Canonicalize a Swift base reference to a bare type name.
///
/// Strips generic parameter lists (`Foo<T>` → `Foo`) and any qualifying
/// path (`pkg.Foo` → `Foo`).
fn canonical_swift_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Strip generic parameter list: `Foo<Bar>` → `Foo`.
    let head = trimmed.split('<').next().unwrap_or(trimmed).trim();
    // Strip qualifying path: `Module.Foo` → `Foo`.
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Parse `import_declaration` nodes into `ImportSpec`s.
///
/// Swift import declarations may name a whole module or one declaration of a
/// specified symbol kind. Per-symbol kinds are stripped; the module path still
/// resolves via short-tail matching.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for import_node in collect_kinds(tree, &["import_declaration"]) {
        // Strip any leading Swift attribute (`@testable`, `@_exported`,
        // `@available(...)`, ...) before the `import ` trim — otherwise
        // the attribute corrupts the module name and fails the package gate.
        let text = strip_swift_import_attribute_prefixes(node_text(&import_node, src))
            .trim_start_matches("import ")
            .trim();
        // Strip the optional symbol-kind keyword so the resulting module path
        // matches what callers reference at use sites.
        // A plain Swift module import makes the module's
        // public declarations available as bare bindings. Symbol-kind imports
        // expose only the named declaration and therefore are not wildcard
        // imports.
        // Retain that semantic distinction as an exact compiler import fact;
        // consumers must not guess it from API names.
        let imports_module_members = ![
            "struct ",
            "class ",
            "func ",
            "var ",
            "let ",
            "typealias ",
            "enum ",
            "protocol ",
        ]
        .iter()
        .any(|kind| text.starts_with(kind));
        let module = text
            .strip_prefix("struct ")
            .or_else(|| text.strip_prefix("class "))
            .or_else(|| text.strip_prefix("func "))
            .or_else(|| text.strip_prefix("var "))
            .or_else(|| text.strip_prefix("let "))
            .or_else(|| text.strip_prefix("typealias "))
            .or_else(|| text.strip_prefix("enum "))
            .or_else(|| text.strip_prefix("protocol "))
            .unwrap_or(text)
            .trim()
            .to_string();
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module,
            alias: None,
            is_wildcard: imports_module_members,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Strip leading Swift attribute tokens from an `import_declaration`'s
/// text so the module name resolves cleanly. `@testable import
/// Foundation` -> `import Foundation`; `@_exported import X` -> `import
/// X`. Handles an optional `(...)` attribute argument list and multiple
/// stacked attributes. A no-op when no leading `@` is present.
fn strip_swift_import_attribute_prefixes(text: &str) -> &str {
    let mut rest = text.trim_start();
    while let Some(after_at) = rest.strip_prefix('@') {
        // Consume the attribute identifier (`testable`, `_exported`, ...).
        let ident_end = after_at
            .find(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
            .unwrap_or(after_at.len());
        if ident_end == 0 {
            break; // bare `@` with no identifier — leave untouched.
        }
        let mut after_ident = after_at[ident_end..].trim_start();
        // Optional balanced argument list, e.g. `@available(...)`.
        if let Some(after_paren) = after_ident.strip_prefix('(') {
            match after_paren.find(')') {
                Some(close) => after_ident = after_paren[close + 1..].trim_start(),
                None => break, // unbalanced — give up rather than mangle.
            }
        }
        rest = after_ident;
    }
    rest
}

/// Synthesize a zero-arg `Method` decl for each Swift computed
/// property — `var cmd: String { data.cmd }` — by extracting the
/// property name + computed-property body. The kit's fn-kind set is
/// `["function_declaration"]`, so `property_declaration` nodes (which
/// is what computed properties parse to in tree-sitter-swift) aren't
/// indexed and a bare property read `let c = cmd` resolves to
/// nothing. A simple member projection remains an exact value place in the
/// synthesized return; it must not be converted into a call merely because
/// Swift executes an accessor behind that syntax.
fn synthesize_swift_computed_property_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let mut next = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(1, |m| m + 1);
    let class_names = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| decl.name.clone())
        .collect::<Vec<_>>();
    let mut synthesized: Vec<Decl> = Vec::new();
    for prop in collect_kinds(tree, &["property_declaration"]) {
        // Only handle computed properties — a `computed_value:
        // computed_property` child. Stored properties (no body) are
        // already represented via `let x: T` field bindings.
        let mut pw = prop.walk();
        let Some(computed) = prop.children(&mut pw).find(|c| c.kind() == "computed_property") else {
            continue;
        };
        // Property name lives under `name: pattern > simple_identifier`.
        let Some(name) = swift_property_name(prop, src) else {
            continue;
        };
        // Extract the body expression text. For
        // `computed_property > statements > <expr>`, take the
        // statements' last named child.
        let Some(body_expression) = swift_computed_body_expression(computed) else {
            continue;
        };
        let body_text = node_text(&body_expression, src).trim().to_string();
        if body_text.is_empty() {
            continue;
        }
        let body_span = span_of(file, &body_expression);
        // Find enclosing class/struct/protocol/extension decl for
        // parent + module path + visibility lookup.
        let Some((parent, module_path, visibility)) = swift_enclosing_type_decl(idx, prop, file) else {
            continue;
        };
        // Skip if a sibling decl with the same name + zero-arg
        // already exists (e.g. an explicit `get` accessor).
        if idx.defs.iter().chain(synthesized.iter()).any(|d| {
            d.parent == parent
                && d.name == name
                && d.params.is_empty()
                && matches!(d.kind, DeclKind::Method | DeclKind::Function)
        }) {
            continue;
        }
        let mut value_flow = expression_flow_from_node_with_handler(body_expression, file, src, &HANDLER);
        if let Some(place) = value_flow.place.clone() {
            let base = value_flow
                .projection
                .as_ref()
                .map(|projection| projection.base.as_str())
                .unwrap_or(place.as_str());
            if !matches!(base, "self" | "super") && swift_has_sibling_property(prop, base, src) {
                value_flow = bonsai_lang_api::ExpressionFlow::from_place(format!("self.{place}"));
            }
        }
        let value_name = value_flow.place.clone();
        // A computed getter is executable code, not merely a return-value
        // projection. Reuse the ordinary adapter lowering for its complete
        // body so calls, assignments, branches and callback registrations
        // retain the same typed events as ordinary methods. Nested callback
        // bodies stay in their own declarations.
        let mut flow_events = walk_flow_events(computed, file, src, &HANDLER, &class_names);
        if !HANDLER.return_kinds.contains(&body_expression.kind()) {
            flow_events.push(FlowEvent::Return {
                span: body_span,
                value_kind: HANDLER
                    .expression_value_kind(body_expression, src)
                    .or(Some(bonsai_lang_api::AssignValueKind::Compound)),
                value_text: Some(body_text),
                value_name,
                value_flow,
            });
        }
        // Name span: the simple_identifier under `name: pattern`.
        let name_span = swift_property_name_span(prop, file).unwrap_or(body_span);
        // This declaration is synthesized after the kit's ordinary callable
        // lowering pass, so derive the same receiver-state summary here from
        // the exact getter events. A computed getter such as
        // `var cmd { data.cmd }` consumes the enclosing instance's `data`
        // field; leaving this empty loses constructor state when a caller
        // evaluates the implicit `self.cmd` access.
        let receiver_state_sources =
            collect_receiver_state_sources(&flow_events, &[], HANDLER.implicit_receiver_names);
        synthesized.push(Decl {
            symbol: bonsai_common::SymbolId::new(next),
            kind: DeclKind::Method,
            name,
            qualified_name: None,
            module_path,
            span: name_span,
            name_span,
            visibility,
            parent,
            body_span: Some(span_of(file, &computed)),
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
            implicit_receiver_names: vec!["self".to_string(), "super".to_string()],
            receiver_state_sources,
            return_type: None,
            is_variadic: false,
        });
        next += 1;
    }
    if !synthesized.is_empty() {
        // These executable owners did not exist during the kit's initial
        // argument projection. Lower their exact argument/callback shapes
        // through that same compiler API before static-value enrichment.
        idx.call_argument_values
            .extend(bonsai_lang_api::kit::extract_call_argument_value_facts(
                tree,
                file,
                &synthesized,
                src,
                &HANDLER,
            ));
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
    idx.defs.extend(synthesized);
    // After synthesis, rewrite bare-name reads of these getters
    // throughout the file's method bodies (`let c = cmd` → `Call cmd; Assign{source_call:cmd}`).
    qualify_swift_implicit_member_reads(idx);
}

/// Synthesize the zero-argument getter Swift generates for each concrete
/// instance stored property.
///
/// Tree-sitter represents stored and computed property reads with the same
/// `navigation_expression`. The frontend already emits a pseudo-call for that
/// operation; this declaration makes the call resolvable from exact class-body
/// syntax rather than guessing that an arbitrary member name is a field.
fn synthesize_swift_stored_property_accessors(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let mut next = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(1, |m| m + 1);
    let mut synthesized = Vec::new();
    for type_node in collect_kinds(tree, &["class_declaration"]) {
        let type_span = span_of(file, &type_node);
        let Some(parent_decl) = idx
            .defs
            .iter()
            .find(|decl| decl.span == type_span && decl.kind == DeclKind::Class)
        else {
            continue;
        };
        let parent = Some(parent_decl.symbol);
        let module_path = parent_decl.module_path.clone();
        let visibility = parent_decl.visibility;
        let Some(body) = first_named_child_of_kind(&type_node, "class_body") else {
            continue;
        };
        let mut cursor = body.walk();
        for property in body.named_children(&mut cursor) {
            if property.kind() != "property_declaration"
                || swift_property_is_computed(property)
                || swift_property_is_type_member(property, src)
            {
                continue;
            }
            let Some(name) = swift_property_name(property, src) else {
                continue;
            };
            if idx.defs.iter().chain(synthesized.iter()).any(|decl| {
                decl.parent == parent
                    && decl.name == name
                    && decl.params.is_empty()
                    && matches!(decl.kind, DeclKind::Method | DeclKind::Function)
            }) {
                continue;
            }
            let name_span =
                swift_property_name_span(property, file).unwrap_or_else(|| span_of(file, &property));
            let field = format!("self.{name}");
            synthesized.push(Decl {
                symbol: bonsai_common::SymbolId::new(next),
                kind: DeclKind::Method,
                name,
                qualified_name: None,
                module_path: module_path.clone(),
                span: name_span,
                name_span,
                visibility,
                parent,
                body_span: Some(name_span),
                flow_events: vec![FlowEvent::Return {
                    span: name_span,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                    value_text: Some(field.clone()),
                    value_name: Some(field.clone()),
                    value_flow: bonsai_lang_api::ExpressionFlow::from_place(field.clone()),
                }],
                has_implicit_returns: false,
                params: Vec::new(),
                param_annotations: Vec::new(),
                param_default_calls: Vec::new(),
                type_aliases: Vec::new(),
                bases: Vec::new(),
                receiver_param_index: None,
                receiver_field_writes: Vec::new(),
                receiver_field_initializers: Vec::new(),
                implicit_receiver_names: vec!["self".to_string(), "super".to_string()],
                receiver_state_sources: vec![field],
                return_type: None,
                is_variadic: false,
            });
            next += 1;
        }
    }
    idx.defs.extend(synthesized);
}

/// Extract the property name from the current grammar's
/// `property_declaration > name: pattern > simple_identifier` shape.
fn swift_property_name(prop: Node<'_>, src: &[u8]) -> Option<String> {
    let pattern = prop.child_by_field_name("name")?;
    if let Some(identifier) = first_named_child_of_kind(&pattern, "simple_identifier") {
        let name = node_text(&identifier, src).trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

/// Span of a `property_declaration`'s name token, for stamping the
/// synthesized accessor's `name_span` precisely.
fn swift_property_name_span(prop: Node<'_>, file: FileId) -> Option<Span> {
    let pattern = prop.child_by_field_name("name")?;
    if let Some(identifier) = first_named_child_of_kind(&pattern, "simple_identifier") {
        return Some(span_of(file, &identifier));
    }
    None
}

/// Return the exact expression node from a `computed_property` body.
/// Tree-sitter Swift wraps it in `statements`; retaining the node lets every
/// later value/call fact use grammar fields instead of reparsing rendered
/// source.
fn swift_computed_body_expression(computed: Node<'_>) -> Option<Node<'_>> {
    let mut cw = computed.walk();
    let stmts = computed.children(&mut cw).find(|c| c.kind() == "statements")?;
    let mut sw = stmts.walk();
    let named: Vec<_> = stmts.children(&mut sw).filter(|c| c.is_named()).collect();
    named.last().copied()
}

/// Prove that an unqualified computed-property value starts at an instance
/// member declared in the same nominal body. The proof is purely lexical CST
/// membership; no capitalization convention or external API spelling is
/// involved.
fn swift_has_sibling_property(prop: Node<'_>, member: &str, src: &[u8]) -> bool {
    let mut ancestor = prop.parent();
    let mut body = None;
    while let Some(node) = ancestor {
        if node.kind() == "class_body" {
            body = Some(node);
            break;
        }
        ancestor = node.parent();
    }
    let Some(body) = body else {
        return false;
    };
    let mut cursor = body.walk();
    let found = body.named_children(&mut cursor).any(|child| {
        child.kind() == "property_declaration" && swift_property_name(child, src).as_deref() == Some(member)
    });
    found
}

/// Walk up from `node` to the enclosing nominal/protocol declaration and
/// return its symbol / module / visibility for
/// parenting synthesized accessor decls.
fn swift_enclosing_type_decl(
    idx: &DeclIndex,
    node: Node<'_>,
    file: FileId,
) -> Option<(
    Option<bonsai_common::SymbolId>,
    bonsai_lang_api::ModulePath,
    Visibility,
)> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if matches!(n.kind(), "class_declaration" | "protocol_declaration") {
            let span = span_of(file, &n);
            return idx
                .defs
                .iter()
                .find(|d| d.span == span)
                .map(|d| (Some(d.symbol), d.module_path.clone(), d.visibility));
        }
        cur = n.parent();
    }
    None
}

/// Mirror `qualify_csharp_implicit_member_reads` / `qualify_dart_...`
/// for Swift: bare reads of a sibling zero-arg member (`let c = cmd`)
/// are compiler-style implicit-`self` member calls. Preserve that receiver
/// explicitly so resolution and receiver-field flow use the AST's lexical
/// class context rather than treating the getter as a free function.
fn qualify_swift_implicit_member_reads(index: &mut DeclIndex) {
    bonsai_lang_api::qualify_implicit_member_reads_in_index(index, |name| ImplicitMemberReadCall {
        source_call: format!("self.{name}"),
        call_name: format!("self.{name}"),
        receiver: Some("self".to_string()),
        call_kind: CallKind::Method,
    });
}

/// Synthesize the compiler constructor represented by each associated-value
/// enum case.  Swift's grammar exposes the case name and an exact ordered
/// `enum_type_parameters` list, but no explicit function declaration.  The
/// positional payload bindings below are generic compiler IR: pattern flow
/// later projects the constructed enum value without the adapter knowing what
/// the payload means.
fn synthesize_swift_enum_case_constructors(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    use bonsai_lang_api::FieldWrite;

    let enum_owners = idx
        .defs
        .iter()
        .filter(|decl| decl.kind == DeclKind::Enum)
        .map(|decl| {
            (
                decl.span,
                decl.symbol,
                decl.name.clone(),
                decl.module_path.clone(),
                decl.visibility,
            )
        })
        .collect::<Vec<_>>();
    let mut next = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let mut constructors = Vec::new();

    for entry in collect_kinds(tree, &["enum_entry"]) {
        let Some(owner_node) = entry
            .parent()
            .and_then(|body| body.parent())
            .filter(|owner| owner.kind() == "class_declaration")
        else {
            continue;
        };
        let owner_span = span_of(file, &owner_node);
        let Some((_, owner_symbol, owner_name, module_path, visibility)) =
            enum_owners.iter().find(|(span, ..)| *span == owner_span)
        else {
            continue;
        };
        let (Some(name_node), Some(parameters)) = (
            entry.child_by_field_name("name"),
            entry.child_by_field_name("data_contents"),
        ) else {
            continue;
        };
        let name = node_text(&name_node, src).trim();
        if name.is_empty() || parameters.kind() != "enum_type_parameters" {
            continue;
        }
        let mut parameter_cursor = parameters.walk();
        let parameter_nodes = parameters
            .named_children(&mut parameter_cursor)
            .collect::<Vec<_>>();
        if parameter_nodes.is_empty() {
            continue;
        }
        let params = (0..parameter_nodes.len())
            .map(|index| format!("value{index}"))
            .collect::<Vec<_>>();
        let receiver_field_writes = parameter_nodes
            .iter()
            .enumerate()
            .map(|(index, node)| FieldWrite {
                span: span_of(file, node),
                target: format!("self.value{index}"),
                source_param_indices: vec![index],
            })
            .collect();
        constructors.push(Decl {
            symbol: bonsai_common::SymbolId::new(next),
            kind: DeclKind::Constructor,
            name: name.to_string(),
            qualified_name: Some(format!("{owner_name}.{name}")),
            module_path: module_path.clone(),
            span: span_of(file, &entry),
            name_span: span_of(file, &name_node),
            visibility: *visibility,
            parent: Some(*owner_symbol),
            body_span: Some(span_of(file, &entry)),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params,
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes,
            receiver_field_initializers: Vec::new(),
            implicit_receiver_names: vec!["self".to_string()],
            receiver_state_sources: Vec::new(),
            return_type: Some(owner_name.clone()),
            is_variadic: false,
        });
        next = next.saturating_add(1);
    }
    idx.defs.extend(constructors);
}

/// Synthesize a memberwise initializer (Constructor decl) for each
/// Swift struct that has no explicit `init`. Swift's compiler
/// synthesizes one automatically with one labeled param per stored
/// `var`/`let` property; without surfacing this to the IDG,
/// `Envelope(kind:, cmd:, ...)` resolves to nothing and field-
/// projection never reaches the caller's allocation.
fn synthesize_swift_memberwise_struct_inits(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    use bonsai_lang_api::FieldWrite;
    let mut next = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(1, |m| m + 1);
    let mut synthesized: Vec<Decl> = Vec::new();
    // Tree-sitter-swift unifies `class`, `struct`, `enum`, and
    // `actor` under `class_declaration`. Disambiguate by inspecting
    // the prefix text between the node's start and its `name:` child
    // — that range contains only modifiers + the immediate keyword,
    // so `struct` appearing there definitively names THIS decl as a
    // struct (avoids false positives from nested `struct Bar {}` in
    // an outer `class Foo { ... }`). Only structs get a compiler-
    // synthesized memberwise init.
    for struct_node in collect_kinds(tree, &["class_declaration"]) {
        let Some(name_node) = struct_node.child_by_field_name("name") else {
            continue;
        };
        let prefix_start = struct_node.start_byte();
        let prefix_end = name_node.start_byte();
        if prefix_end <= prefix_start || prefix_end > src.len() {
            continue;
        }
        let Ok(prefix) = std::str::from_utf8(&src[prefix_start..prefix_end]) else {
            continue;
        };
        let is_struct = prefix
            .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
            .any(|t| t == "struct");
        if !is_struct {
            continue;
        }
        let struct_span = span_of(file, &struct_node);
        let Some(struct_decl) = idx
            .defs
            .iter()
            .find(|d| d.span == struct_span && is_class_like(d.kind))
        else {
            continue;
        };
        let parent_sym = struct_decl.symbol;
        let module_path = struct_decl.module_path.clone();
        let visibility = struct_decl.visibility;
        let class_name = struct_decl.name.clone();
        let class_name_span = struct_decl.name_span;
        // Skip if an explicit Constructor already exists under this
        // parent (an `init` block).
        let has_explicit_init = idx
            .defs
            .iter()
            .any(|d| matches!(d.kind, DeclKind::Constructor) && d.parent == Some(parent_sym));
        if has_explicit_init {
            continue;
        }
        // Collect stored property names (skip computed properties).
        let body = first_named_child_of_kind(&struct_node, "class_body");
        let Some(body) = body else { continue };
        let mut params: Vec<(String, Span)> = Vec::new();
        let mut bw = body.walk();
        for child in body.children(&mut bw) {
            if child.kind() != "property_declaration" {
                continue;
            }
            // Skip computed properties (they have a `computed_value`
            // child) — those aren't part of the memberwise init.
            let mut pw = child.walk();
            let has_computed = child.children(&mut pw).any(|c| c.kind() == "computed_property");
            if has_computed {
                continue;
            }
            let Some(name) = swift_property_name(child, src) else {
                continue;
            };
            let span = swift_property_name_span(child, file).unwrap_or(span_of(file, &child));
            params.push((name, span));
        }
        if params.is_empty() {
            continue;
        }
        let param_names: Vec<String> = params.iter().map(|(n, _)| n.clone()).collect();
        let receiver_field_writes: Vec<FieldWrite> = params
            .iter()
            .enumerate()
            .map(|(idx, (name, span))| FieldWrite {
                span: *span,
                target: format!("self.{name}"),
                source_param_indices: vec![idx],
            })
            .collect();
        synthesized.push(Decl {
            symbol: bonsai_common::SymbolId::new(next),
            kind: DeclKind::Constructor,
            name: class_name.clone(),
            qualified_name: None,
            module_path: module_path.clone(),
            span: class_name_span,
            name_span: class_name_span,
            visibility,
            parent: Some(parent_sym),
            body_span: Some(class_name_span),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: param_names.clone(),
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes,
            receiver_field_initializers: Vec::new(),
            implicit_receiver_names: vec!["self".to_string()],
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
        next += 1;
        // Synthesize a zero-arg accessor `Method` per stored property,
        // mirroring Java record accessors so `envelope.cmd()` resolves
        // to a callable that returns `self.<cmd>` — without this, the
        // synthesized computed-property pass for `Repository.cmd`
        // (whose body becomes `Call{data.cmd}`) can't dispatch to a
        // Method on `Envelope` and the chain stops at the struct boundary.
        for (name, span) in &params {
            let already = idx.defs.iter().chain(synthesized.iter()).any(|d| {
                d.parent == Some(parent_sym)
                    && d.name == *name
                    && d.params.is_empty()
                    && matches!(d.kind, DeclKind::Method | DeclKind::Function)
            });
            if already {
                continue;
            }
            let field = format!("self.{name}");
            synthesized.push(Decl {
                symbol: bonsai_common::SymbolId::new(next),
                kind: DeclKind::Method,
                name: name.clone(),
                qualified_name: None,
                module_path: module_path.clone(),
                span: *span,
                name_span: *span,
                visibility,
                parent: Some(parent_sym),
                body_span: Some(*span),
                flow_events: vec![FlowEvent::Return {
                    span: *span,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                    value_text: Some(field.clone()),
                    value_name: Some(field.clone()),
                    value_flow: bonsai_lang_api::ExpressionFlow::from_place(field.clone()),
                }],
                has_implicit_returns: false,
                params: Vec::new(),
                param_annotations: Vec::new(),
                param_default_calls: Vec::new(),
                type_aliases: Vec::new(),
                bases: Vec::new(),
                receiver_param_index: None,
                receiver_field_writes: Vec::new(),
                receiver_field_initializers: Vec::new(),
                implicit_receiver_names: vec!["self".to_string()],
                receiver_state_sources: vec![field],
                return_type: None,
                is_variadic: false,
            });
            next += 1;
        }
    }
    idx.defs.extend(synthesized);
}

fn swift_constructor_field_params(
    index: &DeclIndex,
) -> std::collections::HashMap<String, Vec<(usize, String)>> {
    let mut out: std::collections::HashMap<String, Vec<(usize, String)>> = std::collections::HashMap::new();
    for decl in &index.defs {
        if !matches!(decl.kind, DeclKind::Constructor) || decl.receiver_field_writes.is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        for write in &decl.receiver_field_writes {
            let Some(field) = swift_receiver_field_tail(&write.target) else {
                continue;
            };
            for idx in &write.source_param_indices {
                fields.push((*idx, field.clone()));
            }
        }
        if !fields.is_empty() {
            fields.sort();
            fields.dedup();
            out.insert(decl.name.clone(), fields);
        }
    }
    out
}

fn swift_receiver_field_tail(target: &str) -> Option<String> {
    let mut parts = target.split('.').map(str::trim).filter(|part| !part.is_empty());
    let root = parts.next()?;
    if !matches!(root, "self" | "this" | "receiver") {
        return None;
    }
    parts.next().map(str::to_string)
}

fn synthesize_swift_constructor_field_assignments(
    events: &mut Vec<FlowEvent>,
    constructor_field_params: &std::collections::HashMap<String, Vec<(usize, String)>>,
) {
    let original = std::mem::take(events);
    let mut rewritten = Vec::with_capacity(original.len());
    let constructor_calls = (0..original.len())
        .map(|event_index| {
            swift_constructor_call_for_assignment_event(&original, event_index, constructor_field_params)
        })
        .collect::<Vec<_>>();
    for (event_index, mut event) in original.into_iter().enumerate() {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                synthesize_swift_constructor_field_assignments(then_events, constructor_field_params);
                synthesize_swift_constructor_field_assignments(else_events, constructor_field_params);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                synthesize_swift_constructor_field_assignments(body, constructor_field_params);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                synthesize_swift_constructor_field_assignments(body, constructor_field_params);
                synthesize_swift_constructor_field_assignments(catch_events, constructor_field_params);
                synthesize_swift_constructor_field_assignments(finally_events, constructor_field_params);
            }
            _ => {}
        }
        let mut synthetic = Vec::new();
        if let FlowEvent::Assign { span, target, .. } = &event {
            let target = target.trim();
            if !target.is_empty() && target != "_" {
                if let Some((constructor, args)) = constructor_calls[event_index].as_ref() {
                    let fields = constructor_field_params.get(constructor).into_iter().flatten();
                    for (param_idx, field) in fields {
                        let Some(arg) = args.get(*param_idx) else {
                            continue;
                        };
                        let source_names = arg.clone();
                        if source_names.is_empty() {
                            continue;
                        }
                        synthetic.push(FlowEvent::Assign {
                            span: *span,
                            target: format!("{target}.{field}"),
                            source_name: (source_names.len() == 1).then(|| source_names[0].clone()),
                            source_call: None,
                            source_call_args: Vec::new(),
                            source_names,
                            declares_new_binding: false,
                            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                        });
                    }
                }
            }
        }
        rewritten.push(event);
        rewritten.extend(synthetic);
    }
    *events = rewritten;
}

fn swift_constructor_call_for_assignment_event(
    events: &[FlowEvent],
    event_index: usize,
    constructor_field_params: &std::collections::HashMap<String, Vec<(usize, String)>>,
) -> Option<(String, Vec<Vec<String>>)> {
    let FlowEvent::Assign { span, .. } = events.get(event_index)? else {
        return None;
    };
    events.iter().skip(event_index + 1).find_map(|event| {
        let FlowEvent::Call {
            name,
            span: call_span,
            args,
            ..
        } = event
        else {
            return None;
        };
        if call_span.file != span.file || call_span.start < span.start || call_span.end > span.end {
            return None;
        }
        let constructor = swift_constructor_call_tail(name).to_string();
        constructor_field_params.contains_key(&constructor).then(|| {
            (
                constructor,
                args.iter()
                    .map(|arg| {
                        let mut sources = arg.source_names.clone();
                        if let Some(place) = arg.place.as_ref() {
                            if !sources.iter().any(|source| source == place) {
                                sources.push(place.clone());
                            }
                        }
                        sources.sort();
                        sources.dedup();
                        sources
                    })
                    .collect(),
            )
        })
    })
}

fn swift_constructor_call_tail(call: &str) -> &str {
    call.split(['.', ':'])
        .filter(|part| !part.trim().is_empty())
        .next_back()
        .map(str::trim)
        .unwrap_or(call.trim())
}
