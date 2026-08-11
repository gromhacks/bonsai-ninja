//! Go language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, collect_kinds, first_named_child_of_kind, language_from_pack,
        node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, CallKind, CallTargetExtraction,
    CharacterConstraintDomain, CharacterConstraintFact, CharacterConstraintOutput, CompilerGuardFact,
    ConditionEquality, ConditionExpressionFact, ConditionOperandFact, DeclIndex, ExpressionField,
    ExpressionFlow, ExpressionPlaceExtraction, FlowEvent, GrammarHandler, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, SameOriginPathConstraintFact,
    StaticScalarValue, StaticStringMapEntry, StringCompositionFact, StringCompositionPart, TypeAliasBinding,
    Visibility,
};
use tree_sitter::Node;

fn go_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let target = match node.kind() {
        "call_expression" => node.child_by_field_name("function")?,
        "composite_literal" => node.child_by_field_name("type")?,
        _ => return None,
    };
    let full_text = node_text(&target, src).trim();
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text: full_text.to_string(),
    })
}

/// Lower a selector whose receiver includes a zero-argument call into its
/// canonical compiler place (`c.Request().Body`). The adapter owns the CST
/// fields and punctuation; shared matching never learns provider/API names.
fn go_expression_places(node: Node<'_>, src: &[u8]) -> ExpressionPlaceExtraction {
    fn place(node: Node<'_>, src: &[u8]) -> Option<String> {
        match node.kind() {
            "identifier" => {
                let value = node_text(&node, src).trim();
                (!value.is_empty()).then(|| value.to_string())
            }
            "selector_expression" | "field_expression" => {
                let base = place(node.child_by_field_name("operand")?, src)?;
                let field = node_text(&node.child_by_field_name("field")?, src).trim();
                (!field.is_empty()).then(|| format!("{base}.{field}"))
            }
            "call_expression" => {
                let function = node.child_by_field_name("function")?;
                let arguments = node.child_by_field_name("arguments")?;
                let mut cursor = arguments.walk();
                if arguments.named_children(&mut cursor).next().is_some() {
                    return None;
                }
                place(function, src).map(|callee| format!("{callee}()"))
            }
            "parenthesized_expression" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let child = children.next()?;
                children.next().is_none().then(|| place(child, src)).flatten()
            }
            _ => None,
        }
    }

    if !matches!(node.kind(), "selector_expression" | "field_expression") {
        return ExpressionPlaceExtraction::default();
    }
    place(node, src).map_or_else(ExpressionPlaceExtraction::default, |place| {
        ExpressionPlaceExtraction {
            places: vec![place],
            consumed_node_ids: vec![node.id()],
        }
    })
}

fn go_type_switch_alias(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "type_switch_statement")
        .then(|| {
            Some((
                node.child_by_field_name("alias")?,
                node.child_by_field_name("value")?,
            ))
        })
        .flatten()
}

fn go_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "for_statement" {
        return None;
    }
    let mut cursor = node.walk();
    let range = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "range_clause")?;
    let binding = range
        .child_by_field_name("left")
        .or_else(|| range.named_child(0))?;
    let iterable = range
        .child_by_field_name("right")
        .or_else(|| range.named_child(1))?;
    Some((binding, iterable))
}
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("go");
const PACK_NAME: &str = "go";
// `composite_literal` is included so struct-literal initialisers
// surface as call sites (constructor-like). `go_statement` is NOT
// added: tree-sitter-go nests the actual `call_expression` as the
// statement's named child, so the standard recursion already picks
// up `workerFn(x)`. `send_statement` is handled via
// `pseudo_call_event` (lowered to a `send(channel, value)` call so
// the value's taint surfaces) — adding it as a generic call_kind
// would mis-extract the channel as the callee.
const GO_CALL_KINDS: &[&str] = &["call_expression", "composite_literal"];

fn go_indirect_place_operand(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "unary_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let has_indirection = node
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "*" | "&"));
    has_indirection
        .then(|| node.child_by_field_name("operand"))
        .flatten()
}

type GoRangeAssignments = Vec<FlowEvent>;
type GoRangeLoopAssignments = Vec<(Span, GoRangeAssignments)>;
type GoRangeAssignmentsByDecl = Vec<(Span, GoRangeLoopAssignments)>;
type GoIfInitAssignments = Vec<FlowEvent>;
type GoIfInitAssignmentsByDecl = Vec<(Span, Vec<(Span, GoIfInitAssignments)>)>;
type GoIndexAssignments = Vec<FlowEvent>;
type GoIndexAssignmentsByDecl = Vec<(Span, Vec<(Span, GoIndexAssignments)>)>;

fn apply_go_type_declaration_kinds(index: &mut DeclIndex, tree: &Tree, file: FileId) {
    for type_spec in collect_kinds(tree, &["type_spec"]) {
        let kind = match type_spec.child_by_field_name("type").map(|node| node.kind()) {
            Some("struct_type") => bonsai_lang_api::DeclKind::Struct,
            Some("interface_type") => bonsai_lang_api::DeclKind::Interface,
            _ => bonsai_lang_api::DeclKind::TypeAlias,
        };
        let span = span_of(file, &type_spec);
        if let Some(declaration) = index.defs.iter_mut().find(|declaration| declaration.span == span) {
            declaration.kind = kind;
        }
    }
}

const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &[
        "nil",
        "int_literal",
        "float_literal",
        "imaginary_literal",
        "true",
        "false",
    ],
    string_literal_kinds: &["interpreted_string_literal", "raw_string_literal", "rune_literal"],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["///", "/**"],
    parameter_container_kinds: &["parameter_list"],
    parameter_kinds: &["parameter_declaration", "variadic_parameter_declaration"],
    parameter_annotation_name_extractor: None,
    variadic_parameter_kinds: &["variadic_parameter"],
    binding_identifier_kinds: &["identifier"],
    identifier_kinds: &["identifier"],
    aggregate_pattern_kinds: &["expression_list"],
    named_aggregate_kinds: &["literal_value"],
    positional_aggregate_kinds: &["literal_value"],
    aggregate_pair_kinds: &["keyed_element"],
    aggregate_key_field_names: &["key"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["identifier", "field_identifier"],
    aggregate_syntax_only_kinds: &["type_identifier"],
    transparent_call_wrapper_kinds: &["selector_expression", "parenthesized_expression"],
    single_expression_group_kinds: &["expression_list"],
    assignment_target_wrapper_kinds: &["var_spec"],
    binding_declaration_keyword_spellings: &["var", "const", "type"],
    fn_kinds: &["function_declaration", "method_declaration"],
    class_kinds: &["type_spec"],
    class_decl_kinds: &[("type_spec", bonsai_lang_api::DeclKind::TypeAlias)],
    method_kinds: &["method_declaration"],
    if_kinds: &[
        "if_statement",
        "expression_switch_statement",
        "type_switch_statement",
    ],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    branch_alias_extractor: Some(go_type_switch_alias),
    loop_body_field_names: &["body"],
    loop_body_kinds: &["block", "expression_statement"],
    branch_arm_kinds: &["block", "expression_case", "type_case", "default_case"],
    for_kinds: &["for_statement"],
    foreach_binding_extractor: Some(go_foreach_binding),
    call_kinds: GO_CALL_KINDS,
    constructor_call_kinds: &["composite_literal"],
    call_callee_field_names: &["function", "type"],
    constructor_type_field_names: &["type"],
    call_target_extractor: Some(go_call_target),
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list", "literal_value"],
    lambda_body_field_names: &["body"],
    special_forms: &[],
    pseudo_call_extractor: Some(extract_go_pseudo_call),
    syntax_event_extractor: None,
    pseudo_call_receiver_extractor: Some(extract_go_pseudo_call_receiver),
    argument_passing_mode_extractor: Some(go_argument_passing_mode),
    indirect_place_operand_extractor: Some(go_indirect_place_operand),
    call_ref_kinds: GO_CALL_KINDS,
    member_expression_kinds: &["selector_expression", "field_expression"],
    subscript_expression_kinds: &["index_expression"],
    member_base_field_names: &["operand"],
    member_name_field_names: &["field"],
    subscript_base_field_names: &["operand"],
    subscript_index_field_names: &["index"],
    static_subscript_key_extractor: Some(go_static_subscript_key),
    expression_place_extractor: Some(go_expression_places),
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    method_receiver_param_index: Some(0),
    assignment_kinds: &[
        "assignment_statement",
        "short_var_declaration",
        // `var_declaration` is a statement wrapper around one or more
        // `var_spec` nodes. Lowering both manufactures a second assignment
        // whose target is the declared type (`var repo Runner = ...` would
        // produce `Runner = ...`). The parsed `var_spec` owns the exact
        // `name` / `type` / `value` relationships and is the only value
        // operation here.
        "var_spec",
        "const_spec",
    ],
    compound_assignment_operators: &[
        "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|=", "&^=",
    ],
    type_only_declaration_kinds: &["var_spec", "const_spec"],
    return_kinds: &["return_statement"],
    lambda_kinds: &["func_literal"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &["label"],
    defer_kinds: &["defer_statement"],
    ..bonsai_lang_api::EMPTY_HANDLER
};

fn go_argument_passing_mode(argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
    if [argument, value].into_iter().any(|node| {
        node.kind() == "unary_expression" && {
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

fn extract_go_pseudo_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "send_statement" {
        return None;
    }
    let channel = node.child_by_field_name("channel")?;
    let value = node.child_by_field_name("value")?;
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: Some(node_text(&channel, src).trim().to_string()),
        receiver_types: Vec::new(),
        name: "send".to_string(),
        call_kind: CallKind::ChannelSend,
        args: vec![
            call_arg_from_node_with_handler(channel, file, src, None, handler)?,
            call_arg_from_node_with_handler(value, file, src, None, handler)?,
        ],
    })
}

fn extract_go_pseudo_call_receiver<'tree>(node: Node<'tree>, _src: &[u8]) -> Option<Node<'tree>> {
    (node.kind() == "send_statement")
        .then(|| node.child_by_field_name("channel"))
        .flatten()
}

/// Tree-sitter adapter for the Go programming language.
#[derive(Debug, Default, Copy, Clone)]
pub struct GoAdapter;

impl GoAdapter {
    /// Construct a fresh adapter; the type carries no state.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for GoAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Go"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["go"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["any", "interface{}"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            // Go receiver identifiers are explicit syntax on each method
            // declaration and are carried by receiver_param_index.
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Go module_path = workspace-relative package directory plus
        // the file's `package <name>` declaration. The package name
        // alone is not semantic identity: unrelated command packages
        // are often all named `main`, and must not resolve into one
        // another. Falls back to file-stem when the package
        // declaration isn't present.
        let parsed = parse_with(PACK_NAME, file, ctx);
        let package_segment = parsed.as_ref().and_then(|(snapshot, tree)| {
            extract_go_package(tree.root_node(), snapshot.text.as_bytes())
                .map(|name| go_module_segments(file, ctx, &name))
        });
        if let Some(segments) = package_segment {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            // No `package` clause (parse error or fragment) — fall back
            // to file-stem so cross-file lookups still match by name.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        // Go's exported/unexported convention is fully name-based:
        // uppercase first letter = exported (Public); everything else
        // is package-private (Visibility::Module).
        for decl in &mut idx.defs {
            if let Some(first_char) = decl.name.chars().next() {
                if !first_char.is_ascii_uppercase() {
                    decl.visibility = Visibility::Module;
                }
            }
        }
        // Per-decl `type_aliases` from typed parameters and method
        // receivers. Go signatures always carry an explicit type on
        // every binding, so this is the most reliable surface for
        // semantic-identity narrowing across all the supported
        // languages. Brings Go in lockstep with Java/Kotlin/Scala/
        // TS/C#/Swift/Rust/Python/Dart per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parsed {
            let src = snapshot.text.as_bytes();
            apply_go_type_declaration_kinds(&mut idx, &tree, file);
            populate_go_condition_expressions(&mut idx.branch_conditions, &tree, file, src);
            let exact_argument_flows = populate_go_call_argument_values(&mut idx, &tree, file, src);
            populate_go_assignment_values(&mut idx, &tree, file, src);
            idx.string_compositions = go_string_compositions(&idx, &tree, file, src);
            idx.same_origin_path_constraints = go_same_origin_path_constraints(&idx, &tree, file, src);
            idx.compiler_guards = go_compiler_guards(&tree, file, src);
            let return_value_flows = collect_go_return_value_flows(&tree, file, src);
            populate_go_exact_callable_assignments(&mut idx, &tree, file, src);
            // Phase-6 return-type extraction: `func f() T {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            // Go uses `result` field for return type in the grammar.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            let aliases_by_span = collect_go_method_type_aliases(&tree, file, src);
            let method_receivers_by_span = collect_go_method_receiver_types(&tree, file, src);
            let bases_by_span = collect_go_class_bases(&tree, file, src);
            let range_assignments_by_span = collect_go_range_assignments_by_decl(&tree, file, src);
            let if_init_assignments_by_span = collect_go_if_init_assignments_by_decl(&tree, file, src);
            let index_assignments_by_span = collect_go_index_assignments_by_decl(&tree, file, src);
            let class_symbols: Vec<(String, SymbolId)> = idx
                .defs
                .iter()
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        bonsai_lang_api::DeclKind::Class
                            | bonsai_lang_api::DeclKind::Struct
                            | bonsai_lang_api::DeclKind::Interface
                    )
                })
                .map(|decl| (decl.name.clone(), decl.symbol))
                .collect();
            for decl in &mut idx.defs {
                rewrite_go_exact_call_args(&mut decl.flow_events, &exact_argument_flows);
                rewrite_go_return_values(&mut decl.flow_events, &return_value_flows);
                if let Some(aliases) = aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
                {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(receiver_type) = method_receivers_by_span
                    .iter()
                    .find_map(|(span, ty)| (*span == decl.span).then_some(ty))
                {
                    if let Some((_, class_symbol)) = class_symbols
                        .iter()
                        .find(|(class_name, _)| class_name == receiver_type)
                    {
                        decl.parent = Some(*class_symbol);
                    }
                }
                if let Some(bases) = bases_by_span
                    .iter()
                    .find_map(|(span, bases)| (*span == decl.span).then_some(bases))
                {
                    decl.bases = bases.clone();
                }
                if let Some(range_assignments) = range_assignments_by_span
                    .iter()
                    .find_map(|(span, assignments)| (*span == decl.span).then_some(assignments.as_slice()))
                {
                    augment_go_range_assignments(&mut decl.flow_events, range_assignments);
                }
                if let Some(if_init_assignments) = if_init_assignments_by_span
                    .iter()
                    .find_map(|(span, assignments)| (*span == decl.span).then_some(assignments.as_slice()))
                {
                    augment_go_if_init_assignments(
                        &mut decl.flow_events,
                        if_init_assignments,
                        &decl.type_aliases,
                    );
                }
                if let Some(index_assignments) = index_assignments_by_span
                    .iter()
                    .find_map(|(span, assignments)| (*span == decl.span).then_some(assignments.as_slice()))
                {
                    replace_go_index_selection_assignments(&mut decl.flow_events, index_assignments);
                }
            }
            // Go `if init; condition` and range/index rewrites above add exact
            // call events that the generic first lowering pass cannot see.
            // Rejoin argument syntax only after those adapter-owned FlowEvents
            // are final, then attach Go-decoded literals/aggregates. This is a
            // compiler pass-order dependency, not a source-text fallback.
            idx.call_argument_values = bonsai_lang_api::kit::extract_call_argument_value_facts(
                &tree, file, &idx.defs, src, &HANDLER,
            );
            let final_argument_flows = populate_go_call_argument_values(&mut idx, &tree, file, src);
            for decl in &mut idx.defs {
                rewrite_go_exact_call_args(&mut decl.flow_events, &final_argument_flows);
            }
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut idx,
                &tree,
                file,
                src,
                &HANDLER,
                go_static_scalar,
            );
            // Character transforms consume final rewritten flow events and
            // adapter-decoded call scalars. Building this table earlier makes
            // escaped literals and adapter-synthesized calls invisible.
            idx.character_constraints = go_character_constraints(&idx, &tree, file, src);
        }
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        apply_go_projected_receiver_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Lower Go composite literals into the shared aggregate-value IR.
///
/// Tree-sitter-go represents `bson.M{"field": bson.M{"$eq": value}}` as
/// `composite_literal -> literal_value -> keyed_element`, including another
/// `composite_literal` below the keyed value. The language-neutral extractor
/// deliberately does not assign semantics to Go's `literal_value` wrapper, so
/// this adapter pass replaces only those argument facts whose exact CST node
/// is a Go composite literal.
fn populate_go_call_argument_values(
    index: &mut DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, ExpressionFlow> {
    let mut value_nodes = std::collections::HashMap::new();
    let mut exact_flows = std::collections::HashMap::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if go_adapter_owned_value_shape(node).is_some() {
            let span = span_of(file, &node);
            value_nodes.insert((span.start, span.end), node);
            exact_flows.insert(span, lower_go_value_expression(node, file, src));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    for fact in &mut index.call_argument_values {
        let Some(node) = value_nodes.get(&(fact.argument_span.start, fact.argument_span.end)) else {
            continue;
        };
        fact.value_flow = lower_go_value_expression(*node, file, src);
    }
    exact_flows
}

fn populate_go_assignment_values(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut value_nodes = std::collections::HashMap::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if go_adapter_owned_value_shape(node).is_some() {
            let span = span_of(file, &node);
            value_nodes.insert((span.start, span.end), node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    for fact in &mut index.assignment_values {
        let Some(node) = value_nodes.get(&(fact.value_span.start, fact.value_span.end)) else {
            continue;
        };
        fact.value_flow = lower_go_value_expression(*node, file, src);
    }
}

fn collect_go_return_value_flows(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, ExpressionFlow> {
    let mut flows = std::collections::HashMap::new();
    for return_node in collect_kinds(tree, &["return_statement"]) {
        let Some(values) = return_node.named_child(0) else {
            continue;
        };
        let value_flow = if values.kind() == "expression_list" && values.named_child_count() > 1 {
            let mut tuple_items = Vec::with_capacity(values.named_child_count());
            let mut cursor = values.walk();
            for value in values.named_children(&mut cursor) {
                tuple_items.push(lower_go_value_expression(value, file, src));
            }
            ExpressionFlow {
                tuple_items,
                ..ExpressionFlow::default()
            }
        } else if values.kind() == "expression_list" {
            values
                .named_child(0)
                .map_or_else(ExpressionFlow::default, |value| {
                    lower_go_value_expression(value, file, src)
                })
        } else {
            lower_go_value_expression(values, file, src)
        };
        flows.insert(span_of(file, &return_node), value_flow);
    }
    flows
}

/// Lower a keyed Go composite-literal field whose value is an exact
/// single-return function literal into an assignment fact for `base.field`.
/// Multi-statement, branching, or fallthrough callbacks deliberately emit no
/// exact return summary.
fn populate_go_exact_callable_assignments(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut additions = Vec::new();
    for keyed in collect_kinds(tree, &["keyed_element"]) {
        let Some(key) = keyed.child_by_field_name("key").or_else(|| keyed.named_child(0)) else {
            continue;
        };
        let Some(field) = go_static_aggregate_key(key, src) else {
            continue;
        };
        let Some(mut value) = keyed
            .child_by_field_name("value")
            .or_else(|| keyed.named_child(1))
        else {
            continue;
        };
        while value.kind() == "literal_element" && value.named_child_count() == 1 {
            value = value.named_child(0).expect("single named child");
        }
        if value.kind() != "func_literal" {
            continue;
        }
        let Some(return_value) = go_exact_single_return_value(value) else {
            continue;
        };
        let callable_span = span_of(file, &value);
        let Some(container_assignment) = index
            .assignment_values
            .iter()
            .filter(|fact| {
                fact.assignment_span.start <= callable_span.start
                    && callable_span.end <= fact.assignment_span.end
            })
            .min_by_key(|fact| fact.assignment_span.len())
        else {
            continue;
        };
        let Some(base) = container_assignment.target.as_deref() else {
            continue;
        };
        additions.push(bonsai_lang_api::AssignmentValueFact {
            assignment_span: span_of(file, &keyed),
            target: Some(format!("{base}.{field}")),
            target_is_immutable: false,
            target_owner: None,
            target_span: Some(span_of(file, &key)),
            value_span: callable_span,
            call_sites: Vec::new(),
            value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                value, file, src, &HANDLER,
            ),
            exact_callable_return: Some(bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                return_value,
                file,
                src,
                &HANDLER,
            )),
            exact_static_call_args: None,
            direct_call_name: None,
            direct_call_receiver: None,
        });
    }
    index.assignment_values.extend(additions);
    index
        .assignment_values
        .sort_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end));
    index.assignment_values.dedup();
}

fn go_exact_single_return_value(callable: Node<'_>) -> Option<Node<'_>> {
    let body = callable.child_by_field_name("body")?;
    let statements = if body.named_child_count() == 1
        && body
            .named_child(0)
            .is_some_and(|child| child.kind() == "statement_list")
    {
        body.named_child(0)?
    } else {
        body
    };
    if statements.named_child_count() != 1 {
        return None;
    }
    let return_statement = statements.named_child(0)?;
    if return_statement.kind() != "return_statement" {
        return None;
    }
    let values = return_statement.named_child(0)?;
    if values.kind() == "expression_list" {
        (values.named_child_count() == 1)
            .then(|| values.named_child(0))
            .flatten()
    } else {
        Some(values)
    }
}

fn lower_go_value_expression(mut node: Node<'_>, file: FileId, src: &[u8]) -> ExpressionFlow {
    while matches!(
        node.kind(),
        "literal_element"
            | "expression"
            | "expression_list"
            | "parenthesized_expression"
            | "unary_expression"
    ) && node.named_child_count() == 1
    {
        node = node.named_child(0).expect("single named child");
    }
    if node.kind() == "composite_literal" {
        let body = node
            .child_by_field_name("body")
            .or_else(|| first_named_child_of_kind(&node, "literal_value"));
        return body.map_or_else(ExpressionFlow::default, |body| {
            lower_go_literal_value(body, file, src)
        });
    }
    if let Some(flow) = go_index_selection_value_flow(node, file, src) {
        return flow;
    }
    bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER)
}

/// Return the adapter-owned value at the end of a single-expression wrapper
/// chain. Go's grammar places address-taken composite literals beneath
/// `expression_list -> unary_expression`, while ordinary call arguments can
/// expose the literal directly. This is a Tree-sitter shape decision: no
/// rendered expression is reparsed and no type/API spelling participates.
fn go_adapter_owned_value_shape(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(node.kind(), "composite_literal" | "index_expression") {
            return Some(node);
        }
        if !matches!(
            node.kind(),
            "literal_element"
                | "expression"
                | "expression_list"
                | "parenthesized_expression"
                | "unary_expression"
        ) || node.named_child_count() != 1
        {
            return None;
        }
        node = node.named_child(0)?;
    }
}

/// A dynamic map/array key chooses which stored value is read; the key does
/// not become the value. Go's comma-ok result is likewise a clean boolean
/// membership fact. Treating the index operand as scalar value flow invents
/// an implicit-flow edge and makes static lookup tables appear attacker
/// controlled.
fn go_index_selection_value_flow(node: Node<'_>, file: FileId, src: &[u8]) -> Option<ExpressionFlow> {
    if node.kind() != "index_expression" {
        return None;
    }
    let collection = node
        .child_by_field_name("operand")
        .or_else(|| node.named_child(0))?;
    Some(lower_go_value_expression(collection, file, src))
}

fn go_expression_flow_source_names(flow: &ExpressionFlow) -> Vec<String> {
    fn collect(flow: &ExpressionFlow, out: &mut Vec<String>) {
        if let Some(place) = flow.place.as_ref().filter(|place| !place.trim().is_empty()) {
            push_unique_string(out, place.clone());
        }
        for source in &flow.source_names {
            push_unique_string(out, source.clone());
        }
        for field in &flow.aggregate_fields {
            collect(&field.value, out);
        }
        for item in &flow.tuple_items {
            collect(item, out);
        }
        for spread in &flow.spreads {
            collect(spread, out);
        }
    }

    let mut out = Vec::new();
    collect(flow, &mut out);
    out
}

fn rewrite_go_exact_call_args(
    events: &mut [FlowEvent],
    flows: &std::collections::HashMap<Span, ExpressionFlow>,
) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    let Some(flow) = flows.get(&arg.span) else {
                        continue;
                    };
                    arg.place = flow.place.clone();
                    arg.source_names = go_expression_flow_source_names(flow);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_go_exact_call_args(then_events, flows);
                rewrite_go_exact_call_args(else_events, flows);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_go_exact_call_args(body, flows);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_go_exact_call_args(body, flows);
                rewrite_go_exact_call_args(catch_events, flows);
                rewrite_go_exact_call_args(finally_events, flows);
            }
            _ => {}
        }
    }
}

fn rewrite_go_return_values(
    events: &mut [FlowEvent],
    flows: &std::collections::HashMap<Span, ExpressionFlow>,
) {
    for event in events {
        match event {
            FlowEvent::Return {
                span,
                value_name,
                value_flow,
                ..
            } => {
                let Some(exact) = flows.get(span) else {
                    continue;
                };
                *value_flow = exact.clone();
                if !exact.tuple_items.is_empty() {
                    *value_name = None;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_go_return_values(then_events, flows);
                rewrite_go_return_values(else_events, flows);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_go_return_values(body, flows);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_go_return_values(body, flows);
                rewrite_go_return_values(catch_events, flows);
                rewrite_go_return_values(finally_events, flows);
            }
            _ => {}
        }
    }
}

fn lower_go_literal_value(node: Node<'_>, file: FileId, src: &[u8]) -> ExpressionFlow {
    let mut fields = Vec::new();
    let mut items = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "keyed_element" {
            let key = child.child_by_field_name("key").or_else(|| child.named_child(0));
            let value = child
                .child_by_field_name("value")
                .or_else(|| child.named_child(1));
            let (Some(key), Some(value)) = (key, value) else {
                continue;
            };
            let Some(name) = go_static_aggregate_key(key, src) else {
                continue;
            };
            fields.push(ExpressionField {
                name,
                value_span: Some(span_of(file, &value)),
                value: lower_go_value_expression(value, file, src),
            });
        } else {
            items.push(lower_go_value_expression(child, file, src));
        }
    }
    ExpressionFlow {
        aggregate_fields: fields,
        tuple_items: items,
        ..ExpressionFlow::default()
    }
}

fn go_static_aggregate_key(mut node: Node<'_>, src: &[u8]) -> Option<String> {
    while node.kind() == "literal_element" && node.named_child_count() == 1 {
        node = node.named_child(0)?;
    }
    go_static_string_literal(node, src).or_else(|| {
        matches!(node.kind(), "identifier" | "field_identifier" | "type_identifier")
            .then(|| node_text(&node, src).trim().to_string())
            .filter(|name| !name.is_empty())
    })
}

/// Attach Go's boolean-expression grammar to the language-neutral condition
/// IR. Go owns these operator spellings; shared analysis sees only semantic
/// `Any`/`All`/`Not`/`Equality` nodes and exact expression spans.
fn populate_go_condition_expressions(
    facts: &mut [bonsai_lang_api::BranchConditionFact],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    for branch in collect_kinds(tree, &["if_statement"]) {
        let branch_span = span_of(file, &branch);
        let Some(condition) = branch.child_by_field_name("condition") else {
            continue;
        };
        let Some(fact) = facts.iter_mut().find(|fact| fact.branch_span == branch_span) else {
            continue;
        };
        fact.expression = Some(lower_go_condition_expression(condition, file, src));
    }
}

fn lower_go_condition_expression(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionExpressionFact {
    if node.kind() == "parenthesized_expression" {
        if let Some(inner) = node.named_child(0) {
            return lower_go_condition_expression(inner, file, src);
        }
    }

    let span = span_of(file, &node);
    if node.kind() == "unary_expression" {
        if let Some(operand) = node
            .child_by_field_name("operand")
            .or_else(|| node.named_child(0))
        {
            let prefix = src
                .get(node.start_byte()..operand.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if prefix == Some("!") {
                return ConditionExpressionFact::Not {
                    span,
                    operand: Box::new(lower_go_condition_expression(operand, file, src)),
                };
            }
        }
    }

    if node.kind() == "binary_expression" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            match operator {
                Some("||") => {
                    return merge_go_condition_junction(
                        span,
                        lower_go_condition_expression(left, file, src),
                        lower_go_condition_expression(right, file, src),
                        false,
                    );
                }
                Some("&&") => {
                    return merge_go_condition_junction(
                        span,
                        lower_go_condition_expression(left, file, src),
                        lower_go_condition_expression(right, file, src),
                        true,
                    );
                }
                Some("==" | "!=") => {
                    let relation = if operator == Some("==") {
                        ConditionEquality::Equal
                    } else {
                        ConditionEquality::NotEqual
                    };
                    return ConditionExpressionFact::Equality {
                        span,
                        relation,
                        left: go_condition_operand(left, file, src),
                        right: go_condition_operand(right, file, src),
                    };
                }
                _ => {}
            }
        }
    }

    if node.kind() == "index_expression" {
        if let (Some(collection), Some(subject)) = (
            node.child_by_field_name("operand"),
            node.child_by_field_name("index"),
        ) {
            return ConditionExpressionFact::Membership {
                span,
                subject: go_condition_operand(subject, file, src),
                collection: go_condition_operand(collection, file, src),
                then_contains: true,
            };
        }
    }

    ConditionExpressionFact::Atom { span }
}

fn merge_go_condition_junction(
    span: Span,
    left: ConditionExpressionFact,
    right: ConditionExpressionFact,
    all: bool,
) -> ConditionExpressionFact {
    let mut operands = Vec::new();
    let mut push = |operand: ConditionExpressionFact| match (all, operand) {
        (true, ConditionExpressionFact::All { operands: nested, .. })
        | (false, ConditionExpressionFact::Any { operands: nested, .. }) => operands.extend(nested),
        (_, operand) => operands.push(operand),
    };
    push(left);
    push(right);
    if all {
        ConditionExpressionFact::All { span, operands }
    } else {
        ConditionExpressionFact::Any { span, operands }
    }
}

fn go_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    ConditionOperandFact {
        span: span_of(file, &node),
        value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER),
        static_string: go_static_string_literal(node, src),
        static_value: go_static_scalar(node, src),
    }
}

fn go_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "nil" => Some(StaticScalarValue::Null),
        "interpreted_string_literal" | "raw_string_literal" => {
            Some(StaticScalarValue::String(go_static_string_literal(node, src)?))
        }
        _ => None,
    }
}

fn go_static_subscript_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    match go_static_scalar(node, src)? {
        StaticScalarValue::String(value) => Some(value),
        StaticScalarValue::Boolean(_) | StaticScalarValue::Null => None,
    }
}

fn go_static_string_literal(node: Node<'_>, src: &[u8]) -> Option<String> {
    let text = node_text(&node, src);
    match node.kind() {
        "interpreted_string_literal" => {
            let inner = text.strip_prefix('"')?.strip_suffix('"')?;
            decode_go_interpreted_string(inner)
        }
        "raw_string_literal" => text
            .strip_prefix('`')
            .and_then(|inner| inner.strip_suffix('`'))
            // Go discards carriage returns inside raw string literals.
            .map(|inner| inner.replace('\r', "")),
        _ => None,
    }
}

/// Decode Go's specified interpreted-string escapes from the parsed literal
/// body. Go strings are byte sequences, so byte/octal escapes are assembled
/// before UTF-8 conversion. A valid multi-byte sequence remains exact while
/// an arbitrary non-UTF-8 Go string fails closed because `StaticScalarValue`
/// stores Unicode text.
fn decode_go_interpreted_string(inner: &str) -> Option<String> {
    let chars = inner.chars().collect::<Vec<_>>();
    let mut output = Vec::with_capacity(inner.len());
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        index += 1;
        if character != '\\' {
            let mut encoded = [0_u8; 4];
            output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            continue;
        }
        let escape = *chars.get(index)?;
        index += 1;
        match escape {
            'a' => output.push(0x07),
            'b' => output.push(0x08),
            'f' => output.push(0x0c),
            'n' => output.push(b'\n'),
            'r' => output.push(b'\r'),
            't' => output.push(b'\t'),
            'v' => output.push(0x0b),
            '\\' => output.push(b'\\'),
            '"' => output.push(b'"'),
            'x' => {
                let value = decode_go_escape_digits(&chars, &mut index, 2, 16)?;
                output.push(u8::try_from(value).ok()?);
            }
            'u' => {
                let value = decode_go_escape_digits(&chars, &mut index, 4, 16)?;
                let character = char::from_u32(value)?;
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
            'U' => {
                let value = decode_go_escape_digits(&chars, &mut index, 8, 16)?;
                let character = char::from_u32(value)?;
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
            first @ '0'..='7' => {
                let mut value = first.to_digit(8)?;
                for _ in 0..2 {
                    value = value
                        .checked_mul(8)?
                        .checked_add(chars.get(index)?.to_digit(8)?)?;
                    index += 1;
                }
                output.push(u8::try_from(value).ok()?);
            }
            _ => return None,
        }
    }
    String::from_utf8(output).ok()
}

fn decode_go_escape_digits(chars: &[char], index: &mut usize, count: usize, radix: u32) -> Option<u32> {
    let mut value = 0_u32;
    for _ in 0..count {
        value = value
            .checked_mul(radix)?
            .checked_add(chars.get(*index)?.to_digit(radix)?)?;
        *index += 1;
    }
    Some(value)
}

/// Lower complete Go string concatenations from Tree-sitter expressions.
/// Facts are expression-owned so consumers can join both assignment values
/// and nested call arguments without parsing rendered source.
fn go_string_compositions(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<StringCompositionFact> {
    let mut facts = Vec::new();
    for expression in collect_kinds(tree, &["binary_expression"]) {
        let mut parts = Vec::new();
        if !lower_go_string_composition(expression, file, src, &mut parts) || parts.len() < 2 {
            continue;
        }
        let value_span = span_of(file, &expression);
        let target = index
            .assignment_values
            .iter()
            .find(|assignment| assignment.value_span == value_span)
            .and_then(|assignment| assignment.target.clone());
        facts.push(StringCompositionFact {
            container_span: index
                .assignment_values
                .iter()
                .find(|assignment| assignment.value_span == value_span)
                .map_or(value_span, |assignment| assignment.assignment_span),
            value_span,
            target,
            parts,
        });
    }
    facts.sort_by_key(|fact| {
        (
            fact.container_span.start,
            fact.container_span.end,
            fact.value_span.start,
            fact.value_span.end,
        )
    });
    facts.dedup();
    facts
}

fn lower_go_string_composition(
    mut node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<StringCompositionPart>,
) -> bool {
    while matches!(node.kind(), "parenthesized_expression" | "expression_list")
        && node.named_child_count() == 1
    {
        let Some(inner) = node.named_child(0) else {
            return false;
        };
        node = inner;
    }
    if let Some(value) = go_static_string_literal(node, src) {
        out.push(StringCompositionPart::Literal { value });
        return true;
    }
    if node.kind() == "call_expression" {
        let Some(function) = node.child_by_field_name("function") else {
            return false;
        };
        out.push(StringCompositionPart::Call {
            span: span_of(file, &function),
        });
        return true;
    }
    if node.kind() != "binary_expression" {
        let flow = bonsai_lang_api::kit::expression_flow_from_node_with_handler(node, file, src, &HANDLER);
        if let Some(place) = flow.place {
            out.push(StringCompositionPart::Place { place });
            return true;
        }
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    go_binary_operator(node, left, right, src) == Some("+")
        && lower_go_string_composition(left, file, src, out)
        && lower_go_string_composition(right, file, src, out)
}

/// Prove the exact Go callback-map shape that replaces every C0/DEL control
/// character and otherwise preserves its input rune. The frontend records
/// the imported provider identity but assigns it no security meaning; sink
/// rule semantics decide which provider implements this contract.
fn go_character_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterConstraintFact> {
    let imports = parse_imports(tree, src, file);
    let mut facts = go_guarded_append_character_constraints(index);
    facts.extend(go_configured_character_substitution_constraints(index));
    if imports.is_empty() {
        return facts;
    }
    for function in collect_kinds(tree, &["function_declaration", "method_declaration"]) {
        let function_span = span_of(file, &function);
        let Some(decl) = index.defs.iter().find(|decl| decl.span == function_span) else {
            continue;
        };
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let statements = go_block_statements(body);
        let [return_statement] = statements.as_slice() else {
            continue;
        };
        let Some(call) = go_single_expression(*return_statement) else {
            continue;
        };
        if call.kind() != "call_expression" {
            continue;
        }
        let (Some(callee), Some(arguments)) = (
            call.child_by_field_name("function"),
            call.child_by_field_name("arguments"),
        ) else {
            continue;
        };
        let Some(provider_call) = go_imported_selector_identity(callee, &imports, src) else {
            continue;
        };
        let Some(provider_alias) = callee
            .child_by_field_name("operand")
            .map(|operand| node_text(&operand, src).trim())
        else {
            continue;
        };
        if go_binding_shadows_name(function, provider_alias, src) {
            continue;
        }
        let mut cursor = arguments.walk();
        let argument_nodes: Vec<_> = arguments.named_children(&mut cursor).collect();
        let [callback, input] = argument_nodes.as_slice() else {
            continue;
        };
        if input.kind() != "identifier" {
            continue;
        }
        let input_name = node_text(input, src).trim();
        let Some(input_param_index) = decl.params.iter().position(|parameter| parameter == input_name) else {
            continue;
        };
        if !go_map_callback_replaces_controls(*callback, src) {
            continue;
        }
        facts.push(CharacterConstraintFact {
            function_span,
            transform_span: span_of(file, &callee),
            input_place: input_name.to_string(),
            input_param_index: Some(input_param_index),
            output: CharacterConstraintOutput::Return,
            domain: CharacterConstraintDomain::ProviderBound {
                factory_call: provider_call.clone(),
                operation_call: provider_call,
                domain: Box::new(CharacterConstraintDomain::ExcludesExact {
                    characters: vec!["\r".to_string(), "\n".to_string()],
                }),
            },
        });
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.transform_span.start));
    facts.dedup();
    facts
}

/// Lower configured, exact pairwise character transformers without assigning
/// security meaning to their APIs. For a unique binding initialized by a
/// direct call with complete static string pairs, a later one-argument method
/// call on that binding carries the provider identities and mapping into the
/// typed IR. Rules decide whether a particular factory/operation pair and
/// mapping are a sanitizer for their sink category.
fn go_configured_character_substitution_constraints(index: &DeclIndex) -> Vec<CharacterConstraintFact> {
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct BindingKey {
        owner_span: Option<Span>,
        name: String,
    }

    struct ConfiguredTransform {
        assignment_span: Span,
        factory_call: String,
        mappings: Vec<StaticStringMapEntry>,
    }

    let mut arguments_by_call = std::collections::HashMap::new();
    for argument in &index.call_argument_values {
        arguments_by_call
            .entry((argument.call_span.start, argument.call_span.end))
            .or_insert_with(Vec::new)
            .push(argument);
    }
    for arguments in arguments_by_call.values_mut() {
        arguments.sort_by_key(|argument| argument.argument_index);
    }
    let mut call_spans = arguments_by_call.keys().copied().collect::<Vec<_>>();
    call_spans.sort_unstable();
    let direct_arguments = |assignment: &bonsai_lang_api::AssignmentValueFact| {
        // Assignment call sites cover the parsed call expression, while call
        // argument facts use the adapter-normalized callee span. Select the
        // first callee contained by the direct RHS value using a sorted span
        // index. The outer call starts before any nested argument call, so
        // this preserves the AST relationship without rescanning every call
        // argument for every assignment.
        let offset = call_spans.partition_point(|(start, _)| *start < assignment.value_span.start);
        let call_span = call_spans[offset..]
            .iter()
            .take_while(|(start, _)| *start < assignment.value_span.end)
            .find(|(_, end)| *end <= assignment.value_span.end)?;
        let arguments = arguments_by_call.get(call_span)?;
        arguments
            .iter()
            .enumerate()
            .all(|(index, argument)| argument.argument_index == index)
            .then_some(arguments.as_slice())
    };

    let mut binding_write_counts = std::collections::HashMap::new();
    for assignment in &index.assignment_values {
        let Some(binding) = assignment.target.as_deref() else {
            continue;
        };
        let key = BindingKey {
            owner_span: go_callable_owner(index, assignment.assignment_span).map(|decl| decl.span),
            name: binding.to_string(),
        };
        *binding_write_counts.entry(key).or_insert(0_usize) += 1;
    }

    let mut configured = std::collections::HashMap::new();
    for assignment in &index.assignment_values {
        let (Some(binding), Some(factory_call), Some(arguments)) = (
            assignment.target.as_deref(),
            assignment.direct_call_name.as_deref(),
            direct_arguments(assignment),
        ) else {
            continue;
        };
        if arguments.is_empty() || arguments.len() % 2 != 0 {
            continue;
        }
        let scalars = arguments
            .iter()
            .map(|argument| argument.static_value.as_ref())
            .collect::<Option<Vec<_>>>();
        let Some(scalars) = scalars else {
            continue;
        };
        let mappings = scalars
            .chunks_exact(2)
            .map(|pair| match (&pair[0], &pair[1]) {
                (StaticScalarValue::String(key), StaticScalarValue::String(value)) => {
                    Some(StaticStringMapEntry {
                        key: key.clone(),
                        value: value.clone(),
                    })
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>();
        let Some(mappings) = mappings else {
            continue;
        };
        let key = BindingKey {
            owner_span: go_callable_owner(index, assignment.assignment_span).map(|decl| decl.span),
            name: binding.to_string(),
        };
        if binding_write_counts.get(&key) != Some(&1) {
            continue;
        }
        configured.insert(
            key,
            ConfiguredTransform {
                assignment_span: assignment.assignment_span,
                factory_call: factory_call.to_string(),
                mappings,
            },
        );
    }

    type AssignmentOutputs<'a> = std::collections::HashMap<
        &'a str,
        std::collections::HashMap<&'a str, Vec<&'a bonsai_lang_api::AssignmentValueFact>>,
    >;
    let mut assignment_outputs: AssignmentOutputs<'_> = std::collections::HashMap::new();
    for assignment in &index.assignment_values {
        let (Some(receiver), Some(call_name)) = (
            assignment.direct_call_receiver.as_deref(),
            assignment.direct_call_name.as_deref(),
        ) else {
            continue;
        };
        if assignment.target.is_some() {
            assignment_outputs
                .entry(receiver)
                .or_default()
                .entry(call_name)
                .or_default()
                .push(assignment);
        }
    }

    let mut facts = Vec::new();
    for owner in &index.defs {
        let mut calls = Vec::new();
        collect_go_flow_calls(&owner.flow_events, &mut calls);
        for call in calls {
            let FlowEvent::Call {
                span,
                name: operation_call,
                receiver: Some(receiver),
                args,
                ..
            } = call
            else {
                continue;
            };
            let [argument] = args.as_slice() else {
                continue;
            };
            let local_key = BindingKey {
                owner_span: Some(owner.span),
                name: receiver.clone(),
            };
            let global_key = BindingKey {
                owner_span: None,
                name: receiver.clone(),
            };
            let transform = configured
                .get(&local_key)
                .filter(|transform| transform.assignment_span.start < span.start)
                .or_else(|| {
                    (!binding_write_counts.contains_key(&local_key)
                        && !owner.params.iter().any(|parameter| parameter == receiver))
                    .then(|| configured.get(&global_key))
                    .flatten()
                });
            let Some(transform) = transform else {
                continue;
            };
            let input_place = argument
                .place
                .as_ref()
                .or_else(|| argument.source_names.first())
                .cloned()
                .unwrap_or_default();
            let output = assignment_outputs
                .get(receiver.as_str())
                .and_then(|calls| calls.get(operation_call.as_str()))
                .into_iter()
                .flatten()
                .filter(|assignment| {
                    assignment.value_span.start <= span.start && span.end <= assignment.value_span.end
                })
                .min_by_key(|assignment| assignment.value_span.len())
                .and_then(|assignment| assignment.target.clone())
                .map_or(CharacterConstraintOutput::Expression { span: *span }, |target| {
                    CharacterConstraintOutput::Assignment { target }
                });
            facts.push(CharacterConstraintFact {
                function_span: owner.span,
                transform_span: *span,
                input_param_index: owner
                    .params
                    .iter()
                    .position(|parameter| parameter == &input_place),
                input_place,
                output,
                domain: CharacterConstraintDomain::ProviderBound {
                    factory_call: transform.factory_call.clone(),
                    operation_call: operation_call.to_string(),
                    domain: Box::new(CharacterConstraintDomain::SubstitutesExact {
                        mappings: transform.mappings.clone(),
                    }),
                },
            });
        }
    }
    facts
}

fn collect_go_flow_calls<'a>(events: &'a [FlowEvent], calls: &mut Vec<&'a FlowEvent>) {
    for event in events {
        match event {
            FlowEvent::Call { .. } => calls.push(event),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_go_flow_calls(then_events, calls);
                collect_go_flow_calls(else_events, calls);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_go_flow_calls(body, calls);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_go_flow_calls(body, calls);
                collect_go_flow_calls(catch_events, calls);
                collect_go_flow_calls(finally_events, calls);
            }
            FlowEvent::Assign { .. }
            | FlowEvent::AggregateAssign { .. }
            | FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. }
            | FlowEvent::Yield { .. }
            | FlowEvent::Await { .. }
            | FlowEvent::Lifecycle { .. } => {}
        }
    }
}

fn go_span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

fn go_callable_owner(index: &DeclIndex, span: Span) -> Option<&bonsai_lang_api::Decl> {
    index
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            ) && !(decl.name_span == decl.span && decl.body_span == Some(decl.span))
                && go_span_contains(decl.span, span)
        })
        .min_by_key(|decl| decl.span.len())
}

/// Lower a Go byte/rune loop that constructs a fresh buffer exclusively by
/// appending characters accepted by one parsed allowlist condition. `append`
/// and `make` are Go predeclared functions, so their semantics belong to the
/// frontend. Which excluded characters matter to a sink remains rulepack
/// data through `CharacterConstraintSemantics`.
fn go_guarded_append_character_constraints(index: &DeclIndex) -> Vec<CharacterConstraintFact> {
    let mut facts = Vec::new();
    for decl in &index.defs {
        let mut assignments = Vec::new();
        collect_go_assignments_with_guard(&decl.flow_events, None, &mut assignments);
        let mut targets = assignments
            .iter()
            .filter_map(|assignment| assignment.appended.as_ref().map(|_| assignment.target.clone()))
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();

        for target in targets {
            let writes = assignments
                .iter()
                .filter(|assignment| assignment.target == target)
                .collect::<Vec<_>>();
            if writes.is_empty() || !writes.iter().any(|assignment| assignment.clean_initialization) {
                continue;
            }
            let guarded_writes = writes
                .iter()
                .filter(|assignment| assignment.appended.is_some())
                .collect::<Vec<_>>();
            if guarded_writes.is_empty()
                || writes
                    .iter()
                    .any(|assignment| !assignment.clean_initialization && assignment.appended.is_none())
            {
                continue;
            }

            let mut input = None::<(String, usize)>;
            let mut transform_span = None::<Span>;
            let mut valid = true;
            for write in guarded_writes {
                let Some(appended) = write.appended.as_deref() else {
                    valid = false;
                    break;
                };
                if write
                    .guard_condition
                    .as_deref()
                    .is_none_or(|condition| !go_character_allowlist_condition(condition, appended))
                {
                    valid = false;
                    break;
                }
                let sources = assignments
                    .iter()
                    .filter(|assignment| assignment.span.start < write.span.start)
                    .filter(|assignment| assignment.target == appended)
                    .max_by_key(|assignment| (assignment.span.start, assignment.span.end))
                    .map(|assignment| assignment.source_names.as_slice())
                    .unwrap_or(&[]);
                let candidates = decl
                    .params
                    .iter()
                    .enumerate()
                    .filter(|(_, parameter)| sources.iter().any(|source| source == *parameter))
                    .map(|(index, parameter)| (parameter.clone(), index))
                    .collect::<Vec<_>>();
                let [candidate] = candidates.as_slice() else {
                    valid = false;
                    break;
                };
                if input.as_ref().is_some_and(|current| current != candidate) {
                    valid = false;
                    break;
                }
                input = Some(candidate.clone());
                transform_span = Some(transform_span.map_or(write.span, |current| {
                    if (write.span.start, write.span.end) < (current.start, current.end) {
                        write.span
                    } else {
                        current
                    }
                }));
            }
            let (Some((input_place, input_param_index)), Some(transform_span)) = (input, transform_span)
            else {
                continue;
            };
            if !valid {
                continue;
            }
            facts.push(CharacterConstraintFact {
                function_span: decl.span,
                transform_span,
                input_place,
                input_param_index: Some(input_param_index),
                output: CharacterConstraintOutput::Assignment { target },
                domain: CharacterConstraintDomain::ExcludesExact {
                    characters: vec!["\r".to_string(), "\n".to_string()],
                },
            });
        }
    }
    facts
}

struct GoGuardedAssignment {
    span: Span,
    target: String,
    source_names: Vec<String>,
    appended: Option<String>,
    clean_initialization: bool,
    guard_condition: Option<String>,
}

fn collect_go_assignments_with_guard(
    events: &[FlowEvent],
    guard_condition: Option<&str>,
    out: &mut Vec<GoGuardedAssignment>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_names,
                source_call,
                source_call_args,
                value_kind,
                ..
            } => {
                let appended = (source_call.as_deref() == Some("append")
                    && source_call_args.len() >= 2
                    && source_call_args[0].trim() == target.trim())
                .then(|| source_call_args[1].trim().to_string());
                let clean_initialization = source_call.as_deref() == Some("make")
                    || (source_names.is_empty()
                        && source_call_args.is_empty()
                        && matches!(
                            value_kind,
                            Some(
                                bonsai_lang_api::AssignValueKind::Literal
                                    | bonsai_lang_api::AssignValueKind::Unknown
                            )
                        ));
                out.push(GoGuardedAssignment {
                    span: *span,
                    target: target.trim().to_string(),
                    source_names: source_names.clone(),
                    appended,
                    clean_initialization,
                    guard_condition: guard_condition.map(str::to_string),
                });
            }
            FlowEvent::Branch {
                condition,
                then_events,
                else_events,
                ..
            } => {
                collect_go_assignments_with_guard(then_events, condition.as_deref().or(guard_condition), out);
                collect_go_assignments_with_guard(else_events, guard_condition, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_go_assignments_with_guard(body, guard_condition, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_go_assignments_with_guard(body, guard_condition, out);
                collect_go_assignments_with_guard(catch_events, guard_condition, out);
                collect_go_assignments_with_guard(finally_events, guard_condition, out);
            }
            _ => {}
        }
    }
}

fn go_character_allowlist_condition(condition: &str, variable: &str) -> bool {
    let variable = variable.trim();
    if variable.is_empty() {
        return false;
    }
    let compact = condition
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let printable_floor = [
        format!("{variable}>=0x20"),
        format!("{variable}>0x1f"),
        format!("{variable}>=32"),
        format!("{variable}>31"),
        format!("0x20<={variable}"),
        format!("0x1f<{variable}"),
        format!("32<={variable}"),
        format!("31<{variable}"),
    ]
    .into_iter()
    .any(|needle| compact.contains(&needle));
    let excludes = |literal: &str| {
        compact.contains(&format!("{variable}!={literal}"))
            || compact.contains(&format!("{literal}!={variable}"))
    };
    let crlf_excluded = printable_floor
        || (excludes("'\\r'") && excludes("'\\n'"))
        || (excludes("\"\\r\"") && excludes("\"\\n\""));
    let del_excluded = [
        format!("{variable}!=0x7f"),
        format!("{variable}<0x7f"),
        format!("{variable}<=0x7e"),
        format!("0x7f!={variable}"),
        format!("0x7f>{variable}"),
        format!("0x7e>={variable}"),
        format!("{variable}!=127"),
        format!("{variable}<127"),
        format!("{variable}<=126"),
    ]
    .into_iter()
    .any(|needle| compact.contains(&needle));
    crlf_excluded && (del_excluded || !printable_floor)
}

/// Prove a caller-local postcondition for a helper predicate that accepts
/// only one-leading-slash paths. The frontend composes two Go syntax facts:
/// the helper's exact boolean return and a rejecting branch that overwrites
/// the original parameter with a static fallback. Shared security analysis
/// sees only the resulting same-origin path fact.
fn go_same_origin_path_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<SameOriginPathConstraintFact> {
    let functions = collect_kinds(tree, &["function_declaration", "method_declaration"]);
    let safe_helpers = functions
        .iter()
        .filter_map(|function| {
            let function_span = span_of(file, function);
            let decl = index.defs.iter().find(|decl| decl.span == function_span)?;
            let input = decl.params.first()?;
            let body = function.child_by_field_name("body")?;
            let statements = go_block_statements(body);
            let [return_statement] = statements.as_slice() else {
                return None;
            };
            let expression = go_single_expression(*return_statement)?;
            go_same_origin_predicate_expression(expression, input, src).then(|| decl.name.clone())
        })
        .collect::<std::collections::HashSet<_>>();
    if safe_helpers.is_empty() {
        return Vec::new();
    }
    let mut facts = Vec::new();
    for function in functions {
        let function_span = span_of(file, &function);
        let Some(decl) = index.defs.iter().find(|decl| decl.span == function_span) else {
            continue;
        };
        for branch in collect_go_owned_if_statements(function) {
            let (Some(condition), Some(consequence)) = (
                branch.child_by_field_name("condition"),
                branch.child_by_field_name("consequence"),
            ) else {
                continue;
            };
            if branch.child_by_field_name("alternative").is_some() {
                continue;
            }
            let Some((helper, target)) = go_negated_single_arg_call_node(condition, src) else {
                continue;
            };
            if !safe_helpers.contains(&helper) || !go_block_assigns_static_fallback(consequence, &target, src)
            {
                continue;
            }
            let guard_span = span_of(file, &branch);
            let input_param_index = decl.params.iter().position(|parameter| parameter == &target);
            if go_place_assigned_after(&decl.flow_events, &target, guard_span.end) {
                continue;
            }
            facts.push(SameOriginPathConstraintFact {
                function_span: decl.span,
                guard_span,
                input_place: target,
                input_param_index,
                provider_call: None,
                rejects_scheme: true,
                rejects_authority: true,
                requires_absolute_path: true,
                rejects_scheme_relative_path: true,
            });
        }
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.guard_span.start));
    facts.dedup();
    facts
}

fn go_same_origin_predicate_expression(expression: Node<'_>, input: &str, src: &[u8]) -> bool {
    let compact = node_text(&expression, src)
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let first_is_slash =
        compact.contains(&format!("{input}[0]=='/'")) || compact.contains(&format!("{input}[0]==\"/\""));
    let second_is_not_slash =
        compact.contains(&format!("{input}[1]!='/'")) || compact.contains(&format!("{input}[1]!=\"/\""));
    let length_checked = compact.contains(&format!("len({input})>0"))
        && (compact.contains(&format!("len({input})==1")) || compact.contains(&format!("len({input})>1")));
    first_is_slash && second_is_not_slash && length_checked
}

fn collect_go_owned_if_statements(function: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut pending = function
        .child_by_field_name("body")
        .into_iter()
        .collect::<Vec<_>>();
    while let Some(node) = pending.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "func_literal" {
                continue;
            }
            if child.kind() == "if_statement" {
                out.push(child);
            }
            pending.push(child);
        }
    }
    out
}

fn go_negated_single_arg_call_node(mut condition: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    while condition.kind() == "parenthesized_expression" {
        condition = condition.named_child(0)?;
    }
    if condition.kind() != "unary_expression" || !node_text(&condition, src).trim_start().starts_with('!') {
        return None;
    }
    let call = condition
        .child_by_field_name("operand")
        .or_else(|| condition.named_child(0))?;
    if call.kind() != "call_expression" {
        return None;
    }
    let (Some(function), Some(arguments)) = (
        call.child_by_field_name("function"),
        call.child_by_field_name("arguments"),
    ) else {
        return None;
    };
    if function.kind() != "identifier" {
        return None;
    }
    let mut cursor = arguments.walk();
    let args = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    let [argument] = args.as_slice() else {
        return None;
    };
    if argument.kind() != "identifier" {
        return None;
    }
    Some((
        node_text(&function, src).trim().to_string(),
        node_text(argument, src).trim().to_string(),
    ))
}

fn go_block_assigns_static_fallback(block: Node<'_>, target: &str, src: &[u8]) -> bool {
    let statements = go_block_statements(block);
    let [assignment] = statements.as_slice() else {
        return false;
    };
    if assignment.kind() != "assignment_statement" {
        return false;
    }
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    let left_values = go_expression_list_values(left);
    let right_values = go_expression_list_values(right);
    let ([left], [right]) = (left_values.as_slice(), right_values.as_slice()) else {
        return false;
    };
    left.kind() == "identifier"
        && node_text(left, src).trim() == target
        && go_static_string_literal(*right, src).is_some()
        && src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .is_some_and(|operator| operator.trim() == "=")
}

fn go_place_assigned_after(events: &[FlowEvent], place: &str, after: u64) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Assign { span, target, .. } => span.start > after && target.trim() == place,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            go_place_assigned_after(then_events, place, after)
                || go_place_assigned_after(else_events, place, after)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            go_place_assigned_after(body, place, after)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            go_place_assigned_after(body, place, after)
                || go_place_assigned_after(catch_events, place, after)
                || go_place_assigned_after(finally_events, place, after)
        }
        _ => false,
    })
}

const GO_GUARD_CALLBACK_SELECTOR_PINNED: &str = "callback.selector-result-pinned";

fn go_compiler_guards(tree: &Tree, file: FileId, src: &[u8]) -> Vec<CompilerGuardFact> {
    let imports = parse_imports(tree, src, file);
    let filepath_aliases = imports
        .iter()
        .filter(|import| import.module == "path/filepath")
        .filter_map(|import| import.alias.as_deref())
        .collect::<Vec<_>>();
    let relative_boundary_helpers = go_relative_path_boundary_helpers(tree, file, src, &filepath_aliases);
    let mut facts = Vec::new();
    for call in collect_kinds(tree, &["call_expression"]) {
        let Some(callee) = call.child_by_field_name("function") else {
            continue;
        };
        let guarded_call_span = span_of(file, &callee);
        if let Some((proof_span, evidence)) = go_callback_selector_pin_guard(call, file, src) {
            if let Some(function_span) = go_enclosing_function_span(call, file) {
                facts.push(CompilerGuardFact {
                    function_span,
                    guarded_call_span,
                    proof_span,
                    capability: GO_GUARD_CALLBACK_SELECTOR_PINNED.to_string(),
                    evidence,
                });
            }
        }
        if let Some(proof_span) = go_relative_path_boundary_helper_call(call, &relative_boundary_helpers, src)
        {
            if let Some(function_span) = go_enclosing_function_span(call, file) {
                facts.push(CompilerGuardFact {
                    function_span,
                    guarded_call_span,
                    proof_span,
                    capability: bonsai_lang_api::COMPILER_GUARD_RELATIVE_PATH_BOUNDARY_REJECTION.to_string(),
                    evidence: Vec::new(),
                });
            }
        }
    }
    facts.sort_by_key(|fact| {
        (
            fact.function_span.start,
            fact.guarded_call_span.start,
            fact.capability.clone(),
        )
    });
    facts.dedup();
    facts
}

fn go_relative_path_boundary_helpers(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    filepath_aliases: &[&str],
) -> Vec<(String, Span)> {
    let mut helpers = Vec::new();
    for function in collect_kinds(tree, &["function_declaration"]) {
        let (Some(name), Some(parameters), Some(result), Some(body)) = (
            function.child_by_field_name("name"),
            function.child_by_field_name("parameters"),
            function.child_by_field_name("result"),
            function.child_by_field_name("body"),
        ) else {
            continue;
        };
        if node_text(&result, src).trim() != "bool" {
            continue;
        }
        let parameter_declarations = collect_kinds_under(&parameters, &["parameter_declaration"]);
        let [parameter] = parameter_declarations.as_slice() else {
            continue;
        };
        let Some(parameter_name) = parameter.child_by_field_name("name") else {
            continue;
        };
        let parameter_name = node_text(&parameter_name, src).trim();
        let statements = go_block_statements(body);
        let [statement] = statements.as_slice() else {
            continue;
        };
        let Some(expression) = go_single_expression(*statement) else {
            continue;
        };
        if go_relative_path_boundary_expression(expression, parameter_name, filepath_aliases, src) {
            helpers.push((node_text(&name, src).trim().to_string(), span_of(file, &function)));
        }
    }
    helpers.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.start.cmp(&right.1.start)));
    helpers.dedup();
    helpers
}

fn go_relative_path_boundary_expression(
    expression: Node<'_>,
    parameter: &str,
    filepath_aliases: &[&str],
    src: &[u8],
) -> bool {
    let (Some(left), Some(right)) = (
        expression.child_by_field_name("left"),
        expression.child_by_field_name("right"),
    ) else {
        return false;
    };
    if expression.kind() != "binary_expression"
        || go_binary_operator(expression, left, right, src) != Some("&&")
    {
        return false;
    }
    (go_relative_path_length_guard(left, parameter, src)
        && go_relative_path_prefix_equality(right, parameter, filepath_aliases, src))
        || (go_relative_path_length_guard(right, parameter, src)
            && go_relative_path_prefix_equality(left, parameter, filepath_aliases, src))
}

fn go_relative_path_length_guard(expression: Node<'_>, parameter: &str, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        expression.child_by_field_name("left"),
        expression.child_by_field_name("right"),
    ) else {
        return false;
    };
    if expression.kind() != "binary_expression"
        || go_binary_operator(expression, left, right, src) != Some(">=")
        || node_text(&right, src).trim() != "3"
        || left.kind() != "call_expression"
    {
        return false;
    }
    let (Some(function), Some(arguments)) = (
        left.child_by_field_name("function"),
        left.child_by_field_name("arguments"),
    ) else {
        return false;
    };
    let mut cursor = arguments.walk();
    let args = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    function.kind() == "identifier"
        && node_text(&function, src).trim() == "len"
        && matches!(args.as_slice(), [argument] if argument.kind() == "identifier" && node_text(argument, src).trim() == parameter)
}

fn go_relative_path_prefix_equality(
    expression: Node<'_>,
    parameter: &str,
    filepath_aliases: &[&str],
    src: &[u8],
) -> bool {
    let (Some(left), Some(right)) = (
        expression.child_by_field_name("left"),
        expression.child_by_field_name("right"),
    ) else {
        return false;
    };
    if expression.kind() != "binary_expression"
        || go_binary_operator(expression, left, right, src) != Some("==")
    {
        return false;
    }
    (go_relative_path_slice_prefix(left, parameter, src)
        && go_relative_path_boundary_value(right, filepath_aliases, src))
        || (go_relative_path_slice_prefix(right, parameter, src)
            && go_relative_path_boundary_value(left, filepath_aliases, src))
}

fn go_relative_path_slice_prefix(expression: Node<'_>, parameter: &str, src: &[u8]) -> bool {
    expression.kind() == "slice_expression"
        && expression
            .child_by_field_name("operand")
            .is_some_and(|operand| node_text(&operand, src).trim() == parameter)
        && expression.child_by_field_name("start").is_none()
        && expression
            .child_by_field_name("end")
            .is_some_and(|end| node_text(&end, src).trim() == "3")
}

fn go_relative_path_boundary_value(expression: Node<'_>, filepath_aliases: &[&str], src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        expression.child_by_field_name("left"),
        expression.child_by_field_name("right"),
    ) else {
        return false;
    };
    if expression.kind() != "binary_expression"
        || go_binary_operator(expression, left, right, src) != Some("+")
        || go_static_string_literal(left, src).as_deref() != Some("..")
        || right.kind() != "call_expression"
    {
        return false;
    }
    let (Some(function), Some(arguments)) = (
        right.child_by_field_name("function"),
        right.child_by_field_name("arguments"),
    ) else {
        return false;
    };
    let mut cursor = arguments.walk();
    let args = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    function.kind() == "identifier"
        && node_text(&function, src).trim() == "string"
        && matches!(args.as_slice(), [argument] if filepath_aliases.iter().any(|alias| go_selector_is(*argument, alias, "Separator", src)))
}

fn go_relative_path_boundary_helper_call(
    call: Node<'_>,
    helpers: &[(String, Span)],
    src: &[u8],
) -> Option<Span> {
    let (Some(function), Some(arguments)) = (
        call.child_by_field_name("function"),
        call.child_by_field_name("arguments"),
    ) else {
        return None;
    };
    if function.kind() != "identifier" {
        return None;
    }
    let mut cursor = arguments.walk();
    let args = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    if !matches!(args.as_slice(), [argument] if argument.kind() == "identifier") {
        return None;
    }
    let name = node_text(&function, src).trim();
    helpers
        .iter()
        .find_map(|(helper, proof_span)| (helper == name).then_some(*proof_span))
}

fn go_callback_selector_pin_guard(call: Node<'_>, file: FileId, src: &[u8]) -> Option<(Span, Vec<String>)> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let args: Vec<_> = arguments.named_children(&mut cursor).collect();
    let (callback_index, callback) = args
        .iter()
        .enumerate()
        .find(|(_, argument)| argument.kind() == "func_literal")?;
    let params = callback.child_by_field_name("parameters")?;
    let parameter = collect_kinds_under(&params, &["parameter_declaration"])
        .into_iter()
        .next()?
        .child_by_field_name("name")?;
    let token = node_text(&parameter, src).trim();
    let statements = go_block_statements(callback.child_by_field_name("body")?);
    let [guard, success] = statements.as_slice() else {
        return None;
    };
    if guard.kind() != "if_statement" || guard.child_by_field_name("alternative").is_some() {
        return None;
    }
    let condition = guard.child_by_field_name("condition")?;
    let (left, right) = (
        condition.child_by_field_name("left")?,
        condition.child_by_field_name("right")?,
    );
    if condition.kind() != "binary_expression"
        || go_binary_operator(condition, left, right, src) != Some("!=")
    {
        return None;
    }
    let selector_call = (left.kind() == "call_expression").then_some(left)?;
    let selector_function = selector_call.child_by_field_name("function")?;
    let mut selector_chain = Vec::new();
    if !go_collect_selector_chain(selector_function, src, &mut selector_chain)
        || selector_chain.first().map(String::as_str) != Some(token)
        || selector_chain.len() < 2
    {
        return None;
    }
    let expected = go_static_string_literal(right, src)?;
    if expected.is_empty() {
        return None;
    }
    let rejection = go_block_statements(guard.child_by_field_name("consequence")?);
    let [rejection] = rejection.as_slice() else {
        return None;
    };
    let rejected_values = go_return_values(*rejection)?;
    if rejected_values.len() < 2 || rejected_values[0].kind() != "nil" || rejected_values[1].kind() == "nil" {
        return None;
    }
    let success_values = go_return_values(*success)?;
    if success_values.len() < 2 || success_values[0].kind() == "nil" || success_values[1].kind() != "nil" {
        return None;
    }
    Some((
        span_of(file, guard),
        vec![
            format!("callback-argument:{callback_index}"),
            format!("selector:{}", selector_chain[1..].join(".")),
            format!("literal:{}", expected.to_ascii_lowercase()),
        ],
    ))
}

fn go_collect_selector_chain(node: Node<'_>, src: &[u8], out: &mut Vec<String>) -> bool {
    match node.kind() {
        "identifier" => {
            out.push(node_text(&node, src).trim().to_string());
            true
        }
        "selector_expression" => {
            let (Some(operand), Some(field)) = (
                node.child_by_field_name("operand"),
                node.child_by_field_name("field"),
            ) else {
                return false;
            };
            if !go_collect_selector_chain(operand, src, out) || field.kind() != "field_identifier" {
                return false;
            }
            out.push(node_text(&field, src).trim().to_string());
            true
        }
        _ => false,
    }
}

fn go_enclosing_function_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn go_enclosing_function_span(node: Node<'_>, file: FileId) -> Option<Span> {
    Some(span_of(file, &go_enclosing_function_node(node)?))
}

fn go_return_values(statement: Node<'_>) -> Option<Vec<Node<'_>>> {
    if statement.kind() != "return_statement" {
        return None;
    }
    let expression = statement.named_child(0)?;
    if expression.kind() == "expression_list" {
        let mut cursor = expression.walk();
        Some(expression.named_children(&mut cursor).collect())
    } else {
        Some(vec![expression])
    }
}

fn go_map_callback_replaces_controls(callback: Node<'_>, src: &[u8]) -> bool {
    if callback.kind() != "func_literal" {
        return false;
    }
    let (Some(parameters), Some(body)) = (
        callback.child_by_field_name("parameters"),
        callback.child_by_field_name("body"),
    ) else {
        return false;
    };
    let parameter_declarations = collect_kinds_under(&parameters, &["parameter_declaration"]);
    let [parameter] = parameter_declarations.as_slice() else {
        return false;
    };
    let Some(name) = parameter.child_by_field_name("name") else {
        return false;
    };
    let rune = node_text(&name, src).trim();
    let statements = go_block_statements(body);
    let [guard, fallback] = statements.as_slice() else {
        return false;
    };
    if guard.kind() != "if_statement" || guard.child_by_field_name("alternative").is_some() {
        return false;
    }
    let (Some(condition), Some(consequence)) = (
        guard.child_by_field_name("condition"),
        guard.child_by_field_name("consequence"),
    ) else {
        return false;
    };
    if !go_eval_rune_predicate(condition, rune, 10, src) || !go_eval_rune_predicate(condition, rune, 13, src)
    {
        return false;
    }
    let replacement_statements = go_block_statements(consequence);
    let [replacement_return] = replacement_statements.as_slice() else {
        return false;
    };
    let Some(replacement) = go_single_expression(*replacement_return) else {
        return false;
    };
    let Some(replacement_value) = go_static_rune(replacement, src) else {
        return false;
    };
    replacement_value != '\r'
        && replacement_value != '\n'
        && go_single_expression(*fallback)
            .is_some_and(|value| value.kind() == "identifier" && node_text(&value, src).trim() == rune)
}

fn go_block_statements(block: Node<'_>) -> Vec<Node<'_>> {
    let list = if block.kind() == "statement_list" {
        block
    } else {
        let mut cursor = block.walk();
        let Some(list) = block
            .named_children(&mut cursor)
            .find(|child| child.kind() == "statement_list")
        else {
            return Vec::new();
        };
        list
    };
    let mut cursor = list.walk();
    list.named_children(&mut cursor).collect()
}

fn go_single_expression(statement: Node<'_>) -> Option<Node<'_>> {
    if statement.kind() != "return_statement" {
        return None;
    }
    let mut expression = statement.named_child(0)?;
    while expression.kind() == "expression_list" && expression.named_child_count() == 1 {
        expression = expression.named_child(0)?;
    }
    Some(expression)
}

fn go_selector_is(node: Node<'_>, receiver: &str, field: &str, src: &[u8]) -> bool {
    node.kind() == "selector_expression"
        && node
            .child_by_field_name("operand")
            .is_some_and(|operand| node_text(&operand, src).trim() == receiver)
        && node
            .child_by_field_name("field")
            .is_some_and(|name| node_text(&name, src).trim() == field)
}

fn go_imported_selector_identity(node: Node<'_>, imports: &[ImportSpec], src: &[u8]) -> Option<String> {
    if node.kind() != "selector_expression" {
        return None;
    }
    let operand = node.child_by_field_name("operand")?;
    let field = node.child_by_field_name("field")?;
    if operand.kind() != "identifier" || field.kind() != "field_identifier" {
        return None;
    }
    let alias = node_text(&operand, src).trim();
    let member = node_text(&field, src).trim();
    if alias.is_empty() || member.is_empty() {
        return None;
    }
    imports
        .iter()
        .find(|import| import.alias.as_deref() == Some(alias))
        .map(|import| format!("{}.{}", import.module, member))
}

fn go_binding_shadows_name(function: Node<'_>, expected: &str, src: &[u8]) -> bool {
    collect_kinds_under(
        &function,
        &["parameter_declaration", "short_var_declaration", "var_spec"],
    )
    .into_iter()
    .any(|binding| {
        binding
            .child_by_field_name("name")
            .is_some_and(|name| node_text(&name, src).trim() == expected)
            || binding.kind() == "short_var_declaration"
                && binding.named_child(0).is_some_and(|left| {
                    collect_kinds_under(&left, &["identifier"])
                        .iter()
                        .any(|name| node_text(name, src).trim() == expected)
                })
    })
}

fn go_eval_rune_predicate(node: Node<'_>, rune: &str, value: i64, src: &[u8]) -> bool {
    if node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        return node
            .named_child(0)
            .is_some_and(|inner| go_eval_rune_predicate(inner, rune, value, src));
    }
    if node.kind() != "binary_expression" {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    match go_binary_operator(node, left, right, src) {
        Some("||") => {
            go_eval_rune_predicate(left, rune, value, src) || go_eval_rune_predicate(right, rune, value, src)
        }
        Some("&&") => {
            go_eval_rune_predicate(left, rune, value, src) && go_eval_rune_predicate(right, rune, value, src)
        }
        Some(operator @ ("<" | "<=" | ">" | ">=" | "==" | "!=")) => {
            let Some(left) = go_rune_operand(left, rune, value, src) else {
                return false;
            };
            let Some(right) = go_rune_operand(right, rune, value, src) else {
                return false;
            };
            match operator {
                "<" => left < right,
                "<=" => left <= right,
                ">" => left > right,
                ">=" => left >= right,
                "==" => left == right,
                "!=" => left != right,
                _ => false,
            }
        }
        _ => false,
    }
}

fn go_binary_operator<'a>(
    _node: Node<'_>,
    left: Node<'_>,
    right: Node<'_>,
    src: &'a [u8],
) -> Option<&'a str> {
    src.get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim)
}

fn go_rune_operand(node: Node<'_>, rune: &str, value: i64, src: &[u8]) -> Option<i64> {
    if node.kind() == "identifier" && node_text(&node, src).trim() == rune {
        return Some(value);
    }
    let text = node_text(&node, src).trim().replace('_', "");
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn go_static_rune(node: Node<'_>, src: &[u8]) -> Option<char> {
    let text = node_text(&node, src).trim();
    let inner = text.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut chars = inner.chars();
    let value = chars.next()?;
    chars.next().is_none().then_some(value)
}

/// Parse `import` declarations into `ImportSpec` records.
///
/// Surfaces both the imported module path and the local binding name
/// so the resolver and taint engine can match qualified identifiers
/// like `fmt.Println` against the right module.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Two shapes:
    //   1. Single: `import "path"` or `import alias "path"` —
    //      a direct `import_spec` child.
    //   2. Grouped: `import ( "a"; "b" )` — `import_spec` children
    //      nested inside `import_spec_list`. Walking each
    //      `import_declaration`'s descendants (rather than re-scanning
    //      the whole tree per declaration) keeps this O(N).
    for declaration in collect_kinds(tree, &["import_declaration"]) {
        let specs = collect_kinds_under(&declaration, &["import_spec"]);
        for spec in specs {
            let Some(path_node) = spec.child_by_field_name("path") else {
                continue;
            };
            // Prefer the unquoted string content; fall back to manually
            // stripping `"` / `` ` `` if the grammar didn't expose it.
            let module = first_named_child_of_kind(&path_node, "interpreted_string_literal_content")
                .map(|content| node_text(&content, src).to_string())
                .unwrap_or_else(|| {
                    node_text(&path_node, src)
                        .trim_matches(|ch: char| matches!(ch, '"' | '`'))
                        .to_string()
                });
            if module.is_empty() {
                continue;
            }
            // `import f "fmt"` / `import . "x"` / `import _ "x"`
            let explicit_alias = spec
                .child_by_field_name("name")
                .map(|name_node| node_text(&name_node, src).to_string());
            // `.` makes the module a wildcard import (members enter the
            // current scope unprefixed).
            let is_wildcard = explicit_alias.as_deref() == Some(".");
            // Go binds an unaliased import's local name to the path
            // tail: `import "io/fs"` → `fs`, `import "fmt"` → `fmt`.
            // Surface that binding as an explicit `alias` so taint's
            // qualified-alias gate sees a Go alias map for
            // `fmt.Println` instead of falling through to bare-tail
            // resolution. `_` / `.` aliases bind no local name, so
            // we skip them. Coupled with the self-binding and
            // path-style detectors in `bonsai_resolve` and
            // the canonical callgraph resolver.
            let alias = if explicit_alias.is_some() {
                let alias_text = explicit_alias.as_deref();
                // `_` (blank) and `.` (wildcard) bind no local name.
                if matches!(alias_text, Some("_" | ".")) {
                    None
                } else {
                    explicit_alias
                }
            } else {
                // Unaliased: synthesize the Go-implicit binding from
                // the path tail.
                go_default_import_binding(&module)
            };
            imports.push(ImportSpec {
                span: span_of(file, &spec),
                module,
                alias,
                is_wildcard,
                original_name: None,
                scope: ImportScope::Module,
            });
        }
    }
    imports
}

fn go_default_import_binding(module: &str) -> Option<String> {
    let mut components = module.rsplit('/');
    let tail = components.next()?.trim();
    if tail.is_empty() {
        return None;
    }
    // Semantic import versioning appends `/vN` (N >= 2) without changing
    // the package declaration's default identifier. `…/jwt/v5` therefore
    // binds `jwt`, not `v5`, unless the source supplies an explicit alias.
    let version_suffix = tail
        .strip_prefix('v')
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse::<u64>().ok())
        .is_some_and(|version| version >= 2);
    if version_suffix {
        components
            .next()
            .filter(|component| !component.is_empty())
            .map(str::to_string)
    } else {
        Some(tail.to_string())
    }
}

/// Walk the subtree rooted at `root` and return every named descendant
/// whose kind is in `kinds`. Local helper because `collect_kinds`
/// walks the entire tree from the root, which would re-scan every
/// `import_declaration` for every declaration.
fn collect_kinds_under<'tree>(
    root: &tree_sitter::Node<'tree>,
    kinds: &[&str],
) -> Vec<tree_sitter::Node<'tree>> {
    let mut matches = Vec::new();
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if kinds.contains(&child.kind()) {
                matches.push(child);
            }
            stack.push(child);
        }
    }
    matches
}

/// Walk every Go function/method declaration once and record
/// parameter type-alias bindings. Go is the easiest case: every
/// formal parameter has an explicit type and the grammar names them
/// uniformly as `parameter_declaration` nodes inside
/// `parameter_list`.
fn collect_go_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut aliases_by_fn = Vec::new();
    for fn_node in collect_kinds(
        tree,
        &["function_declaration", "method_declaration", "func_literal"],
    ) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        // `method_declaration` has a `receiver` (parameter_list with
        // one entry); both function and method have `parameters`.
        if let Some(receiver) = fn_node.child_by_field_name("receiver") {
            collect_go_parameter_aliases(receiver, src, &mut aliases);
        }
        if let Some(params) = fn_node.child_by_field_name("parameters") {
            collect_go_parameter_aliases(params, src, &mut aliases);
        }
        collect_go_func_literal_parameter_aliases(fn_node, src, &mut aliases);
        collect_go_local_type_aliases(fn_node, src, &mut aliases);
        dedup_go_type_aliases(&mut aliases);
        if !aliases.is_empty() {
            aliases_by_fn.push((span_of(file, &fn_node), aliases));
        }
    }
    aliases_by_fn
}

fn collect_go_method_receiver_types(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for method in collect_kinds(tree, &["method_declaration"]) {
        let Some(receiver) = method.child_by_field_name("receiver") else {
            continue;
        };
        let Some(receiver_type) = first_go_parameter_type(receiver, src) else {
            continue;
        };
        out.push((span_of(file, &method), receiver_type));
    }
    out
}

fn first_go_parameter_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameter_declaration" && child.kind() != "variadic_parameter_declaration" {
            continue;
        }
        let Some(type_node) = child.child_by_field_name("type") else {
            continue;
        };
        if let Some(type_name) = canonical_go_type_name(node_text(&type_node, src)) {
            return Some(type_name);
        }
    }
    None
}

fn collect_go_class_bases(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, Vec<String>)> {
    let mut out = Vec::new();
    for type_spec in collect_kinds(tree, &["type_spec"]) {
        let Some(type_node) = type_spec.child_by_field_name("type") else {
            continue;
        };
        if !matches!(type_node.kind(), "struct_type" | "interface_type") {
            continue;
        }
        let mut bases = Vec::new();
        collect_go_embedded_type_names(type_node, src, &mut bases);
        if !bases.is_empty() {
            out.push((span_of(file, &type_spec), bases));
        }
    }
    out
}

fn collect_go_range_assignments_by_decl(tree: &Tree, file: FileId, src: &[u8]) -> GoRangeAssignmentsByDecl {
    let channel_returns = collect_go_channel_return_functions(tree, src);
    let mut out = Vec::new();
    for fn_node in collect_kinds(
        tree,
        &["function_declaration", "method_declaration", "func_literal"],
    ) {
        let mut loop_assignments = Vec::new();
        for for_stmt in collect_kinds_under(&fn_node, &["for_statement"]) {
            let Some(range_clause) = direct_go_range_clause(for_stmt) else {
                continue;
            };
            let assignments = go_range_clause_assignments(range_clause, file, src, &channel_returns);
            if !assignments.is_empty() {
                loop_assignments.push((span_of(file, &for_stmt), assignments));
            }
        }
        if !loop_assignments.is_empty() {
            out.push((span_of(file, &fn_node), loop_assignments));
        }
    }
    out
}

fn collect_go_if_init_assignments_by_decl(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> GoIfInitAssignmentsByDecl {
    let mut out = Vec::new();
    for fn_node in collect_kinds(
        tree,
        &["function_declaration", "method_declaration", "func_literal"],
    ) {
        let mut init_assignments = Vec::new();
        for if_stmt in collect_kinds_under(&fn_node, &["if_statement"]) {
            let Some(init) = if_stmt.child_by_field_name("initializer") else {
                continue;
            };
            let events = go_initializer_assignment_events(init, file, src);
            if !events.is_empty() {
                init_assignments.push((span_of(file, &if_stmt), events));
            }
        }
        if !init_assignments.is_empty() {
            out.push((span_of(file, &fn_node), init_assignments));
        }
    }
    out
}

/// Collect assignments whose exact Go CST reads through an index expression.
///
/// The generic expression walker conservatively sees both `table` and `key` in
/// `table[key]`. Go's runtime semantics are sharper: the key selects a stored
/// value but is not part of that value. Replace the generic events from these
/// exact syntax nodes so the shared engine receives the compiler fact instead
/// of trying to recover language semantics from tokens.
fn collect_go_index_assignments_by_decl(tree: &Tree, file: FileId, src: &[u8]) -> GoIndexAssignmentsByDecl {
    let mut out = Vec::new();
    for fn_node in collect_kinds(
        tree,
        &["function_declaration", "method_declaration", "func_literal"],
    ) {
        let mut assignments = Vec::new();
        for assignment in collect_kinds_under(&fn_node, &["short_var_declaration", "assignment_statement"]) {
            let Some(right) = assignment.child_by_field_name("right") else {
                continue;
            };
            if !go_expression_list_values(right)
                .iter()
                .any(|value| go_index_selection_value_flow(*value, file, src).is_some())
            {
                continue;
            }
            let events = go_initializer_assignment_events(assignment, file, src);
            if !events.is_empty() {
                assignments.push((span_of(file, &assignment), events));
            }
        }
        if !assignments.is_empty() {
            out.push((span_of(file, &fn_node), assignments));
        }
    }
    out
}

fn collect_go_channel_return_functions(tree: &Tree, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_declaration", "method_declaration"]) {
        let Some(result) = fn_node.child_by_field_name("result") else {
            continue;
        };
        if !go_type_text_is_channel(node_text(&result, src)) {
            continue;
        }
        if let Some(name_node) = fn_node.child_by_field_name("name") {
            push_unique_string(&mut out, node_text(&name_node, src).trim().to_string());
        }
    }
    out
}

fn direct_go_range_clause(for_stmt: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = for_stmt.walk();
    for child in for_stmt.named_children(&mut cursor) {
        if child.kind() == "range_clause" {
            return Some(child);
        }
    }
    None
}

fn go_range_clause_assignments(
    range_clause: Node<'_>,
    file: FileId,
    src: &[u8],
    channel_returns: &[String],
) -> Vec<FlowEvent> {
    let Some(left) = range_clause.child_by_field_name("left") else {
        return Vec::new();
    };
    let Some(right) = range_clause.child_by_field_name("right") else {
        return Vec::new();
    };
    let targets = direct_go_range_targets(left, src);
    if targets.is_empty() {
        return Vec::new();
    }
    let span = span_of(file, &range_clause);
    let right_text = node_text(&right, src).trim();
    let mut out = Vec::new();

    if targets.len() >= 2 {
        if let Some(target) = targets.get(1).filter(|target| target.as_str() != "_") {
            out.push(go_range_value_assignment(span, target, right, right_text, src));
        }
        return out;
    }

    let target = &targets[0];
    if target == "_" || !go_range_single_target_is_value(right, src, channel_returns) {
        return Vec::new();
    }
    out.push(go_range_value_assignment(span, target, right, right_text, src));
    out
}

fn direct_go_range_targets(left: Node<'_>, src: &[u8]) -> Vec<String> {
    if left.kind() == "identifier" {
        return vec![node_text(&left, src).trim().to_string()];
    }
    let mut out = Vec::new();
    let mut cursor = left.walk();
    for child in left.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            out.push(node_text(&child, src).trim().to_string());
        }
    }
    out
}

fn go_range_value_assignment(
    span: Span,
    target: &str,
    right: Node<'_>,
    right_text: &str,
    src: &[u8],
) -> FlowEvent {
    let call = go_call_expression_parts(right, src);
    let source_call = call.as_ref().map(|(name, _)| name.clone());
    let source_call_args = if source_call.is_some() {
        call.map(|(_, args)| args).unwrap_or_default()
    } else {
        Vec::new()
    };
    let source_name = if source_call.is_none() {
        go_bare_value_name(right_text)
    } else {
        None
    };
    let source_names = if source_call.is_none() {
        go_range_value_source_names(right, span.file, src, source_name.as_deref())
    } else {
        Vec::new()
    };
    let value_kind = if source_call.is_some() {
        bonsai_lang_api::AssignValueKind::CallResult
    } else {
        bonsai_lang_api::AssignValueKind::Compound
    };
    FlowEvent::Assign {
        span,
        target: target.to_string(),
        source_name,
        source_call,
        source_call_args,
        source_names,
        declares_new_binding: true,
        value_kind: Some(value_kind),
    }
}

fn go_range_single_target_is_value(right: Node<'_>, src: &[u8], channel_returns: &[String]) -> bool {
    if right.kind() == "channel_type" || go_type_text_is_channel(node_text(&right, src)) {
        return true;
    }
    if let Some((callee, _)) = go_call_expression_parts(right, src) {
        return channel_returns.iter().any(|return_name| return_name == &callee);
    }
    false
}

fn go_call_expression_parts(node: Node<'_>, src: &[u8]) -> Option<(String, Vec<String>)> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node
        .child_by_field_name("function")
        .map(|function| node_text(&function, src).trim().to_string())
        .filter(|name| !name.is_empty())?;
    let args = node
        .child_by_field_name("arguments")
        .map(|arguments| {
            let mut out = Vec::new();
            let mut cursor = arguments.walk();
            for child in arguments.named_children(&mut cursor) {
                let text = node_text(&child, src).trim();
                if !text.is_empty() {
                    out.push(text.to_string());
                }
            }
            out
        })
        .unwrap_or_default();
    Some((callee, args))
}

fn go_initializer_assignment_events(init: Node<'_>, file: FileId, src: &[u8]) -> Vec<FlowEvent> {
    if !matches!(init.kind(), "short_var_declaration" | "assignment_statement") {
        return Vec::new();
    }
    let Some(left) = init.child_by_field_name("left") else {
        return Vec::new();
    };
    let Some(right) = init.child_by_field_name("right") else {
        return Vec::new();
    };
    let targets = direct_go_range_targets(left, src);
    let rhs_values = go_expression_list_values(right);
    if targets.is_empty() || rhs_values.is_empty() {
        return Vec::new();
    }
    let span = span_of(file, &init);
    let mut out = Vec::new();
    for (idx, target) in targets.iter().enumerate() {
        if target == "_" {
            continue;
        }
        let rhs = rhs_values
            .get(idx)
            .copied()
            .or_else(|| rhs_values.first().copied());
        let Some(rhs) = rhs else {
            continue;
        };
        let call = go_call_expression_parts(rhs, src);
        let (source_name, source_call, source_call_args, source_names, value_kind) =
            if let Some(flow) = go_index_selection_value_flow(rhs, file, src) {
                // `value, ok := table[key]`: only the selected value inherits
                // the table's stored-value provenance. `ok` is a membership
                // boolean and neither result inherits the selector key.
                let source_names = if idx == 0 {
                    go_expression_flow_source_names(&flow)
                } else {
                    Vec::new()
                };
                (
                    None,
                    None,
                    Vec::new(),
                    source_names,
                    Some(bonsai_lang_api::AssignValueKind::Compound),
                )
            } else if let Some((callee, args)) = call.clone() {
                (
                    None,
                    Some(callee),
                    args,
                    Vec::new(),
                    Some(bonsai_lang_api::AssignValueKind::CallResult),
                )
            } else {
                let rhs_text = node_text(&rhs, src).trim();
                let source_name = go_bare_value_name(rhs_text);
                (
                    source_name.clone(),
                    None,
                    Vec::new(),
                    go_range_value_source_names(rhs, span.file, src, source_name.as_deref()),
                    Some(bonsai_lang_api::AssignValueKind::Compound),
                )
            };
        out.push(FlowEvent::Assign {
            span,
            target: target.to_string(),
            source_name,
            source_call,
            source_call_args,
            source_names,
            declares_new_binding: init.kind() == "short_var_declaration",
            value_kind,
        });
        if call.is_some() {
            if let Some(call_event) = go_call_event_from_node(rhs, file, src) {
                out.push(call_event);
            }
        }
    }
    out
}

fn go_expression_list_values(node: Node<'_>) -> Vec<Node<'_>> {
    if node.kind() != "expression_list" {
        return vec![node];
    }
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        out.push(child);
    }
    out
}

fn go_call_event_from_node(call: Node<'_>, file: FileId, src: &[u8]) -> Option<FlowEvent> {
    if call.kind() != "call_expression" {
        return None;
    }
    let callee_node = call.child_by_field_name("function")?;
    let callee = node_text(&callee_node, src).trim();
    if callee.is_empty() {
        return None;
    }
    let receiver = callee.rsplit_once('.').map(|(recv, _)| recv.to_string());
    let call_kind = if receiver.is_some() {
        bonsai_lang_api::CallKind::Method
    } else {
        bonsai_lang_api::CallKind::Function
    };
    let mut args = Vec::new();
    if let Some(arguments) = call.child_by_field_name("arguments") {
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            if let Some(argument) = call_arg_from_node_with_handler(argument, file, src, None, &HANDLER) {
                args.push(argument);
            }
        }
    }
    Some(FlowEvent::Call {
        span: span_of(file, &call),
        name: callee.to_string(),
        receiver,
        receiver_types: Vec::new(),
        call_kind,
        args,
    })
}

fn go_range_value_source_names(
    right: Node<'_>,
    file: FileId,
    src: &[u8],
    source_name: Option<&str>,
) -> Vec<String> {
    let mut names = go_expression_flow_source_names(&lower_go_value_expression(right, file, src));
    if let Some(source_name) = source_name {
        names.retain(|name| name != source_name);
    }
    names
}

fn go_type_text_is_channel(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("<-chan ")
        || trimmed.starts_with("chan<- ")
        || trimmed.starts_with("chan ")
        || trimmed == "chan"
}

fn augment_go_range_assignments(events: &mut Vec<FlowEvent>, range_assignments: &[(Span, Vec<FlowEvent>)]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_go_range_assignments(then_events, range_assignments);
                augment_go_range_assignments(else_events, range_assignments);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_go_range_assignments(body, range_assignments);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_go_range_assignments(body, range_assignments);
                augment_go_range_assignments(catch_events, range_assignments);
                augment_go_range_assignments(finally_events, range_assignments);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        if let FlowEvent::Assign { span, .. } = &event {
            if range_assignments.iter().any(|(loop_span, _)| loop_span == span) {
                continue;
            }
        }
        if let FlowEvent::Loop { span, .. } = &event {
            if let Some(assignments) = range_assignments
                .iter()
                .find_map(|(loop_span, assignments)| (loop_span == span).then_some(assignments))
            {
                rewritten.extend(assignments.iter().cloned());
            }
        }
        rewritten.push(event);
    }
    *events = rewritten;
}

fn augment_go_if_init_assignments(
    events: &mut Vec<FlowEvent>,
    if_init_assignments: &[(Span, Vec<FlowEvent>)],
    aliases: &[TypeAliasBinding],
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_go_if_init_assignments(then_events, if_init_assignments, aliases);
                augment_go_if_init_assignments(else_events, if_init_assignments, aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_go_if_init_assignments(body, if_init_assignments, aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_go_if_init_assignments(body, if_init_assignments, aliases);
                augment_go_if_init_assignments(catch_events, if_init_assignments, aliases);
                augment_go_if_init_assignments(finally_events, if_init_assignments, aliases);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        if let FlowEvent::Branch { span, .. } = &event {
            if let Some(init_events) = if_init_assignments
                .iter()
                .find_map(|(if_span, init_events)| (if_span == span).then_some(init_events))
            {
                rewritten.extend(init_events.iter().cloned().map(|mut event| {
                    enrich_go_synthetic_receiver_types(&mut event, aliases);
                    event
                }));
            }
        }
        rewritten.push(event);
    }
    *events = rewritten;
}

fn replace_go_index_selection_assignments(
    events: &mut Vec<FlowEvent>,
    index_assignments: &[(Span, GoIndexAssignments)],
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                replace_go_index_selection_assignments(then_events, index_assignments);
                replace_go_index_selection_assignments(else_events, index_assignments);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                replace_go_index_selection_assignments(body, index_assignments);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                replace_go_index_selection_assignments(body, index_assignments);
                replace_go_index_selection_assignments(catch_events, index_assignments);
                replace_go_index_selection_assignments(finally_events, index_assignments);
            }
            _ => {}
        }
    }

    let mut replaced = std::collections::HashSet::new();
    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let replacement = match &event {
            FlowEvent::Assign { span, .. } => index_assignments
                .iter()
                .find_map(|(assignment_span, exact)| (assignment_span == span).then_some(exact)),
            _ => None,
        };
        if let Some(exact) = replacement {
            let span = match &event {
                FlowEvent::Assign { span, .. } => *span,
                _ => unreachable!("replacement is only selected for assignments"),
            };
            if replaced.insert(span) {
                rewritten.extend(exact.iter().cloned());
            }
            continue;
        }
        rewritten.push(event);
    }
    *events = rewritten;
}

fn enrich_go_synthetic_receiver_types(event: &mut FlowEvent, aliases: &[TypeAliasBinding]) {
    let FlowEvent::Call {
        receiver: Some(receiver),
        receiver_types,
        ..
    } = event
    else {
        return;
    };
    if !receiver_types.is_empty() {
        return;
    }
    for alias in aliases {
        if alias.name == *receiver {
            push_unique_string(receiver_types, alias.type_name.clone());
        }
    }
}

fn collect_go_embedded_type_names(node: Node<'_>, src: &[u8], bases: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "field_declaration" {
            let named_field = current.child_by_field_name("name").is_some();
            if !named_field {
                if let Some(type_node) = current.child_by_field_name("type") {
                    if let Some(base) = canonical_go_type_name(node_text(&type_node, src)) {
                        push_unique_string(bases, base);
                    }
                } else if let Some(base) = first_type_identifier_text(current, src) {
                    push_unique_string(bases, base);
                }
            }
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn collect_go_local_type_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    for var_spec in collect_kinds_under(&node, &["var_spec"]) {
        let names = go_var_spec_names(var_spec, src);
        if names.is_empty() {
            continue;
        }
        let declared_type = var_spec
            .child_by_field_name("type")
            .and_then(|type_node| canonical_go_type_name(node_text(&type_node, src)));
        let concrete_type = var_spec
            .child_by_field_name("value")
            .and_then(|value_node| first_go_composite_literal_type(value_node, src));
        let concrete_qualified_type = var_spec
            .child_by_field_name("value")
            .and_then(|value_node| first_go_composite_literal_qualified_type(value_node, src));
        // WS2: `var c = make().(Foo)` — the type assertion is the only
        // type signal; binds the (first) name to the asserted type.
        let assertion_type = var_spec
            .child_by_field_name("value")
            .and_then(|value_node| go_direct_type_assertion_type(value_node, src));
        for (index, name) in names.iter().enumerate() {
            if let Some(ty) = declared_type.as_deref() {
                push_go_type_alias(aliases, name, ty);
            }
            if let Some(ty) = concrete_type.as_deref() {
                push_go_type_alias(aliases, name, ty);
            }
            if let Some(ty) = concrete_qualified_type.as_deref() {
                push_go_type_alias(aliases, name, ty);
            }
            if index == 0 {
                if let Some(ty) = assertion_type.as_deref() {
                    push_go_type_alias(aliases, name, ty);
                }
            }
        }
    }
    // Short declarations are not `var_spec` nodes. Bind each top-level LHS
    // to the corresponding AST-proven composite-literal type, and retain the
    // comma-ok type-assertion handling for the first result. In particular,
    // `client := &http.Client{}` must produce `client: http.Client`; using
    // only the composite literal's package receiver (`http`) makes
    // `client.Get` indistinguishable from the package function `http.Get`.
    for short_var in collect_kinds_under(&node, &["short_var_declaration"]) {
        let (Some(left), Some(right)) = (
            short_var.child_by_field_name("left"),
            short_var.child_by_field_name("right"),
        ) else {
            continue;
        };
        let mut left_cursor = left.walk();
        let names = left
            .named_children(&mut left_cursor)
            .filter(|child| child.kind() == "identifier")
            .collect::<Vec<_>>();
        let mut right_cursor = right.walk();
        let values = right.named_children(&mut right_cursor).collect::<Vec<_>>();
        for (name_node, value_node) in names.iter().zip(values.iter()) {
            let name = node_text(name_node, src).trim();
            if let Some(ty) = first_go_composite_literal_type(*value_node, src) {
                push_go_type_alias(aliases, name, &ty);
            }
            if let Some(ty) = first_go_composite_literal_qualified_type(*value_node, src) {
                push_go_type_alias(aliases, name, &ty);
            }
        }
        // `c := make().(Foo)` — bind only the first LHS value; a comma-ok
        // second result is a boolean, never the asserted type.
        if let (Some(name_node), Some(ty)) = (names.first(), go_direct_type_assertion_type(right, src)) {
            push_go_type_alias(aliases, node_text(name_node, src).trim(), &ty);
        }
    }
}

/// WS2: the asserted type of a direct type-assertion RHS (`x.(Foo)` ->
/// `Foo`), unwrapping a single-element `expression_list` / parens. Returns
/// `None` for any other RHS shape so only a genuine assertion types the
/// local (a nested assertion inside a call arg must not leak).
fn go_direct_type_assertion_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut n = node;
    while matches!(n.kind(), "expression_list" | "parenthesized_expression") {
        let mut cursor = n.walk();
        n = n.named_children(&mut cursor).next()?;
    }
    if n.kind() == "type_assertion_expression" {
        let type_node = n.child_by_field_name("type")?;
        return canonical_go_type_name(node_text(&type_node, src));
    }
    None
}

fn apply_go_projected_receiver_aliases(idx: &mut DeclIndex) {
    for decl in &mut idx.defs {
        if decl.type_aliases.is_empty() {
            continue;
        }
        let base_aliases = decl.type_aliases.clone();
        let mut projected = Vec::new();
        collect_go_projected_receiver_aliases(&decl.flow_events, &base_aliases, &mut projected);
        for alias in projected {
            if !decl.type_aliases.contains(&alias) {
                decl.type_aliases.push(alias);
            }
        }
    }
}

fn collect_go_projected_receiver_aliases(
    events: &[FlowEvent],
    base_aliases: &[TypeAliasBinding],
    out: &mut Vec<TypeAliasBinding>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                receiver: Some(receiver),
                ..
            } => {
                if let Some(root) = go_projected_receiver_root(receiver) {
                    for alias in base_aliases.iter().filter(|alias| alias.name == root) {
                        let projected = TypeAliasBinding {
                            name: receiver.clone(),
                            type_name: alias.type_name.clone(),
                        };
                        if !out.contains(&projected) {
                            out.push(projected);
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_go_projected_receiver_aliases(then_events, base_aliases, out);
                collect_go_projected_receiver_aliases(else_events, base_aliases, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_go_projected_receiver_aliases(body, base_aliases, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_go_projected_receiver_aliases(body, base_aliases, out);
                collect_go_projected_receiver_aliases(catch_events, base_aliases, out);
                collect_go_projected_receiver_aliases(finally_events, base_aliases, out);
            }
            FlowEvent::Call { receiver: None, .. }
            | FlowEvent::Assign { .. }
            | FlowEvent::AggregateAssign { .. }
            | FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. }
            | FlowEvent::Yield { .. }
            | FlowEvent::Await { .. }
            | FlowEvent::Lifecycle { .. } => {}
        }
    }
}

fn go_projected_receiver_root(receiver: &str) -> Option<&str> {
    if receiver.contains('(') || receiver.contains(')') {
        return None;
    }
    let (root, rest) = receiver.split_once('.')?;
    if !go_identifier_like(root) {
        return None;
    }
    let first_projection = rest.split('.').next().unwrap_or(rest);
    go_identifier_like(first_projection).then_some(root)
}

fn go_identifier_like(segment: &str) -> bool {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn go_var_spec_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let type_start = node
        .child_by_field_name("type")
        .map(|type_node| type_node.start_byte())
        .unwrap_or(usize::MAX);
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= type_start {
            continue;
        }
        if child.kind() == "identifier" {
            let name = node_text(&child, src).trim();
            if !name.is_empty() {
                push_unique_string(&mut names, name.to_string());
            }
        }
    }
    names
}

fn go_bare_value_name(value: &str) -> Option<String> {
    let value = value.trim();
    go_identifier_like(value).then(|| value.to_string())
}

fn first_go_composite_literal_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "composite_literal" {
            if let Some(type_node) = current.child_by_field_name("type") {
                if let Some(type_name) = canonical_go_type_name(node_text(&type_node, src)) {
                    return Some(type_name);
                }
            }
        }
        let mut cursor = current.walk();
        let children: Vec<_> = current.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

fn first_go_composite_literal_qualified_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "composite_literal" {
            if let Some(type_node) = current.child_by_field_name("type") {
                if let Some(type_name) = qualified_go_type_name(node_text(&type_node, src)) {
                    return Some(type_name);
                }
            }
        }
        let mut cursor = current.walk();
        let children: Vec<_> = current.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

fn first_type_identifier_text(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "type_identifier" | "qualified_type") {
            if let Some(type_name) = canonical_go_type_name(node_text(&current, src)) {
                return Some(type_name);
            }
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    let value = value.trim();
    if value.is_empty() || values.iter().any(|existing| existing == value) {
        return;
    }
    values.push(value.to_string());
}

/// Visit a `parameter_list` node and forward each parameter
/// declaration to `go_parameter_decl_aliases`.
fn collect_go_parameter_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        // Variadic parameters (`...T`) follow the same shape as a
        // normal parameter declaration.
        if child.kind() == "parameter_declaration" || child.kind() == "variadic_parameter_declaration" {
            go_parameter_decl_aliases(child, src, aliases);
        }
    }
}

fn collect_go_func_literal_parameter_aliases(
    fn_node: Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    for literal in collect_kinds_under(&fn_node, &["func_literal"]) {
        if let Some(params) = literal.child_by_field_name("parameters") {
            collect_go_parameter_aliases(params, src, aliases);
        }
    }
}

/// Bind every identifier in a single `parameter_declaration` to its
/// canonical type name.
fn go_parameter_decl_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    // Go grammar: `parameter_declaration` has a `name:` field
    // (sometimes a list of identifiers `a, b, c Type`) and a `type:`
    // field. Pointer / qualified / generic types still resolve to
    // the bare type name through `canonical_go_type_name`.
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(canonical) = canonical_go_type_name(node_text(&type_node, src)) else {
        return;
    };
    // Also keep the package-qualified form when present (`gin.Context`
    // alongside `Context`). The unqualified canonical drives method
    // dispatch lookup; the qualified form is what the rule-matcher
    // chases through the alias map for the package gate
    // (`alias_map.get("gin")` → `Namespace{github.com/gin-gonic/gin}`).
    let qualified =
        qualified_go_type_name(node_text(&type_node, src)).filter(|qualified| qualified != &canonical);
    // A single `parameter_declaration` may bind multiple identifiers
    // sharing one type (`a, b string`). Iterate every identifier
    // child rather than just `child_by_field_name("name")`.
    let mut cursor = node.walk();
    let mut bound_any = false;
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            let name = node_text(&child, src).trim().to_string();
            if !name.is_empty() {
                push_go_type_alias(aliases, &name, &canonical);
                if let Some(q) = qualified.as_deref() {
                    push_go_type_alias(aliases, &name, q);
                }
                bound_any = true;
            }
        }
    }
    if !bound_any {
        // Fallback for grammar shapes that don't expose identifiers
        // as direct named children — try the explicit `name` field.
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(&name_node, src).trim().to_string();
            if !name.is_empty() {
                push_go_type_alias(aliases, &name, &canonical);
                if let Some(q) = qualified.as_deref() {
                    push_go_type_alias(aliases, &name, q);
                }
            }
        }
    }
}

/// Strip pointer / array / map / generic wrappers but keep the
/// package qualifier when present. `*gin.Context` → `gin.Context`,
/// `*http.Request` → `http.Request`, `[]string` → `string`,
/// `Foo[T]` → `Foo`. Returns `None` when no qualifier survives the
/// strip (so callers can skip the redundant push).
fn qualified_go_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('*').trim_start_matches('&').trim();
    let after_brackets = if let Some(rest) = trimmed.strip_prefix("[]") {
        rest.trim()
    } else if let Some(rest) = trimmed.strip_prefix("map[") {
        rest.split_once(']')
            .map_or(rest, |(_, value_type)| value_type)
            .trim()
    } else if trimmed.starts_with('[') {
        trimmed
            .split_once(']')
            .map_or(trimmed, |(_, value_type)| value_type)
            .trim()
    } else {
        trimmed
    };
    let without_generic = after_brackets.split('[').next().unwrap_or(after_brackets).trim();
    if without_generic.contains('.') && !without_generic.is_empty() {
        Some(without_generic.to_string())
    } else {
        None
    }
}

/// Strip pointer / qualified / generic wrappers down to the
/// rightmost bare type identifier. `*http.Request` →
/// `Request`, `[]string` → `string`, `map[string]int` → `int`,
/// `Foo[T]` → `Foo`.
fn canonical_go_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('*').trim_start_matches('&').trim();
    // Strip slice / array / map prefixes if present; keep the
    // value type for the binding.
    let after_brackets = if let Some(rest) = trimmed.strip_prefix("[]") {
        rest.trim()
    } else if let Some(rest) = trimmed.strip_prefix("map[") {
        // `map[K]V` → V (most relevant for taint propagation).
        rest.split_once(']')
            .map_or(rest, |(_, value_type)| value_type)
            .trim()
    } else if trimmed.starts_with('[') {
        // Fixed-size array `[N]T` — strip up to the closing bracket.
        trimmed
            .split_once(']')
            .map_or(trimmed, |(_, value_type)| value_type)
            .trim()
    } else {
        trimmed
    };
    // Drop any generic instantiation suffix (`Foo[T]` → `Foo`).
    let without_generic = after_brackets.split('[').next().unwrap_or(after_brackets).trim();
    // Drop the package qualifier (`http.Request` → `Request`).
    let bare = without_generic
        .rsplit('.')
        .next()
        .unwrap_or(without_generic)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Append a type-alias binding, skipping no-op entries (empty names
/// or self-bindings where `name == type_name`).
fn push_go_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    aliases.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

/// Drop duplicate `(name, type_name)` pairs in place while preserving
/// insertion order.
fn dedup_go_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}

/// Find the `package <name>` declaration at the top of a Go file
/// and return the package name. Files without a package declaration
/// (rare; would be a parse error in real Go) return None.
fn extract_go_package(root: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        let mut sub = child.walk();
        for subchild in child.children(&mut sub) {
            if subchild.kind() == "package_identifier" || subchild.kind() == "identifier" {
                return Some(node_text(&subchild, src).to_string());
            }
        }
    }
    None
}

fn go_module_segments(file: FileId, ctx: &AdapterContext<'_>, package_name: &str) -> Vec<String> {
    let mut segments: Vec<String> = ctx
        .workspace_relative_path(file)
        .and_then(|path| {
            let parent = path.parent()?;
            Some(
                parent
                    .components()
                    .filter_map(|component| match component {
                        std::path::Component::Normal(part) => {
                            let text = part.to_string_lossy();
                            (!text.is_empty()).then(|| text.into_owned())
                        }
                        _ => None,
                    })
                    .collect(),
            )
        })
        .unwrap_or_default();
    if segments.last().is_none_or(|last| last != package_name) {
        segments.push(package_name.to_string());
    }
    segments
}
