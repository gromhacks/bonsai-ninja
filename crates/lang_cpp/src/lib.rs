//! C++ language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        c_family_preproc_imports, collect_kinds, collect_param_type_aliases,
        expression_operand_names_with_handler, first_named_child_of_kind, language_from_pack,
        named_child_call_args_with_handler, node_text, parse_with, span_of, walk_flow_events,
    },
    AdapterContext, AdapterError, AggregateLayout, ArgumentPassingMode, CallKind, CallTargetExtraction,
    DeclIndex, DeclKind, FieldWrite, FlowEvent, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasBinding, TypeAliasVocabulary, Visibility,
    EMPTY_HANDLER,
};

/// C++ parameter shape: `parameter_declaration` carries `type` and
/// `declarator` fields (the declarator may be a pointer / array /
/// reference wrapper around the binding identifier). The kit
/// helper drops back to `child_by_field_name("declarator")` when
/// `name` isn't present, then walks down to the inner identifier.
// `parameter_declaration` covers the function's formal parameters;
// `declaration` covers local stack-allocated bindings inside the
// body (`Box obj;`, `Logger log = ...;`). Both shapes carry a
// `type` field and a `declarator` field, so the kit's generic
// param-alias extractor pulls a `name : Type` binding from either.
const CPP_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition"],
    param_kinds: &["parameter_declaration", "declaration"],
    name_field: "declarator",
    type_field: "type",
};
use tree_sitter::{Language, Node, Tree};

fn cpp_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "for_range_loop")
        .then(|| {
            Some((
                node.child_by_field_name("declarator")?,
                node.child_by_field_name("right")?,
            ))
        })
        .flatten()
}

pub const LANG_ID: LanguageId = LanguageId::new("cpp");
const PACK_NAME: &str = "cpp";
const CPP_CALL_KINDS: &[&str] = &["call_expression", "new_expression"];

fn cpp_indirect_place_operand(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "pointer_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let has_indirection = node
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "*" | "&"));
    has_indirection
        .then(|| node.child_by_field_name("argument"))
        .flatten()
}

/// C++ call targets are grammar-delimited `function`/`type` nodes. Preserve
/// the complete callable path (`absl::GetFlag`, `object.method`, and operator
/// calls), while removing parsed template-argument nodes: `tokenize<T>` and
/// its declaration `tokenize` are one compiler callable identity. The adapter
/// owns this CST normalization so shared resolution never parses `<...>`.
fn cpp_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let target = match node.kind() {
        "call_expression" => node.child_by_field_name("function")?,
        "new_expression" => node.child_by_field_name("type")?,
        _ => return None,
    };
    let full_text = cpp_call_target_without_template_arguments(target, src);
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

fn cpp_call_target_without_template_arguments(target: Node<'_>, src: &[u8]) -> String {
    let mut argument_ranges = Vec::new();
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        if node.kind() == "template_argument_list" {
            argument_ranges.push(node.byte_range());
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    if argument_ranges.is_empty() {
        return node_text(&target, src).trim().to_string();
    }
    argument_ranges.sort_by_key(|range| (range.start, range.end));
    let mut out = String::new();
    let mut cursor = target.start_byte();
    for range in argument_ranges {
        if range.start > cursor {
            out.push_str(std::str::from_utf8(&src[cursor..range.start]).unwrap_or_default());
        }
        cursor = cursor.max(range.end);
    }
    if cursor < target.end_byte() {
        out.push_str(std::str::from_utf8(&src[cursor..target.end_byte()]).unwrap_or_default());
    }
    out.trim().to_string()
}

const HANDLER: GrammarHandler = GrammarHandler {
    literal_value_kinds: &["null", "nullptr", "true", "false"],
    string_literal_kinds: &[
        "string_literal",
        "raw_string_literal",
        "char_literal",
        "concatenated_string",
    ],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["///", "//!", "/**"],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["parameter_list"],
    parameter_kinds: &["parameter_declaration", "optional_parameter_declaration"],
    parameter_annotation_kinds: &["attribute"],
    variadic_parameter_kinds: &["variadic_parameter", "variadic_declaration"],
    binding_identifier_kinds: &["identifier"],
    anonymous_variadic_token: Some("..."),
    identifier_kinds: &["identifier"],
    named_aggregate_kinds: &["initializer_list"],
    positional_aggregate_kinds: &["initializer_list"],
    aggregate_pair_kinds: &["initializer_pair"],
    aggregate_key_field_names: &["designator"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["field_identifier"],
    aggregate_syntax_only_kinds: &["type_identifier"],
    transparent_call_wrapper_kinds: &[
        "field_expression",
        "scoped_identifier",
        "parenthesized_expression",
        "await_expression",
        "co_await_expression",
    ],
    single_expression_group_kinds: &["expression_list"],
    assignment_target_wrapper_kinds: &[
        "init_declarator",
        "declarator",
        "function_declarator",
        "pointer_declarator",
        "reference_declarator",
        "parenthesized_declarator",
    ],
    binding_declaration_keyword_spellings: &["auto", "const"],
    fn_kinds: &["function_definition"],
    call_kinds: CPP_CALL_KINDS,
    constructor_call_kinds: &["new_expression"],
    call_callee_field_names: &["function"],
    constructor_type_field_names: &["type"],
    call_target_extractor: Some(cpp_call_target),
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list"],
    writeback_operand_field_names: &["argument"],
    indirect_place_operand_extractor: Some(cpp_indirect_place_operand),
    lambda_body_field_names: &["body"],
    pseudo_call_extractor: Some(extract_cpp_pseudo_call),
    syntax_event_extractor: Some(extract_cpp_syntax_event),
    argument_passing_mode_extractor: Some(cpp_argument_passing_mode),
    expression_value_kind_extractor: Some(cpp_expression_value_kind),
    call_ref_kinds: CPP_CALL_KINDS,
    member_expression_kinds: &["field_expression", "qualified_identifier", "scoped_identifier"],
    subscript_expression_kinds: &["subscript_expression"],
    member_base_field_names: &["argument", "scope"],
    member_name_field_names: &["field", "name"],
    subscript_base_field_names: &["argument"],
    subscript_index_field_names: &["index"],
    syntax_error_tolerant_call_names: &["va_arg", "__builtin_va_arg"],
    value_free_expression_kinds: &["sizeof_expression", "alignof_expression"],
    class_kinds: &["class_specifier", "struct_specifier", "union_specifier"],
    class_decl_kinds: &[
        ("class_specifier", DeclKind::Class),
        ("struct_specifier", DeclKind::Struct),
        ("union_specifier", DeclKind::Struct),
    ],
    method_context_kinds: &["class_specifier", "struct_specifier", "union_specifier"],
    if_kinds: &["if_statement", "conditional_expression", "switch_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["compound_statement", "expression_statement"],
    branch_arm_kinds: &["compound_statement", "expression_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &["for_range_loop"],
    foreach_binding_extractor: Some(cpp_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    assignment_kinds: &["assignment_expression", "init_declarator"],
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="],
    positional_aggregate_assignment_kinds: &["init_declarator"],
    positional_aggregate_value_kinds: &["initializer_list"],
    return_kinds: &["return_statement", "co_return_statement"],
    throw_kinds: &["throw_statement"],
    lambda_kinds: &["lambda_expression"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    yield_kinds: &["co_yield_statement"],
    yield_value_field_names: &["argument", "value"],
    try_body_field_names: &["body"],
    await_kinds: &["co_await_expression"],
    // `this` for instance methods; C++ has no `super` keyword, but
    // `Base::method()` is a qualified call that the resolver
    // already narrows by qualified-name matching, so the explicit
    // implicit-receiver list stays at `this`.
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    implicit_receiver_names: &["this"],
    ..EMPTY_HANDLER
};

fn cpp_expression_value_kind(node: Node<'_>, _src: &[u8]) -> Option<bonsai_lang_api::AssignValueKind> {
    matches!(
        node.kind(),
        "string_literal" | "char_literal" | "number_literal" | "true" | "false" | "nullptr"
    )
    .then_some(bonsai_lang_api::AssignValueKind::Literal)
}

fn cpp_argument_passing_mode(argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
    if [argument, value].into_iter().any(|node| {
        matches!(node.kind(), "pointer_expression" | "unary_expression") && {
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

fn extract_cpp_pseudo_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "delete_expression" {
        return None;
    }
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: None,
        receiver_types: Vec::new(),
        name: "delete".to_string(),
        call_kind: CallKind::Operator,
        args: named_child_call_args_with_handler(&node, file, src, handler),
    })
}

/// Lower C++ direct initialization (`Type value(args)`) as the constructor
/// call it denotes. Tree-sitter represents this as an `init_declarator` whose
/// value is an `argument_list`, not as a `call_expression`; without this
/// adapter-owned CST rule the compiler sees the assignment and nested
/// argument calls but loses the constructor boundary itself.
fn extract_cpp_syntax_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    let (name, value) = match node.kind() {
        "init_declarator" => {
            let value = node.child_by_field_name("value")?;
            if value.kind() != "argument_list" {
                return None;
            }
            let declaration = node.parent().filter(|parent| parent.kind() == "declaration")?;
            let type_node = declaration.child_by_field_name("type")?;
            (cpp_type_descriptor_name(&type_node, src)?, value)
        }
        // A constructor's member/base initializer list lives outside its
        // compound body. The adapter explicitly walks that list below; base
        // identifiers resolve to constructor declarations, while member
        // identifiers remain unresolved unless their own typed declaration
        // provides a callable identity.
        "field_initializer" => {
            let name_node = node.named_child(0)?;
            let value = first_named_child_of_kind(&node, "argument_list")?;
            (node_text(&name_node, src).trim().to_string(), value)
        }
        _ => return None,
    };
    if name.is_empty() {
        return None;
    }
    Some(FlowEvent::Call {
        span: span_of(file, &value),
        receiver: None,
        receiver_types: Vec::new(),
        name,
        call_kind: CallKind::Constructor,
        args: named_child_call_args_with_handler(&value, file, src, handler),
    })
}

/// Zero-sized adapter handle; all state lives in the shared parser pack.
#[derive(Debug, Default, Copy, Clone)]
pub struct CppAdapter;

impl CppAdapter {
    /// Construct a fresh adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for CppAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "C++"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.h` is shared with C. The registry preserves both candidates and
        // the database selects the grammar whose concrete syntax tree has the
        // fewest errors, preferring C on an exact tie. This mirrors a compiler
        // frontend's translation-unit context without guessing from names or
        // repository paths, using the syntax facts available without a
        // compile-command database.
        &["cpp", "cc", "cxx", "hpp", "hh", "hxx", "h"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        bonsai_lang_api::c_family_declaration_macro_recovery_edits(
            snapshot,
            vfs,
            tree,
            &["va_arg", "__builtin_va_arg"],
        )
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Macros: same story as C — tree-sitter-cpp parses
        // `STR_CPY(...)` / `LOG(...)` / `assert(...)` as ordinary
        // call expressions and the engine narrows them by name.
        // `#define` expansion is not performed.
        LanguageCapabilities {
            macros: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                rooted_prefixes: &["::"],
                repeatable_rooted_prefixes: &[],
            },
            // C++ constructors are class-named; the kind-based
            // `DeclKind::Constructor` lookup is authoritative.
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &["this"],
            same_directory_unqualified_calls: true,
            build_target_linkage: true,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        mark_cpp_constructors(&mut decl_index);
        // Populate qualified_name + module_path + visibility per the
        // semantic-identity contract
        // (`docs/contributing/design-patterns.mdx::Semantic Resolution Always`).
        // Two TU-private surfaces in C++:
        //   - `static` storage class on a free function (C-inherited).
        //   - Definition inside an anonymous namespace.
        // Both must surface as `Visibility::Private` so the resolver
        // refuses cross-TU linking by name.
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        let private_function_names = collect_tu_private_function_names(file, ctx);
        for decl in &mut decl_index.defs {
            if private_function_names.contains(&decl.name) {
                decl.visibility = Visibility::Private;
            }
        }
        // Per-class `bases`: `class C : public Base, private Other {…}`
        // → ["Base", "Other"]. C++ exposes them as a single
        // `base_class_clause` whose access_specifier+type_identifier
        // pairs alternate. Per-decl `type_aliases` from typed
        // parameters bring C++ in lockstep with the rest per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `T foo() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, &tree, src, &HANDLER);
            let bases_by_span = collect_cpp_class_bases(&tree, file, src);
            let fields_by_class = collect_cpp_class_fields(&tree, file, src);
            decl_index.aggregate_layouts = fields_by_class
                .iter()
                .map(|(_, type_name, fields)| AggregateLayout {
                    type_name: type_name.clone(),
                    fields: fields.clone(),
                })
                .collect();
            let fields_by_parent = cpp_fields_by_parent_symbol(&decl_index, &fields_by_class);
            let access_by_span = collect_cpp_member_visibility(&tree, file, src);
            let alias_map = collect_param_type_aliases(&tree, file, src, &CPP_TYPE_ALIASES);
            // WS2: `auto c = static_cast<Foo>(x)` / `auto c = (Foo) x` — the
            // kit types declared-type locals (`Foo c = make()`) but not the
            // inferred-`auto` form, where the type lives only on the cast.
            let cast_aliases = collect_cpp_cast_aliases(&tree, file, src).into_iter().fold(
                std::collections::HashMap::<Span, Vec<TypeAliasBinding>>::new(),
                |mut by_span, (span, binding)| {
                    by_span.entry(span).or_default().push(binding);
                    by_span
                },
            );
            let initializer_specs = collect_cpp_initializer_field_specs(&tree, file, src)
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>();
            let initializer_events = collect_cpp_constructor_initializer_events(&tree, file, src)
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>();
            for decl in &mut decl_index.defs {
                if let Some(events) = initializer_events.get(&decl.span) {
                    let mut ordered = events.clone();
                    ordered.append(&mut decl.flow_events);
                    decl.flow_events = ordered;
                }
                if let Some(fields) = decl.parent.and_then(|parent| fields_by_parent.get(&parent)) {
                    bonsai_lang_api::qualify_receiver_field_expression_flows(
                        &mut decl.flow_events,
                        fields,
                        "this",
                    );
                }
                if let Some(visibility) = access_by_span.get(&decl.span).copied() {
                    decl.visibility = visibility;
                }
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(bindings) = cast_aliases.get(&decl.span) {
                    decl.type_aliases.extend(bindings.iter().cloned());
                }
                collapse_cpp_same_type_copy_initializers(&mut decl.flow_events, &decl.type_aliases);
                // Repair catch-param bindings: the kit's generic
                // extractor picks the first identifier descendant of
                // the catch clause, which on C++ `catch (const T& e)`
                // is the type identifier rather than the binding.
                fix_cpp_catch_params(&mut decl.flow_events, &tree, src);
                // Bases only attach to class-shaped decls; skip
                // free functions, methods, vars, etc.
                if let Some(specs) = initializer_specs.get(&decl.span) {
                    for spec in specs {
                        let source_param_indices = decl
                            .params
                            .iter()
                            .enumerate()
                            .filter_map(|(idx, param)| {
                                spec.sources
                                    .iter()
                                    .any(|source| cpp_source_mentions_param(source, param))
                                    .then_some(idx)
                            })
                            .collect::<Vec<_>>();
                        if source_param_indices.is_empty() {
                            continue;
                        }
                        decl.receiver_field_writes.push(FieldWrite {
                            span: spec.span,
                            target: format!("this.{}", spec.field),
                            source_param_indices,
                        });
                    }
                    decl.receiver_field_writes
                        .sort_by_key(|write| (write.span.start, write.target.clone()));
                    decl.receiver_field_writes.dedup_by(|a, b| {
                        a.span == b.span
                            && a.target == b.target
                            && a.source_param_indices == b.source_param_indices
                    });
                }
                if !is_class_like(decl.kind) {
                    continue;
                }
                if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
            }
        }
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            let has_variadic_param = decl
                .params
                .iter()
                .any(|param| param == bonsai_lang_api::kit::SYNTHETIC_VARARGS_PARAM);
            bonsai_lang_api::kit::normalize_variadic_builtin_flow(
                &mut decl.flow_events,
                has_variadic_param,
                &["va_start", "__builtin_va_start"],
                &["va_arg", "__builtin_va_arg"],
            );
            apply_cpp_moved_argument_places(&mut decl.flow_events);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing follows constructor CST
        // nodes and declaration resolution, never identifier capitalization.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// C++ direct-list initialization with one value of the declared type is copy
/// construction, not positional aggregate initialization:
/// `Envelope valid{env}` carries the whole object. Tree-sitter deliberately
/// uses the same `initializer_list` node as `Envelope env{kind, cmd}`, so the
/// adapter resolves the distinction from its parsed declaration types before
/// shared aggregate lowering assigns positional field names.
fn collapse_cpp_same_type_copy_initializers(events: &mut Vec<FlowEvent>, aliases: &[TypeAliasBinding]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collapse_cpp_same_type_copy_initializers(then_events, aliases);
                collapse_cpp_same_type_copy_initializers(else_events, aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collapse_cpp_same_type_copy_initializers(body, aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collapse_cpp_same_type_copy_initializers(body, aliases);
                collapse_cpp_same_type_copy_initializers(catch_events, aliases);
                collapse_cpp_same_type_copy_initializers(finally_events, aliases);
            }
            _ => {}
        }
    }
    events.retain(|event| {
        let FlowEvent::AggregateAssign {
            target,
            type_name,
            value_flow,
            ..
        } = event
        else {
            return true;
        };
        if !value_flow.aggregate_fields.is_empty()
            || !value_flow.spreads.is_empty()
            || value_flow.tuple_items.len() != 1
        {
            return true;
        }
        let Some(source) = value_flow.tuple_items[0].place.as_deref() else {
            return true;
        };
        let declared_type = type_name.as_deref().or_else(|| {
            aliases
                .iter()
                .find(|alias| alias.name == *target)
                .map(|alias| alias.type_name.as_str())
        });
        let source_type = aliases
            .iter()
            .find(|alias| alias.name == source)
            .map(|alias| alias.type_name.as_str());
        let (Some(declared_type), Some(source_type)) = (declared_type, source_type) else {
            return true;
        };
        bonsai_lang_api::kit::canonical_simple_type_name(declared_type)
            != bonsai_lang_api::kit::canonical_simple_type_name(source_type)
    });
}

fn collect_cpp_constructor_initializer_events(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<FlowEvent>)> {
    let mut out = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let Some(initializers) = first_named_child_of_kind(&function, "field_initializer_list") else {
            continue;
        };
        let events = walk_flow_events(initializers, file, src, &HANDLER, &[]);
        if !events.is_empty() {
            out.push((span_of(file, &function), events));
        }
    }
    out
}

/// Preserve object identity through a parsed move expression nested inside a
/// larger call argument (`run(std::move(env))`). Lifecycle injection has
/// already classified the inner call from the adapter-owned C++ semantics;
/// this pass uses only that semantic event plus AST spans to mark the outer
/// argument as the same addressable place. The IDG can then forward exact
/// descendant fields without knowing any library function names.
fn apply_cpp_moved_argument_places(events: &mut [FlowEvent]) {
    let mut moved = Vec::new();
    collect_cpp_moved_events(events, &mut moved);
    apply_cpp_moved_argument_places_with_events(events, &moved);
}

fn collect_cpp_moved_events(events: &[FlowEvent], out: &mut Vec<(Span, String)>) {
    for event in events {
        match event {
            FlowEvent::Lifecycle {
                span,
                name,
                transition,
            } if transition == "moved" && !name.is_empty() => out.push((*span, name.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_cpp_moved_events(then_events, out);
                collect_cpp_moved_events(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_cpp_moved_events(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_cpp_moved_events(body, out);
                collect_cpp_moved_events(catch_events, out);
                collect_cpp_moved_events(finally_events, out);
            }
            _ => {}
        }
    }
}

fn apply_cpp_moved_argument_places_with_events(events: &mut [FlowEvent], moved: &[(Span, String)]) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    if arg.place.is_some() {
                        continue;
                    }
                    let candidate = moved.iter().find_map(|(span, name)| {
                        (arg.span.file == span.file
                            && arg.span.start <= span.start
                            && span.end <= arg.span.end
                            && arg.source_names.iter().any(|source| source == name))
                        .then_some(name)
                    });
                    if let Some(candidate) = candidate {
                        arg.place = Some(candidate.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_cpp_moved_argument_places_with_events(then_events, moved);
                apply_cpp_moved_argument_places_with_events(else_events, moved);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_cpp_moved_argument_places_with_events(body, moved);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_cpp_moved_argument_places_with_events(body, moved);
                apply_cpp_moved_argument_places_with_events(catch_events, moved);
                apply_cpp_moved_argument_places_with_events(finally_events, moved);
            }
            _ => {}
        }
    }
}

/// C++ constructors are identified by the grammar-owned class/member
/// relationship: a member whose identifier equals its parent class identifier
/// is a constructor.  This uses declaration identity emitted from the CST;
/// downstream resolution never guesses from capitalization or a name list.
fn mark_cpp_constructors(decl_index: &mut DeclIndex) {
    let class_names = decl_index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.symbol, decl.name.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    for decl in &mut decl_index.defs {
        if !matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
            continue;
        }
        let Some(parent_name) = decl.parent.and_then(|parent| class_names.get(&parent)) else {
            continue;
        };
        if decl.name == *parent_name {
            decl.kind = DeclKind::Constructor;
            if decl.implicit_receiver_names.is_empty() {
                decl.implicit_receiver_names.push("this".to_string());
            }
        }
    }
}

fn collect_cpp_class_fields(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String, Vec<String>)> {
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, &["class_specifier", "struct_specifier", "union_specifier"]) {
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "type_identifier"))
        else {
            continue;
        };
        let Some(body) = class_node.child_by_field_name("body") else {
            continue;
        };
        let mut fields = Vec::new();
        let mut body_cursor = body.walk();
        for field_decl in body
            .named_children(&mut body_cursor)
            .filter(|child| child.kind() == "field_declaration")
        {
            for child_index in 0..field_decl.child_count() {
                if field_decl.field_name_for_child(child_index as u32) != Some("declarator") {
                    continue;
                }
                let Some(child) = field_decl.child(child_index as u32) else {
                    continue;
                };
                if !child.is_named() || cpp_declarator_is_function(child) {
                    continue;
                }
                if let Some(identifier) = cpp_binding_identifier(child) {
                    let name = node_text(&identifier, src).trim();
                    if !name.is_empty() && !fields.iter().any(|field| field == name) {
                        fields.push(name.to_string());
                    }
                }
            }
        }
        if !fields.is_empty() {
            out.push((
                span_of(file, &class_node),
                node_text(&name_node, src).trim().to_string(),
                fields,
            ));
        }
    }
    out
}

fn cpp_declarator_is_function(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "function_declarator" {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn cpp_binding_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if matches!(node.kind(), "identifier" | "field_identifier") {
        return Some(node);
    }
    for field in ["declarator", "name"] {
        if let Some(child) = node.child_by_field_name(field) {
            if let Some(identifier) = cpp_binding_identifier(child) {
                return Some(identifier);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(identifier) = cpp_binding_identifier(child) {
            return Some(identifier);
        }
    }
    None
}

fn cpp_fields_by_parent_symbol(
    index: &DeclIndex,
    fields_by_class: &[(Span, String, Vec<String>)],
) -> std::collections::HashMap<bonsai_common::SymbolId, std::collections::HashSet<String>> {
    index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .filter_map(|decl| {
            fields_by_class
                .iter()
                .find(|(span, name, _)| *span == decl.span || *name == decl.name)
                .map(|(_, _, fields)| (decl.symbol, fields.iter().cloned().collect()))
        })
        .collect()
}

/// Collect every C++ function name that's TU-private:
///
/// - Function definitions with a `static` storage class specifier.
/// - Function definitions whose body lives inside an anonymous
///   `namespace { ... }` block (no namespace identifier).
fn collect_tu_private_function_names(
    file: FileId,
    ctx: &AdapterContext<'_>,
) -> std::collections::HashSet<String> {
    let mut private_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Bail conservatively on any I/O / parser failure.
    let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
        return private_names;
    };
    let src = snapshot.text.as_bytes();
    let root = tree.root_node();
    walk_for_tu_private(root, src, false, &mut private_names);
    private_names
}

#[derive(Clone, Debug)]
struct CppInitializerFieldSpec {
    span: Span,
    field: String,
    sources: Vec<String>,
}

fn collect_cpp_initializer_field_specs(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<CppInitializerFieldSpec>)> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_definition"]) {
        let Some(initializers) = first_named_child_of_kind(&fn_node, "field_initializer_list") else {
            continue;
        };
        let mut specs = Vec::new();
        let mut cursor = initializers.walk();
        for init in initializers.named_children(&mut cursor) {
            if init.kind() != "field_initializer" {
                continue;
            }
            let Some(field_node) = first_named_child_of_kind(&init, "field_identifier") else {
                continue;
            };
            let Some(value_node) = first_named_child_of_kind(&init, "argument_list") else {
                continue;
            };
            let field = node_text(&field_node, src).trim().to_string();
            let sources = expression_operand_names_with_handler(&value_node, src, &HANDLER);
            if field.is_empty() || sources.is_empty() {
                continue;
            }
            specs.push(CppInitializerFieldSpec {
                span: span_of(file, &init),
                field,
                sources,
            });
        }
        if !specs.is_empty() {
            out.push((span_of(file, &fn_node), specs));
        }
    }
    out
}

fn cpp_source_mentions_param(source: &str, param: &str) -> bool {
    let source = bonsai_common::normalize_qualified_name(source);
    let param = bonsai_common::normalize_qualified_name(param);
    source == param
        || source
            .strip_prefix(&param)
            .is_some_and(|projection| projection.starts_with('.'))
}

fn collect_cpp_member_visibility(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut out = std::collections::HashMap::new();
    for class_node in collect_kinds(tree, &["class_specifier", "struct_specifier"]) {
        let default_visibility = if class_node.kind() == "struct_specifier" {
            Visibility::Public
        } else {
            Visibility::Private
        };
        let mut current_visibility = default_visibility;
        if let Some(body) = class_node.child_by_field_name("body") {
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                if child.kind() == "access_specifier" {
                    current_visibility = cpp_access_visibility(node_text(&child, src), default_visibility);
                    continue;
                }
                if child.kind() == "function_definition" {
                    out.insert(span_of(file, &child), current_visibility);
                }
            }
        }
    }
    out
}

fn cpp_access_visibility(raw: &str, default_visibility: Visibility) -> Visibility {
    match raw.trim().trim_end_matches(':') {
        "public" => Visibility::Public,
        "protected" => Visibility::Protected,
        "private" => Visibility::Private,
        _ => default_visibility,
    }
}

/// Recursive walker tracking whether we're currently inside an
/// anonymous namespace; when we are, every nested function definition
/// counts as TU-private even without a `static` specifier.
fn walk_for_tu_private(
    root: Node<'_>,
    src: &[u8],
    inside_anonymous_ns: bool,
    private_names: &mut std::collections::HashSet<String>,
) {
    let mut stack = vec![(root, inside_anonymous_ns)];
    while let Some((node, inside_anonymous_ns)) = stack.pop() {
        if node.kind() == "function_definition"
            && (inside_anonymous_ns || function_has_static_specifier(&node, src))
        {
            if let Some(name) = function_name(&node, src) {
                private_names.insert(name);
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // An anonymous namespace child flips the flag for the
            // subtree; inner namespaces inherit privacy.
            let entering_anonymous = inside_anonymous_ns
                || (child.kind() == "namespace_definition" && !namespace_is_named(&child));
            stack.push((child, entering_anonymous));
        }
    }
}

/// True when a `namespace_definition` has any identifier — a missing
/// name means the namespace is anonymous (TU-local).
fn namespace_is_named(node: &Node<'_>) -> bool {
    if node.child_by_field_name("name").is_some() {
        return true;
    }
    let mut cursor = node.walk();
    let has_identifier = node
        .children(&mut cursor)
        .any(|child| child.kind() == "namespace_identifier" || child.kind() == "identifier");
    has_identifier
}

/// True when `node` (a `function_definition`) carries a `static`
/// storage-class specifier as a direct child.
fn function_has_static_specifier(node: &Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "storage_class_specifier" && node_text(&child, src) == "static" {
            return true;
        }
    }
    false
}

/// Resolve the bare function name from a `function_definition`'s
/// declarator chain. Falls through pointer / reference declarators.
fn function_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    extract_function_identifier(&declarator, src)
}

/// Recursively unwrap a declarator subtree until a leaf identifier
/// surfaces. Includes destructor / operator names so e.g. `~Foo` or
/// `operator==` still produce a name.
fn extract_function_identifier(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if matches!(
        node.kind(),
        "identifier" | "field_identifier" | "destructor_name" | "operator_name"
    ) {
        return Some(node_text(node, src).to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = extract_function_identifier(&child, src) {
            return Some(found);
        }
    }
    None
}

/// True for decl kinds that may carry a base list — only those need
/// `bases` populated.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk C++ class / struct specifiers and collect bare base type
/// names. Grammar shape (verified):
///
///   `class Echo : public Base, private Other { … };` →
///     (class_specifier name: (type_identifier)
///        (base_class_clause (access_specifier) (type_identifier)
///                           (access_specifier) (type_identifier))
///        body: (field_declaration_list))
///
/// Within `base_class_clause`, parents are listed as
/// `type_identifier` / `qualified_identifier` / `template_type`
/// nodes (alternating with `access_specifier` keywords). Generic /
/// qualified bases collapse to the bare tail.
fn collect_cpp_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_specifier", "struct_specifier", "union_specifier"];
    for class_node in collect_kinds(tree, class_kinds) {
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "type_identifier"))
            .or_else(|| first_named_child_of_kind(&class_node, "identifier"))
        else {
            continue;
        };
        let class_name = node_text(&name_node, src).trim();
        if class_name.is_empty() {
            continue;
        }
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for class_child in class_node.named_children(&mut class_cursor) {
            // Bases live exclusively under the `base_class_clause`
            // child; everything else (the body, attributes, etc.) is
            // skipped.
            if class_child.kind() != "base_class_clause" {
                continue;
            }
            let mut clause_cursor = class_child.walk();
            for clause_child in class_child.named_children(&mut clause_cursor) {
                match clause_child.kind() {
                    "type_identifier"
                    | "qualified_identifier"
                    | "template_type"
                    | "scoped_type_identifier" => {
                        if let Some(name) = canonical_cpp_base_name(node_text(&clause_child, src)) {
                            // Dedup so `class C : public Base, public Base` collapses.
                            if !bases.iter().any(|existing| existing == &name) {
                                bases.push(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), class_name.to_string(), bases));
        }
    }
    bases_by_class
}

/// WS2 cast typing for `auto`-LHS locals: `auto c = static_cast<Foo>(x)` and
/// `auto c = (Foo) x`. The kit's param-alias extractor already types the
/// declared-type form `Foo c = make()`, but NOT the inferred-`auto` form where
/// the class lives only on the cast initializer. Mirrors the Java/C#
/// `var c = (Foo) x` handling. Returns `(enclosing-fn span, binding)` pairs;
/// the fn span matches the function decl's `span` so the caller merges into
/// `decl.type_aliases`. Only fires when the declared type IS `auto`
/// (`placeholder_type_specifier`) — never clobbers a real declared type — and
/// reads the init_declarator's DIRECT `value` so a cast nested in a call
/// argument cannot mistype the local.
fn collect_cpp_cast_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, TypeAliasBinding)> {
    let mut out = Vec::new();
    for decl_node in collect_kinds(tree, &["declaration"]) {
        let Some(type_node) = decl_node.child_by_field_name("type") else {
            continue;
        };
        if type_node.kind() != "placeholder_type_specifier" {
            continue;
        }
        let Some(init) = first_named_child_of_kind(&decl_node, "init_declarator") else {
            continue;
        };
        let Some(decl_field) = init.child_by_field_name("declarator") else {
            continue;
        };
        let name_node = if decl_field.kind() == "identifier" {
            decl_field
        } else {
            match cpp_first_descendant_of_kind(&decl_field, "identifier") {
                Some(n) => n,
                None => continue,
            }
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let Some(value) = init.child_by_field_name("value") else {
            continue;
        };
        let Some(type_name) = cpp_cast_type_of_value(&value, src) else {
            continue;
        };
        let Some(fn_span) = cpp_enclosing_fn_span(&decl_node, file) else {
            continue;
        };
        out.push((fn_span, TypeAliasBinding { name, type_name }));
    }
    out
}

/// Cast target type of a direct initializer value, or `None` for any non-cast
/// shape. Handles C-style `(Foo) x` (`cast_expression`) and the `*_cast<Foo>(x)`
/// family (a `call_expression` whose `function` is a `template_function` named
/// `static_cast` / `reinterpret_cast` / `dynamic_cast` / `const_cast`).
fn cpp_cast_type_of_value(value: &Node<'_>, src: &[u8]) -> Option<String> {
    match value.kind() {
        "cast_expression" => {
            let type_node = value.child_by_field_name("type")?;
            cpp_type_descriptor_name(&type_node, src)
        }
        "call_expression" => {
            let func = value.child_by_field_name("function")?;
            if func.kind() != "template_function" {
                return None;
            }
            let name = func.child_by_field_name("name")?;
            if !matches!(
                node_text(&name, src).trim(),
                "static_cast" | "reinterpret_cast" | "dynamic_cast" | "const_cast"
            ) {
                return None;
            }
            let args = func.child_by_field_name("arguments")?;
            cpp_type_descriptor_name(&args, src)
        }
        _ => None,
    }
}

/// Bare tail name of the first `type_identifier` under a `type_descriptor` /
/// `template_argument_list` node (`ns::Foo<T>*` → `Foo`).
fn cpp_type_descriptor_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let ti = if node.kind() == "type_identifier" {
        *node
    } else {
        cpp_first_descendant_of_kind(node, "type_identifier")?
    };
    canonical_cpp_base_name(node_text(&ti, src))
}

/// First descendant found by an iterative syntax-tree walk, or `None`.
fn cpp_first_descendant_of_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            if child.kind() == kind {
                return Some(child);
            }
            stack.push(child);
        }
    }
    None
}

/// Span of the nearest enclosing `function_definition` (matches the function
/// decl's `span` so cast aliases merge into the right method's type_aliases).
fn cpp_enclosing_fn_span(node: &Node<'_>, file: FileId) -> Option<bonsai_common::Span> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if n.kind() == "function_definition" {
            return Some(span_of(file, &n));
        }
        cur = n.parent();
    }
    None
}

/// Reduce a base-class type expression to its bare tail identifier:
/// strip template arguments and namespace qualifiers so
/// `ns::Base<T>` → `Base`.
fn canonical_cpp_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let without_template = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let bare = without_template
        .rsplit("::")
        .next()
        .unwrap_or(without_template)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Translate `#include` directives and `using` declarations into
/// `ImportSpec`s. The two flavours produce indistinguishable
/// downstream lookups; `using namespace` is recorded as a wildcard import.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = c_family_preproc_imports(tree, src, file);
    // C-style preproc_include + C++ `using namespace X;` / `using X::Y;`.
    for using_node in collect_kinds(tree, &["using_declaration"]) {
        // The path is the declaration's single named child. The anonymous
        // `namespace` token distinguishes the wildcard form, so semantic
        // classification never depends on re-tokenizing statement text.
        //
        //   * `using namespace X::Y;` — wildcard import; brings every
        //     name in `X::Y` into scope, no single local binding.
        //   * `using X::Y::Z;`        — single-symbol import; binds
        //     `Z` locally to `X::Y::Z`.
        let is_wildcard_namespace = (0..using_node.child_count())
            .filter_map(|index| u32::try_from(index).ok())
            .any(|index| {
                using_node
                    .child(index)
                    .is_some_and(|child| child.kind() == "namespace")
            });
        let mut path_cursor = using_node.walk();
        let Some(path_node) = using_node
            .named_children(&mut path_cursor)
            .find(|child| matches!(child.kind(), "identifier" | "qualified_identifier"))
        else {
            continue;
        };
        let mut path_segments = cpp_import_path_segments(path_node, src);
        if path_segments.is_empty() {
            continue;
        }
        if is_wildcard_namespace {
            imports.push(ImportSpec {
                span: span_of(file, &using_node),
                module: path_segments.join("::"),
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Module,
            });
        } else if let Some(original_name) = path_segments.pop() {
            imports.push(ImportSpec {
                span: span_of(file, &using_node),
                module: path_segments.join("::"),
                alias: None,
                is_wildcard: false,
                original_name: Some(original_name),
                scope: ImportScope::Module,
            });
        }
    }
    // C++ `namespace h = util;` — explicit namespace alias. The
    // `name` field is the local alias (`h`); the `aliased` /
    // `value` field is the original namespace identifier (`util`).
    // Bind `h` as a `Namespace` target so `h::helper(...)` resolves
    // to `util::helper(...)`.
    for alias_node in collect_kinds(tree, &["namespace_alias_definition"]) {
        let alias_name_node = alias_node.child_by_field_name("name").or_else(|| {
            let mut cursor = alias_node.walk();
            let mut found = None;
            for child in alias_node.named_children(&mut cursor) {
                if matches!(child.kind(), "identifier" | "namespace_identifier") {
                    found = Some(child);
                    break;
                }
            }
            found
        });
        let module_name_node = alias_node
            .child_by_field_name("aliased")
            .or_else(|| alias_node.child_by_field_name("value"))
            .or_else(|| {
                let alias_name_node = alias_name_node?;
                let mut cursor = alias_node.walk();
                let target = alias_node.named_children(&mut cursor).find(|child| {
                    *child != alias_name_node
                        && matches!(
                            child.kind(),
                            "namespace_identifier" | "nested_namespace_specifier"
                        )
                });
                target
            });
        let (Some(alias_name_node), Some(module_name_node)) = (alias_name_node, module_name_node) else {
            continue;
        };
        let alias_name = node_text(&alias_name_node, src).trim().to_string();
        let module = node_text(&module_name_node, src).trim().to_string();
        if alias_name.is_empty() || module.is_empty() || alias_name == module {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &alias_node),
            module,
            alias: Some(alias_name),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn cpp_import_path_segments(path: Node<'_>, src: &[u8]) -> Vec<String> {
    if path.kind() == "qualified_identifier" {
        let mut segments = path
            .child_by_field_name("scope")
            .map(|scope| cpp_import_path_segments(scope, src))
            .unwrap_or_default();
        if let Some(name) = path.child_by_field_name("name") {
            segments.extend(cpp_import_path_segments(name, src));
        }
        return segments;
    }
    if path.kind() == "nested_namespace_specifier" {
        let mut segments = Vec::new();
        let mut cursor = path.walk();
        for child in path.named_children(&mut cursor) {
            segments.extend(cpp_import_path_segments(child, src));
        }
        return segments;
    }
    let segment = node_text(&path, src).trim();
    if segment.is_empty() {
        Vec::new()
    } else {
        vec![segment.to_string()]
    }
}

/// Repair `catch_param` on C++ `Try` events. The kit's generic
/// extractor returns the first identifier descendant of the catch
/// clause, which on `catch (const std::exception& e)` is the type
/// identifier rather than the binding. We re-extract the binding
/// from the parse tree via the standard `parameter_declaration` →
/// `declarator` → identifier chain.
fn fix_cpp_catch_params(events: &mut [bonsai_lang_api::FlowEvent], tree: &Tree, src: &[u8]) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if let Some(name) = cpp_catch_param_binding(node, src) {
                        *catch_param = Some(name);
                    }
                }
                fix_cpp_catch_params(body, tree, src);
                fix_cpp_catch_params(catch_events, tree, src);
                fix_cpp_catch_params(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                fix_cpp_catch_params(then_events, tree, src);
                fix_cpp_catch_params(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                fix_cpp_catch_params(body, tree, src);
            }
            _ => {}
        }
    }
}

fn cpp_catch_param_binding(try_node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut tcur = try_node.walk();
    for child in try_node.named_children(&mut tcur) {
        if child.kind() != "catch_clause" {
            continue;
        }
        // catch_clause > parameter_list > parameter_declaration > declarator > identifier.
        let mut ccur = child.walk();
        for sub in child.named_children(&mut ccur) {
            let target = if sub.kind() == "parameter_list" {
                let mut pcur = sub.walk();
                let mut found: Option<Node<'_>> = None;
                for c in sub.named_children(&mut pcur) {
                    if c.kind() == "parameter_declaration" {
                        found = Some(c);
                        break;
                    }
                }
                found
            } else if sub.kind() == "parameter_declaration" {
                Some(sub)
            } else {
                None
            };
            let Some(pdecl) = target else { continue };
            // The `declarator` field of `parameter_declaration` is the
            // binding. For `const T& e`, the declarator is a
            // reference_declarator → identifier. For bare `T e`, the
            // declarator is an identifier.
            let decl = pdecl.child_by_field_name("declarator");
            if let Some(decl) = decl {
                if let Some(ident) = first_identifier_descendant_cpp(decl) {
                    return Some(node_text(&ident, src).trim().to_string());
                }
            }
            // Fallback: trailing identifier among the named children.
            let mut pcur = pdecl.walk();
            let mut last_ident: Option<Node<'_>> = None;
            for n in pdecl.named_children(&mut pcur) {
                if let Some(found) = first_identifier_descendant_cpp(n) {
                    last_ident = Some(found);
                }
            }
            if let Some(n) = last_ident {
                return Some(node_text(&n, src).trim().to_string());
            }
        }
    }
    None
}

fn first_identifier_descendant_cpp<'a>(node: Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "identifier" || node.kind() == "field_identifier" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_identifier_descendant_cpp(child) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod import_tests {
    use super::*;

    fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
        let language = language_from_pack(PACK_NAME).expect("cpp grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set cpp grammar");
        let tree = parser.parse(src.as_bytes(), None).expect("parse cpp source");
        parse_imports(&tree, src.as_bytes(), FileId::new(0))
    }

    #[test]
    fn using_declarations_are_lowered_from_cst_nodes() {
        let imports = parse_import_specs(
            "using /* trivia */ namespace alpha::beta;\n\
             using alpha::beta::Thing;\n\
             namespace short_name = alpha::beta;\n",
        );

        assert!(imports
            .iter()
            .any(|spec| spec.module == "alpha::beta" && spec.is_wildcard));
        assert!(imports.iter().any(|spec| {
            spec.module == "alpha::beta"
                && spec.alias.is_none()
                && spec.original_name.as_deref() == Some("Thing")
        }));
        assert!(imports.iter().any(|spec| {
            spec.module == "alpha::beta"
                && spec.alias.as_deref() == Some("short_name")
                && spec.original_name.is_none()
        }));
    }
}
