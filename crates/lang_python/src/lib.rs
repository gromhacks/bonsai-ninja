//! Python language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        call_arg_from_nodes_with_handler, collect_kinds, language_from_pack, node_text,
        normalize_call_name_whitespace, parse_with, span_of,
    },
    AdapterContext, AdapterError, AssignmentValueIndex, CallArg, CallKind, CharacterClass,
    CharacterConstraintDomain, CharacterConstraintFact, CharacterConstraintOutput,
    CharacterSubstitutionDomain, CharacterSubstitutionFact, ConditionEquality, ConditionExpressionFact,
    ConditionOperandFact, DeclIndex, DeclKind, FiniteLiteralSelectionFact, FlowEvent, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    SameOriginPathConstraintFact, StaticScalarValue, StaticStringMapEntry, StringCompositionFact,
    StringCompositionPart, TypeAliasBinding, Visibility, EMPTY_HANDLER,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("python");
const PACK_NAME: &str = "python";

/// Python lifecycle transitions: file/socket/lock/task closure forms.
const PYTHON_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
    bonsai_lang_api::LifecycleTransition {
        call_match: "close",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "shutdown",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "cancel",
        transition: "cancelled",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "release",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "destroy",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "os.close",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "os.unlink",
        transition: "freed",
        arg_index: 0,
    },
];

const HANDLER: GrammarHandler = GrammarHandler {
    nested_type_ownership: true,
    fn_kinds: &["function_definition"],
    class_kinds: &["class_definition"],
    class_decl_kinds: &[("class_definition", DeclKind::Class)],
    method_kinds: &[],
    method_context_kinds: &["class_definition"],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: &["__init__"],
    if_kinds: &[
        "if_statement",
        "conditional_expression",
        "match_statement",
        "elif_clause",
    ],
    for_kinds: &["for_statement"],
    foreach_kinds: &[],
    while_kinds: &["while_statement"],
    do_kinds: &[],
    loop_kinds: &[],
    call_kinds: &["call"],
    nested_call_component_kinds: &[],
    pseudo_call_extractor: None,
    syntax_event_extractor: None,
    pseudo_call_receiver_extractor: None,
    argument_passing_mode_extractor: None,
    assignment_kinds: &["assignment", "augmented_assignment", "named_expression"],
    return_kinds: &["return_statement"],
    throw_kinds: &["raise_statement"],
    lambda_kinds: &["lambda"],
    try_kinds: &["try_statement"],
    catch_kinds: &["except_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    yield_kinds: &["yield"],
    await_kinds: &["await"],
    defer_kinds: &[],
    using_kinds: &["with_statement"],
    special_forms: &[],
    runtime_type_guard_calls: &["isinstance"],
    runtime_type_guard_operators: &[],
    runtime_typeof_operators: &[],
    runtime_type_equality_operators: &[],
    value_free_expression_kinds: &[],
    value_free_call_names: &[],
    value_free_unary_operators: &[],
    call_ref_kinds: &["call"],
    member_expression_kinds: &["attribute"],
    subscript_expression_kinds: &["subscript"],
    sigil_variable_kinds: &[],
    global_variable_kinds: &[],
    subscript_base_call_refs: true,
    non_call_ref_names: &[],
    synthetic_call_ref_names: &[],
    call_name_suffix_tokens: &[],
    syntax_error_tolerant_call_names: &[],
    callable_reference_kinds: &[],
    callable_reference_extractor: None,
    method_receiver_param_index: Some(0),
    // `self` for ordinary instance methods; `super` so `super().foo()`
    // and `super(Class, self).foo()` resolve to the parent class's
    // `foo` via the engine's `resolve_super_method_candidates`. The adapter
    // normalizes these call receivers to the two forms declared below.
    implicit_receiver_names: &["self", "super"],
    implicit_receiver_prefixes: EMPTY_HANDLER.implicit_receiver_prefixes,
    tail_expression_returns: EMPTY_HANDLER.tail_expression_returns,
    void_return_type_names: EMPTY_HANDLER.void_return_type_names,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct PythonAdapter;

impl PythonAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for PythonAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Python"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["py", "pyi"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Reflection: the adapter rewrites the constant-string forms
        // of `getattr` / `setattr` / `hasattr` into attribute calls
        // before the engine sees them (see
        // `rewrite_python_constant_reflection`). Dynamic forms with a
        // computed name remain unrewritten and rules anchored on the
        // reflective shape are still rejected at rulepack load time.
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["Any", "object"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            reflection: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            // Static attribute/subscript projections are exact, but Python
            // still has dynamic subscripts and reflective projections whose
            // selected field is unknowable from syntax alone. Keep the
            // workspace field universe open for those aggregate reads.
            field_places_complete: false,
            constructor_method_names: &["__init__"],
            bare_call_constructor_syntax: true,
            super_receiver_tokens: &["super", "super()"],
            // Python's receiver is the adapter-proven first method parameter;
            // `self` is a convention, not an implicit grammar token.
            implicit_receiver_tokens: &[],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax {
                wrapper_calls: &["type"],
                class_object_suffixes: &[".__class__"],
            },
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Python module path: the dotted module name derived from the
        // file path. e.g. `pkg/sub/foo.py` -> ["pkg", "sub", "foo"].
        // Falls back to file-stem if the path isn't usable.
        // Workspace-relative path → dotted module path. Adapters
        // without a workspace root (unit tests) fall through to
        // file-stem-only via the helper below.
        let segments: Vec<String> = ctx
            .workspace_relative_path(file)
            .and_then(|path| {
                let stem = path.file_stem()?.to_string_lossy().into_owned();
                let mut segs: Vec<String> = path
                    .parent()?
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect();
                segs.push(stem);
                Some(segs)
            })
            .unwrap_or_default();
        if segments.is_empty() {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        } else {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        }
        // Python privacy is convention-based but the `__name` (dunder)
        // form triggers actual name-mangling at runtime, so the
        // resolver should treat it as truly Private. Single-underscore
        // `_name` is convention only — keep `Public`.
        for decl in &mut idx.defs {
            if decl.name.starts_with("__") && !decl.name.ends_with("__") {
                decl.visibility = Visibility::Private;
            }
        }
        // `__all__ = ["foo", "bar"]` (or the tuple form) declares the
        // names exported by `from module import *` ONLY. It is NOT a
        // visibility boundary: `from module import run_query` and
        // `import module; module.run_query(x)` are legal for names
        // absent from `__all__`. Downgrading unlisted top-level decls
        // to `Visibility::Module` made the resolver drop every
        // cross-module flow through an internal helper (the common
        // "public API in __all__, sink-bearing helpers omitted" idiom),
        // a soundness false-negative. We therefore keep such decls
        // `Public` and let the `__name` -> Private dunder rule above be
        // the only visibility filter. Precise wildcard-import narrowing
        // (consult `__all__` only on the `from module import *` path)
        // belongs in the resolver as a separate exported-names fact.
        // Per-decl `type_aliases`: walk the tree and record
        // `param: Type` annotations plus FastAPI-style binder
        // markers (`param: T = Body(...)` / `Depends(...)` /
        // `Query(...)` / `Header(...)` / `Cookie(...)` /
        // `Form(...)` / `File(...)` / `Path(...)`). The matcher
        // consults `Decl.type_aliases` when resolving
        // `attribute: [Type, method]` rules, so this lets
        // `[UploadFile, filename]` and similar receiver-typed sink
        // and source rules fire on Python code per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            populate_python_condition_expressions(&mut idx, &tree, file, src);
            idx.string_compositions = python_string_compositions(&tree, file, src);
            idx.finite_literal_selections = python_finite_literal_selections(&idx, &tree, file, src);
            idx.character_substitutions = python_character_substitutions(&idx, &tree, file, src);
            idx.character_constraints = python_character_constraints(&idx, &tree, file, src);
            idx.same_origin_path_constraints = python_same_origin_path_constraints(&idx, &tree, file, src);
            // Phase-6 return-type extraction: `def f() -> T:` populates
            // `Decl.return_type`, which `apply_assign_call_result_types`
            // then propagates onto LHS type_aliases.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            let aliases_by_span = collect_python_method_type_aliases(&tree, file, src);
            let param_binders_by_span = collect_python_param_binder_annotations(&tree, file, src);
            for decl in &mut idx.defs {
                if let Some(aliases) = aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
                {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(binders) = param_binders_by_span
                    .iter()
                    .find_map(|(span, binders)| (*span == decl.span).then_some(binders))
                {
                    merge_python_param_binder_annotations(decl, binders);
                }
            }
            // Per-class `bases`: `class C(Base, Mixin):` →
            // ["Base", "Mixin"]. Lets `kind: param` rules require
            // an ancestor type (`in_class: [WebSocketHandler]`
            // matching a user `class Echo(WebSocketHandler):`).
            let bases_by_span = collect_python_class_bases(&tree, file, src);
            for decl in &mut idx.defs {
                if !matches!(decl.kind, bonsai_lang_api::DeclKind::Class) {
                    continue;
                }
                if let Some(bases) = bases_by_span
                    .iter()
                    .find_map(|(span, bases)| (*span == decl.span).then_some(bases))
                {
                    decl.bases = bases.clone();
                }
            }
            let match_pattern_bindings = collect_python_match_pattern_bindings(&tree, file, src);
            let iterable_yield_bindings = collect_python_iterable_yield_bindings(&tree, file, src);
            let property_fn_spans = collect_python_property_function_spans(&tree, file, src);
            let property_aliases = collect_python_property_aliases(&idx, &property_fn_spans);
            let property_aliases_by_decl = python_property_aliases_by_decl(&idx, &property_aliases);
            let assignment_values = AssignmentValueIndex::new(&idx.assignment_values);
            let assignment_projected_reads = collect_python_assignment_projected_reads(&tree, file, src);
            let call_argument_places = collect_python_call_argument_places(&tree, file, src);
            let return_places = collect_python_return_places(&tree, file, src);
            let callable_spans: Vec<Span> = idx
                .defs
                .iter()
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        bonsai_lang_api::DeclKind::Function
                            | bonsai_lang_api::DeclKind::Method
                            | bonsai_lang_api::DeclKind::Constructor
                    )
                })
                .map(|decl| decl.span)
                .collect();
            for decl in &mut idx.defs {
                let owned_match_patterns: Vec<PythonMatchPatternBindings> = match_pattern_bindings
                    .iter()
                    .filter(|pattern| python_match_pattern_owned_by_decl(pattern, decl.span, &callable_spans))
                    .cloned()
                    .collect();
                let owned_yield_bindings = iterable_yield_bindings
                    .iter()
                    .filter(|event| {
                        python_span_owned_by_decl(python_flow_event_span(event), decl.span, &callable_spans)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let comprehension_iterable_calls =
                    collect_python_comprehension_iterable_call_events(&tree, file, src, decl.span);
                augment_python_match_pattern_flow_events(&mut decl.flow_events, &owned_match_patterns);
                augment_python_comprehension_flow_events(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                    &assignment_values,
                );
                insert_python_flow_events_by_span(
                    &mut decl.flow_events,
                    decl.span,
                    &comprehension_iterable_calls,
                );
                insert_python_iterable_yield_bindings(&mut decl.flow_events, &owned_yield_bindings);
                augment_python_dict_flow_events(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                    &assignment_values,
                    &assignment_projected_reads,
                );
                if let Some(property_aliases_for_decl) = property_aliases_by_decl.get(&decl.symbol) {
                    augment_python_property_flow_events(&mut decl.flow_events, property_aliases_for_decl);
                }
                rewrite_python_constant_reflection(&mut decl.flow_events);
                rewrite_python_generator_send(&mut decl.flow_events);
                augment_python_asyncio_to_thread_calls(&mut decl.flow_events);
                apply_python_call_argument_places(&mut decl.flow_events, &call_argument_places);
                apply_python_return_places(&mut decl.flow_events, &return_places);
            }
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut idx,
                &tree,
                file,
                src,
                &HANDLER,
                python_static_scalar,
            );
        }
        // Append `FlowEvent::Lifecycle` for recognised Python
        // resource transitions (`f.close()`, `task.cancel()`,
        // `lock.release()`, `cm.__exit__`).
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, PYTHON_LIFECYCLE_TRANSITIONS);
        }
        // Precompute `self.<field> → Type` bindings from each class's
        // constructor `receiver_field_writes` so receiver-typed
        // dispatch through stable instance state is an O(1) lookup
        // against the method's `type_aliases` instead of a per-call
        // walk over sibling decls.
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Lower Python's boolean-expression grammar into the shared semantic
/// condition IR. Operator spellings are consumed here, in the language
/// frontend; security and dataflow analyses only see `Any`/`All`/`Not`,
/// equality, membership, and exact syntax spans.
fn populate_python_condition_expressions(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for branch in collect_kinds(tree, &["if_statement", "elif_clause"]) {
        let branch_span = span_of(file, &branch);
        let Some(condition) = branch.child_by_field_name("condition") else {
            continue;
        };
        let Some(fact) = index
            .branch_conditions
            .iter_mut()
            .find(|fact| fact.branch_span == branch_span)
        else {
            continue;
        };
        fact.expression = Some(lower_python_condition_expression(condition, file, src));
    }
}

fn lower_python_condition_expression(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionExpressionFact {
    if matches!(
        node.kind(),
        "parenthesized_expression" | "parenthesized_expression_list"
    ) {
        if let Some(inner) = node.named_child(0) {
            return lower_python_condition_expression(inner, file, src);
        }
    }

    let span = span_of(file, &node);
    if node.kind() == "not_operator" {
        if let Some(operand) = node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("operand"))
            .or_else(|| node.named_child(0))
        {
            return ConditionExpressionFact::Not {
                span,
                operand: Box::new(lower_python_condition_expression(operand, file, src)),
            };
        }
    }

    if node.kind() == "boolean_operator" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            match operator {
                Some("or") => {
                    return merge_python_condition_junction(
                        span,
                        lower_python_condition_expression(left, file, src),
                        lower_python_condition_expression(right, file, src),
                        false,
                    );
                }
                Some("and") => {
                    return merge_python_condition_junction(
                        span,
                        lower_python_condition_expression(left, file, src),
                        lower_python_condition_expression(right, file, src),
                        true,
                    );
                }
                _ => {}
            }
        }
    }

    if node.kind() == "comparison_operator" && node.named_child_count() == 2 {
        if let (Some(left), Some(right)) = (node.named_child(0), node.named_child(1)) {
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            match operator {
                Some("==" | "!=") => {
                    return ConditionExpressionFact::Equality {
                        span,
                        relation: if operator == Some("==") {
                            ConditionEquality::Equal
                        } else {
                            ConditionEquality::NotEqual
                        },
                        left: python_condition_operand(left, file, src),
                        right: python_condition_operand(right, file, src),
                    };
                }
                Some("in" | "not in") => {
                    return ConditionExpressionFact::Membership {
                        span,
                        subject: python_condition_operand(left, file, src),
                        collection: python_condition_operand(right, file, src),
                        then_contains: operator == Some("in"),
                    };
                }
                _ => {}
            }
        }
    }

    if node.kind() == "call" {
        let function = node.child_by_field_name("function");
        let arguments = node.child_by_field_name("arguments");
        if let (Some(function), Some(arguments)) = (function, arguments) {
            let mut cursor = arguments.walk();
            let values: Vec<_> = arguments.named_children(&mut cursor).collect();
            if function.kind() == "identifier"
                && node_text(&function, src).trim() == "isinstance"
                && values.len() == 2
                && matches!(
                    values[1].kind(),
                    "identifier" | "type" | "attribute" | "generic_type"
                )
            {
                let type_name = node_text(&values[1], src).trim().to_string();
                if !type_name.is_empty() {
                    return ConditionExpressionFact::TypeTest {
                        span,
                        subject: python_condition_operand(values[0], file, src),
                        type_name,
                    };
                }
            }
        }
    }

    if matches!(node.kind(), "identifier" | "attribute" | "subscript") {
        return ConditionExpressionFact::Truthy {
            span,
            operand: python_condition_operand(node, file, src),
        };
    }

    ConditionExpressionFact::Atom { span }
}

fn merge_python_condition_junction(
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

fn python_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    let value_node = python_condition_dynamic_value_node(node, src);
    ConditionOperandFact {
        span: span_of(file, &node),
        value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(
            value_node, file, src, &HANDLER,
        ),
        static_string: python_static_string(node, src),
        static_value: python_static_scalar(node, src),
    }
}

/// Preserve the exact dynamic operand of Python's common falsey-fallback
/// expression (`value or <static>`). The complete operand span remains on the
/// condition fact, while value-flow points at the Tree-sitter node whose
/// runtime value is being constrained. This is language semantics, not a
/// security classification.
fn python_condition_dynamic_value_node<'tree>(mut node: Node<'tree>, src: &[u8]) -> Node<'tree> {
    loop {
        if matches!(
            node.kind(),
            "parenthesized_expression" | "parenthesized_expression_list"
        ) {
            if let Some(inner) = node.named_child(0) {
                node = inner;
                continue;
            }
        }
        if node.kind() == "boolean_operator" {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                let operator = src
                    .get(left.end_byte()..right.start_byte())
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .map(str::trim);
                if operator == Some("or") && python_static_scalar(right, src).is_some() {
                    node = left;
                    continue;
                }
            }
        }
        return node;
    }
}

fn python_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "none" => Some(StaticScalarValue::Null),
        "string" => Some(StaticScalarValue::String(python_static_string(node, src)?)),
        _ => None,
    }
}

fn python_static_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let text = node_text(&node, src).trim();
    let quote_start = text.find(['\'', '"'])?;
    let prefix = text.get(..quote_start)?.to_ascii_lowercase();
    if prefix.contains('f') || prefix.contains('b') || prefix.chars().any(|ch| !matches!(ch, 'r' | 'u')) {
        return None;
    }
    let quoted = text.get(quote_start..)?;
    let delimiter = if quoted.starts_with("'''") {
        "'''"
    } else if quoted.starts_with("\"\"\"") {
        "\"\"\""
    } else if quoted.starts_with('\'') {
        "'"
    } else if quoted.starts_with('"') {
        "\""
    } else {
        return None;
    };
    let inner = quoted.strip_prefix(delimiter)?.strip_suffix(delimiter)?;
    if prefix.contains('r') {
        return Some(inner.to_string());
    }
    let mut decoded = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        decoded.push(match characters.next()? {
            'r' => '\r',
            'n' => '\n',
            't' => '\t',
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            'x' => {
                let digits = [characters.next()?, characters.next()?];
                let value = u8::from_str_radix(&digits.iter().collect::<String>(), 16).ok()?;
                char::from(value)
            }
            _ => return None,
        });
    }
    Some(decoded)
}

fn python_character_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterConstraintFact> {
    let mut facts = python_comprehension_character_constraints(index, tree, file, src);
    facts.extend(python_regex_substitution_constraints(index, tree, file, src));
    facts.extend(python_regex_validation_constraints(index, tree, file, src));
    facts.sort_by_key(|fact| (fact.transform_span.start, fact.transform_span.end));
    facts.dedup_by_key(|fact| fact.transform_span);
    facts
}

fn python_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<FiniteLiteralSelectionFact> {
    let assignments = collect_kinds(tree, &["assignment"]);
    let mut finite_maps = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" || !python_finite_static_map(value, src) {
            continue;
        }
        let name = node_text(&target, src).trim().to_string();
        let owner = python_lexical_owner(index, span_of(file, assignment));
        let writes = assignments
            .iter()
            .filter(|candidate| {
                candidate
                    .child_by_field_name("left")
                    .is_some_and(|left| left.kind() == "identifier" && node_text(&left, src).trim() == name)
            })
            .count();
        let projected_write = assignments.iter().any(|candidate| {
            candidate.child_by_field_name("left").is_some_and(|left| {
                left.kind() == "subscript"
                    && left.child_by_field_name("value").is_some_and(|base| {
                        base.kind() == "identifier" && node_text(&base, src).trim() == name
                    })
            })
        });
        let aliases_or_mutations = collect_kinds(tree, &["assignment", "augmented_assignment", "call"])
            .into_iter()
            .any(|candidate| python_map_binding_may_escape_or_mutate(candidate, &name, assignment.id(), src))
            || python_map_binding_has_unsafe_use(tree, &name, assignment.id(), src);
        if writes == 1 && !projected_write && !aliases_or_mutations {
            finite_maps.push((name, assignment.end_byte(), owner));
        }
    }

    let mut facts = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" || value.kind() != "conditional_expression" {
            continue;
        }
        let mut cursor = value.walk();
        let operands: Vec<_> = value.named_children(&mut cursor).collect();
        let [selected, condition, fallback] = operands.as_slice() else {
            continue;
        };
        if !python_positive_finite_membership(*condition, *selected, src)
            || !python_finite_membership_literal(*fallback, src)
        {
            continue;
        }
        facts.push(FiniteLiteralSelectionFact {
            selection_span: span_of(file, &value),
            assignment_span: Some(span_of(file, assignment)),
            target: Some(node_text(&target, src).trim().to_string()),
            call_span: None,
            argument_index: None,
        });
    }
    for call in collect_kinds(tree, &["call"]) {
        let Some((function, _)) = python_call_parts(call) else {
            continue;
        };
        let Some((receiver, method)) = python_attribute_parts(function, src) else {
            continue;
        };
        if method != "get" || receiver.kind() != "identifier" {
            continue;
        }
        let map_name = node_text(&receiver, src).trim();
        let selection_span = span_of(file, &call);
        let owner = python_lexical_owner(index, selection_span);
        let parameter_shadows_module = owner.is_some_and(|owner| {
            index
                .defs
                .iter()
                .find(|decl| decl.span == owner)
                .is_some_and(|decl| decl.params.iter().any(|parameter| parameter == map_name))
        });
        let finite_match = finite_maps.iter().any(|(name, declaration_end, binding_owner)| {
            name == map_name
                && *declaration_end <= call.start_byte()
                && (*binding_owner == owner || (binding_owner.is_none() && !parameter_shadows_module))
        });
        if !finite_match {
            continue;
        }
        let Some(assignment) = index
            .assignment_values
            .iter()
            .filter(|fact| {
                fact.target.is_some()
                    && fact.value_span.start <= selection_span.start
                    && selection_span.end <= fact.value_span.end
            })
            .min_by_key(|fact| fact.value_span.len())
        else {
            continue;
        };
        facts.push(FiniteLiteralSelectionFact {
            selection_span,
            assignment_span: Some(assignment.assignment_span),
            target: assignment.target.clone(),
            call_span: None,
            argument_index: None,
        });
    }
    facts.sort_by_key(|fact| {
        let span = fact.assignment_span.unwrap_or(fact.selection_span);
        (span.start, span.end, fact.selection_span.start)
    });
    facts.dedup();
    facts
}

/// `selected if selected in {<finite literals>} else <literal>` can only
/// produce one of the literals named by the syntax. This is Python runtime
/// semantics owned by the adapter; whether that finite selection sanitizes a
/// sink remains rulepack policy.
fn python_positive_finite_membership(condition: Node<'_>, selected: Node<'_>, src: &[u8]) -> bool {
    if condition.kind() != "comparison_operator" || selected.kind() != "identifier" {
        return false;
    }
    let mut cursor = condition.walk();
    let operands: Vec<_> = condition.named_children(&mut cursor).collect();
    let [subject, collection] = operands.as_slice() else {
        return false;
    };
    if subject.kind() != "identifier"
        || node_text(subject, src).trim() != node_text(&selected, src).trim()
        || !matches!(collection.kind(), "set" | "list" | "tuple")
    {
        return false;
    }
    let operator = src
        .get(subject.end_byte()..collection.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    if operator != Some("in") {
        return false;
    }
    let mut collection_cursor = collection.walk();
    let values: Vec<_> = collection.named_children(&mut collection_cursor).collect();
    !values.is_empty()
        && values
            .into_iter()
            .all(|value| python_finite_membership_literal(value, src))
}

fn python_finite_membership_literal(node: Node<'_>, src: &[u8]) -> bool {
    match node.kind() {
        "string" => python_static_string(node, src).is_some(),
        "integer" | "float" | "true" | "false" | "none" => true,
        _ => false,
    }
}

fn python_character_substitutions(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterSubstitutionFact> {
    let assignments = collect_kinds(tree, &["assignment"]);
    let mut tables = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let Some(entries) = python_static_string_map(value, src) else {
            continue;
        };
        let name = node_text(&target, src).trim().to_string();
        let writes = assignments
            .iter()
            .filter(|candidate| {
                candidate
                    .child_by_field_name("left")
                    .is_some_and(|left| left.kind() == "identifier" && node_text(&left, src).trim() == name)
            })
            .count();
        let projected_write = assignments.iter().any(|candidate| {
            candidate.child_by_field_name("left").is_some_and(|left| {
                left.kind() == "subscript"
                    && left.child_by_field_name("value").is_some_and(|base| {
                        base.kind() == "identifier" && node_text(&base, src).trim() == name
                    })
            })
        });
        let aliases_or_mutations = collect_kinds(tree, &["assignment", "augmented_assignment", "call"])
            .into_iter()
            .any(|candidate| python_map_binding_may_escape_or_mutate(candidate, &name, assignment.id(), src))
            || python_map_binding_has_unsafe_use(tree, &name, assignment.id(), src);
        if writes == 1 && !projected_write && !aliases_or_mutations {
            tables.push((
                name,
                assignment.end_byte(),
                python_lexical_owner(index, span_of(file, assignment)),
                entries,
            ));
        }
    }

    let mut facts = Vec::new();
    for return_node in collect_kinds(tree, &["return_statement"]) {
        let Some(returned) = return_node.named_child(0) else {
            continue;
        };
        let Some((join_function, join_arguments)) = python_call_parts(returned) else {
            continue;
        };
        let Some((join_receiver, join_method)) = python_attribute_parts(join_function, src) else {
            continue;
        };
        if join_method != "join" || python_static_string(join_receiver, src).as_deref() != Some("") {
            continue;
        }
        let generator = if join_arguments.kind() == "generator_expression" {
            join_arguments
        } else {
            let arguments = python_argument_nodes(join_arguments);
            let [generator] = arguments.as_slice() else {
                continue;
            };
            *generator
        };
        let Some((table, input_place)) = python_static_map_substitution_generator(generator, src) else {
            continue;
        };
        let transform_span = span_of(file, &return_node);
        let Some(decl) = python_enclosing_callable(index, transform_span) else {
            continue;
        };
        if !python_is_single_statement_return(return_node) {
            continue;
        }
        let Some(input_param_index) = decl.params.iter().position(|parameter| parameter == &input_place)
        else {
            continue;
        };
        let owner = python_lexical_owner(index, transform_span);
        let Some((_, _, _, exact_mappings)) =
            tables.iter().find(|(name, declaration_end, binding_owner, _)| {
                name == &table
                    && *declaration_end <= return_node.start_byte()
                    && (*binding_owner == owner || binding_owner.is_none())
            })
        else {
            continue;
        };
        facts.push(CharacterSubstitutionFact {
            function_span: decl.span,
            transform_span,
            input_param_index,
            exact_mappings: exact_mappings.clone(),
            table,
            domain: CharacterSubstitutionDomain::TableKeysWithIdentityFallback,
        });
    }
    facts.sort_by_key(|fact| (fact.transform_span.start, fact.transform_span.end));
    facts.dedup_by_key(|fact| fact.transform_span);
    facts
}

fn python_static_string_map(node: Node<'_>, src: &[u8]) -> Option<Vec<StaticStringMapEntry>> {
    if node.kind() != "dictionary" || node.named_child_count() == 0 {
        return None;
    }
    let mut entries = Vec::new();
    let mut cursor = node.walk();
    for entry in node.named_children(&mut cursor) {
        if entry.kind() != "pair" {
            return None;
        }
        let key = entry
            .child_by_field_name("key")
            .and_then(|key| python_static_string(key, src))?;
        let value = entry
            .child_by_field_name("value")
            .and_then(|value| python_static_string(value, src))?;
        entries.push(StaticStringMapEntry { key, value });
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    entries.dedup_by(|left, right| left.key == right.key && left.value == right.value);
    Some(entries)
}

fn python_static_map_substitution_generator(generator: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    if generator.kind() != "generator_expression" {
        return None;
    }
    let body = generator.named_child(0)?;
    let (function, arguments) = python_call_parts(body)?;
    let (receiver, method) = python_attribute_parts(function, src)?;
    if receiver.kind() != "identifier" || method != "get" {
        return None;
    }
    let table = node_text(&receiver, src).trim().to_string();
    let lookup_arguments = python_argument_nodes(arguments);
    let [key, fallback] = lookup_arguments.as_slice() else {
        return None;
    };
    if key.kind() != "identifier" || fallback.kind() != "identifier" {
        return None;
    }
    let loop_variable = node_text(key, src).trim().to_string();
    if node_text(fallback, src).trim() != loop_variable {
        return None;
    }
    let mut cursor = generator.walk();
    let clauses = generator.named_children(&mut cursor).skip(1).collect::<Vec<_>>();
    let [for_clause] = clauses.as_slice() else {
        return None;
    };
    if for_clause.kind() != "for_in_clause" {
        return None;
    }
    let left = for_clause
        .child_by_field_name("left")
        .or_else(|| for_clause.named_child(0))?;
    let right = for_clause
        .child_by_field_name("right")
        .or_else(|| for_clause.named_child(1))?;
    if left.kind() != "identifier" || node_text(&left, src).trim() != loop_variable {
        return None;
    }
    let input_place = python_identity_fallback_input(right, src)?;
    Some((table, input_place))
}

fn python_identity_fallback_input(mut node: Node<'_>, src: &[u8]) -> Option<String> {
    while node.kind() == "parenthesized_expression" {
        node = node.named_child(0)?;
    }
    if node.kind() == "identifier" {
        return Some(node_text(&node, src).trim().to_string());
    }
    if node.kind() != "boolean_operator" {
        return None;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return None;
    };
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    (operator == Some("or")
        && left.kind() == "identifier"
        && python_static_string(right, src).as_deref() == Some(""))
    .then(|| node_text(&left, src).trim().to_string())
}

fn python_lexical_owner(index: &DeclIndex, span: bonsai_common::Span) -> Option<bonsai_common::Span> {
    index
        .defs
        .iter()
        .filter(|decl| {
            decl.name != "__module__"
                && matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor | DeclKind::Class
                )
                && decl.span.start <= span.start
                && span.end <= decl.span.end
        })
        .min_by_key(|decl| decl.span.len())
        .map(|decl| decl.span)
}

fn python_map_binding_may_escape_or_mutate(
    node: Node<'_>,
    map_name: &str,
    declaration_id: usize,
    src: &[u8],
) -> bool {
    if node.id() == declaration_id {
        return false;
    }
    match node.kind() {
        "assignment" | "augmented_assignment" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            left.is_some_and(|left| {
                (left.kind() == "identifier" && node_text(&left, src).trim() == map_name)
                    || (left.kind() == "subscript"
                        && left.child_by_field_name("value").is_some_and(|base| {
                            base.kind() == "identifier" && node_text(&base, src).trim() == map_name
                        }))
            }) || right.is_some_and(|right| {
                right.kind() == "identifier" && node_text(&right, src).trim() == map_name
            })
        }
        "call" => {
            let Some((function, _)) = python_call_parts(node) else {
                return false;
            };
            python_attribute_parts(function, src).is_some_and(|(receiver, method)| {
                receiver.kind() == "identifier"
                    && node_text(&receiver, src).trim() == map_name
                    && method != "get"
            })
        }
        _ => false,
    }
}

fn python_map_binding_has_unsafe_use(tree: &Tree, map_name: &str, declaration_id: usize, src: &[u8]) -> bool {
    collect_kinds(tree, &["identifier"])
        .into_iter()
        .any(|identifier| {
            if node_text(&identifier, src).trim() != map_name {
                return false;
            }
            if identifier
                .parent()
                .is_some_and(|parent| parent.kind() == "assignment" && parent.id() == declaration_id)
            {
                return false;
            }
            let Some(attribute) = identifier.parent().filter(|parent| parent.kind() == "attribute") else {
                // Reading one entry from a complete immutable literal map
                // cannot introduce the dynamic key into its selected value.
                // Projected writes were rejected above; this is only the
                // parsed value/base position of a subscript expression.
                if identifier.parent().is_some_and(|parent| {
                    parent.kind() == "subscript"
                        && parent
                            .child_by_field_name("value")
                            .is_some_and(|value| value.id() == identifier.id())
                }) {
                    return false;
                }
                return true;
            };
            if attribute
                .child_by_field_name("object")
                .is_none_or(|object| object.id() != identifier.id())
            {
                return true;
            }
            let Some(call) = attribute.parent().filter(|parent| parent.kind() == "call") else {
                return true;
            };
            call.child_by_field_name("function")
                .is_none_or(|function| function.id() != attribute.id())
                || attribute
                    .child_by_field_name("attribute")
                    .is_none_or(|method| node_text(&method, src).trim() != "get")
        })
}

fn python_finite_static_map(node: Node<'_>, src: &[u8]) -> bool {
    if node.kind() != "dictionary" || node.named_child_count() == 0 {
        return false;
    }
    let mut cursor = node.walk();
    let finite = node.named_children(&mut cursor).all(|entry| {
        entry.kind() == "pair"
            && entry
                .child_by_field_name("key")
                .is_some_and(|key| python_static_string(key, src).is_some())
            && entry
                .child_by_field_name("value")
                .is_some_and(|value| python_statically_constructed_value(value, src))
    });
    finite
}

fn python_statically_constructed_value(node: Node<'_>, src: &[u8]) -> bool {
    match node.kind() {
        "string" | "concatenated_string" => python_static_string(node, src).is_some(),
        "integer" | "float" | "true" | "false" | "none" => true,
        "list" | "tuple" | "set" | "dictionary" => {
            let mut cursor = node.walk();
            let finite = node.named_children(&mut cursor).all(|child| {
                if child.kind() == "pair" {
                    child
                        .child_by_field_name("key")
                        .is_some_and(|key| python_statically_constructed_value(key, src))
                        && child
                            .child_by_field_name("value")
                            .is_some_and(|value| python_statically_constructed_value(value, src))
                } else {
                    python_statically_constructed_value(child, src)
                }
            });
            finite
        }
        "call" => {
            let Some((_, arguments)) = python_call_parts(node) else {
                return false;
            };
            python_argument_nodes(arguments)
                .into_iter()
                .all(|argument| python_statically_constructed_value(argument, src))
        }
        _ => false,
    }
}

fn python_comprehension_character_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterConstraintFact> {
    let mut facts = Vec::new();
    for assignment in collect_kinds(tree, &["assignment"]) {
        let Some(target_node) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(mut value_node) = assignment.child_by_field_name("right") else {
            continue;
        };
        if target_node.kind() != "identifier" {
            continue;
        }
        while matches!(value_node.kind(), "subscript" | "parenthesized_expression") {
            let Some(inner) = value_node
                .child_by_field_name("value")
                .or_else(|| value_node.named_child(0))
            else {
                break;
            };
            value_node = inner;
        }
        let Some((function, arguments)) = python_call_parts(value_node) else {
            continue;
        };
        let Some((receiver, method)) = python_attribute_parts(function, src) else {
            continue;
        };
        if method != "join" || python_static_string(receiver, src).as_deref() != Some("") {
            continue;
        }
        let generator = if arguments.kind() == "generator_expression" {
            arguments
        } else {
            let args = python_argument_nodes(arguments);
            let [generator] = args.as_slice() else {
                continue;
            };
            *generator
        };
        let Some((input_place, classes, exact_characters)) =
            python_filtered_character_generator(generator, src)
        else {
            continue;
        };
        let transform_span = span_of(file, &assignment);
        let Some(decl) = python_enclosing_callable(index, transform_span) else {
            continue;
        };
        let target = node_text(&target_node, src).trim().to_string();
        let input_param_index = decl.params.iter().position(|param| param == &input_place);
        facts.push(CharacterConstraintFact {
            function_span: decl.span,
            transform_span,
            input_place,
            input_param_index,
            output: CharacterConstraintOutput::Assignment { target },
            domain: CharacterConstraintDomain::AllowOnly {
                classes,
                exact_characters,
            },
        });
    }
    facts
}

fn python_filtered_character_generator(
    generator: Node<'_>,
    src: &[u8],
) -> Option<(String, Vec<CharacterClass>, Vec<String>)> {
    if generator.kind() != "generator_expression" {
        return None;
    }
    let body = generator.named_child(0)?;
    if body.kind() != "identifier" {
        return None;
    }
    let loop_variable = node_text(&body, src).trim();
    let mut cursor = generator.walk();
    let clauses: Vec<_> = generator.named_children(&mut cursor).skip(1).collect();
    let [for_clause, if_clause] = clauses.as_slice() else {
        return None;
    };
    if for_clause.kind() != "for_in_clause" || if_clause.kind() != "if_clause" {
        return None;
    }
    let left = for_clause
        .child_by_field_name("left")
        .or_else(|| for_clause.named_child(0))?;
    let right = for_clause
        .child_by_field_name("right")
        .or_else(|| for_clause.named_child(1))?;
    if left.kind() != "identifier"
        || right.kind() != "identifier"
        || node_text(&left, src).trim() != loop_variable
    {
        return None;
    }
    let condition = if_clause
        .child_by_field_name("condition")
        .or_else(|| if_clause.named_child(0))?;
    let mut classes = Vec::new();
    let mut exact_characters = Vec::new();
    if !python_character_predicate(condition, loop_variable, src, &mut classes, &mut exact_characters) {
        return None;
    }
    classes.sort_by_key(|class| match class {
        CharacterClass::Alphabetic => 0,
        CharacterClass::Alphanumeric => 1,
        CharacterClass::Digit => 2,
    });
    classes.dedup();
    exact_characters.sort();
    exact_characters.dedup();
    Some((
        node_text(&right, src).trim().to_string(),
        classes,
        exact_characters,
    ))
}

fn python_character_predicate(
    node: Node<'_>,
    variable: &str,
    src: &[u8],
    classes: &mut Vec<CharacterClass>,
    exact_characters: &mut Vec<String>,
) -> bool {
    if node.kind() == "boolean_operator" {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        let operator = src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        return operator == Some("or")
            && python_character_predicate(left, variable, src, classes, exact_characters)
            && python_character_predicate(right, variable, src, classes, exact_characters);
    }
    if let Some((function, arguments)) = python_call_parts(node) {
        let Some((receiver, method)) = python_attribute_parts(function, src) else {
            return false;
        };
        if receiver.kind() != "identifier"
            || node_text(&receiver, src).trim() != variable
            || !python_argument_nodes(arguments).is_empty()
        {
            return false;
        }
        let class = match method {
            "isalpha" => CharacterClass::Alphabetic,
            "isalnum" => CharacterClass::Alphanumeric,
            "isdigit" => CharacterClass::Digit,
            _ => return false,
        };
        classes.push(class);
        return true;
    }
    if node.kind() != "comparison_operator" || node.named_child_count() != 2 {
        return false;
    }
    let (Some(left), Some(right)) = (node.named_child(0), node.named_child(1)) else {
        return false;
    };
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    if operator != Some("==") {
        return false;
    }
    let literal = if left.kind() == "identifier" && node_text(&left, src).trim() == variable {
        python_static_string(right, src)
    } else if right.kind() == "identifier" && node_text(&right, src).trim() == variable {
        python_static_string(left, src)
    } else {
        None
    };
    let Some(literal) = literal.filter(|value| value.chars().count() == 1) else {
        return false;
    };
    exact_characters.push(literal);
    true
}

fn python_regex_substitution_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterConstraintFact> {
    let assignments = collect_kinds(tree, &["assignment"]);
    let mut compiled = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let Some((function, arguments)) = python_call_parts(value) else {
            continue;
        };
        let args = python_argument_nodes(arguments);
        let Some(pattern) = args.first().and_then(|node| python_static_string(*node, src)) else {
            continue;
        };
        let Some(characters) = python_exact_regex_character_class(&pattern) else {
            continue;
        };
        let name = node_text(&target, src).trim().to_string();
        let writes = assignments
            .iter()
            .filter(|candidate| {
                candidate
                    .child_by_field_name("left")
                    .is_some_and(|left| node_text(&left, src).trim() == name)
            })
            .count();
        if writes == 1 {
            compiled.push((
                name,
                span_of(file, assignment),
                characters,
                node_text(&function, src).trim().to_string(),
            ));
        }
    }

    let mut facts = Vec::new();
    for return_node in collect_kinds(tree, &["return_statement"]) {
        let Some(call) = return_node.named_child(0) else {
            continue;
        };
        let Some((function, arguments)) = python_call_parts(call) else {
            continue;
        };
        let Some((receiver, _)) = python_attribute_parts(function, src) else {
            continue;
        };
        if receiver.kind() != "identifier" {
            continue;
        }
        let receiver_name = node_text(&receiver, src).trim();
        let Some((_, _, mut excluded, factory_call)) = compiled
            .iter()
            .find(|(name, assignment_span, _, _)| {
                name == receiver_name && assignment_span.start < return_node.start_byte() as u64
            })
            .cloned()
        else {
            continue;
        };
        let args = python_argument_nodes(arguments);
        let [replacement, input] = args.as_slice() else {
            continue;
        };
        let (Some(replacement), true) = (
            python_exact_replacement_string(*replacement, src),
            input.kind() == "identifier",
        ) else {
            continue;
        };
        excluded.retain(|character| !replacement.contains(character));
        if excluded.is_empty() {
            continue;
        }
        let return_span = span_of(file, &return_node);
        let Some(decl) = python_enclosing_callable(index, return_span) else {
            continue;
        };
        if !python_is_single_statement_return(return_node) {
            continue;
        }
        let input_place = node_text(input, src).trim().to_string();
        let Some(input_param_index) = decl.params.iter().position(|param| param == &input_place) else {
            continue;
        };
        facts.push(CharacterConstraintFact {
            function_span: decl.span,
            transform_span: return_span,
            input_place,
            input_param_index: Some(input_param_index),
            output: CharacterConstraintOutput::Return,
            domain: CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call: node_text(&function, src).trim().to_string(),
                domain: Box::new(CharacterConstraintDomain::ExcludesExact { characters: excluded }),
            },
        });
    }
    facts
}

/// Lower a compiled-regex rejection guard as a provider-bound alphabet fact.
/// The frontend proves anchoring, the accepted character domain, branch
/// polarity, and terminal rejection from Python syntax. It records the exact
/// factory and predicate calls but does not decide that those APIs are a
/// sanitizer; rulepack metadata performs that selection.
fn python_regex_validation_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterConstraintFact> {
    let assignments = collect_kinds(tree, &["assignment"]);
    let mut compiled = Vec::new();
    for assignment in &assignments {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let Some((function, arguments)) = python_call_parts(value) else {
            continue;
        };
        let args = python_argument_nodes(arguments);
        let Some(pattern) = args.first().and_then(|node| python_static_string(*node, src)) else {
            continue;
        };
        let Some(domain) = python_anchored_regex_character_domain(&pattern) else {
            continue;
        };
        let name = node_text(&target, src).trim().to_string();
        if assignments
            .iter()
            .filter(|candidate| {
                candidate
                    .child_by_field_name("left")
                    .is_some_and(|left| node_text(&left, src).trim() == name)
            })
            .count()
            != 1
        {
            continue;
        }
        compiled.push((
            name,
            span_of(file, assignment),
            node_text(&function, src).trim().to_string(),
            domain,
        ));
    }

    let mut facts = Vec::new();
    for branch in collect_kinds(tree, &["if_statement"]) {
        let (Some(condition), Some(consequence)) = (
            branch.child_by_field_name("condition"),
            branch.child_by_field_name("consequence"),
        ) else {
            continue;
        };
        if branch.child_by_field_name("alternative").is_some() || !python_block_abruptly_exits(consequence) {
            continue;
        }
        let Some(call) = python_negated_guard_call(condition) else {
            continue;
        };
        let Some((function, arguments)) = python_call_parts(call) else {
            continue;
        };
        let Some((receiver, _)) = python_attribute_parts(function, src) else {
            continue;
        };
        if receiver.kind() != "identifier" {
            continue;
        }
        let args = python_argument_nodes(arguments);
        let [input] = args.as_slice() else {
            continue;
        };
        let Some(input_place) = python_exact_guarded_identifier(*input, src) else {
            continue;
        };
        let receiver_name = node_text(&receiver, src).trim();
        let Some((_, _, factory_call, domain)) = compiled
            .iter()
            .filter(|(name, span, _, _)| name == receiver_name && span.start < branch.start_byte() as u64)
            .max_by_key(|(_, span, _, _)| (span.start, span.end))
            .cloned()
        else {
            continue;
        };
        let branch_span = span_of(file, &branch);
        let Some(decl) = python_enclosing_callable(index, branch_span) else {
            continue;
        };
        if assignments.iter().any(|assignment| {
            assignment.start_byte() > branch.end_byte()
                && assignment.end_byte() <= decl.span.end as usize
                && assignment
                    .child_by_field_name("left")
                    .is_some_and(|left| node_text(&left, src).trim() == input_place)
        }) {
            continue;
        }
        facts.push(CharacterConstraintFact {
            function_span: decl.span,
            transform_span: branch_span,
            input_param_index: decl.params.iter().position(|parameter| parameter == &input_place),
            input_place: input_place.clone(),
            output: CharacterConstraintOutput::Assignment { target: input_place },
            domain: CharacterConstraintDomain::ProviderBound {
                factory_call,
                operation_call: node_text(&function, src).trim().to_string(),
                domain: Box::new(domain),
            },
        });
    }
    facts
}

fn python_negated_guard_call(mut condition: Node<'_>) -> Option<Node<'_>> {
    while matches!(
        condition.kind(),
        "parenthesized_expression" | "parenthesized_expression_list"
    ) {
        condition = condition.named_child(0)?;
    }
    if condition.kind() != "not_operator" {
        return None;
    }
    condition
        .child_by_field_name("argument")
        .or_else(|| condition.named_child(0))
}

fn python_block_abruptly_exits(block: Node<'_>) -> bool {
    let mut cursor = block.walk();
    let last = block
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment")
        .last();
    last.is_some_and(|node| matches!(node.kind(), "return_statement" | "raise_statement"))
}

fn python_exact_guarded_identifier(mut node: Node<'_>, src: &[u8]) -> Option<String> {
    while node.kind() == "parenthesized_expression" {
        node = node.named_child(0)?;
    }
    (node.kind() == "identifier").then(|| node_text(&node, src).trim().to_string())
}

fn python_anchored_regex_character_domain(pattern: &str) -> Option<CharacterConstraintDomain> {
    let body = pattern.strip_prefix('^')?.strip_suffix('$')?;
    if body.is_empty() || body.contains("[^") || body.contains("(?") {
        return None;
    }
    let mut in_class = false;
    let mut escaped = false;
    let mut class = String::new();
    for character in body.chars() {
        if escaped {
            if !matches!(character, '.' | '-' | '_' | 'd' | 'w') {
                return None;
            }
            escaped = false;
            if in_class {
                class.push(character);
            }
            continue;
        }
        match character {
            '\\' => escaped = true,
            '[' if !in_class => {
                in_class = true;
                class.clear();
            }
            ']' if in_class => {
                if !python_safe_regex_character_class(&class) {
                    return None;
                }
                in_class = false;
            }
            '/' => return None,
            '.' if !in_class => return None,
            character if in_class => class.push(character),
            character if character.is_ascii_alphanumeric() || "_-()|{}?+*,".contains(character) => {}
            _ => return None,
        }
    }
    if escaped || in_class {
        return None;
    }
    Some(CharacterConstraintDomain::ExcludesExact {
        characters: vec!["/".to_string(), "\\".to_string()],
    })
}

fn python_safe_regex_character_class(class: &str) -> bool {
    if class.is_empty() || class.contains('/') || class.contains('\\') {
        return false;
    }
    let without_ranges = class.replace("A-Z", "").replace("a-z", "").replace("0-9", "");
    without_ranges
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
}

fn python_exact_replacement_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    python_static_string(node, src)
}

fn python_exact_regex_character_class(pattern: &str) -> Option<Vec<String>> {
    let inner = pattern.strip_prefix('[')?.strip_suffix(']')?;
    if inner.starts_with('^') {
        return None;
    }
    let mut characters = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '-' {
            return None;
        }
        let decoded = if character != '\\' {
            character
        } else {
            match chars.next()? {
                'r' => '\r',
                'n' => '\n',
                't' => '\t',
                '\\' => '\\',
                '"' => '"',
                '\'' => '\'',
                'x' => {
                    let digits = [chars.next()?, chars.next()?];
                    let value = u8::from_str_radix(&digits.iter().collect::<String>(), 16).ok()?;
                    char::from(value)
                }
                _ => return None,
            }
        };
        characters.push(decoded.to_string());
    }
    characters.sort();
    characters.dedup();
    (!characters.is_empty()).then_some(characters)
}

fn python_call_parts(call: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (call.kind() == "call").then_some((
        call.child_by_field_name("function")?,
        call.child_by_field_name("arguments")?,
    ))
}

fn python_attribute_parts<'a>(attribute: Node<'a>, src: &'a [u8]) -> Option<(Node<'a>, &'a str)> {
    if attribute.kind() != "attribute" {
        return None;
    }
    let object = attribute.child_by_field_name("object")?;
    let name = attribute.child_by_field_name("attribute")?;
    Some((object, node_text(&name, src).trim()))
}

fn python_argument_nodes(arguments: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "keyword_argument")
        .collect()
}

fn python_enclosing_callable(index: &DeclIndex, span: Span) -> Option<&bonsai_lang_api::Decl> {
    index
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            ) && decl.span.start <= span.start
                && span.end <= decl.span.end
        })
        .min_by_key(|decl| decl.span.len())
}

fn python_is_single_statement_return(return_node: Node<'_>) -> bool {
    return_node.parent().is_some_and(|block| {
        block.kind() == "block"
            && block
                .named_children(&mut block.walk())
                .filter(|node| node.kind() != "comment")
                .count()
                == 1
    })
}

fn python_same_origin_path_constraints(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<SameOriginPathConstraintFact> {
    let imports = parse_imports(tree, src, file);
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let function_span = span_of(file, &function);
        let Some(decl) = index.defs.iter().find(|decl| decl.span == function_span) else {
            continue;
        };
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let mut cursor = body.walk();
        let statements: Vec<_> = body
            .named_children(&mut cursor)
            .filter(|node| node.kind() != "comment")
            .collect();
        let [assignment, guard, final_return] = statements.as_slice() else {
            continue;
        };
        if assignment.kind() != "expression_statement" && assignment.kind() != "assignment" {
            continue;
        }
        let assignment = if assignment.kind() == "assignment" {
            *assignment
        } else {
            assignment.named_child(0).unwrap_or(*assignment)
        };
        let (Some(parsed_node), Some(parser_call)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if parsed_node.kind() != "identifier" {
            continue;
        }
        let parsed = node_text(&parsed_node, src).trim();
        let Some((parser, parser_arguments)) = python_call_parts(parser_call) else {
            continue;
        };
        let Some(provider_call) = python_imported_call_identity(parser, &imports, src) else {
            continue;
        };
        let parser_args = python_argument_nodes(parser_arguments);
        let [input_node] = parser_args.as_slice() else {
            continue;
        };
        if input_node.kind() != "identifier" {
            continue;
        }
        let input = node_text(input_node, src).trim();
        let Some(input_param_index) = decl.params.iter().position(|parameter| parameter == input) else {
            continue;
        };
        if guard.kind() != "if_statement" || guard.child_by_field_name("alternative").is_some() {
            continue;
        }
        let (Some(condition), Some(consequence)) = (
            guard.child_by_field_name("condition"),
            guard.child_by_field_name("consequence"),
        ) else {
            continue;
        };
        if !python_block_returns_static_path(consequence, src, "/")
            || !python_return_is_exact_place(*final_return, input, src)
        {
            continue;
        }
        let mut terms = Vec::new();
        python_collect_or_terms(condition, src, &mut terms);
        if terms.len() != 4 {
            continue;
        }
        let rejects_scheme = terms
            .iter()
            .any(|term| python_attribute_is(*term, parsed, "scheme", src));
        let rejects_authority = terms
            .iter()
            .any(|term| python_attribute_is(*term, parsed, "netloc", src));
        let requires_absolute_path = terms.iter().any(|term| {
            term.kind() == "not_operator"
                && term
                    .named_child(0)
                    .is_some_and(|operand| python_startswith_literal(operand, input, "/", src))
        });
        let rejects_scheme_relative_path = terms
            .iter()
            .any(|term| python_startswith_literal(*term, input, "//", src));
        if rejects_scheme && rejects_authority && requires_absolute_path && rejects_scheme_relative_path {
            facts.push(SameOriginPathConstraintFact {
                function_span,
                guard_span: span_of(file, guard),
                input_place: input.to_string(),
                input_param_index: Some(input_param_index),
                provider_call: Some(provider_call),
                rejects_scheme,
                rejects_authority,
                requires_absolute_path,
                rejects_scheme_relative_path,
            });
        }
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.guard_span.start));
    facts.dedup();
    facts
}

fn python_imported_call_identity(callee: Node<'_>, imports: &[ImportSpec], src: &[u8]) -> Option<String> {
    let rendered = node_text(&callee, src).trim();
    if rendered.is_empty() {
        return None;
    }
    for import in imports {
        if let Some(original) = import.original_name.as_deref() {
            let local = import.alias.as_deref().unwrap_or(original);
            if rendered == local {
                return Some(format!("{}.{}", import.module, original));
            }
            if let Some(suffix) = rendered
                .strip_prefix(local)
                .and_then(|tail| tail.strip_prefix('.'))
            {
                return Some(format!("{}.{}.{}", import.module, original, suffix));
            }
            continue;
        }
        if rendered == import.module || rendered.starts_with(&format!("{}.", import.module)) {
            return Some(rendered.to_string());
        }
        let Some(local) = import.alias.as_deref() else {
            continue;
        };
        if rendered == local {
            return Some(import.module.clone());
        }
        if let Some(suffix) = rendered
            .strip_prefix(local)
            .and_then(|tail| tail.strip_prefix('.'))
        {
            return Some(format!("{}.{}", import.module, suffix));
        }
    }
    None
}

fn python_collect_or_terms<'tree>(node: Node<'tree>, src: &[u8], out: &mut Vec<Node<'tree>>) {
    if node.kind() == "boolean_operator" {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            out.push(node);
            return;
        };
        let operator = src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        if operator == Some("or") {
            python_collect_or_terms(left, src, out);
            python_collect_or_terms(right, src, out);
            return;
        }
    }
    out.push(node);
}

fn python_attribute_is(node: Node<'_>, object: &str, field: &str, src: &[u8]) -> bool {
    python_attribute_parts(node, src).is_some_and(|(receiver, name)| {
        receiver.kind() == "identifier" && node_text(&receiver, src).trim() == object && name == field
    })
}

fn python_startswith_literal(node: Node<'_>, receiver: &str, literal: &str, src: &[u8]) -> bool {
    let Some((function, arguments)) = python_call_parts(node) else {
        return false;
    };
    let Some((object, method)) = python_attribute_parts(function, src) else {
        return false;
    };
    let args = python_argument_nodes(arguments);
    object.kind() == "identifier"
        && node_text(&object, src).trim() == receiver
        && method == "startswith"
        && args
            .as_slice()
            .first()
            .and_then(|node| python_static_string(*node, src))
            .as_deref()
            == Some(literal)
        && args.len() == 1
}

fn python_block_returns_static_path(block: Node<'_>, src: &[u8], expected: &str) -> bool {
    let mut cursor = block.walk();
    let statements: Vec<_> = block
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment")
        .collect();
    let [return_node] = statements.as_slice() else {
        return false;
    };
    return_node.kind() == "return_statement"
        && return_node
            .named_child(0)
            .and_then(|value| python_static_string(value, src))
            .as_deref()
            == Some(expected)
}

fn python_return_is_exact_place(return_node: Node<'_>, expected: &str, src: &[u8]) -> bool {
    return_node.kind() == "return_statement"
        && return_node
            .named_child(0)
            .is_some_and(|value| value.kind() == "identifier" && node_text(&value, src).trim() == expected)
}

/// Lower Python string concatenation and `value or literal` fallback syntax
/// into a complete, typed composition. Unsupported operands fail closed, so
/// consumers never infer safety from a partial expression.
fn python_string_compositions(tree: &Tree, file: FileId, src: &[u8]) -> Vec<StringCompositionFact> {
    let mut facts = Vec::new();
    for assignment in collect_kinds(tree, &["assignment"]) {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let mut parts = Vec::new();
        if lower_python_string_composition(value, file, src, &mut parts) && parts.len() > 1 {
            facts.push(StringCompositionFact {
                container_span: span_of(file, &assignment),
                value_span: span_of(file, &value),
                target: Some(node_text(&target, src).trim().to_string()),
                parts,
            });
        }
    }
    for return_node in collect_kinds(tree, &["return_statement"]) {
        let Some(value) = return_node.named_child(0) else {
            continue;
        };
        let mut parts = Vec::new();
        if lower_python_string_composition(value, file, src, &mut parts) && parts.len() > 1 {
            facts.push(StringCompositionFact {
                container_span: span_of(file, &return_node),
                value_span: span_of(file, &value),
                target: None,
                parts,
            });
        }
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

fn lower_python_string_composition(
    mut node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<StringCompositionPart>,
) -> bool {
    while matches!(
        node.kind(),
        "parenthesized_expression" | "parenthesized_expression_list"
    ) {
        let Some(inner) = node.named_child(0) else {
            return false;
        };
        node = inner;
    }
    if let Some(value) = python_static_string(node, src) {
        out.push(StringCompositionPart::Literal { value });
        return true;
    }
    if node.kind() == "string" && lower_python_formatted_string(node, src, out) {
        return true;
    }
    if let Some(place) = python_exact_place(node, src) {
        out.push(StringCompositionPart::Place { place });
        return true;
    }
    if let Some((function, _)) = python_call_parts(node) {
        out.push(StringCompositionPart::Call {
            span: span_of(file, &function),
        });
        return true;
    }
    if node.kind() == "binary_operator" {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        let operator = src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        return operator == Some("+")
            && lower_python_string_composition(left, file, src, out)
            && lower_python_string_composition(right, file, src, out);
    }
    if node.kind() == "boolean_operator" {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        let operator = src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        let (Some(place), Some(fallback)) = (python_exact_place(left, src), python_static_string(right, src))
        else {
            return false;
        };
        if operator == Some("or") {
            out.push(StringCompositionPart::PlaceOrLiteral { place, fallback });
            return true;
        }
    }
    false
}

fn lower_python_formatted_string(node: Node<'_>, src: &[u8], out: &mut Vec<StringCompositionPart>) -> bool {
    let text = node_text(&node, src).trim();
    let Some(quote_start) = text.find(['\'', '"']) else {
        return false;
    };
    let prefix = text[..quote_start].to_ascii_lowercase();
    if !prefix.contains('f')
        || prefix.contains('b')
        || prefix
            .chars()
            .any(|character| !matches!(character, 'f' | 'r' | 'u'))
    {
        return false;
    }
    let mut saw_interpolation = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_start" | "string_end" => {}
            "string_content" => {
                let value = node_text(&child, src);
                if value.contains('\\') {
                    return false;
                }
                push_python_composition_literal(out, value);
            }
            "interpolation" => {
                let Some(expression) = child
                    .child_by_field_name("expression")
                    .or_else(|| child.named_child(0))
                else {
                    return false;
                };
                let Some(place) = python_exact_place(expression, src) else {
                    return false;
                };
                out.push(StringCompositionPart::Place { place });
                saw_interpolation = true;
            }
            _ => return false,
        }
    }
    saw_interpolation
}

fn push_python_composition_literal(out: &mut Vec<StringCompositionPart>, value: &str) {
    if value.is_empty() {
        return;
    }
    if let Some(StringCompositionPart::Literal { value: previous }) = out.last_mut() {
        previous.push_str(value);
    } else {
        out.push(StringCompositionPart::Literal {
            value: value.to_string(),
        });
    }
}

fn python_exact_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => {
            let name = node_text(&node, src).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            let object = python_exact_place(object, src)?;
            let attribute = node_text(&attribute, src).trim();
            (!attribute.is_empty()).then(|| format!("{object}.{attribute}"))
        }
        "parenthesized_expression" | "parenthesized_expression_list" => {
            python_exact_place(node.named_child(0)?, src)
        }
        _ => None,
    }
}

/// FastAPI / Starlette parameter-binder markers. When a parameter's
/// default-value is a call to one of these names, the binder
/// determines the runtime type more reliably than the declared
/// annotation. `param: str = Body(...)` semantically receives an
/// envelope from the request body even though the annotation says
/// `str`.
const FASTAPI_BINDER_MARKERS: &[&str] = &[
    "Body", "Depends", "Query", "Header", "Cookie", "Form", "File", "Path",
];

/// Walk every function/method/lambda body once and record the
/// parameter type-alias bindings emitted by typed parameters or
/// FastAPI-style binder default calls. Returns `(decl_span,
/// aliases)` pairs so `extract_declarations` can attach them to
/// the right `Decl`.
fn collect_python_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_definition", "lambda"]) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        if let Some(params) = fn_node.child_by_field_name("parameters") {
            collect_python_parameter_aliases(params, src, &mut aliases);
        }
        dedup_python_type_aliases(&mut aliases);
        if !aliases.is_empty() {
            out.push((span_of(file, &fn_node), aliases));
        }
    }
    out
}

fn collect_python_param_binder_annotations(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<(String, String)>)> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_definition", "lambda"]) {
        let mut binders = Vec::new();
        if let Some(params) = fn_node.child_by_field_name("parameters") {
            collect_python_parameter_binder_annotations(params, src, &mut binders);
        }
        dedup_python_param_binders(&mut binders);
        if !binders.is_empty() {
            out.push((span_of(file, &fn_node), binders));
        }
    }
    out
}

fn collect_python_parameter_binder_annotations(node: Node<'_>, src: &[u8], out: &mut Vec<(String, String)>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "typed_default_parameter" | "default_parameter" => {
                if let Some(binding) = python_param_binder_annotation(child, src) {
                    out.push(binding);
                }
            }
            _ => collect_python_parameter_binder_annotations(child, src, out),
        }
    }
}

fn python_param_binder_annotation(node: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    let name_node = node
        .child_by_field_name("name")
        .or_else(|| first_named_child_of_kind(node, &["identifier"]))?;
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value_node = node.child_by_field_name("value")?;
    let binder = python_binder_call_marker(value_node, src)?;
    Some((name, binder))
}

fn dedup_python_param_binders(binders: &mut Vec<(String, String)>) {
    let mut deduped = Vec::new();
    for (name, binder) in binders.drain(..) {
        if !deduped
            .iter()
            .any(|(existing_name, existing_binder)| existing_name == &name && existing_binder == &binder)
        {
            deduped.push((name, binder));
        }
    }
    *binders = deduped;
}

fn merge_python_param_binder_annotations(decl: &mut bonsai_lang_api::Decl, binders: &[(String, String)]) {
    if decl.params.is_empty() || binders.is_empty() {
        return;
    }
    if decl.param_annotations.len() < decl.params.len() {
        decl.param_annotations.resize_with(decl.params.len(), Vec::new);
    }
    for (name, binder) in binders {
        let Some(idx) = decl.params.iter().position(|param| param == name) else {
            continue;
        };
        let anns = &mut decl.param_annotations[idx];
        if !anns.iter().any(|existing| existing == binder) {
            anns.push(binder.clone());
            anns.sort();
            anns.dedup();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PythonPropertyAlias {
    class_symbol: SymbolId,
    property_name: String,
    receiver_name: String,
    target_tail: String,
}

fn collect_python_property_function_spans(tree: &Tree, file: FileId, src: &[u8]) -> Vec<Span> {
    let mut spans = Vec::new();
    for decorated in collect_kinds(tree, &["decorated_definition"]) {
        if !python_decorated_definition_has_property(&decorated, src) {
            continue;
        }
        let Some(function) = first_named_child_of_kind(decorated, &["function_definition"]) else {
            continue;
        };
        let span = span_of(file, &function);
        if !spans.contains(&span) {
            spans.push(span);
        }
    }
    spans
}

fn python_decorated_definition_has_property(node: &Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    let has_property = node
        .named_children(&mut cursor)
        .any(|child| child.kind() == "decorator" && python_decorator_is_property(&child, src));
    has_property
}

fn python_decorator_is_property(node: &Node<'_>, src: &[u8]) -> bool {
    let text = node_text(node, src).trim();
    text.strip_prefix('@')
        .map(str::trim)
        .is_some_and(|decorator| decorator == "property")
}

fn collect_python_property_aliases(idx: &DeclIndex, property_fn_spans: &[Span]) -> Vec<PythonPropertyAlias> {
    let mut aliases = Vec::new();
    for decl in &idx.defs {
        if !property_fn_spans.contains(&decl.span) {
            continue;
        }
        let Some(class_symbol) = decl.parent else {
            continue;
        };
        let Some(receiver_idx) = decl.receiver_param_index else {
            continue;
        };
        let Some(receiver_name) = decl.params.get(receiver_idx) else {
            continue;
        };
        let Some(target_tail) = python_property_return_tail(decl, receiver_name) else {
            continue;
        };
        aliases.push(PythonPropertyAlias {
            class_symbol,
            property_name: decl.name.clone(),
            receiver_name: receiver_name.clone(),
            target_tail,
        });
    }
    aliases
}

fn python_property_return_tail(decl: &bonsai_lang_api::Decl, receiver_name: &str) -> Option<String> {
    for event in &decl.flow_events {
        if let Some(tail) = python_property_return_tail_from_event(event, receiver_name) {
            return Some(tail);
        }
    }
    None
}

fn python_property_return_tail_from_event(
    event: &bonsai_lang_api::FlowEvent,
    receiver_name: &str,
) -> Option<String> {
    match event {
        bonsai_lang_api::FlowEvent::Return { value_flow, .. } => value_flow
            .projection
            .as_ref()
            .filter(|projection| projection.base == receiver_name)
            .map(|projection| projection.path.join("."))
            .filter(|tail| !tail.is_empty()),
        bonsai_lang_api::FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => then_events
            .iter()
            .chain(else_events.iter())
            .find_map(|event| python_property_return_tail_from_event(event, receiver_name)),
        bonsai_lang_api::FlowEvent::Loop { body, .. }
        | bonsai_lang_api::FlowEvent::Defer { body, .. }
        | bonsai_lang_api::FlowEvent::Using { body, .. } => body
            .iter()
            .find_map(|event| python_property_return_tail_from_event(event, receiver_name)),
        bonsai_lang_api::FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => body
            .iter()
            .chain(catch_events.iter())
            .chain(finally_events.iter())
            .find_map(|event| python_property_return_tail_from_event(event, receiver_name)),
        _ => None,
    }
}

fn python_property_aliases_for_decl(
    idx: &DeclIndex,
    decl: &bonsai_lang_api::Decl,
    property_aliases: &[PythonPropertyAlias],
) -> Vec<PythonPropertyAlias> {
    let Some(class_symbol) = decl.parent else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen_classes = std::collections::HashSet::new();
    collect_python_property_aliases_for_class(
        idx,
        class_symbol,
        property_aliases,
        &mut seen_classes,
        &mut out,
    );
    if let Some(receiver_name) = python_decl_receiver_name(decl) {
        for alias in &mut out {
            alias.receiver_name.clone_from(&receiver_name);
        }
    }
    out
}

fn python_decl_receiver_name(decl: &bonsai_lang_api::Decl) -> Option<String> {
    decl.receiver_param_index
        .and_then(|idx| decl.params.get(idx))
        .filter(|name| !name.trim().is_empty())
        .cloned()
}

fn python_property_aliases_by_decl(
    idx: &DeclIndex,
    property_aliases: &[PythonPropertyAlias],
) -> std::collections::HashMap<SymbolId, Vec<PythonPropertyAlias>> {
    let mut by_decl = std::collections::HashMap::new();
    for decl in &idx.defs {
        let aliases = python_property_aliases_for_decl(idx, decl, property_aliases);
        if !aliases.is_empty() {
            by_decl.insert(decl.symbol, aliases);
        }
    }
    by_decl
}

fn collect_python_property_aliases_for_class(
    idx: &DeclIndex,
    class_symbol: SymbolId,
    property_aliases: &[PythonPropertyAlias],
    seen_classes: &mut std::collections::HashSet<SymbolId>,
    out: &mut Vec<PythonPropertyAlias>,
) {
    if !seen_classes.insert(class_symbol) {
        return;
    }
    for alias in property_aliases
        .iter()
        .filter(|alias| alias.class_symbol == class_symbol)
    {
        if !out.iter().any(|existing| existing == alias) {
            out.push(alias.clone());
        }
    }
    let Some(class_decl) = idx.defs.iter().find(|decl| decl.symbol == class_symbol) else {
        return;
    };
    for base in &class_decl.bases {
        let Some(base_symbol) = idx
            .defs
            .iter()
            .find(|decl| {
                matches!(decl.kind, bonsai_lang_api::DeclKind::Class)
                    && (decl.name == *base || decl.name == base.rsplit('.').next().unwrap_or(base))
            })
            .map(|decl| decl.symbol)
        else {
            continue;
        };
        collect_python_property_aliases_for_class(idx, base_symbol, property_aliases, seen_classes, out);
    }
}

fn augment_python_property_flow_events(
    events: &mut [bonsai_lang_api::FlowEvent],
    property_aliases: &[PythonPropertyAlias],
) {
    if property_aliases.is_empty() {
        return;
    }
    for event in events {
        match event {
            bonsai_lang_api::FlowEvent::Assign { source_names, .. } => {
                augment_python_property_source_names(source_names, property_aliases);
            }
            bonsai_lang_api::FlowEvent::Call { args, .. } => {
                for arg in args {
                    augment_python_property_source_names(&mut arg.source_names, property_aliases);
                }
            }
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_python_property_flow_events(then_events, property_aliases);
                augment_python_property_flow_events(else_events, property_aliases);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                augment_python_property_flow_events(body, property_aliases);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_python_property_flow_events(body, property_aliases);
                augment_python_property_flow_events(catch_events, property_aliases);
                augment_python_property_flow_events(finally_events, property_aliases);
            }
            _ => {}
        }
    }
}

fn augment_python_property_source_names(
    source_names: &mut Vec<String>,
    property_aliases: &[PythonPropertyAlias],
) {
    let existing = source_names.clone();
    for source in existing {
        for alias in property_aliases {
            if let Some(rewritten) = python_property_alias_source_name(&source, alias) {
                push_python_source_name(source_names, rewritten);
            }
        }
    }
}

fn python_property_alias_source_name(source: &str, alias: &PythonPropertyAlias) -> Option<String> {
    let prefix = format!("{}.{}", alias.receiver_name, alias.property_name);
    let source = source.trim();
    if source == prefix {
        return Some(format!("{}.{}", alias.receiver_name, alias.target_tail));
    }
    let tail = source.strip_prefix(&prefix)?.strip_prefix('.')?;
    if tail.is_empty() {
        return None;
    }
    Some(format!("{}.{}.{}", alias.receiver_name, alias.target_tail, tail))
}

fn augment_python_comprehension_flow_events(
    events: &mut [bonsai_lang_api::FlowEvent],
    source: &str,
    assignment_values: &AssignmentValueIndex,
) {
    for event in events {
        match event {
            bonsai_lang_api::FlowEvent::Assign {
                span, source_names, ..
            } => {
                if let Some(rhs) = assignment_values.rendering(*span, source) {
                    for iterable in python_comprehension_iterables(rhs) {
                        push_python_source_name(source_names, iterable);
                    }
                }
            }
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_python_comprehension_flow_events(then_events, source, assignment_values);
                augment_python_comprehension_flow_events(else_events, source, assignment_values);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                augment_python_comprehension_flow_events(body, source, assignment_values);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_python_comprehension_flow_events(body, source, assignment_values);
                augment_python_comprehension_flow_events(catch_events, source, assignment_values);
                augment_python_comprehension_flow_events(finally_events, source, assignment_values);
            }
            _ => {}
        }
    }
}

fn collect_python_comprehension_iterable_call_events(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    decl_span: Span,
) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for clause in collect_kinds(tree, &["for_in_clause"]) {
        let clause_span = span_of(file, &clause);
        if !python_span_contains(decl_span, clause_span) || !python_for_in_clause_is_comprehension(&clause) {
            continue;
        }
        let Some(iterable) = clause.child_by_field_name("right") else {
            continue;
        };
        collect_python_call_events_from_node(iterable, file, src, &mut out);
    }
    out.sort_by_key(|event| python_flow_event_span(event).start);
    out.dedup_by(|left, right| python_flow_event_same_call(left, right));
    out
}

fn python_for_in_clause_is_comprehension(clause: &Node<'_>) -> bool {
    let mut parent = clause.parent();
    while let Some(node) = parent {
        if matches!(
            node.kind(),
            "list_comprehension"
                | "dict_comprehension"
                | "dictionary_comprehension"
                | "set_comprehension"
                | "generator_expression"
        ) {
            return true;
        }
        if matches!(
            node.kind(),
            "function_definition" | "lambda" | "for_statement" | "while_statement" | "if_statement" | "block"
        ) {
            return false;
        }
        parent = node.parent();
    }
    false
}

fn collect_python_call_events_from_node(node: Node<'_>, file: FileId, src: &[u8], out: &mut Vec<FlowEvent>) {
    if node.kind() == "call" {
        if let Some(event) = build_python_call_event(node, file, src) {
            out.push(event);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_call_events_from_node(child, file, src, out);
    }
}

fn build_python_call_event(node: Node<'_>, file: FileId, src: &[u8]) -> Option<FlowEvent> {
    if node.kind() != "call" {
        return None;
    }
    let callee_node = node.child_by_field_name("function")?;
    let name = normalize_call_name_whitespace(node_text(&callee_node, src));
    if name.is_empty() {
        return None;
    }
    let receiver = python_call_receiver_from_name(&name);
    let call_kind = if receiver.is_some() {
        CallKind::Method
    } else {
        CallKind::Function
    };
    let mut args = Vec::new();
    if let Some(arguments) = node.child_by_field_name("arguments") {
        let mut cursor = arguments.walk();
        for arg in arguments.named_children(&mut cursor) {
            let (name, value_node) = if arg.kind() == "keyword_argument" {
                let key = arg
                    .child_by_field_name("name")
                    .map(|node| node_text(&node, src).trim().to_string())
                    .filter(|name| !name.is_empty());
                let value = arg.child_by_field_name("value").unwrap_or(arg);
                (key, value)
            } else {
                (None, arg)
            };
            if let Some(argument) =
                call_arg_from_nodes_with_handler(arg, value_node, file, src, name, &HANDLER)
            {
                let mut argument = argument;
                if let Some(place) = python_exact_expression_place(value_node, src) {
                    argument.place = Some(place);
                }
                args.push(argument);
            }
        }
    }
    Some(FlowEvent::Call {
        span: span_of(file, &callee_node),
        name,
        receiver,
        receiver_types: Vec::new(),
        call_kind,
        args,
    })
}

/// Exact addressable call arguments lowered from Python's Tree-sitter nodes.
///
/// The shared call walker deliberately does not interpret language syntax.
/// Python static subscripts therefore have to become canonical compiler
/// places here: `obj["field"]` is `obj.field`, while `obj[key]` remains an
/// aggregate read because its selected field is not statically known.
fn collect_python_call_argument_places(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            let value = if argument.kind() == "keyword_argument" {
                argument.child_by_field_name("value").unwrap_or(argument)
            } else {
                argument
            };
            let Some(place) = python_exact_expression_place(value, src) else {
                continue;
            };
            out.push((span_of(file, &argument), place));
        }
    }
    out.sort_by_key(|(span, _)| (span.start, span.end));
    out.dedup_by_key(|(span, _)| *span);
    out
}

fn python_exact_expression_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => {
            let name = node_text(&node, src).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            let base = python_exact_expression_place(object, src)?;
            let field = node_text(&attribute, src).trim();
            (!field.is_empty()).then(|| format!("{base}.{field}"))
        }
        "subscript" => {
            let value = node.child_by_field_name("value")?;
            let subscript = node.child_by_field_name("subscript")?;
            let base = python_exact_expression_place(value, src)?;
            let field = python_static_string(subscript, src)?;
            if field.is_empty()
                || !field
                    .chars()
                    .next()
                    .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
                || !field.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            {
                return None;
            }
            Some(format!("{base}.{field}"))
        }
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            let child = node.named_children(&mut cursor).next()?;
            python_exact_expression_place(child, src)
        }
        _ => None,
    }
}

/// Exact addressable return operands lowered from Python's Tree-sitter nodes.
/// Static attribute/subscript returns carry their complete storage place;
/// dynamic subscripts deliberately retain the generic aggregate fact.
fn collect_python_return_places(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for statement in collect_kinds(tree, &["return_statement"]) {
        let Some(value) = statement.named_child(0) else {
            continue;
        };
        let Some(place) = python_exact_expression_place(value, src) else {
            continue;
        };
        out.push((span_of(file, &statement), place));
    }
    out.sort_by_key(|(span, _)| (span.start, span.end));
    out.dedup_by_key(|(span, _)| *span);
    out
}

fn apply_python_return_places(events: &mut [FlowEvent], places: &[(Span, String)]) {
    for event in events {
        match event {
            FlowEvent::Return {
                span,
                value_name,
                value_flow,
                ..
            } => {
                if let Ok(index) = places.binary_search_by_key(&(span.start, span.end), |(candidate, _)| {
                    (candidate.start, candidate.end)
                }) {
                    let place = places[index].1.clone();
                    *value_name = Some(place.clone());
                    value_flow.place = Some(place.clone());
                    value_flow.source_names.clear();
                    value_flow.source_names.push(place);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_python_return_places(then_events, places);
                apply_python_return_places(else_events, places);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_python_return_places(body, places);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_python_return_places(body, places);
                apply_python_return_places(catch_events, places);
                apply_python_return_places(finally_events, places);
            }
            _ => {}
        }
    }
}

fn apply_python_call_argument_places(events: &mut [FlowEvent], places: &[(Span, String)]) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for argument in args {
                    if let Ok(index) = places
                        .binary_search_by_key(&(argument.span.start, argument.span.end), |(span, _)| {
                            (span.start, span.end)
                        })
                    {
                        argument.place = Some(places[index].1.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_python_call_argument_places(then_events, places);
                apply_python_call_argument_places(else_events, places);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_python_call_argument_places(body, places);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_python_call_argument_places(body, places);
                apply_python_call_argument_places(catch_events, places);
                apply_python_call_argument_places(finally_events, places);
            }
            _ => {}
        }
    }
}

/// Lower the value delivered by a direct iterable call into a sparse
/// yield-result binding. Python uses the same `for_statement` grammar shape
/// for synchronous and asynchronous iteration; the IDG only activates this
/// relation when resolution proves that the callee owns a `Yield` endpoint.
/// Ordinary container-returning calls therefore retain their existing return
/// semantics, while generator fields remain field-precise at the loop target.
fn collect_python_iterable_yield_bindings(tree: &Tree, file: FileId, src: &[u8]) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for loop_node in collect_kinds(tree, &["for_statement"]) {
        let (Some(binding), Some(iterable)) = (
            loop_node.child_by_field_name("left"),
            loop_node.child_by_field_name("right"),
        ) else {
            continue;
        };
        let Some(FlowEvent::Call { name, args, .. }) = build_python_call_event(iterable, file, src) else {
            continue;
        };
        let source_call_args = args.into_iter().map(|arg| arg.value_text).collect::<Vec<_>>();
        for target in python_loop_binding_targets(binding, src) {
            out.push(FlowEvent::Assign {
                // Use the loop statement's write span, not the callee token.
                // The generic frontend already lowered the loop binding at
                // this span. Inserting the sparse YieldResult relation next
                // to that event reuses the same IDG write node, so unresolved
                // ordinary iterables cannot overwrite and kill the compiler's
                // local loop flow. `assign_call_site_hint` still joins this
                // containing span to the exact sibling Call event.
                span: span_of(file, &loop_node),
                target,
                source_name: None,
                source_call: Some(name.clone()),
                source_call_args: source_call_args.clone(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: Some(bonsai_lang_api::AssignValueKind::YieldResult),
            });
        }
    }
    out.sort_by_key(|event| {
        let span = python_flow_event_span(event);
        let target = match event {
            FlowEvent::Assign { target, .. } => target.as_str(),
            _ => "",
        };
        (span.start, span.end, target.to_string())
    });
    out.dedup_by(|left, right| match (left, right) {
        (
            FlowEvent::Assign {
                span: left_span,
                target: left_target,
                source_call: left_call,
                ..
            },
            FlowEvent::Assign {
                span: right_span,
                target: right_target,
                source_call: right_call,
                ..
            },
        ) => left_span == right_span && left_target == right_target && left_call == right_call,
        _ => false,
    });
    out
}

/// Place Python's generator relation beside the generic loop-binding event.
///
/// The shared walker lowers a `for` binding before its `Loop` body. Keeping
/// this adapter-owned refinement in the same event vector and at the same
/// statement span makes both facts refer to one compiler write. Appending it
/// inside the body would create a later definition and incorrectly erase the
/// generic binding whenever the iterable resolves to external code.
fn insert_python_iterable_yield_bindings(events: &mut Vec<FlowEvent>, bindings: &[FlowEvent]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_python_iterable_yield_bindings(then_events, bindings);
                insert_python_iterable_yield_bindings(else_events, bindings);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_python_iterable_yield_bindings(body, bindings);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_python_iterable_yield_bindings(body, bindings);
                insert_python_iterable_yield_bindings(catch_events, bindings);
                insert_python_iterable_yield_bindings(finally_events, bindings);
            }
            _ => {}
        }
    }

    let loop_spans = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Loop { span, .. } => Some(*span),
            _ => None,
        })
        .collect::<Vec<_>>();
    for loop_span in loop_spans {
        let Some(mut insert_at) = events
            .iter()
            .position(|event| matches!(event, FlowEvent::Loop { span, .. } if *span == loop_span))
        else {
            continue;
        };
        for binding in bindings
            .iter()
            .filter(|binding| python_flow_event_span(binding) == loop_span)
        {
            if events.iter().any(|existing| existing == binding) {
                continue;
            }
            events.insert(insert_at, binding.clone());
            insert_at += 1;
        }
    }
}

fn python_loop_binding_targets(node: Node<'_>, src: &[u8]) -> Vec<String> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        if node.kind() == "identifier" {
            let name = node_text(&node, src).trim();
            if python_match_capture_identifier(name) {
                out.push(name.to_string());
            }
            return;
        }
        if !matches!(
            node.kind(),
            "pattern_list" | "tuple_pattern" | "list_pattern" | "star_pattern"
        ) {
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect(child, src, out);
        }
    }

    let mut out = Vec::new();
    collect(node, src, &mut out);
    out.sort();
    out.dedup();
    out
}

fn python_call_receiver_from_name(name: &str) -> Option<String> {
    let (receiver, _) = name.rsplit_once('.')?;
    let receiver = receiver.trim();
    (!receiver.is_empty()).then(|| receiver.to_string())
}

fn python_is_identifier_like(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_alphanumeric())
}

fn augment_python_asyncio_to_thread_calls(events: &mut Vec<FlowEvent>) {
    let mut i = 0;
    while i < events.len() {
        match &mut events[i] {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_python_asyncio_to_thread_calls(then_events);
                augment_python_asyncio_to_thread_calls(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_python_asyncio_to_thread_calls(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_python_asyncio_to_thread_calls(body);
                augment_python_asyncio_to_thread_calls(catch_events);
                augment_python_asyncio_to_thread_calls(finally_events);
            }
            _ => {}
        }

        let synthetic = match &events[i] {
            FlowEvent::Call { span, name, args, .. } if python_is_asyncio_to_thread_name(name) => {
                let Some((target, shifted_args)) = python_to_thread_target_and_args(args) else {
                    i += 1;
                    continue;
                };
                let receiver = python_call_receiver_from_name(&target);
                let call_kind = if receiver.is_some() {
                    CallKind::Method
                } else {
                    CallKind::Function
                };
                Some(FlowEvent::Call {
                    span: *span,
                    name: target,
                    receiver,
                    receiver_types: Vec::new(),
                    call_kind,
                    args: shifted_args,
                })
            }
            _ => None,
        };
        if let Some(call) = synthetic {
            events.insert(i + 1, call);
            i += 1;
        }
        i += 1;
    }
}

fn python_is_asyncio_to_thread_name(name: &str) -> bool {
    matches!(name.trim(), "asyncio.to_thread" | "to_thread")
}

fn python_to_thread_target_and_args(args: &[CallArg]) -> Option<(String, Vec<CallArg>)> {
    let target = args.first()?.value_text.trim();
    if !python_is_qualified_identifier_like(target) {
        return None;
    }
    Some((target.to_string(), args.iter().skip(1).cloned().collect()))
}

fn python_is_qualified_identifier_like(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty()
        && text
            .split('.')
            .all(|part| !part.is_empty() && python_is_identifier_like(part))
}

fn insert_python_flow_events_by_span(events: &mut Vec<FlowEvent>, owner_span: Span, synthetic: &[FlowEvent]) {
    for event in events.iter_mut() {
        let event_span = python_flow_event_span(event);
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_python_flow_events_by_span(then_events, event_span, synthetic);
                insert_python_flow_events_by_span(else_events, event_span, synthetic);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_python_flow_events_by_span(body, event_span, synthetic);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_python_flow_events_by_span(body, event_span, synthetic);
                insert_python_flow_events_by_span(catch_events, event_span, synthetic);
                insert_python_flow_events_by_span(finally_events, event_span, synthetic);
            }
            _ => {}
        }
    }

    let mut pending: Vec<FlowEvent> = synthetic
        .iter()
        .filter(|event| {
            let span = python_flow_event_span(event);
            python_span_contains(owner_span, span)
                && !python_event_tree_contains_call(events, event)
                && !events.iter().any(|candidate| {
                    python_flow_event_is_container(candidate)
                        && python_span_contains(python_flow_event_span(candidate), span)
                })
        })
        .cloned()
        .collect();
    pending.sort_by_key(|event| python_flow_event_span(event).start);
    for event in pending {
        let span = python_flow_event_span(&event);
        let insert_at = events
            .iter()
            .position(|existing| python_flow_event_span(existing).start > span.start)
            .unwrap_or(events.len());
        events.insert(insert_at, event);
    }
}

fn python_flow_event_is_container(event: &FlowEvent) -> bool {
    matches!(
        event,
        FlowEvent::Branch { .. }
            | FlowEvent::Loop { .. }
            | FlowEvent::Try { .. }
            | FlowEvent::Defer { .. }
            | FlowEvent::Using { .. }
    )
}

fn python_event_tree_contains_call(events: &[FlowEvent], needle: &FlowEvent) -> bool {
    events.iter().any(|event| {
        python_flow_event_same_call(event, needle)
            || match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    python_event_tree_contains_call(then_events, needle)
                        || python_event_tree_contains_call(else_events, needle)
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => python_event_tree_contains_call(body, needle),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    python_event_tree_contains_call(body, needle)
                        || python_event_tree_contains_call(catch_events, needle)
                        || python_event_tree_contains_call(finally_events, needle)
                }
                _ => false,
            }
    })
}

fn python_flow_event_same_call(left: &FlowEvent, right: &FlowEvent) -> bool {
    matches!(
        (left, right),
        (
            FlowEvent::Call {
                span: left_span,
                name: left_name,
                ..
            },
            FlowEvent::Call {
                span: right_span,
                name: right_name,
                ..
            }
        ) if left_span == right_span && left_name == right_name
    )
}

fn python_comprehension_iterables(rhs: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let iter = rhs.char_indices().peekable();
    for (idx, ch) in iter {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            'i' if rhs[idx..].starts_with("in") && python_keyword_boundary(rhs, idx, idx + 2) => {
                let start = idx + 2;
                let end = python_comprehension_iterable_end(rhs, start, depth);
                for token in python_access_tokens(&rhs[start..end]) {
                    push_python_source_name(&mut out, token);
                }
            }
            _ => {}
        }
    }
    out
}

fn python_keyword_boundary(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !after.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn python_comprehension_iterable_end(text: &str, start: usize, initial_depth: usize) -> usize {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = initial_depth;
    for (idx, ch) in text.char_indices().skip_while(|(idx, _)| *idx < start) {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => {
                if depth <= initial_depth {
                    return idx;
                }
                depth = depth.saturating_sub(1);
            }
            ',' if depth == initial_depth => return idx,
            'i' if depth == initial_depth
                && text[idx..].starts_with("if")
                && python_keyword_boundary(text, idx, idx + 2) =>
            {
                return idx;
            }
            'f' if depth == initial_depth
                && text[idx..].starts_with("for")
                && python_keyword_boundary(text, idx, idx + 3) =>
            {
                return idx;
            }
            _ => {}
        }
    }
    text.len()
}

fn python_access_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars().chain(std::iter::once(' ')) {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            push_python_source_name(&mut out, token.trim_matches('.').to_string());
            token.clear();
            quote = Some(ch);
            continue;
        }
        if ch == '.' || ch == '_' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }
        push_python_source_name(&mut out, token.trim_matches('.').to_string());
        token.clear();
    }
    out
}

fn push_python_source_name(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

#[derive(Clone, Debug)]
struct PythonMatchPatternBindings {
    span: Span,
    subject: String,
    coarse_targets: Vec<String>,
    assignments: Vec<bonsai_lang_api::FlowEvent>,
}

fn collect_python_match_pattern_bindings(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<PythonMatchPatternBindings> {
    let mut out = Vec::new();
    collect_python_match_pattern_bindings_from_node(tree.root_node(), file, src, &mut out);
    out
}

fn collect_python_match_pattern_bindings_from_node(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<PythonMatchPatternBindings>,
) {
    if node.kind() == "match_statement" {
        if let Some(bindings) = collect_python_match_pattern_bindings_for_statement(node, file, src) {
            out.push(bindings);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_match_pattern_bindings_from_node(child, file, src, out);
    }
}

fn collect_python_match_pattern_bindings_for_statement(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<PythonMatchPatternBindings> {
    let subject_node = node.child_by_field_name("subject")?;
    let subject = node_text(&subject_node, src).trim();
    if !python_match_capture_identifier(subject) {
        return None;
    }

    let mut bindings = PythonMatchPatternBindings {
        span: span_of(file, &node),
        subject: subject.to_string(),
        coarse_targets: Vec::new(),
        assignments: Vec::new(),
    };

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_case_clause_pattern_bindings(child, subject, file, src, &mut bindings);
    }

    (!bindings.coarse_targets.is_empty()).then_some(bindings)
}

fn collect_python_case_clause_pattern_bindings(
    case_clause: Node<'_>,
    subject: &str,
    file: FileId,
    src: &[u8],
    bindings: &mut PythonMatchPatternBindings,
) {
    if case_clause.kind() == "case_pattern" {
        collect_python_dict_pattern_bindings(case_clause, subject, file, src, bindings);
        return;
    }

    let mut cursor = case_clause.walk();
    for child in case_clause.named_children(&mut cursor) {
        if child.kind() == "case_pattern" {
            collect_python_dict_pattern_bindings(child, subject, file, src, bindings);
        } else {
            collect_python_case_clause_pattern_bindings(child, subject, file, src, bindings);
        }
    }
}

fn collect_python_dict_pattern_bindings(
    node: Node<'_>,
    subject: &str,
    file: FileId,
    src: &[u8],
    bindings: &mut PythonMatchPatternBindings,
) {
    if node.kind() != "dict_pattern" {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_python_dict_pattern_bindings(child, subject, file, src, bindings);
        }
        return;
    }

    let mut pending_key: Option<String> = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string" => {
                pending_key = python_static_dict_key(node_text(&child, src));
            }
            "case_pattern" => {
                let Some(field) = pending_key.take() else {
                    continue;
                };
                let Some(target) = python_pattern_binding_identifier(child, src) else {
                    continue;
                };
                push_python_source_name(&mut bindings.coarse_targets, target.clone());
                let source = format!("{subject}.{field}");
                if bindings.assignments.iter().any(|event| {
                    matches!(
                        event,
                        bonsai_lang_api::FlowEvent::Assign {
                            span,
                            target: existing_target,
                            source_name: Some(existing_source),
                            ..
                        } if *span == span_of(file, &child)
                            && existing_target == &target
                            && existing_source == &source
                    )
                }) {
                    continue;
                }
                bindings.assignments.push(bonsai_lang_api::FlowEvent::Assign {
                    span: span_of(file, &child),
                    target,
                    source_name: Some(source.clone()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: vec![source],
                    declares_new_binding: false,
                    value_kind: None,
                });
            }
            "splat_pattern" => {
                if let Some(target) = python_splat_pattern_binding_identifier(child, src) {
                    push_python_source_name(&mut bindings.coarse_targets, target);
                }
            }
            _ => {}
        }
    }
}

fn python_pattern_binding_identifier(node: Node<'_>, src: &[u8]) -> Option<String> {
    let text = node_text(&node, src).trim();
    python_match_capture_identifier(text).then(|| text.to_string())
}

fn python_splat_pattern_binding_identifier(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "identifier" {
            continue;
        }
        let text = node_text(&child, src).trim();
        if python_match_capture_identifier(text) {
            return Some(text.to_string());
        }
    }
    let text = node_text(&node, src).trim().trim_start_matches("**").trim();
    python_match_capture_identifier(text).then(|| text.to_string())
}

fn python_match_capture_identifier(text: &str) -> bool {
    if matches!(
        text,
        "" | "_" | "True" | "False" | "None" | "case" | "if" | "in" | "and" | "or" | "not"
    ) {
        return false;
    }
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_alphanumeric())
}

fn augment_python_match_pattern_flow_events(
    events: &mut Vec<bonsai_lang_api::FlowEvent>,
    patterns: &[PythonMatchPatternBindings],
) {
    if patterns.is_empty() {
        return;
    }
    let mut inserted_patterns = Vec::new();
    augment_python_match_pattern_flow_events_inner(events, patterns, &mut inserted_patterns);
    insert_missing_python_match_pattern_assignments(events, patterns, &inserted_patterns);
}

fn augment_python_match_pattern_flow_events_inner(
    events: &mut Vec<bonsai_lang_api::FlowEvent>,
    patterns: &[PythonMatchPatternBindings],
    inserted_patterns: &mut Vec<usize>,
) {
    for event in events.iter_mut() {
        match event {
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_python_match_pattern_flow_events_inner(then_events, patterns, inserted_patterns);
                augment_python_match_pattern_flow_events_inner(else_events, patterns, inserted_patterns);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                augment_python_match_pattern_flow_events_inner(body, patterns, inserted_patterns);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_python_match_pattern_flow_events_inner(body, patterns, inserted_patterns);
                augment_python_match_pattern_flow_events_inner(catch_events, patterns, inserted_patterns);
                augment_python_match_pattern_flow_events_inner(finally_events, patterns, inserted_patterns);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let replacement = if let bonsai_lang_api::FlowEvent::Assign {
            span,
            target,
            source_name,
            source_call,
            ..
        } = &event
        {
            python_match_pattern_replacement(
                patterns,
                *span,
                target,
                source_name.as_deref(),
                source_call.as_deref(),
            )
        } else {
            None
        };

        if let Some(pattern_idx) = replacement {
            if !inserted_patterns.contains(&pattern_idx) {
                rewritten.extend(patterns[pattern_idx].assignments.clone());
                inserted_patterns.push(pattern_idx);
            }
            continue;
        }

        rewritten.push(event);
    }
    *events = rewritten;
}

fn insert_missing_python_match_pattern_assignments(
    events: &mut Vec<bonsai_lang_api::FlowEvent>,
    patterns: &[PythonMatchPatternBindings],
    inserted_patterns: &[usize],
) {
    for (pattern_idx, pattern) in patterns.iter().enumerate() {
        if inserted_patterns.contains(&pattern_idx) {
            continue;
        }
        let insert_at = events
            .iter()
            .position(|event| python_flow_event_span(event).start >= pattern.span.start)
            .unwrap_or(events.len());
        for assignment in pattern.assignments.iter().rev() {
            events.insert(insert_at, assignment.clone());
        }
    }
}

fn python_match_pattern_replacement(
    patterns: &[PythonMatchPatternBindings],
    span: Span,
    target: &str,
    source_name: Option<&str>,
    source_call: Option<&str>,
) -> Option<usize> {
    if source_call.is_some_and(|source_call| !source_call.is_empty()) {
        return None;
    }
    patterns.iter().position(|pattern| {
        pattern.span == span
            && source_name == Some(pattern.subject.as_str())
            && pattern.coarse_targets.iter().any(|candidate| candidate == target)
    })
}

fn python_match_pattern_owned_by_decl(
    pattern: &PythonMatchPatternBindings,
    decl_span: Span,
    callable_spans: &[Span],
) -> bool {
    python_span_owned_by_decl(pattern.span, decl_span, callable_spans)
}

fn python_span_owned_by_decl(span: Span, decl_span: Span, callable_spans: &[Span]) -> bool {
    if !python_span_contains(decl_span, span) {
        return false;
    }
    let Some(owner) = callable_spans
        .iter()
        .copied()
        .filter(|candidate| python_span_contains(*candidate, span))
        .min_by_key(|span| span.end.saturating_sub(span.start))
    else {
        return false;
    };
    owner == decl_span
}

fn python_span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

fn python_flow_event_span(event: &bonsai_lang_api::FlowEvent) -> Span {
    match event {
        bonsai_lang_api::FlowEvent::Assign { span, .. }
        | bonsai_lang_api::FlowEvent::AggregateAssign { span, .. }
        | bonsai_lang_api::FlowEvent::Call { span, .. }
        | bonsai_lang_api::FlowEvent::Return { span, .. }
        | bonsai_lang_api::FlowEvent::Throw { span, .. }
        | bonsai_lang_api::FlowEvent::Branch { span, .. }
        | bonsai_lang_api::FlowEvent::Loop { span, .. }
        | bonsai_lang_api::FlowEvent::Try { span, .. }
        | bonsai_lang_api::FlowEvent::Defer { span, .. }
        | bonsai_lang_api::FlowEvent::Using { span, .. }
        | bonsai_lang_api::FlowEvent::Yield { span, .. }
        | bonsai_lang_api::FlowEvent::Await { span, .. }
        | bonsai_lang_api::FlowEvent::Break { span, .. }
        | bonsai_lang_api::FlowEvent::Continue { span, .. }
        | bonsai_lang_api::FlowEvent::Lifecycle { span, .. } => *span,
    }
}

fn augment_python_dict_flow_events(
    events: &mut Vec<bonsai_lang_api::FlowEvent>,
    source: &str,
    assignment_values: &AssignmentValueIndex,
    assignment_projected_reads: &[(Span, Vec<String>)],
) {
    for event in events.iter_mut() {
        match event {
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_python_dict_flow_events(
                    then_events,
                    source,
                    assignment_values,
                    assignment_projected_reads,
                );
                augment_python_dict_flow_events(
                    else_events,
                    source,
                    assignment_values,
                    assignment_projected_reads,
                );
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                augment_python_dict_flow_events(body, source, assignment_values, assignment_projected_reads);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_python_dict_flow_events(body, source, assignment_values, assignment_projected_reads);
                augment_python_dict_flow_events(
                    catch_events,
                    source,
                    assignment_values,
                    assignment_projected_reads,
                );
                augment_python_dict_flow_events(
                    finally_events,
                    source,
                    assignment_values,
                    assignment_projected_reads,
                );
            }
            _ => {}
        }
    }

    let mut known_fields: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let mut synthetic = Vec::new();
        if let bonsai_lang_api::FlowEvent::Assign { span, target, .. } = &event {
            if let Some(rhs) = assignment_values.rendering(*span, source) {
                for (field, value) in python_dict_field_initializers(rhs) {
                    push_python_source_name(known_fields.entry(target.clone()).or_default(), field.clone());
                    let source_names = python_value_source_names(&value);
                    synthetic.push(bonsai_lang_api::FlowEvent::Assign {
                        span: *span,
                        target: format!("{target}.{field}"),
                        source_name: None,
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names,
                        declares_new_binding: false,
                        value_kind: None,
                    });
                }
                for field_read in assignment_projected_reads
                    .binary_search_by_key(&(span.start, span.end), |(candidate, _)| {
                        (candidate.start, candidate.end)
                    })
                    .ok()
                    .and_then(|index| assignment_projected_reads.get(index))
                    .map_or(&[][..], |(_, reads)| reads.as_slice())
                {
                    synthetic.push(bonsai_lang_api::FlowEvent::Assign {
                        span: *span,
                        target: target.clone(),
                        source_name: Some(field_read.clone()),
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: vec![field_read.clone()],
                        declares_new_binding: false,
                        value_kind: None,
                    });
                }
                for spread in python_dict_spreads(rhs) {
                    if let Some(fields) = known_fields.get(&spread).cloned() {
                        for field in fields {
                            synthetic.push(bonsai_lang_api::FlowEvent::Assign {
                                span: *span,
                                target: format!("{target}.{field}"),
                                source_name: Some(format!("{spread}.{field}")),
                                source_call: None,
                                source_call_args: Vec::new(),
                                source_names: vec![format!("{spread}.{field}")],
                                declares_new_binding: false,
                                value_kind: None,
                            });
                            push_python_source_name(known_fields.entry(target.clone()).or_default(), field);
                        }
                    }
                }
            }
        }
        rewritten.push(event);
        rewritten.extend(synthetic);
    }
    *events = rewritten;
}

/// AST-derived projected reads on assignment right-hand sides.
///
/// The generic expression walker intentionally treats a subscript as an
/// aggregate unless the owning adapter proves its key is static. Python can
/// prove literal string subscripts from the CST, so it emits an additional
/// exact read beside the conservative aggregate fact. Dynamic keys remain
/// aggregate reads and therefore cannot be mistaken for a sibling field.
fn collect_python_assignment_projected_reads(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<String>)> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        if node.kind() == "subscript" {
            if let Some(place) = python_exact_expression_place(node, src) {
                push_python_source_name(out, place);
                return;
            }
        }
        if node.kind() == "call" {
            let selected_field = (|| {
                let function = node.child_by_field_name("function")?;
                let (receiver, method) = python_attribute_parts(function, src)?;
                if method != "get" {
                    return None;
                }
                let arguments = node.child_by_field_name("arguments")?;
                let first = python_argument_nodes(arguments).into_iter().next()?;
                let field = python_static_string(first, src)?;
                let base = python_exact_expression_place(receiver, src)?;
                Some(format!("{base}.{field}"))
            })();
            if let Some(place) = selected_field {
                push_python_source_name(out, place);
                return;
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect(child, src, out);
        }
    }

    let mut reads = Vec::new();
    for assignment in collect_kinds(tree, &["assignment", "named_expression"]) {
        let Some(value) = assignment.child_by_field_name("right") else {
            continue;
        };
        // Aggregate members already lower independently to field writes.
        // Adding their projected operands as a second whole-target
        // assignment would overwrite those fields at the same statement and
        // erase the exact spread/return relation.
        if matches!(value.kind(), "dictionary" | "list" | "set" | "tuple") {
            continue;
        }
        let mut projected = Vec::new();
        collect(value, src, &mut projected);
        if !projected.is_empty() {
            reads.push((span_of(file, &assignment), projected));
        }
    }
    reads.sort_by_key(|(span, _)| (span.start, span.end));
    reads
}

fn python_value_source_names(text: &str) -> Vec<String> {
    let mut out = python_access_tokens(text);
    for field_read in python_static_subscript_field_reads(text) {
        push_python_source_name(&mut out, field_read);
    }
    for field_read in python_static_get_field_reads(text) {
        push_python_source_name(&mut out, field_read);
    }
    out
}

fn python_static_subscript_field_reads(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '[' if depth == 0 => {
                let Some(receiver) = python_receiver_before_index(text, idx) else {
                    depth = depth.saturating_add(1);
                    continue;
                };
                let Some(end) = python_matching_bracket_end(text, idx + 1) else {
                    depth = depth.saturating_add(1);
                    continue;
                };
                if let Some(field) = python_static_dict_key(&text[idx + 1..end]) {
                    push_python_source_name(&mut out, format!("{receiver}.{field}"));
                }
                depth = depth.saturating_add(1);
            }
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    out
}

fn python_static_get_field_reads(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '.' if depth == 0 && text[idx..].starts_with(".get(") => {
                let Some(receiver) = python_receiver_before_dot_get(text, idx) else {
                    continue;
                };
                let args_start = idx + ".get(".len();
                let Some(args_end) = python_matching_paren_end(text, args_start) else {
                    continue;
                };
                let args = &text[args_start..args_end];
                let Some(first_arg) = python_split_top_level(args, ',').into_iter().next() else {
                    continue;
                };
                if let Some(field) = python_static_dict_key(&first_arg) {
                    push_python_source_name(&mut out, format!("{receiver}.{field}"));
                }
            }
            _ => {}
        }
    }
    out
}

fn python_receiver_before_index(text: &str, index_idx: usize) -> Option<String> {
    let prefix = text.get(..index_idx)?;
    let mut start = index_idx;
    for (idx, ch) in prefix.char_indices().rev() {
        if ch == '.' || ch == '_' || ch.is_ascii_alphanumeric() {
            start = idx;
            continue;
        }
        break;
    }
    let receiver = text[start..index_idx].trim_matches('.');
    if receiver.is_empty() {
        None
    } else {
        Some(receiver.to_string())
    }
}

fn python_receiver_before_dot_get(text: &str, dot_idx: usize) -> Option<String> {
    let prefix = text.get(..dot_idx)?;
    let mut start = dot_idx;
    for (idx, ch) in prefix.char_indices().rev() {
        if ch == '.' || ch == '_' || ch.is_ascii_alphanumeric() {
            start = idx;
            continue;
        }
        break;
    }
    let receiver = text[start..dot_idx].trim_matches('.');
    if receiver.is_empty() {
        None
    } else {
        Some(receiver.to_string())
    }
}

fn python_matching_bracket_end(text: &str, args_start: usize) -> Option<usize> {
    python_matching_delimiter_end(text, args_start, '[', ']')
}

fn python_matching_paren_end(text: &str, args_start: usize) -> Option<usize> {
    python_matching_delimiter_end(text, args_start, '(', ')')
}

fn python_matching_delimiter_end(
    text: &str,
    args_start: usize,
    open_delimiter: char,
    close_delimiter: char,
) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 1usize;
    for (idx, ch) in text.char_indices().skip_while(|(idx, _)| *idx < args_start) {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            ch if ch == open_delimiter => depth = depth.saturating_add(1),
            ch if ch == close_delimiter => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn python_dict_field_initializers(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for body in python_dict_bodies(text) {
        for part in python_split_top_level(&body, ',') {
            if part.trim_start().starts_with("**") {
                continue;
            }
            let Some((key, value)) = python_split_top_level_once(&part, ':') else {
                continue;
            };
            let Some(field) = python_static_dict_key(&key) else {
                continue;
            };
            out.push((field, value.trim().to_string()));
        }
    }
    out
}

fn python_dict_spreads(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for body in python_dict_bodies(text) {
        for part in python_split_top_level(&body, ',') {
            let Some(rest) = part.trim_start().strip_prefix("**") else {
                continue;
            };
            for token in python_access_tokens(rest) {
                push_python_source_name(&mut out, token);
            }
        }
    }
    out
}

fn python_dict_bodies(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '{' => stack.push(idx),
            '}' => {
                if let Some(start) = stack.pop() {
                    if start < idx {
                        out.push(text[start + 1..idx].to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn python_split_top_level(text: &str, delimiter: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ch if ch == delimiter && depth == 0 => {
                let part = text[start..idx].trim();
                if !part.is_empty() {
                    out.push(part.to_string());
                }
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    let part = text[start..].trim();
    if !part.is_empty() {
        out.push(part.to_string());
    }
    out
}

fn python_split_top_level_once(text: &str, delimiter: char) -> Option<(String, String)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ch if ch == delimiter && depth == 0 => {
                return Some((text[..idx].to_string(), text[idx + ch.len_utf8()..].to_string()));
            }
            _ => {}
        }
    }
    None
}

fn python_static_dict_key(text: &str) -> Option<String> {
    let key = text
        .trim()
        .strip_prefix('"')
        .and_then(|part| part.strip_suffix('"'))
        .or_else(|| {
            text.trim()
                .strip_prefix('\'')
                .and_then(|part| part.strip_suffix('\''))
        })?
        .trim();
    if key.is_empty()
        || !key
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !key.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(key.to_string())
}

fn collect_python_parameter_aliases(node: Node<'_>, src: &[u8], out: &mut Vec<TypeAliasBinding>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "typed_parameter" | "typed_default_parameter" => {
                python_typed_parameter_alias(child, src, out);
            }
            "default_parameter" => {
                python_default_parameter_alias(child, src, out);
            }
            // Recurse for nested parameter lists (lambda's `parameters`
            // node sometimes nests under `lambda_parameters`).
            _ => collect_python_parameter_aliases(child, src, out),
        }
    }
}

fn python_typed_parameter_alias(node: Node<'_>, src: &[u8], out: &mut Vec<TypeAliasBinding>) {
    let Some(name_node) = first_named_child_of_kind(node, &["identifier"]) else {
        return;
    };
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return;
    }
    // Default value can name a FastAPI binder which overrides the
    // declared annotation as the resolved-receiver type.
    if let Some(value_node) = node.child_by_field_name("value") {
        if let Some(binder) = python_binder_call_marker(value_node, src) {
            push_python_type_alias(out, &name, &binder);
            return;
        }
    }
    // Type annotation: `name: T` — `type` field, which is a `type` node
    // wrapping a `genericised_type` / `identifier` / etc.
    let type_node = node.child_by_field_name("type");
    if let Some(t) = type_node {
        if let Some(canonical) = canonical_python_type_name(node_text(&t, src)) {
            push_python_type_alias(out, &name, &canonical);
        }
    }
}

fn python_default_parameter_alias(node: Node<'_>, src: &[u8], out: &mut Vec<TypeAliasBinding>) {
    // `name = Body(...)` (no annotation); FastAPI binder still
    // surfaces a meaningful receiver type.
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return;
    }
    if let Some(value_node) = node.child_by_field_name("value") {
        if let Some(binder) = python_binder_call_marker(value_node, src) {
            push_python_type_alias(out, &name, &binder);
        }
    }
}

/// When `value` is a call expression whose callee is one of the
/// FastAPI / Starlette parameter-binder names (`Body`, `Depends`,
/// `Query`, …), return the binder's name so the matcher can route
/// the parameter through `attribute: [Body, …]` rules.
fn python_binder_call_marker(value: Node<'_>, src: &[u8]) -> Option<String> {
    if value.kind() != "call" {
        return None;
    }
    let function = value.child_by_field_name("function")?;
    let text = node_text(&function, src);
    let bare = text.rsplit('.').next().unwrap_or(text).trim();
    if FASTAPI_BINDER_MARKERS.contains(&bare) {
        return Some(bare.to_string());
    }
    None
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kinds: &[&str]) -> Option<Node<'a>> {
    let count = node.named_child_count();
    for i in 0..count {
        let idx = u32::try_from(i).ok()?;
        let child = node.named_child(idx)?;
        if kinds.contains(&child.kind()) {
            return Some(child);
        }
    }
    None
}

/// Strip generics / unions / subscripts down to the leftmost
/// receiver-shaped identifier. `List[str]` → `List`,
/// `Optional[Request]` → `Optional`, `dict[str, int]` → `dict`.
/// The matcher resolves through the canonical-shape table for
/// generic shapes when relevant.
fn canonical_python_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().split('|').next().unwrap_or(raw).trim();
    let head = trimmed.split('[').next().unwrap_or(trimmed).trim();
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

fn push_python_type_alias(out: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    out.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

fn dedup_python_type_aliases(out: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    out.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}

/// Walk every `class_definition` once and record the bare base-type
/// names listed in the parenthesized parent list. `class C(A, B):`
/// → `[("A".into(), "B".into())]` keyed by the class decl's span.
fn collect_python_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, &["class_definition"]) {
        let Some(superclasses) = class_node.child_by_field_name("superclasses") else {
            continue;
        };
        let mut bases: Vec<String> = Vec::new();
        let count = superclasses.named_child_count();
        for i in 0..count {
            let Some(idx) = u32::try_from(i).ok() else {
                continue;
            };
            let Some(child) = superclasses.named_child(idx) else {
                continue;
            };
            // Skip kwargs and other non-base entries (`metaclass=Foo`).
            if child.kind() == "keyword_argument" {
                continue;
            }
            let raw = node_text(&child, src);
            if let Some(canonical) = canonical_python_type_name(raw) {
                if !bases.iter().any(|b| b == &canonical) {
                    bases.push(canonical);
                }
            }
        }
        if !bases.is_empty() {
            out.push((span_of(file, &class_node), bases));
        }
    }
    out
}

fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut out = Vec::new();
    // `import X` / `import X as Y` — `import_statement` with one or more
    // `name:` children, each either a `dotted_name` or an
    // `aliased_import` (name + alias).
    for import_node in collect_kinds(tree, &["import_statement"]) {
        let mut cursor = import_node.walk();
        for child in import_node.named_children(&mut cursor) {
            // Two shapes: `import X` (dotted_name) or `import X as Y` (aliased_import).
            let (module_node, alias_text) = if child.kind() == "aliased_import" {
                let module_field = child.child_by_field_name("name");
                let alias_field = child
                    .child_by_field_name("alias")
                    .map(|alias_node| node_text(&alias_node, src).to_string());
                (module_field, alias_field)
            } else if child.kind() == "dotted_name" {
                (Some(child), None)
            } else {
                continue;
            };
            let Some(module_name_node) = module_node else {
                continue;
            };
            let module_name = node_text(&module_name_node, src).trim().to_string();
            if module_name.is_empty() {
                continue;
            }
            // Bare `import X` and `import X.Y` bind the FIRST segment
            // as the local name (`X` in both forms) — Python imports
            // a module by binding its head, not its leaf. Without a
            // self-binding alias here, the resolver cannot rewrite
            // `service.load_file(...)` through the workspace
            // `service` module, so cross-module edges from
            // `import`-form callers stay invisible. The `import X.Y
            // as Z` form already supplied an alias and skips this
            // fallback; wildcard imports never apply because
            // `import *` isn't a Python `import_statement` shape
            // (only `from X import *` is).
            let alias = alias_text.or_else(|| {
                module_name
                    .split('.')
                    .next()
                    .map(str::trim)
                    .filter(|leaf| !leaf.is_empty())
                    .map(str::to_string)
            });
            out.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module_name,
                alias,
                is_wildcard: false,
                original_name: None,
                scope: ImportScope::Module,
            });
        }
    }
    // `from X import Y [as Z]` / `from . import Y` — emit one ImportSpec
    // per imported symbol (`from x import y as z` → original=y, alias=z).
    for from_import_node in collect_kinds(tree, &["import_from_statement"]) {
        let Some(module_node) = from_import_node.child_by_field_name("module_name") else {
            continue;
        };
        let module_name = node_text(&module_node, src).trim().to_string();
        let mut cursor = from_import_node.walk();
        // (original_name, alias) pairs — one per imported symbol.
        let mut imported_symbols: Vec<(Option<String>, Option<String>)> = Vec::new();
        let mut is_wildcard = false;
        for child in from_import_node.named_children(&mut cursor) {
            // Skip the module child itself; we already captured it above.
            if child.id() == module_node.id() {
                continue;
            }
            if child.kind() == "wildcard_import" {
                is_wildcard = true;
                continue;
            }
            if child.kind() == "aliased_import" {
                let original_name = child
                    .child_by_field_name("name")
                    .map(|name_node| node_text(&name_node, src).to_string());
                let alias_text = child
                    .child_by_field_name("alias")
                    .map(|alias_node| node_text(&alias_node, src).to_string());
                imported_symbols.push((original_name, alias_text));
            } else if child.kind() == "dotted_name" {
                imported_symbols.push((Some(node_text(&child, src).to_string()), None));
            }
        }
        // Bare `from X import *` — emit a single wildcard ImportSpec.
        if imported_symbols.is_empty() {
            out.push(ImportSpec {
                span: span_of(file, &from_import_node),
                module: module_name,
                alias: None,
                is_wildcard,
                original_name: None,
                scope: ImportScope::Module,
            });
        } else {
            // One ImportSpec per imported symbol so call resolution can
            // bind `y` to the unaliased original name and `z` to the alias.
            for (original_name, alias_text) in imported_symbols {
                out.push(ImportSpec {
                    span: span_of(file, &from_import_node),
                    module: module_name.clone(),
                    alias: alias_text,
                    is_wildcard,
                    original_name,
                    scope: ImportScope::Module,
                });
            }
        }
    }
    out
}

/// Rewrite Python's reflective `getattr(obj, "literal", default)` /
/// `setattr(obj, "literal", value)` / `hasattr(obj, "literal")` shapes
/// into the equivalent attribute access. The kit emits the call as
/// `Call { name: "getattr", args: [{value_text: "obj"}, {value_text:
/// "\"literal\""}, ...] }`. We rewrite to the synthesized call
/// `Call { name: "obj.literal", receiver: Some("obj"), args: [...] }`
/// so the resolver narrows the dispatch like a normal method call.
///
/// This is the constant-string sub-case of P2.1; dynamic forms
/// (`getattr(obj, runtime_name)`) stay unrewritten and the engine's
/// `reflection: Unsupported` rule continues to gate them out.
///
/// The transformation lives in the Python adapter (not the engine)
/// because `getattr` / `setattr` / `hasattr` are Python-language-
/// specific names. The taint engine sees the rewritten call as just
/// another method dispatch.
fn rewrite_python_constant_reflection(events: &mut [bonsai_lang_api::FlowEvent]) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            // `getattr(obj, "literal")` / `setattr(obj, "literal", v)` /
            // `hasattr(obj, "literal")` — only the first two args matter
            // for the rewrite.
            FlowEvent::Call {
                name, receiver, args, ..
            } if matches!(name.as_str(), "getattr" | "setattr" | "hasattr") && args.len() >= 2 => {
                let receiver_arg = &args[0];
                let attr_arg = &args[1];
                // Skip dynamic forms — the rule-load gate still rejects
                // rules anchored on the reflective shape, which is the
                // safe fallback when the attribute name isn't constant.
                if !is_python_string_literal(&attr_arg.value_text) {
                    continue;
                }
                let attr_name = strip_python_string_quotes(&attr_arg.value_text);
                if attr_name.is_empty() {
                    continue;
                }
                let receiver_text = receiver_arg.value_text.trim();
                if receiver_text.is_empty() {
                    continue;
                }
                // Synthesize the direct attribute call: `getattr(obj,
                // "process")(...)` becomes `obj.process(...)` from the
                // engine's perspective.
                *name = format!("{receiver_text}.{attr_name}");
                *receiver = Some(receiver_text.to_string());
            }
            // Reflective calls can hide in any container — recurse.
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_python_constant_reflection(then_events);
                rewrite_python_constant_reflection(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_python_constant_reflection(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_python_constant_reflection(body);
                rewrite_python_constant_reflection(catch_events);
                rewrite_python_constant_reflection(finally_events);
            }
            _ => {}
        }
    }
}

/// True iff `text` looks like a Python string literal. Accepts both
/// double- and single-quoted forms (Python treats them equivalently);
/// rejects f-strings, raw strings, and any non-quoted identifier.
fn is_python_string_literal(text: &str) -> bool {
    let trimmed = text.trim();
    let starts_with_quote = trimmed.starts_with('"') || trimmed.starts_with('\'');
    let ends_with_quote = trimmed.ends_with('"') || trimmed.ends_with('\'');
    starts_with_quote && ends_with_quote && trimmed.len() >= 2
}

/// Strip the outermost matching quote pair from a Python string literal.
/// Caller is expected to have already validated the input via
/// `is_python_string_literal`; this just yields the inner text.
fn strip_python_string_quotes(text: &str) -> String {
    text.trim()
        .trim_start_matches(['"', '\''])
        .trim_end_matches(['"', '\''])
        .to_string()
}

/// Rewrite `g.send(value)` (Python's coroutine resume) into a
/// synthesized direct call to the generator factory whose result `g`
/// was bound to. After the rewrite, the engine's normal
/// interprocedural propagation taints the generator function's body
/// when `value` is tainted.
///
/// Pattern recognized:
///   `g = gen()`             ← Assign with source_call: "gen"
///   `g.send(arg)`           ← Call with name: "g.send", receiver: "g"
///
/// Effect: rewrite the second event into
///   `Call { name: "gen", args: [arg] }`
///
/// Generators without a recognizable factory binding are left alone.
/// Dynamic forms (`gens[i].send(...)`) likewise stay unrewritten;
/// the engine's existing yield-as-return-equivalent model still
/// applies for those.
#[allow(clippy::case_sensitive_file_extension_comparisons)] // `.send` is a method name, not an extension
fn rewrite_python_generator_send(events: &mut [bonsai_lang_api::FlowEvent]) {
    use bonsai_lang_api::{CallKind, FlowEvent};
    use std::collections::HashMap;
    let mut gen_factories: HashMap<String, String> = HashMap::new();
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                target, source_call, ..
            } => {
                if let Some(call) = source_call {
                    // Only register simple bare-identifier factories
                    // — `gen()` not `pkg.gen(args)` — to keep the
                    // rewrite low-risk. The right-hand call must
                    // also have no qualifying receiver.
                    if !call.contains('.') && !call.is_empty() {
                        gen_factories.insert(target.clone(), call.clone());
                    }
                }
            }
            FlowEvent::Call {
                name,
                receiver,
                args,
                call_kind,
                ..
            } => {
                let Some(rcv) = receiver.clone() else {
                    continue;
                };
                if !name.ends_with(".send") {
                    continue;
                }
                let Some(factory) = gen_factories.get(&rcv) else {
                    continue;
                };
                name.clone_from(factory);
                *receiver = None;
                *call_kind = CallKind::Function;
                let _ = args; // first arg becomes the resumed value, propagated as-is.
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_python_generator_send(then_events);
                rewrite_python_generator_send(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_python_generator_send(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_python_generator_send(body);
                rewrite_python_generator_send(catch_events);
                rewrite_python_generator_send(finally_events);
            }
            _ => {}
        }
    }
}
