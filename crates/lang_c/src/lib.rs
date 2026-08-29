//! C language adapter.
mod preprocessor;

use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        c_family_preproc_imports, collect_kinds, collect_param_type_aliases, first_named_child_of_kind,
        language_from_pack, node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, CompilerGuardFact, Decl, DeclIndex, DeclKind,
    FlowEvent, GrammarHandler, GuardedValueFilterFact, ImportIndex, ImportSpec, LanguageAdapter,
    LanguageCapabilities, LanguageId, ModulePath, TypeAliasBinding, TypeAliasVocabulary, Visibility,
    EMPTY_HANDLER,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("c");
const PACK_NAME: &str = "c";

fn c_indirect_place_operand(node: Node<'_>) -> Option<Node<'_>> {
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

const HANDLER: GrammarHandler = GrammarHandler {
    literal_value_kinds: &["null", "true", "false"],
    string_literal_kinds: &["string_literal", "char_literal"],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["///", "//!", "/**"],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["parameter_list"],
    parameter_kinds: &["parameter_declaration"],
    parameter_annotation_kinds: &["attribute"],
    variadic_parameter_kinds: &["variadic_parameter"],
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
    transparent_call_wrapper_kinds: &["field_expression", "parenthesized_expression"],
    single_expression_group_kinds: &[],
    assignment_target_wrapper_kinds: &[
        "init_declarator",
        "function_declarator",
        "pointer_declarator",
        "parenthesized_declarator",
    ],
    binding_declaration_keyword_spellings: &["auto", "const"],
    fn_kinds: &["function_definition"],
    if_kinds: &["if_statement", "conditional_expression", "switch_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["compound_statement", "expression_statement"],
    loop_update_field_names: &["update"],
    branch_arm_kinds: &["compound_statement", "expression_statement"],
    exclusive_branch_arm_kinds: &["case_statement"],
    fallthrough_branch_arm_kinds: &["case_statement"],
    for_kinds: &["for_statement"],
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    call_kinds: &["call_expression"],
    call_callee_field_names: &["function"],
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list"],
    writeback_operand_field_names: &["argument"],
    indirect_place_operand_extractor: Some(c_indirect_place_operand),
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: Some(c_argument_passing_mode),
    expression_value_kind_extractor: Some(c_expression_value_kind),
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    value_free_expression_kinds: &["sizeof_expression", "alignof_expression"],
    call_ref_kinds: &["call_expression"],
    member_expression_kinds: &["field_expression"],
    subscript_expression_kinds: &["subscript_expression"],
    member_base_field_names: &["argument"],
    member_name_field_names: &["field"],
    subscript_base_field_names: &["argument"],
    subscript_index_field_names: &["index"],
    syntax_error_tolerant_call_names: &["va_arg", "__builtin_va_arg"],
    class_kinds: &["struct_specifier", "union_specifier"],
    class_decl_kinds: &[
        ("struct_specifier", bonsai_lang_api::DeclKind::Struct),
        ("union_specifier", bonsai_lang_api::DeclKind::Struct),
    ],
    assignment_kinds: &["assignment_expression", "init_declarator"],
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="],
    positional_aggregate_assignment_kinds: &["init_declarator"],
    positional_aggregate_value_kinds: &["initializer_list"],
    return_kinds: &["return_statement"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    nested_type_ownership: false,
    ..EMPTY_HANDLER
};

/// Tree-sitter syntax inspected by C-specific lowering outside `HANDLER`.
/// Keeping this inventory executable makes grammar upgrades fail loudly
/// instead of silently disabling a guarded-filter or visibility fact.
const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[
    ("custom lowering", "*"),
    ("custom lowering", "&"),
    ("custom lowering", "array_declarator"),
    ("custom lowering", "assignment_expression"),
    ("custom lowering", "binary_expression"),
    ("custom lowering", "call_expression"),
    ("custom lowering", "char_literal"),
    ("custom lowering", "compound_statement"),
    ("custom lowering", "do_statement"),
    ("custom lowering", "ERROR"),
    ("custom lowering", "for_statement"),
    ("custom lowering", "function_definition"),
    ("custom lowering", "identifier"),
    ("custom lowering", "if_statement"),
    ("custom lowering", "init_declarator"),
    ("custom lowering", "initializer_list"),
    ("custom lowering", "number_literal"),
    ("custom lowering", "parenthesized_expression"),
    ("custom lowering", "pointer_expression"),
    ("custom lowering", "storage_class_specifier"),
    ("custom lowering", "string_literal"),
    ("custom lowering", "subscript_expression"),
    ("custom lowering", "unary_expression"),
    ("custom lowering", "while_statement"),
];

fn c_expression_value_kind(node: Node<'_>, _src: &[u8]) -> Option<bonsai_lang_api::AssignValueKind> {
    matches!(node.kind(), "string_literal" | "char_literal" | "number_literal")
        .then_some(bonsai_lang_api::AssignValueKind::Literal)
}

fn c_argument_passing_mode(argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
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

/// C function parameters: every binding is `Type declarator`. The
/// kit's `param_alias_from_node` consults `child_by_field_name("type")`
/// for the type, falls back to `child_by_field_name("declarator")`
/// for the binding identifier (`leaf_identifier_text` walks the
/// pointer/array declarator chain to find the inner identifier),
/// and accepts lowercase primitive types (`int`, `char`, `void`,
/// `unsigned`) per the cross-language `canonical_short_type_name`.
const C_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition"],
    param_kinds: &["parameter_declaration"],
    name_field: "declarator",
    type_field: "type",
};

/// Zero-sized adapter handle; all state lives in the shared parser pack.
#[derive(Debug, Default, Copy, Clone)]
pub struct CAdapter;

impl CAdapter {
    /// Construct a fresh adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for CAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "C"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["c", "h"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn parse_context_fingerprint(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
    ) -> u64 {
        bonsai_lang_api::c_family_preprocessor_context_fingerprint(snapshot, vfs)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        self.parse_recovery_edit_batches(snapshot, vfs, tree)
            .into_iter()
            .flatten()
            .collect()
    }
    fn parse_recovery_edit_batches(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<Vec<bonsai_lang_api::ParseRecoveryEdit>> {
        let conditionals = if tree.root_node().has_error() {
            preprocessor::PreprocessorMap::parse(snapshot.text.as_ref())
                .branch_free_directive_spans()
                .into_iter()
                .map(|span| bonsai_lang_api::ParseRecoveryEdit::new(span.start, span.end))
                .collect()
        } else {
            Vec::new()
        };
        let declarations = bonsai_lang_api::c_family_declaration_macro_recovery_edits(
            snapshot,
            vfs,
            tree,
            &["va_arg", "__builtin_va_arg"],
        );
        [conditionals, declarations]
            .into_iter()
            .filter(|batch| !batch.is_empty())
            .collect()
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Macros: tree-sitter-c parses `STR_CPY(dest, src)` and
        // `LOG(fmt, ...)` as ordinary `call_expression` nodes, so the
        // call-graph layer narrows their callee resolution by name.
        // `#define` expansion is intentionally not performed (would
        // require a real preprocessor pass), so macros that expand to
        // multi-statement bodies still degrade to `OverApproximate`.
        // The `Partial` claim covers the call-shape recognition that
        // already works.
        LanguageCapabilities {
            macros: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
            same_directory_unqualified_calls: true,
            build_target_linkage: true,
            callable_declaration_family: bonsai_lang_api::CallableDeclarationFamily::SameSignature,
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
                ..DeclIndex::default()
            };
        };
        let src = snapshot.text.as_bytes();
        let mut decl_index = decl_index_from_tree_with_handler(file, src, &tree, &HANDLER);
        append_recovered_error_wrapped_functions(&mut decl_index, file, &tree, src);
        // Populate qualified_name + module_path + visibility from C
        // syntax. C has no language-level module boundary, so the
        // file stem is the closest semantic anchor — that's what
        // distinguishes two `static void error(...)` decls in
        // unrelated translation units. See
        // `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        let static_function_names = collect_static_function_names(&tree, src);
        for decl in &mut decl_index.defs {
            // `static` storage class scopes the symbol to this TU.
            if static_function_names.contains(&decl.name) {
                decl.visibility = Visibility::Private;
            }
        }
        // Per-decl `type_aliases` from typed parameters. C is fully
        // typed — every parameter declares both a type and a
        // declarator that resolves to the binding identifier. The
        // kit helper handles the declarator-walking that strips
        // pointer / array wrappers down to the inner name. Brings
        // the C adapter in lockstep with the rest per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        let valid_function_names = collect_function_definition_names_with_body(file, &tree, src);
        decl_index.defs.retain(|decl| {
            if !matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            ) {
                return true;
            }
            !is_c_reserved_decl_name(&decl.name)
                && valid_function_names
                    .get(&decl.span)
                    .is_some_and(|name| name == &decl.name)
        });
        // Phase-6 return-type extraction: `T foo() {}` populates
        // `Decl.return_type` for `apply_assign_call_result_types`.
        // C's `function_definition` uses the `type` field for return type.
        bonsai_lang_api::populate_decl_return_types(&mut decl_index, &tree, src, &HANDLER);
        bonsai_lang_api::kit::inject_c_family_function_pointer_aliases(&mut decl_index, &tree, src, file);
        let alias_map = collect_param_type_aliases(&tree, file, src, &C_TYPE_ALIASES);
        for decl in &mut decl_index.defs {
            if let Some(aliases) = alias_map.get(&decl.span) {
                decl.type_aliases = aliases.clone();
            }
        }
        mark_c_addressed_aggregate_arguments(&mut decl_index, &tree, src);
        decl_index.guarded_value_filters = c_guarded_value_filter_facts(&decl_index, &tree, file, src);
        decl_index.compiler_guards = c_numeric_upper_bound_call_guards(&tree, file, src);
        decl_index
            .compiler_guards
            .extend(c_compound_predicate_call_guards(&tree, file, src));
        decl_index.compiler_guards.sort_by(|left, right| {
            (
                left.function_span.start,
                left.guarded_call_span.start,
                left.capability.as_str(),
                left.evidence.as_slice(),
            )
                .cmp(&(
                    right.function_span.start,
                    right.guarded_call_span.start,
                    right.capability.as_str(),
                    right.evidence.as_slice(),
                ))
        });
        decl_index.compiler_guards.dedup();
        decl_index.finite_literal_selections = decl_index
            .defs
            .iter()
            .filter_map(|decl| {
                bonsai_lang_api::kit::complete_finite_literal_return_span(&decl.flow_events).map(
                    |selection_span| bonsai_lang_api::FiniteLiteralSelectionFact {
                        selection_span,
                        assignment_span: None,
                        target: None,
                        call_span: None,
                        argument_index: None,
                    },
                )
            })
            .collect();
        bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut decl_index.finite_literal_selections);
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
        }
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Lower C's element-at-a-time filtered-buffer construction without assigning
/// security meaning to the predicate call. A security rule must match the
/// exact predicate span before this compiler fact can receive sanitizer
/// credit.
fn c_guarded_value_filter_facts(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<GuardedValueFilterFact> {
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let function_span = span_of(file, &function);
        if !index.defs.iter().any(|decl| decl.span == function_span) {
            continue;
        }
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let assignments = descendant_nodes_of_kind(body, "assignment_expression");
        let initializers = descendant_nodes_of_kind(body, "init_declarator");
        for branch in descendant_nodes_of_kind(body, "if_statement") {
            if !has_loop_ancestor_within(branch, function) {
                continue;
            }
            let Some(condition) = branch.child_by_field_name("condition") else {
                continue;
            };
            let mut predicates = Vec::new();
            collect_positively_required_predicate_calls(condition, src, &mut predicates);
            let Some(consequence) = branch.child_by_field_name("consequence") else {
                continue;
            };
            for predicate in predicates {
                let Some(input_place) = predicate_subscript_input(predicate, src) else {
                    continue;
                };
                for write in descendant_nodes_of_kind(consequence, "assignment_expression") {
                    let Some((output_place, copied_input)) = filtered_element_copy(write, src) else {
                        continue;
                    };
                    if copied_input != input_place
                        || !output_is_zero_initialized(&initializers, &output_place, write.start_byte(), src)
                        || !output_has_only_filtered_or_zero_writes(&assignments, &output_place, write, src)
                        || !output_is_zero_terminated_after(
                            &assignments,
                            &output_place,
                            write.end_byte(),
                            src,
                        )
                    {
                        continue;
                    }
                    let predicate_callee = predicate.child_by_field_name("function").unwrap_or(predicate);
                    facts.push(GuardedValueFilterFact {
                        function_span,
                        predicate_call_span: span_of(file, &predicate_callee),
                        write_span: span_of(file, &write),
                        input_place: input_place.clone(),
                        output_place,
                    });
                }
            }
        }
    }
    facts.sort_by(|left, right| {
        (
            left.function_span.start,
            left.predicate_call_span.start,
            left.write_span.start,
            left.input_place.as_str(),
            left.output_place.as_str(),
        )
            .cmp(&(
                right.function_span.start,
                right.predicate_call_span.start,
                right.write_span.start,
                right.input_place.as_str(),
                right.output_place.as_str(),
            ))
    });
    facts.dedup();
    facts
}

const C_GUARD_CALL_ARGUMENT_NUMERIC_UPPER_BOUND: &str = "call-argument.numeric-upper-bound";
const C_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST: &str = "terminal-predicate.compound-static-allowlist";

#[derive(Clone)]
struct CCompoundPredicateSummary {
    name: String,
    evidence: Vec<String>,
}

/// Relate an arbitrary local boolean predicate to later calls without giving
/// any provider or security meaning to its spelling. The emitted evidence is
/// a normalized description of exact syntax: a static prefix comparison, a
/// derived token, finite literal collection membership, complete boolean
/// returns, and exact sibling-call configuration. Rules decide whether those
/// operations form a security boundary for a particular sink.
fn c_compound_predicate_call_guards(tree: &Tree, file: FileId, src: &[u8]) -> Vec<CompilerGuardFact> {
    let static_collections = c_static_string_collections(tree, src);
    let summaries = collect_kinds(tree, &["function_definition"])
        .into_iter()
        .filter_map(|function| c_compound_predicate_summary(function, src, &static_collections))
        .collect::<Vec<_>>();
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let calls = descendant_nodes_of_kind(body, "call_expression");
        for branch in descendant_nodes_of_kind(body, "if_statement") {
            let (Some(condition), Some(consequence)) = (
                branch.child_by_field_name("condition"),
                branch.child_by_field_name("consequence"),
            ) else {
                continue;
            };
            if !c_statement_is_terminal(consequence) {
                continue;
            }
            let Some(predicate_call) = c_negated_single_call(condition, src) else {
                continue;
            };
            let Some(predicate_name) = predicate_call
                .child_by_field_name("function")
                .map(|node| node_text(&node, src).trim())
            else {
                continue;
            };
            let matching = summaries
                .iter()
                .filter(|summary| summary.name == predicate_name)
                .collect::<Vec<_>>();
            let [summary] = matching.as_slice() else {
                continue;
            };
            let predicate_args = predicate_call
                .child_by_field_name("arguments")
                .map(direct_named_children)
                .unwrap_or_default();
            let [predicate_input] = predicate_args.as_slice() else {
                continue;
            };
            let predicate_input_text = node_text(predicate_input, src).trim();
            for guarded_call in calls
                .iter()
                .copied()
                .filter(|call| call.start_byte() > branch.end_byte())
            {
                let Some(callee) = guarded_call.child_by_field_name("function") else {
                    continue;
                };
                let guarded_args = guarded_call
                    .child_by_field_name("arguments")
                    .map(direct_named_children)
                    .unwrap_or_default();
                let guarded_relations = guarded_args
                    .iter()
                    .enumerate()
                    .filter(|(_, argument)| node_text(argument, src).trim() == predicate_input_text)
                    .map(|(index, _)| format!("guarded-argument:{index}=predicate-argument:0"))
                    .collect::<Vec<_>>();
                if guarded_relations.is_empty() {
                    continue;
                }
                let mut evidence = summary.evidence.clone();
                evidence.extend(guarded_relations);
                evidence.extend(c_related_static_call_evidence(guarded_call, &calls, src));
                evidence.sort();
                evidence.dedup();
                facts.push(CompilerGuardFact {
                    function_span: span_of(file, &function),
                    guarded_call_span: span_of(file, &callee),
                    proof_span: span_of(file, &branch),
                    capability: C_GUARD_TERMINAL_COMPOUND_STATIC_ALLOWLIST.to_string(),
                    evidence,
                });
            }
        }
    }
    facts
}

fn c_compound_predicate_summary(
    function: Node<'_>,
    src: &[u8],
    static_collections: &std::collections::HashMap<String, Vec<String>>,
) -> Option<CCompoundPredicateSummary> {
    let name = c_function_name(function, src)?;
    let parameters = function
        .child_by_field_name("declarator")
        .and_then(|declarator| first_named_child_of_kind(&declarator, "parameter_list"))?
        .named_children(&mut function.walk())
        .filter(|node| node.kind() == "parameter_declaration")
        .filter_map(|parameter| {
            parameter
                .child_by_field_name("declarator")
                .and_then(c_declarator_binding)
                .map(|binding| node_text(&binding, src).trim().to_string())
        })
        .collect::<Vec<_>>();
    let [parameter] = parameters.as_slice() else {
        return None;
    };
    let body = function.child_by_field_name("body")?;
    let returns = descendant_nodes_of_kind(body, "return_statement");
    if returns.len() < 3
        || returns.iter().any(|statement| {
            first_named_child(*statement).is_none_or(|value| {
                value.kind() != "number_literal" || !matches!(node_text(&value, src).trim(), "0" | "1")
            })
        })
    {
        return None;
    }
    let final_return = direct_named_children(body).last().copied()?;
    if final_return.kind() != "return_statement"
        || first_named_child(final_return).is_none_or(|value| node_text(&value, src).trim() != "0")
    {
        return None;
    }
    let prefix = descendant_nodes_of_kind(body, "if_statement")
        .into_iter()
        .find_map(|branch| {
            let consequence = branch.child_by_field_name("consequence")?;
            if !c_return_has_literal(consequence, "0", src) {
                return None;
            }
            let condition = branch.child_by_field_name("condition")?;
            descendant_nodes_of_kind(condition, "call_expression")
                .into_iter()
                .find_map(|call| {
                    let callee = call.child_by_field_name("function")?;
                    let args = direct_named_children(call.child_by_field_name("arguments")?);
                    let [input, literal, length] = args.as_slice() else {
                        return None;
                    };
                    if node_text(input, src).trim() != parameter || literal.kind() != "string_literal" {
                        return None;
                    }
                    let prefix = c_static_string(*literal, src)?;
                    let length = c_integer_literal(*length, src)?;
                    (u128::try_from(prefix.len()).ok()? == length)
                        .then(|| (node_text(&callee, src).trim().to_string(), prefix, length, branch))
                })
        })?;
    let mut host_bindings = descendant_nodes_of_kind(body, "assignment_expression");
    host_bindings.extend(descendant_nodes_of_kind(body, "init_declarator"));
    let host = host_bindings.into_iter().find_map(|assignment| {
        let (left, right) = (
            assignment
                .child_by_field_name("left")
                .or_else(|| assignment.child_by_field_name("declarator"))?,
            assignment
                .child_by_field_name("right")
                .or_else(|| assignment.child_by_field_name("value"))?,
        );
        let left = c_declarator_binding(left)?;
        if right.kind() != "binary_expression" || binary_operator_text(right, src) != Some("+") {
            return None;
        }
        let (base, offset) = (
            right.child_by_field_name("left")?,
            right.child_by_field_name("right")?,
        );
        (node_text(&base, src).trim() == parameter && c_integer_literal(offset, src) == Some(prefix.2))
            .then(|| node_text(&left, src).trim().to_string())
    })?;
    let membership = descendant_nodes_of_kind(body, "if_statement")
        .into_iter()
        .filter(|branch| {
            branch
                .child_by_field_name("consequence")
                .is_some_and(|consequence| c_return_has_literal(consequence, "1", src))
        })
        .find_map(|branch| {
            let condition = branch.child_by_field_name("condition")?;
            let chars = descendant_nodes_of_kind(condition, "char_literal")
                .into_iter()
                .filter_map(|literal| c_static_char(literal, src))
                .collect::<std::collections::BTreeSet<_>>();
            if !chars.contains(&'/') || !chars.contains(&'\0') {
                return None;
            }
            descendant_nodes_of_kind(condition, "call_expression")
                .into_iter()
                .find_map(|call| {
                    let callee = call.child_by_field_name("function")?;
                    let args = direct_named_children(call.child_by_field_name("arguments")?);
                    if args.len() < 2 || node_text(&args[0], src).trim() != host {
                        return None;
                    }
                    let collection = c_subscript_base_identifier(args[1], src)?;
                    static_collections
                        .contains_key(&collection)
                        .then(|| (node_text(&callee, src).trim().to_string(), collection, branch))
                })
        })?;
    let mut evidence = vec![
        "predicate-complete:true".to_string(),
        "finite-static-string-membership:true".to_string(),
        format!("prefix-call:{}", prefix.0),
        format!("prefix-value:string:{}", prefix.1),
        format!("prefix-length:number:{}", prefix.2),
        format!("membership-call:{}", membership.0),
        "membership-token-boundary:true".to_string(),
    ];
    evidence.sort();
    Some(CCompoundPredicateSummary { name, evidence })
}

fn c_function_name(function: Node<'_>, src: &[u8]) -> Option<String> {
    let declarator = function.child_by_field_name("declarator")?;
    let function_declarator = if declarator.kind() == "function_declarator" {
        declarator
    } else {
        first_named_child_of_kind(&declarator, "function_declarator")?
    };
    let binding = c_declarator_binding(function_declarator.child_by_field_name("declarator")?)?;
    Some(node_text(&binding, src).trim().to_string())
}

fn c_negated_single_call<'tree>(condition: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    let condition = c_unwrap_parentheses(condition);
    if condition.kind() != "unary_expression" || node_text(&condition, src).trim().is_empty() {
        return None;
    }
    let argument = condition.child_by_field_name("argument")?;
    (node_text(&condition, src).trim_start().starts_with('!') && argument.kind() == "call_expression")
        .then_some(argument)
}

fn c_return_has_literal(statement: Node<'_>, literal: &str, src: &[u8]) -> bool {
    let return_statement = if statement.kind() == "return_statement" {
        Some(statement)
    } else if statement.kind() == "compound_statement" {
        direct_named_children(statement)
            .into_iter()
            .find(|node| node.kind() == "return_statement")
    } else {
        None
    };
    return_statement
        .and_then(first_named_child)
        .is_some_and(|value| node_text(&value, src).trim() == literal)
}

fn c_static_string(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains('\\')).then(|| inner.to_string())
}

fn c_static_char(node: Node<'_>, src: &[u8]) -> Option<char> {
    match node_text(&node, src).trim() {
        "'/'" => Some('/'),
        "'\\0'" => Some('\0'),
        _ => None,
    }
}

fn c_static_string_collections(tree: &Tree, src: &[u8]) -> std::collections::HashMap<String, Vec<String>> {
    let mut collections = std::collections::HashMap::new();
    for declaration in collect_kinds(tree, &["declaration"])
        .into_iter()
        .filter(|node| !c_has_ancestor_kind(*node, "function_definition"))
    {
        for initializer in descendant_nodes_of_kind(declaration, "init_declarator") {
            let (Some(declarator), Some(value)) = (
                initializer.child_by_field_name("declarator"),
                initializer.child_by_field_name("value"),
            ) else {
                continue;
            };
            if value.kind() != "initializer_list" {
                continue;
            }
            let Some(binding) = c_declarator_binding(declarator) else {
                continue;
            };
            let items = direct_named_children(value);
            let values = items
                .iter()
                .copied()
                .filter_map(|item| c_static_string(item, src))
                .collect::<Vec<_>>();
            if values.is_empty()
                || items.iter().any(|item| {
                    item.kind() != "string_literal"
                        && !(item.kind() == "null" || node_text(item, src).trim() == "NULL")
                })
            {
                continue;
            }
            collections.insert(node_text(&binding, src).trim().to_string(), values);
        }
    }
    collections
}

fn c_has_ancestor_kind(mut node: Node<'_>, kind: &str) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return true;
        }
        node = parent;
    }
    false
}

fn c_subscript_base_identifier(node: Node<'_>, src: &[u8]) -> Option<String> {
    let node = c_unwrap_parentheses(node);
    if node.kind() != "subscript_expression" {
        return None;
    }
    let base = node.child_by_field_name("argument")?;
    (base.kind() == "identifier").then(|| node_text(&base, src).trim().to_string())
}

fn c_related_static_call_evidence(guarded_call: Node<'_>, calls: &[Node<'_>], src: &[u8]) -> Vec<String> {
    let guarded_args = guarded_call
        .child_by_field_name("arguments")
        .map(direct_named_children)
        .unwrap_or_default();
    let Some(guarded_receiver) = guarded_args.first().map(|arg| node_text(arg, src).trim()) else {
        return Vec::new();
    };
    let mut evidence = Vec::new();
    for related in calls.iter().copied().filter(|call| call != &guarded_call) {
        let Some(callee) = related.child_by_field_name("function") else {
            continue;
        };
        let args = related
            .child_by_field_name("arguments")
            .map(direct_named_children)
            .unwrap_or_default();
        if args.first().map(|arg| node_text(arg, src).trim()) != Some(guarded_receiver) {
            continue;
        }
        let name = node_text(&callee, src).trim();
        evidence.push(format!("related-call:{name}:argument:0=guarded-argument:0"));
        for (index, argument) in args.iter().copied().enumerate().skip(1) {
            if let Some(value) = c_static_scalar_evidence(argument, src) {
                evidence.push(format!("related-call:{name}:argument:{index}={value}"));
            }
        }
    }
    evidence
}

fn c_static_scalar_evidence(node: Node<'_>, src: &[u8]) -> Option<String> {
    let node = c_unwrap_parentheses(node);
    match node.kind() {
        "number_literal" => c_integer_literal(node, src).map(|value| format!("number:{value}")),
        "string_literal" => c_static_string(node, src).map(|value| format!("string:{value}")),
        "identifier" => Some(format!("place:{}", node_text(&node, src).trim())),
        _ => None,
    }
}

/// Prove that one call argument is an upper bound for another call argument's
/// destination storage. The adapter deliberately does not name a memory API:
/// it emits argument-role evidence for every exact call shape, and rule data
/// decides which calls and argument positions have security meaning.
fn c_numeric_upper_bound_call_guards(tree: &Tree, file: FileId, src: &[u8]) -> Vec<CompilerGuardFact> {
    let aggregate_fields = c_byte_array_aggregate_fields(tree, src);
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        for call in descendant_nodes_of_kind(body, "call_expression") {
            let Some(callee) = call.child_by_field_name("function") else {
                continue;
            };
            let Some(arguments) = call.child_by_field_name("arguments") else {
                continue;
            };
            let args = direct_named_children(arguments);
            for (destination_index, destination) in args.iter().copied().enumerate() {
                let Some(destination_capacity) =
                    c_byte_storage_capacity(destination, function, &aggregate_fields, src)
                else {
                    continue;
                };
                for (length_index, length) in args.iter().copied().enumerate() {
                    if destination_index == length_index || length.kind() != "identifier" {
                        continue;
                    }
                    let length_name = node_text(&length, src).trim();
                    let Some(proof_span) = c_preceding_numeric_bound_proof(
                        call,
                        function,
                        length_name,
                        destination_capacity,
                        &aggregate_fields,
                        src,
                        file,
                    ) else {
                        continue;
                    };
                    facts.push(CompilerGuardFact {
                        function_span: span_of(file, &function),
                        guarded_call_span: span_of(file, &callee),
                        proof_span,
                        capability: C_GUARD_CALL_ARGUMENT_NUMERIC_UPPER_BOUND.to_string(),
                        evidence: vec![
                            format!("destination-argument:{destination_index}"),
                            format!("length-argument:{length_index}"),
                        ],
                    });
                }
            }
        }
    }
    facts.sort_by(|left, right| {
        (
            left.function_span.start,
            left.guarded_call_span.start,
            left.proof_span.start,
            left.evidence.as_slice(),
        )
            .cmp(&(
                right.function_span.start,
                right.guarded_call_span.start,
                right.proof_span.start,
                right.evidence.as_slice(),
            ))
    });
    facts.dedup();
    facts
}

fn c_aggregate_type_names(tree: &Tree, src: &[u8]) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for definition in collect_kinds(tree, &["type_definition"]) {
        let (Some(aggregate), Some(alias)) = (
            definition.child_by_field_name("type"),
            definition.child_by_field_name("declarator"),
        ) else {
            continue;
        };
        if matches!(aggregate.kind(), "struct_specifier" | "union_specifier")
            && aggregate.child_by_field_name("body").is_some()
        {
            let alias = node_text(&alias, src).trim();
            if !alias.is_empty() {
                names.insert(alias.to_string());
            }
        }
    }
    for aggregate in collect_kinds(tree, &["struct_specifier", "union_specifier"]) {
        if aggregate.child_by_field_name("body").is_none() {
            continue;
        }
        if let Some(name) = aggregate.child_by_field_name("name") {
            let name = node_text(&name, src).trim();
            if !name.is_empty() {
                names.insert(name.to_string());
            }
        }
    }
    names
}

fn c_declaration_has_aggregate_type(
    declaration: Node<'_>,
    aggregates: &std::collections::HashSet<String>,
    src: &[u8],
) -> bool {
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return false;
    };
    match type_node.kind() {
        "type_identifier" => aggregates.contains(node_text(&type_node, src).trim()),
        "struct_specifier" | "union_specifier" => {
            type_node.child_by_field_name("body").is_some()
                || type_node
                    .child_by_field_name("name")
                    .is_some_and(|name| aggregates.contains(node_text(&name, src).trim()))
        }
        _ => false,
    }
}

fn c_enclosing_function_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "function_definition" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn c_visible_parameter<'tree>(function: Node<'tree>, name: &str, src: &[u8]) -> Option<Node<'tree>> {
    let declarator = function.child_by_field_name("declarator")?;
    let matches = collect_kinds_from_node(declarator, &["parameter_declaration"])
        .into_iter()
        .filter(|parameter| c_declaration_binds(*parameter, name, src))
        .collect::<Vec<_>>();
    let [parameter] = matches.as_slice() else {
        return None;
    };
    Some(*parameter)
}

fn c_addressed_aggregate_argument(
    tree: &Tree,
    argument_span: bonsai_common::Span,
    aggregates: &std::collections::HashSet<String>,
    src: &[u8],
) -> bool {
    let Some(argument) = bonsai_lang_api::kit::node_at_span(
        tree.root_node(),
        argument_span,
        &["pointer_expression", "unary_expression"],
    ) else {
        return false;
    };
    let mut cursor = argument.walk();
    if !argument.children(&mut cursor).any(|child| child.kind() == "&") {
        return false;
    }
    let Some(operand) = argument.child_by_field_name("argument").map(c_unwrap_parentheses) else {
        return false;
    };
    // An address of one member (`&record.field`) is a field copy, not a
    // whole-record reconstruction boundary.
    if operand.kind() != "identifier" {
        return false;
    }
    let name = node_text(&operand, src).trim();
    let Some(function) = c_enclosing_function_node(argument) else {
        return false;
    };
    let declaration = c_visible_declaration(function, argument, name, src)
        .or_else(|| c_visible_parameter(function, name, src));
    declaration.is_some_and(|declaration| c_declaration_has_aggregate_type(declaration, aggregates, src))
}

fn mark_c_addressed_aggregate_arguments(index: &mut DeclIndex, tree: &Tree, src: &[u8]) {
    let aggregates = c_aggregate_type_names(tree, src);
    if aggregates.is_empty() {
        return;
    }
    for argument in &mut index.call_argument_values {
        if c_addressed_aggregate_argument(tree, argument.argument_span, &aggregates, src) {
            argument.value_kind = Some(bonsai_lang_api::AssignValueKind::AddressOfAggregate);
        }
    }
}

type CByteArrayAggregateFields = std::collections::HashMap<String, std::collections::HashMap<String, u128>>;

fn c_byte_array_aggregate_fields(tree: &Tree, src: &[u8]) -> CByteArrayAggregateFields {
    let mut aggregates = std::collections::HashMap::new();
    for definition in collect_kinds(tree, &["type_definition"]) {
        let (Some(aggregate), Some(alias)) = (
            definition.child_by_field_name("type"),
            definition.child_by_field_name("declarator"),
        ) else {
            continue;
        };
        if !matches!(aggregate.kind(), "struct_specifier" | "union_specifier") {
            continue;
        }
        let Some(body) = aggregate.child_by_field_name("body") else {
            continue;
        };
        let mut fields = std::collections::HashMap::new();
        for declaration in direct_named_children(body)
            .into_iter()
            .filter(|node| node.kind() == "field_declaration")
        {
            let Some(field_type) = declaration.child_by_field_name("type") else {
                continue;
            };
            if !c_is_byte_type(field_type, src) {
                continue;
            }
            for declarator in direct_named_children(declaration)
                .into_iter()
                .filter(|node| node.kind() == "array_declarator")
            {
                if let Some((name, capacity)) = c_array_declarator_extent(declarator, src) {
                    fields.insert(name, capacity);
                }
            }
        }
        if !fields.is_empty() {
            aggregates.insert(node_text(&alias, src).trim().to_string(), fields);
        }
    }
    aggregates
}

fn c_is_byte_type(node: Node<'_>, src: &[u8]) -> bool {
    let spelling = node_text(&node, src)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    matches!(spelling.as_str(), "char" | "signed char" | "unsigned char")
}

fn c_array_declarator_extent(declarator: Node<'_>, src: &[u8]) -> Option<(String, u128)> {
    let binding = declarator.child_by_field_name("declarator")?;
    let binding = c_declarator_binding(binding)?;
    let size = declarator.child_by_field_name("size")?;
    Some((
        node_text(&binding, src).trim().to_string(),
        c_integer_literal(size, src)?,
    ))
}

fn c_declarator_binding(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(node.kind(), "identifier" | "field_identifier" | "type_identifier") {
            return Some(node);
        }
        node = node.child_by_field_name("declarator")?;
    }
}

fn c_integer_literal(node: Node<'_>, src: &[u8]) -> Option<u128> {
    if node.kind() != "number_literal" {
        return None;
    }
    let spelling = node_text(&node, src).trim();
    let digits = spelling.trim_end_matches(['u', 'U', 'l', 'L']);
    let (radix, digits) = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        (16, hex)
    } else if let Some(binary) = digits.strip_prefix("0b").or_else(|| digits.strip_prefix("0B")) {
        (2, binary)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    u128::from_str_radix(digits, radix).ok()
}

fn c_byte_storage_capacity(
    expression: Node<'_>,
    function: Node<'_>,
    aggregates: &CByteArrayAggregateFields,
    src: &[u8],
) -> Option<u128> {
    let expression = c_unwrap_parentheses(expression);
    match expression.kind() {
        "identifier" => {
            let name = node_text(&expression, src).trim();
            let declaration = c_visible_declaration(function, expression, name, src)?;
            let declaration_type = declaration.child_by_field_name("type")?;
            if !c_is_byte_type(declaration_type, src) {
                return None;
            }
            c_declaration_array_extent(declaration, name, src)
        }
        "field_expression" => {
            let base = c_unwrap_parentheses(expression.child_by_field_name("argument")?);
            if base.kind() != "identifier" {
                return None;
            }
            let base_name = node_text(&base, src).trim();
            let declaration = c_visible_declaration(function, expression, base_name, src)?;
            let aggregate_type = node_text(&declaration.child_by_field_name("type")?, src)
                .trim()
                .to_string();
            let field = node_text(&expression.child_by_field_name("field")?, src)
                .trim()
                .to_string();
            aggregates.get(&aggregate_type)?.get(&field).copied()
        }
        _ => None,
    }
}

fn c_declaration_array_extent(declaration: Node<'_>, name: &str, src: &[u8]) -> Option<u128> {
    direct_named_children(declaration)
        .into_iter()
        .filter(|node| node.kind() == "array_declarator")
        .find_map(|declarator| {
            let (binding, capacity) = c_array_declarator_extent(declarator, src)?;
            (binding == name).then_some(capacity)
        })
}

fn c_visible_declaration<'tree>(
    function: Node<'tree>,
    use_site: Node<'tree>,
    name: &str,
    src: &[u8],
) -> Option<Node<'tree>> {
    descendant_nodes_of_kind(function, "declaration")
        .into_iter()
        .filter(|declaration| declaration.end_byte() <= use_site.start_byte())
        .filter(|declaration| {
            declaration
                .parent()
                .is_some_and(|scope| c_node_contains_lexically(scope, use_site))
        })
        .filter(|declaration| c_declaration_binds(*declaration, name, src))
        .max_by_key(|declaration| declaration.start_byte())
}

fn c_declaration_binds(declaration: Node<'_>, name: &str, src: &[u8]) -> bool {
    direct_named_children(declaration).into_iter().any(|child| {
        c_declarator_binding(child).is_some_and(|binding| node_text(&binding, src).trim() == name)
    })
}

fn c_node_contains_lexically(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

fn c_unwrap_parentheses(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(inner) = first_named_child(node) else {
            break;
        };
        node = inner;
    }
    node
}

fn c_capacity_expression(
    expression: Node<'_>,
    function: Node<'_>,
    aggregates: &CByteArrayAggregateFields,
    src: &[u8],
) -> Option<u128> {
    let expression = c_unwrap_parentheses(expression);
    if expression.kind() == "number_literal" {
        return c_integer_literal(expression, src);
    }
    if expression.kind() != "sizeof_expression" {
        return None;
    }
    let value = expression.child_by_field_name("value")?;
    c_byte_storage_capacity(value, function, aggregates, src)
}

fn c_preceding_numeric_bound_proof(
    call: Node<'_>,
    function: Node<'_>,
    length_name: &str,
    destination_capacity: u128,
    aggregates: &CByteArrayAggregateFields,
    src: &[u8],
    file: FileId,
) -> Option<bonsai_common::Span> {
    let compound = c_enclosing_compound(call, function)?;
    let call_statement = c_direct_child_containing(compound, call)?;
    direct_named_children(compound)
        .into_iter()
        .filter(|statement| statement.kind() == "if_statement")
        .filter(|statement| statement.end_byte() <= call_statement.start_byte())
        .rev()
        .find_map(|guard| {
            let condition = c_unwrap_parentheses(guard.child_by_field_name("condition")?);
            let (bound, accepts_safe_path) =
                c_upper_bound_condition(condition, function, length_name, aggregates, src)?;
            if bound > destination_capacity || !accepts_safe_path {
                return None;
            }
            let consequence = guard.child_by_field_name("consequence")?;
            let establishes_bound =
                c_exact_clamp_assignment(consequence, function, length_name, bound, aggregates, src)
                    || c_statement_is_terminal(consequence);
            if !establishes_bound
                || c_place_assigned_between(function, length_name, guard.end_byte(), call.start_byte(), src)
            {
                return None;
            }
            Some(span_of(file, &guard))
        })
}

/// Return the unsafe-side bound and whether the branch consequence is the
/// unsafe arm. Only `len > bound` / `len >= bound` (and exact reversed forms)
/// establish a safe fallthrough.
fn c_upper_bound_condition(
    condition: Node<'_>,
    function: Node<'_>,
    length_name: &str,
    aggregates: &CByteArrayAggregateFields,
    src: &[u8],
) -> Option<(u128, bool)> {
    if condition.kind() != "binary_expression" {
        return None;
    }
    let left = c_unwrap_parentheses(condition.child_by_field_name("left")?);
    let right = c_unwrap_parentheses(condition.child_by_field_name("right")?);
    let operator = binary_operator_text(condition, src)?;
    if left.kind() == "identifier"
        && node_text(&left, src).trim() == length_name
        && matches!(operator, ">" | ">=")
    {
        return Some((c_capacity_expression(right, function, aggregates, src)?, true));
    }
    if right.kind() == "identifier"
        && node_text(&right, src).trim() == length_name
        && matches!(operator, "<" | "<=")
    {
        return Some((c_capacity_expression(left, function, aggregates, src)?, true));
    }
    None
}

fn c_exact_clamp_assignment(
    consequence: Node<'_>,
    function: Node<'_>,
    length_name: &str,
    bound: u128,
    aggregates: &CByteArrayAggregateFields,
    src: &[u8],
) -> bool {
    let statements = if consequence.kind() == "compound_statement" {
        direct_named_children(consequence)
    } else {
        vec![consequence]
    };
    let [statement] = statements.as_slice() else {
        return false;
    };
    let assignment = if statement.kind() == "expression_statement" {
        first_named_child(*statement)
    } else {
        Some(*statement)
    };
    let Some(assignment) = assignment.filter(|node| node.kind() == "assignment_expression") else {
        return false;
    };
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    left.kind() == "identifier"
        && node_text(&left, src).trim() == length_name
        && assignment_operator_text(assignment, src) == Some("=")
        && c_capacity_expression(right, function, aggregates, src) == Some(bound)
}

fn c_statement_is_terminal(statement: Node<'_>) -> bool {
    if statement.kind() == "return_statement" {
        return true;
    }
    if statement.kind() != "compound_statement" {
        return false;
    }
    direct_named_children(statement)
        .last()
        .is_some_and(|last| c_statement_is_terminal(*last))
}

fn c_place_assigned_between(
    function: Node<'_>,
    place: &str,
    after: usize,
    before: usize,
    src: &[u8],
) -> bool {
    descendant_nodes_of_kind(function, "assignment_expression")
        .into_iter()
        .filter(|assignment| after <= assignment.start_byte() && assignment.end_byte() <= before)
        .any(|assignment| {
            assignment
                .child_by_field_name("left")
                .is_some_and(|left| left.kind() == "identifier" && node_text(&left, src).trim() == place)
        })
}

fn c_enclosing_compound<'tree>(mut node: Node<'tree>, function: Node<'tree>) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "compound_statement" {
            return Some(parent);
        }
        if parent == function {
            return None;
        }
        node = parent;
    }
    None
}

fn c_direct_child_containing<'tree>(compound: Node<'tree>, node: Node<'tree>) -> Option<Node<'tree>> {
    direct_named_children(compound)
        .into_iter()
        .find(|child| c_node_contains_lexically(*child, node))
}

fn direct_named_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn descendant_nodes_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    let mut work = vec![root];
    while let Some(node) = work.pop() {
        if node != root && node.kind() == kind {
            matches.push(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        work.extend(children.into_iter().rev());
    }
    matches
}

fn has_loop_ancestor_within(node: Node<'_>, function: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        if ancestor == function {
            return false;
        }
        if matches!(
            ancestor.kind(),
            "for_statement" | "while_statement" | "do_statement"
        ) {
            return true;
        }
        parent = ancestor.parent();
    }
    false
}

/// Collect calls whose truth is required for the enclosing condition to be
/// true. Positive conjunctions preserve that implication; disjunctions,
/// negation, and comparisons do not.
fn collect_positively_required_predicate_calls<'tree>(
    condition: Node<'tree>,
    src: &[u8],
    out: &mut Vec<Node<'tree>>,
) {
    match condition.kind() {
        "parenthesized_expression" => {
            if let Some(inner) = first_named_child(condition) {
                collect_positively_required_predicate_calls(inner, src, out);
            }
        }
        "call_expression" => out.push(condition),
        "binary_expression" if binary_operator_text(condition, src) == Some("&&") => {
            if let Some(left) = condition.child_by_field_name("left") {
                collect_positively_required_predicate_calls(left, src, out);
            }
            if let Some(right) = condition.child_by_field_name("right") {
                collect_positively_required_predicate_calls(right, src, out);
            }
        }
        _ => {}
    }
}

fn binary_operator_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    let mut cursor = node.walk();
    let operator = node
        .children(&mut cursor)
        .find(|child| !child.is_named())
        .map(|child| node_text(&child, src).trim());
    operator
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let child = node.named_children(&mut cursor).next();
    child
}

fn predicate_subscript_input(predicate: Node<'_>, src: &[u8]) -> Option<String> {
    let arguments = predicate.child_by_field_name("arguments")?;
    let argument = first_named_child(arguments)?;
    let subscripts = node_and_descendants_of_kind(argument, "subscript_expression");
    let [subscript] = subscripts.as_slice() else {
        return None;
    };
    subscript_base_place(*subscript, src)
}

fn node_and_descendants_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    if root.kind() == kind {
        matches.push(root);
    }
    matches.extend(descendant_nodes_of_kind(root, kind));
    matches
}

fn filtered_element_copy(write: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    if assignment_operator_text(write, src)? != "=" {
        return None;
    }
    let left = write.child_by_field_name("left")?;
    let right = write.child_by_field_name("right")?;
    if left.kind() != "subscript_expression" || right.kind() != "subscript_expression" {
        return None;
    }
    Some((
        subscript_base_place(left, src)?,
        subscript_base_place(right, src)?,
    ))
}

fn assignment_operator_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let between = src.get(left.end_byte()..right.start_byte())?;
    std::str::from_utf8(between).ok().map(str::trim)
}

fn subscript_base_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    let base = node.child_by_field_name("argument")?;
    let value = node_text(&base, src).trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn output_is_zero_initialized(initializers: &[Node<'_>], output: &str, before: usize, src: &[u8]) -> bool {
    initializers
        .iter()
        .copied()
        .filter(|declarator| declarator.end_byte() <= before)
        .any(|declarator| {
            let Some(binding) = declarator.child_by_field_name("declarator") else {
                return false;
            };
            let Some(value) = declarator.child_by_field_name("value") else {
                return false;
            };
            binding.kind() == "array_declarator"
                && declarator_base_place(binding, src).as_deref() == Some(output)
                && zero_initializer(value, src)
        })
}

fn declarator_base_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(&node, src).to_string());
    }
    node.child_by_field_name("declarator")
        .and_then(|inner| declarator_base_place(inner, src))
}

fn zero_initializer(node: Node<'_>, src: &[u8]) -> bool {
    if node.kind() != "initializer_list" {
        return false;
    }
    let mut cursor = node.walk();
    let values: Vec<_> = node.named_children(&mut cursor).collect();
    !values.is_empty() && values.into_iter().all(|value| zero_scalar(value, src))
}

fn zero_scalar(node: Node<'_>, src: &[u8]) -> bool {
    matches!(node.kind(), "number_literal" | "char_literal")
        && matches!(node_text(&node, src).trim(), "0" | "'\\0'")
}

fn output_has_only_filtered_or_zero_writes(
    assignments: &[Node<'_>],
    output: &str,
    filtered_write: Node<'_>,
    src: &[u8],
) -> bool {
    let mut dynamic_writes = 0usize;
    for assignment in assignments {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let targets_output = if left.kind() == "subscript_expression" {
            subscript_base_place(left, src).as_deref() == Some(output)
        } else {
            node_text(&left, src).trim() == output
        };
        if !targets_output {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            return false;
        };
        if zero_scalar(right, src) {
            continue;
        }
        dynamic_writes += 1;
        if *assignment != filtered_write || filtered_element_copy(*assignment, src).is_none() {
            return false;
        }
    }
    dynamic_writes == 1
}

fn output_is_zero_terminated_after(assignments: &[Node<'_>], output: &str, after: usize, src: &[u8]) -> bool {
    assignments
        .iter()
        .copied()
        .filter(|assignment| assignment.start_byte() >= after)
        .any(|assignment| {
            assignment
                .child_by_field_name("left")
                .filter(|left| left.kind() == "subscript_expression")
                .and_then(|left| subscript_base_place(left, src))
                .as_deref()
                == Some(output)
                && assignment
                    .child_by_field_name("right")
                    .is_some_and(|right| zero_scalar(right, src))
        })
}

/// Tree-sitter can recover from macro-heavy C headers by stretching a
/// declaration sequence into a bogus `function_definition`. Keep only
/// nodes with an actual compound-statement body; C declarations and
/// function-pointer API tables are not callable definitions.
fn collect_function_definition_names_with_body(
    file: FileId,
    tree: &Tree,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, String> {
    let mut definitions = collect_kinds(tree, &["function_definition"])
        .into_iter()
        .filter(function_definition_has_body)
        .filter_map(|node| function_name(&node, src).map(|name| (span_of(file, &node), name)))
        .collect::<std::collections::HashMap<_, _>>();
    definitions.extend(
        recovered_error_wrapped_functions(file, tree, src)
            .into_iter()
            .map(|recovered| (recovered.span, recovered.name)),
    );
    definitions
}

/// Recover callable ownership when Tree-sitter keeps a C function's exact
/// declarator, brace terminals, and statements but wraps their relationship in
/// an `ERROR` because mutually-exclusive preprocessor branches splice the
/// condition tokens differently.  This does not choose a branch or construct
/// an expression.  It only restores the function scope proven by the parsed
/// declarator and balanced CST brace terminals.
fn append_recovered_error_wrapped_functions(index: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let mut recovered = recovered_error_wrapped_functions(file, tree, src);
    recovered.retain(|candidate| {
        !index.defs.iter().any(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) && decl.name == candidate.name
                && decl.span.start <= candidate.name_span.start
                && candidate.name_span.end <= decl.span.end
        })
    });
    let mut next = index
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .map_or(0, |symbol| symbol.saturating_add(1));
    for mut candidate in recovered {
        candidate.symbol = bonsai_common::SymbolId::new(next);
        next = next.saturating_add(1);
        index.defs.push(candidate);
    }
    index
        .defs
        .sort_by_key(|decl| (decl.span.start, decl.span.end, decl.symbol.raw()));
}

fn recovered_error_wrapped_functions(file: FileId, tree: &Tree, src: &[u8]) -> Vec<Decl> {
    let mut out = Vec::new();
    for error in collect_kinds(tree, &["ERROR"]).into_iter().filter(Node::is_error) {
        let mut direct_cursor = error.walk();
        let direct_children = error.children(&mut direct_cursor).collect::<Vec<_>>();
        let Some(declarator) = direct_children
            .iter()
            .copied()
            .find(|child| child.kind() == "function_declarator")
        else {
            continue;
        };
        let Some(name_node) = function_identifier_node(&declarator) else {
            continue;
        };
        let name = node_text(&name_node, src).trim();
        if name.is_empty() || is_c_reserved_decl_name(name) {
            continue;
        }
        // A real definition has a declaration type before its declarator and
        // an opening compound-statement terminal after it.  Initializers and
        // prototypes cannot satisfy both relationships.
        let has_return_type = direct_children.iter().any(|child| {
            child.end_byte() <= declarator.start_byte()
                && child.is_named()
                && matches!(
                    child.kind(),
                    "primitive_type"
                        | "type_identifier"
                        | "sized_type_specifier"
                        | "struct_specifier"
                        | "union_specifier"
                        | "enum_specifier"
                )
        });
        if !has_return_type {
            continue;
        }
        let Some(open_index) = direct_children
            .iter()
            .position(|child| child.kind() == "{" && child.start_byte() >= declarator.end_byte())
        else {
            continue;
        };
        if direct_children[open_index.saturating_sub(1)..open_index]
            .iter()
            .any(|child| matches!(child.kind(), "=" | ";"))
        {
            continue;
        }
        let open = direct_children[open_index];
        let Some(close) = balanced_cst_closing_brace(error, open) else {
            continue;
        };
        let body_span = bonsai_common::Span::new(file, open.start_byte() as u64, close.end_byte() as u64);
        let declaration_start = direct_children
            .iter()
            .filter(|child| child.end_byte() <= declarator.start_byte())
            .map(Node::start_byte)
            .min()
            .unwrap_or(declarator.start_byte());
        let declaration_span =
            bonsai_common::Span::new(file, declaration_start as u64, close.end_byte() as u64);
        let mut flow_events = bonsai_lang_api::kit::walk_flow_events(error, file, src, &HANDLER, &[]);
        retain_flow_events_in_span(&mut flow_events, body_span);
        let params = c_parameter_bindings(declarator, src);
        let type_aliases = c_parameter_type_aliases(declarator, src);
        let return_type = direct_children
            .iter()
            .find(|child| child.is_named() && child.end_byte() <= declarator.start_byte())
            .map(|node| node_text(node, src).trim().to_string())
            .filter(|value| !value.is_empty());
        out.push(Decl {
            symbol: bonsai_common::SymbolId::new(0),
            kind: DeclKind::Function,
            name: name.to_string(),
            qualified_name: None,
            module_path: ModulePath::default(),
            span: declaration_span,
            name_span: span_of(file, &name_node),
            visibility: Visibility::Public,
            parent: None,
            body_span: Some(body_span),
            flow_events,
            has_implicit_returns: false,
            params,
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases,
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            receiver_field_initializers: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type,
            is_variadic: false,
        });
    }
    out.sort_by_key(|decl| (decl.span.start, decl.span.end));
    out.dedup_by_key(|decl| (decl.span, decl.name.clone()));
    out
}

fn balanced_cst_closing_brace<'tree>(error: Node<'tree>, open: Node<'tree>) -> Option<Node<'tree>> {
    let mut terminals = Vec::new();
    let mut stack = vec![error];
    while let Some(node) = stack.pop() {
        if node.child_count() == 0 {
            if matches!(node.kind(), "{" | "}") && node.start_byte() >= open.start_byte() {
                terminals.push(node);
            }
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    terminals.sort_by_key(|node| (node.start_byte(), node.end_byte()));
    let mut depth = 0_u32;
    for terminal in terminals {
        match terminal.kind() {
            "{" => depth = depth.saturating_add(1),
            "}" if depth == 1 => return Some(terminal),
            "}" => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn function_identifier_node<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    if node.kind() == "identifier" {
        return Some(*node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameter_list" {
            continue;
        }
        if let Some(identifier) = function_identifier_node(&child) {
            return Some(identifier);
        }
    }
    None
}

fn c_parameter_bindings(declarator: Node<'_>, src: &[u8]) -> Vec<String> {
    collect_kinds_from_node(declarator, &["parameter_declaration"])
        .into_iter()
        .filter_map(|parameter| parameter.child_by_field_name("declarator"))
        .filter_map(|declarator| extract_function_identifier(&declarator, src))
        .collect()
}

fn c_parameter_type_aliases(declarator: Node<'_>, src: &[u8]) -> Vec<TypeAliasBinding> {
    collect_kinds_from_node(declarator, &["parameter_declaration"])
        .into_iter()
        .filter_map(|parameter| {
            let name = parameter
                .child_by_field_name("declarator")
                .and_then(|declarator| extract_function_identifier(&declarator, src))?;
            let type_name = parameter
                .child_by_field_name("type")
                .map(|node| node_text(&node, src).trim().to_string())?;
            (!name.is_empty() && !type_name.is_empty()).then_some(TypeAliasBinding { name, type_name })
        })
        .collect()
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
    out.sort_by_key(|node| (node.start_byte(), node.end_byte()));
    out
}

fn retain_flow_events_in_span(events: &mut Vec<FlowEvent>, body: bonsai_common::Span) {
    events.retain_mut(|event| {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                retain_flow_events_in_span(then_events, body);
                retain_flow_events_in_span(else_events, body);
            }
            FlowEvent::Loop { body: events, .. }
            | FlowEvent::Defer { body: events, .. }
            | FlowEvent::Using { body: events, .. } => retain_flow_events_in_span(events, body),
            FlowEvent::Try {
                body: events,
                catch_events,
                finally_events,
                ..
            } => {
                retain_flow_events_in_span(events, body);
                retain_flow_events_in_span(catch_events, body);
                retain_flow_events_in_span(finally_events, body);
            }
            _ => {}
        }
        let span = event.span();
        body.start <= span.start && span.end <= body.end
    });
}

fn function_definition_has_body(node: &Node<'_>) -> bool {
    node.child_by_field_name("body")
        .is_some_and(|body| body.kind() == "compound_statement")
        || first_named_child_of_kind(node, "compound_statement").is_some()
}

fn is_c_reserved_decl_name(name: &str) -> bool {
    matches!(
        name,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
    )
}

/// Walk the C tree and collect every function name whose definition
/// has a `static` storage class. C `static` is translation-unit-private
/// — file-scoped, not module-scoped — so the resolver's
/// `Visibility::Private` filter is the right fit when paired with the
/// adapter's `module_path` of `[file_stem]`.
fn collect_static_function_names(tree: &Tree, src: &[u8]) -> std::collections::HashSet<String> {
    let mut static_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for fn_node in collect_kinds(tree, &["function_definition"]) {
        if !function_has_static_specifier(&fn_node, src) {
            continue;
        }
        if let Some(name) = function_name(&fn_node, src) {
            static_names.insert(name);
        }
    }
    static_names
}

/// True when `node` (a `function_definition`) carries a `static`
/// storage-class specifier as a direct child.
fn function_has_static_specifier(node: &Node<'_>, src: &[u8]) -> bool {
    // tree-sitter-c emits a `storage_class_specifier` child whose
    // text reads "static" when the function is marked static. The
    // specifier appears either as a direct child of
    // `function_definition` or nested inside `declaration_specifiers`.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "storage_class_specifier" && node_text(&child, src) == "static" {
            return true;
        }
    }
    false
}

/// Resolve the bare function name out of a `function_definition` node
/// by descending into its `declarator` field.
fn function_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    // `function_definition` -> declarator -> ... -> identifier.
    // tree-sitter-c usually puts the bare identifier under the
    // `function_declarator` -> `identifier` chain.
    let declarator = node.child_by_field_name("declarator")?;
    extract_function_identifier(&declarator, src)
}

/// Recursively unwrap a declarator subtree until a bare `identifier`
/// surfaces; returns `None` only on completely anonymous declarators.
fn extract_function_identifier(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(node, src).to_string());
    }
    // function_declarator wraps the identifier; pointer_declarator and
    // similar nest inside.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = extract_function_identifier(&child, src) {
            return Some(found);
        }
    }
    None
}

fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    c_family_preproc_imports(tree, src, file)
}
