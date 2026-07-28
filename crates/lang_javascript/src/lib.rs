//! JavaScript language adapter.
use bonsai_common::{FileId, SymbolId};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, CharacterSubstitutionDomain, CharacterSubstitutionFact, ConditionEquality,
    ConditionExpressionFact, ConditionOperandFact, DeclIndex, FiniteLiteralSelectionFact, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    StaticStringMapEntry, StaticStringMapFact, TypeAliasBinding, Visibility,
};
use bonsai_lang_api::{CallArg, DeclKind, FlowEvent};
use std::collections::{HashMap, HashSet};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("javascript");
pub const JS_TS_MODULE_RESOLUTION_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const PACK_NAME: &str = "javascript";
const HANDLER: GrammarHandler = GrammarHandler {
    call_kinds: &["new_expression"],
    constructor_names: &["constructor"],
    ..with_fn_kinds_and_implicit_receivers(
        &[
            "function_declaration",
            "function_expression",
            "method_definition",
            // Generator forms: `function* gen() { ... }`.
            "generator_function_declaration",
            "generator_function",
        ],
        &["this"],
        &[],
    )
};

#[derive(Debug, Default, Copy, Clone)]
pub struct JavaScriptAdapter;

impl JavaScriptAdapter {
    /// Construct a fresh adapter. Stateless; cheap to copy.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for JavaScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "JavaScript"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["js", "mjs", "cjs", "jsx"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_export_aliases: &["exports", "module.exports"],
            module_default_export_names: &["default"],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_method_names: &["constructor"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            module_resolution_extensions: JS_TS_MODULE_RESOLUTION_EXTENSIONS,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            populate_ecmascript_compiler_facts(&mut decl_index, &tree, file, src);
            apply_js_ts_commonjs_named_export_aliases(&mut decl_index, &tree, src, file);
        }
        // Module identity = workspace-relative path with the JS/TS extension stripped.
        let module_segments = ctx
            .workspace_relative_path(file)
            .map(|p| js_ts_module_segments(&p))
            .unwrap_or_default();
        if !module_segments.is_empty() {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut decl_index, module_segments);
        } else {
            // Fall back to the file stem when the workspace root is unknown.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            apply_js_ts_default_export_aliases(&mut decl_index, &tree, snapshot.text.as_bytes(), file);
        }
        // ECMAScript private fields/methods are syntactically marked by a leading `#`.
        for decl in &mut decl_index.defs {
            if decl.name.starts_with('#') {
                decl.visibility = Visibility::Private;
            }
        }
        // Populate `bases` from `class_heritage > extends_clause` so the resolver
        // can narrow virtual-dispatch candidates consistently with TypeScript.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let bases_by_span = collect_javascript_class_bases(&tree, file, src);
            for decl in &mut decl_index.defs {
                if let Some(bases) = bases_by_span
                    .iter()
                    .find_map(|(span, bases)| (*span == decl.span).then_some(bases))
                {
                    decl.bases = bases.clone();
                }
            }
            rewrite_javascript_super_constructor_invocations(&mut decl_index);
            apply_javascript_getter_property_sources(&mut decl_index, &tree, src, file);
        }
        // Recognised JavaScript lifecycle transitions. Mirrors the
        // common Node.js / browser surface: streams (`close`,
        // `destroy`), `AbortController` (`abort`), RxJS-style
        // observables (`unsubscribe`), promises / animations
        // (`cancel`), and pooled resources (`release`).
        const JAVASCRIPT_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "destroy",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "abort",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "unsubscribe",
                transition: "cancelled",
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
        ];
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, JAVASCRIPT_LIFECYCLE_TRANSITIONS);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            rewrite_javascript_object_destructuring_sources(
                &mut decl_index,
                &tree,
                snapshot.text.as_bytes(),
                file,
            );
            inject_javascript_object_literal_field_assigns(
                &mut decl_index,
                &tree,
                snapshot.text.as_bytes(),
                file,
            );
            apply_javascript_array_literal_types(&mut decl_index, &tree, snapshot.text.as_bytes(), file);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing
        // (`const c = new Foo()` → `c: Foo`) so `c.method(...)` carries a
        // resolved receiver type for `receiver_type_in` / `[Type, method]`
        // rules — the memory-endorsed alternative to loosening the package
        // gate for receiver-variable calls. JS class names are uppercase
        // and free functions are camelCase, so the constructor heuristic
        // is reliable here (unlike Go's uppercase-exported-function form).
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_call_receiver_types(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Attach ECMAScript-specific syntax meaning to the language-neutral compiler
/// IR. TypeScript deliberately reuses this lowering because its expression
/// grammar extends ECMAScript; downstream engines see only typed boolean
/// relations and exact decoded literal values.
pub fn populate_ecmascript_compiler_facts(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for branch in collect_kinds(tree, &["if_statement"]) {
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
        fact.expression = Some(lower_ecmascript_condition_expression(condition, file, src));
    }

    for node in collect_kinds(tree, &["string", "string_literal"]) {
        let span = span_of(file, &node);
        let Some(value) = ecmascript_static_string_literal(node, src) else {
            continue;
        };
        if let Some(literal) = index.strings.iter_mut().find(|literal| literal.span == span) {
            literal.static_value = Some(value);
        }
    }
    index.static_string_maps = ecmascript_static_string_maps(index, tree, file, src);
    index.finite_literal_selections = ecmascript_finite_literal_selections(index, tree, file, src);
    index.character_substitutions = ecmascript_character_substitutions(&index.defs, tree, file, src);
}

fn ecmascript_static_string_maps(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<StaticStringMapFact> {
    let mut maps = Vec::new();
    for declarator in collect_kinds(tree, &["variable_declarator"]) {
        let Some(target_node) = declarator.child_by_field_name("name") else {
            continue;
        };
        let Some(value_node) = declarator.child_by_field_name("value") else {
            continue;
        };
        if target_node.kind() != "identifier" || value_node.kind() != "object" {
            continue;
        }
        let target = node_text(&target_node, src).trim();
        if target.is_empty() {
            continue;
        }
        let Some(entries) = ecmascript_exact_string_map_entries(value_node, src) else {
            continue;
        };
        let value_span = span_of(file, &value_node);
        let Some(assignment_span) = index.assignment_values.iter().find_map(|fact| {
            (fact.value_span == value_span && fact.target.as_deref() == Some(target))
                .then_some(fact.assignment_span)
        }) else {
            continue;
        };
        maps.push(StaticStringMapFact {
            assignment_span,
            target: target.to_string(),
            entries,
        });
    }
    maps.sort_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end));
    maps
}

fn ecmascript_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<FiniteLiteralSelectionFact> {
    let bindings = ecmascript_bindings(tree, src);
    if !bindings
        .bindings
        .iter()
        .any(|binding| binding.finite_map.is_some())
    {
        return Vec::new();
    }
    let mut selections = Vec::new();
    for node in collect_kinds(tree, &["call_expression", "subscript_expression"]) {
        let (map_target, object) = if node.kind() == "call_expression" {
            let Some(function) = node.child_by_field_name("function") else {
                continue;
            };
            if function.kind() != "member_expression" {
                continue;
            }
            let Some(object) = function.child_by_field_name("object") else {
                continue;
            };
            let Some(property) = function.child_by_field_name("property") else {
                continue;
            };
            if object.kind() != "identifier" || node_text(&property, src).trim() != "get" {
                continue;
            }
            (node_text(&object, src).trim(), object)
        } else {
            let Some(object) = node.child_by_field_name("object") else {
                continue;
            };
            if object.kind() != "identifier" {
                continue;
            }
            (node_text(&object, src).trim(), object)
        };
        let Some(binding) = bindings.resolve(map_target, object.start_byte(), object.end_byte()) else {
            continue;
        };
        if binding.finite_map.is_none()
            || binding.initializer.end_byte() > node.start_byte()
            || bindings.unsafe_bindings.contains(&binding.declaration.id())
        {
            continue;
        }
        let selection_span = span_of(file, &node);
        let Some(assignment) = index
            .assignment_values
            .iter()
            .filter(|fact| {
                fact.target.is_some()
                    && fact.value_span.file == selection_span.file
                    && fact.value_span.start <= selection_span.start
                    && selection_span.end <= fact.value_span.end
            })
            .min_by_key(|fact| fact.value_span.end.saturating_sub(fact.value_span.start))
        else {
            continue;
        };
        let Some(value_node) =
            bonsai_lang_api::kit::node_at_span(tree.root_node(), assignment.value_span, &[])
        else {
            continue;
        };
        if !ecmascript_expression_is_finite_selection(value_node, node, src, &bindings) {
            continue;
        }
        selections.push(FiniteLiteralSelectionFact {
            selection_span,
            assignment_span: assignment.assignment_span,
            target: assignment.target.clone().expect("checked target"),
        });
    }
    selections.sort_by_key(|fact| {
        (
            fact.assignment_span.start,
            fact.assignment_span.end,
            fact.selection_span.start,
            fact.selection_span.end,
        )
    });
    selections.dedup();
    selections
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EcmascriptFiniteMapKind {
    Object,
    Map,
}

#[derive(Copy, Clone, Debug)]
struct EcmascriptBinding<'tree> {
    name: &'tree str,
    declaration: Node<'tree>,
    initializer: Node<'tree>,
    scope: Node<'tree>,
    finite_map: Option<EcmascriptFiniteMapKind>,
}

struct EcmascriptBindings<'tree> {
    bindings: Vec<EcmascriptBinding<'tree>>,
    by_name: HashMap<String, Vec<usize>>,
    unsafe_bindings: HashSet<usize>,
    object_intrinsic_unshadowed: bool,
}

impl<'tree> EcmascriptBindings<'tree> {
    fn resolve(&self, name: &str, use_start: usize, use_end: usize) -> Option<&EcmascriptBinding<'tree>> {
        let candidates = self.by_name.get(name)?;
        let smallest_scope = candidates
            .iter()
            .map(|index| &self.bindings[*index])
            .filter(|binding| binding.scope.start_byte() <= use_start && use_end <= binding.scope.end_byte())
            .map(|binding| binding.scope.end_byte() - binding.scope.start_byte())
            .min()?;
        let mut candidates = candidates
            .iter()
            .map(|index| &self.bindings[*index])
            .filter(|binding| {
                binding.scope.start_byte() <= use_start
                    && use_end <= binding.scope.end_byte()
                    && binding.scope.end_byte() - binding.scope.start_byte() == smallest_scope
            });
        let binding = candidates.next()?;
        candidates.next().is_none().then_some(binding)
    }
}

fn ecmascript_bindings<'tree>(tree: &'tree Tree, src: &'tree [u8]) -> EcmascriptBindings<'tree> {
    let mut bindings = Vec::new();
    for declarator in collect_kinds(tree, &["variable_declarator"]) {
        let Some(target) = declarator.child_by_field_name("name") else {
            continue;
        };
        if target.kind() != "identifier" {
            continue;
        }
        let Some(scope) = ecmascript_binding_scope(declarator) else {
            continue;
        };
        let name = node_text(&target, src).trim();
        if name.is_empty() {
            continue;
        }
        let is_const = declarator
            .parent()
            .filter(|parent| parent.kind() == "lexical_declaration")
            .and_then(|declaration| declaration.child(0))
            .is_some_and(|keyword| keyword.kind() == "const");
        let is_exported = declarator
            .parent()
            .and_then(|declaration| declaration.parent())
            .is_some_and(|parent| parent.kind() == "export_statement");
        let value = declarator.child_by_field_name("value");
        bindings.push(EcmascriptBinding {
            name,
            declaration: declarator,
            initializer: value.unwrap_or(target),
            scope,
            finite_map: (is_const && !is_exported)
                .then(|| value.and_then(|value| ecmascript_finite_literal_map_kind(value, src)))
                .flatten(),
        });
    }

    for parameters in collect_kinds(tree, &["formal_parameters"]) {
        let Some(owner) = parameters.parent() else {
            continue;
        };
        let Some(scope) = owner.child_by_field_name("body") else {
            continue;
        };
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            let bound = match parameter.kind() {
                "identifier" => Some(parameter),
                "required_parameter" | "optional_parameter" | "rest_pattern" => parameter
                    .child_by_field_name("pattern")
                    .or_else(|| parameter.child_by_field_name("name")),
                _ => None,
            };
            let Some(bound) = bound.filter(|bound| bound.kind() == "identifier") else {
                continue;
            };
            let name = node_text(&bound, src).trim();
            if name.is_empty() {
                continue;
            }
            bindings.push(EcmascriptBinding {
                name,
                declaration: bound,
                initializer: bound,
                scope,
                finite_map: None,
            });
        }
    }
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, binding) in bindings.iter().enumerate() {
        by_name.entry(binding.name.to_string()).or_default().push(index);
    }
    let map_intrinsic_unshadowed =
        !by_name.contains_key("Map") && !ecmascript_declares_static_name(tree, src, "Map");
    let object_intrinsic_unshadowed =
        !by_name.contains_key("Object") && !ecmascript_declares_static_name(tree, src, "Object");
    if !map_intrinsic_unshadowed {
        for binding in &mut bindings {
            if binding.finite_map == Some(EcmascriptFiniteMapKind::Map) {
                binding.finite_map = None;
            }
        }
    }
    let mut compiler_bindings = EcmascriptBindings {
        bindings,
        by_name,
        unsafe_bindings: HashSet::new(),
        object_intrinsic_unshadowed,
    };
    let declaration_identifiers: HashSet<_> = compiler_bindings
        .bindings
        .iter()
        .filter_map(|binding| {
            if binding.declaration.kind() == "variable_declarator" {
                binding
                    .declaration
                    .child_by_field_name("name")
                    .map(|name| name.id())
            } else {
                Some(binding.declaration.id())
            }
        })
        .collect();
    compiler_bindings.unsafe_bindings = collect_kinds(tree, &["identifier"])
        .into_iter()
        .filter_map(|identifier| {
            if declaration_identifiers.contains(&identifier.id()) {
                return None;
            }
            let name = node_text(&identifier, src).trim();
            let binding = compiler_bindings.resolve(name, identifier.start_byte(), identifier.end_byte())?;
            let kind = binding.finite_map?;
            (!ecmascript_identifier_is_read_only_map_use(
                identifier,
                kind,
                src,
                compiler_bindings.object_intrinsic_unshadowed,
            ))
            .then_some(binding.declaration.id())
        })
        .collect();
    compiler_bindings
}

fn ecmascript_declares_static_name(tree: &Tree, src: &[u8], wanted: &str) -> bool {
    collect_kinds(
        tree,
        &[
            "function_declaration",
            "class_declaration",
            "generator_function_declaration",
        ],
    )
    .into_iter()
    .any(|declaration| {
        declaration
            .child_by_field_name("name")
            .is_some_and(|name| node_text(&name, src).trim() == wanted)
    }) || collect_kinds(tree, &["import_statement"])
        .into_iter()
        .any(|import| {
            let mut stack = vec![import];
            while let Some(node) = stack.pop() {
                if matches!(node.kind(), "identifier" | "type_identifier")
                    && node_text(&node, src).trim() == wanted
                {
                    return true;
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            false
        })
}

fn ecmascript_binding_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "for_statement"
                | "for_in_statement"
                | "for_of_statement"
                | "statement_block"
                | "switch_body"
                | "program"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn ecmascript_finite_literal_map_kind(mut node: Node<'_>, src: &[u8]) -> Option<EcmascriptFiniteMapKind> {
    while matches!(
        node.kind(),
        "parenthesized_expression" | "as_expression" | "satisfies_expression" | "type_assertion"
    ) && node.named_child_count() >= 1
    {
        let Some(inner) = node
            .child_by_field_name("expression")
            .or_else(|| node.named_child(0))
        else {
            return None;
        };
        node = inner;
    }
    if node.kind() == "object" {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .all(|child| {
                if child.kind() != "pair" {
                    return false;
                }
                child
                    .child_by_field_name("key")
                    .and_then(|key| ecmascript_static_property_name(key, src))
                    .is_some()
                    && child
                        .child_by_field_name("value")
                        .is_some_and(|value| ecmascript_is_literal_value(value, src))
            })
            .then_some(EcmascriptFiniteMapKind::Object);
    }
    if node.kind() != "new_expression" {
        return None;
    }
    let Some(constructor) = node.child_by_field_name("constructor") else {
        return None;
    };
    if constructor.kind() != "identifier" || node_text(&constructor, src).trim() != "Map" {
        return None;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return None;
    };
    let mut cursor = arguments.walk();
    let values: Vec<_> = arguments.named_children(&mut cursor).collect();
    (values.len() == 1 && ecmascript_is_literal_map_entries(values[0], src))
        .then_some(EcmascriptFiniteMapKind::Map)
}

fn ecmascript_is_literal_map_entries(node: Node<'_>, src: &[u8]) -> bool {
    if node.kind() != "array" {
        return false;
    }
    let mut cursor = node.walk();
    let is_literal = node.named_children(&mut cursor).all(|entry| {
        if entry.kind() != "array" {
            return false;
        }
        let mut entry_cursor = entry.walk();
        let values: Vec<_> = entry.named_children(&mut entry_cursor).collect();
        values.len() == 2
            && ecmascript_is_literal_value(values[0], src)
            && ecmascript_is_literal_value(values[1], src)
    });
    is_literal
}

fn ecmascript_identifier_is_read_only_map_use(
    identifier: Node<'_>,
    kind: EcmascriptFiniteMapKind,
    src: &[u8],
    object_intrinsic_unshadowed: bool,
) -> bool {
    let Some(access) = identifier.parent() else {
        return object_intrinsic_unshadowed
            && ecmascript_identifier_is_safe_has_own_argument(identifier, src);
    };
    if access.child_by_field_name("object").map(|object| object.id()) != Some(identifier.id()) {
        return object_intrinsic_unshadowed
            && ecmascript_identifier_is_safe_has_own_argument(identifier, src);
    }
    if ecmascript_access_is_write_target(access) {
        return false;
    }
    if access.kind() == "subscript_expression" {
        return true;
    }
    if access.kind() != "member_expression" {
        return false;
    }
    let Some(parent) = access.parent() else {
        return true;
    };
    if parent.kind() != "call_expression"
        || parent
            .child_by_field_name("function")
            .map(|function| function.id())
            != Some(access.id())
    {
        return true;
    }
    let Some(property) = access.child_by_field_name("property") else {
        return false;
    };
    let property = node_text(&property, src).trim();
    match kind {
        EcmascriptFiniteMapKind::Map => matches!(
            property,
            "get" | "has" | "entries" | "keys" | "values" | "forEach"
        ),
        EcmascriptFiniteMapKind::Object => false,
    }
}

fn ecmascript_identifier_is_safe_has_own_argument(identifier: Node<'_>, src: &[u8]) -> bool {
    let Some(arguments) = identifier.parent().filter(|parent| parent.kind() == "arguments") else {
        return false;
    };
    let Some(first_argument) = arguments.named_child(0) else {
        return false;
    };
    if first_argument.id() != identifier.id() {
        return false;
    }
    let Some(call) = arguments
        .parent()
        .filter(|parent| parent.kind() == "call_expression")
    else {
        return false;
    };
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    matches!(
        ecmascript_static_member_path(function, src).as_slice(),
        ["Object", "hasOwn"] | ["Object", "prototype", "hasOwnProperty", "call"]
    )
}

fn ecmascript_static_member_path<'a>(node: Node<'_>, src: &'a [u8]) -> Vec<&'a str> {
    if matches!(node.kind(), "identifier" | "property_identifier") {
        let name = node_text(&node, src).trim();
        return (!name.is_empty()).then_some(vec![name]).unwrap_or_default();
    }
    if node.kind() != "member_expression" {
        return Vec::new();
    }
    let Some(object) = node.child_by_field_name("object") else {
        return Vec::new();
    };
    let Some(property) = node.child_by_field_name("property") else {
        return Vec::new();
    };
    let mut path = ecmascript_static_member_path(object, src);
    let property = node_text(&property, src).trim();
    if path.is_empty() || property.is_empty() {
        return Vec::new();
    }
    path.push(property);
    path
}

fn ecmascript_access_is_write_target(access: Node<'_>) -> bool {
    let Some(parent) = access.parent() else {
        return false;
    };
    match parent.kind() {
        "assignment_expression" | "augmented_assignment_expression" => parent
            .child_by_field_name("left")
            .is_some_and(|left| left.id() == access.id()),
        "update_expression" => true,
        "unary_expression" => parent
            .child(0)
            .is_some_and(|operator| operator.kind() == "delete"),
        _ => false,
    }
}

fn ecmascript_expression_is_finite_selection(
    node: Node<'_>,
    selection: Node<'_>,
    src: &[u8],
    bindings: &EcmascriptBindings<'_>,
) -> bool {
    if node.id() == selection.id() {
        return true;
    }
    if selection.start_byte() < node.start_byte() || selection.end_byte() > node.end_byte() {
        return false;
    }
    match node.kind() {
        "parenthesized_expression" | "as_expression" | "satisfies_expression" | "type_assertion" => node
            .named_child(0)
            .is_some_and(|inner| ecmascript_expression_is_finite_selection(inner, selection, src, bindings)),
        "binary_expression" => {
            let Some(left) = node.child_by_field_name("left") else {
                return false;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return false;
            };
            (selection.start_byte() >= left.start_byte()
                && selection.end_byte() <= left.end_byte()
                && ecmascript_expression_is_finite_selection(left, selection, src, bindings)
                && ecmascript_is_literal_value_at(right, src, bindings))
                || (selection.start_byte() >= right.start_byte()
                    && selection.end_byte() <= right.end_byte()
                    && ecmascript_expression_is_finite_selection(right, selection, src, bindings)
                    && ecmascript_is_literal_value_at(left, src, bindings))
        }
        "ternary_expression" => {
            let Some(consequence) = node.child_by_field_name("consequence") else {
                return false;
            };
            let Some(alternative) = node.child_by_field_name("alternative") else {
                return false;
            };
            (selection.start_byte() >= consequence.start_byte()
                && selection.end_byte() <= consequence.end_byte()
                && ecmascript_expression_is_finite_selection(consequence, selection, src, bindings)
                && ecmascript_is_literal_value_at(alternative, src, bindings))
                || (selection.start_byte() >= alternative.start_byte()
                    && selection.end_byte() <= alternative.end_byte()
                    && ecmascript_expression_is_finite_selection(alternative, selection, src, bindings)
                    && ecmascript_is_literal_value_at(consequence, src, bindings))
        }
        _ => false,
    }
}

fn ecmascript_is_literal_value_at(node: Node<'_>, src: &[u8], bindings: &EcmascriptBindings<'_>) -> bool {
    if matches!(node.kind(), "identifier" | "undefined") && node_text(&node, src).trim() == "undefined" {
        return bindings
            .resolve("undefined", node.start_byte(), node.end_byte())
            .is_none();
    }
    ecmascript_is_literal_value(node, src)
}

fn ecmascript_is_literal_value(mut node: Node<'_>, src: &[u8]) -> bool {
    while matches!(
        node.kind(),
        "parenthesized_expression" | "as_expression" | "satisfies_expression" | "type_assertion"
    ) && node.named_child_count() >= 1
    {
        let Some(inner) = node
            .child_by_field_name("expression")
            .or_else(|| node.named_child(0))
        else {
            return false;
        };
        node = inner;
    }
    match node.kind() {
        "string" | "string_literal" => ecmascript_static_string_literal(node, src).is_some(),
        "number" | "true" | "false" | "null" => true,
        "array" => {
            let mut cursor = node.walk();
            let is_literal = node
                .named_children(&mut cursor)
                .all(|child| ecmascript_is_literal_value(child, src));
            is_literal
        }
        "object" => {
            let mut cursor = node.walk();
            let is_literal = node.named_children(&mut cursor).all(|child| {
                child.kind() == "pair"
                    && child
                        .child_by_field_name("key")
                        .and_then(|key| ecmascript_static_property_name(key, src))
                        .is_some()
                    && child
                        .child_by_field_name("value")
                        .is_some_and(|value| ecmascript_is_literal_value(value, src))
            });
            is_literal
        }
        _ => false,
    }
}

fn ecmascript_exact_string_map_entries(object: Node<'_>, src: &[u8]) -> Option<Vec<StaticStringMapEntry>> {
    let mut entries = Vec::new();
    let mut cursor = object.walk();
    for child in object.named_children(&mut cursor) {
        if child.kind() != "pair" {
            return None;
        }
        let key = child.child_by_field_name("key")?;
        let value = child.child_by_field_name("value")?;
        entries.push(StaticStringMapEntry {
            key: ecmascript_static_property_name(key, src)?,
            value: ecmascript_static_string_literal(value, src)?,
        });
    }
    (!entries.is_empty()).then_some(entries)
}

fn ecmascript_static_property_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    ecmascript_static_string_literal(node, src).or_else(|| {
        matches!(node.kind(), "property_identifier" | "identifier")
            .then(|| node_text(&node, src).trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn ecmascript_character_substitutions(
    defs: &[bonsai_lang_api::Decl],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CharacterSubstitutionFact> {
    let mut facts = Vec::new();
    for return_node in collect_kinds(tree, &["return_statement"]) {
        let return_span = span_of(file, &return_node);
        let Some(decl) = defs
            .iter()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && decl.span.start <= return_span.start
                    && return_span.end <= decl.span.end
            })
            .min_by_key(|decl| decl.span.len())
        else {
            continue;
        };
        let Some(expression) = return_node.named_child(0) else {
            continue;
        };
        let Some((input_param_index, table, domain, transform_span)) =
            ecmascript_character_substitution(expression, &decl.params, file, src)
        else {
            continue;
        };
        facts.push(CharacterSubstitutionFact {
            function_span: decl.span,
            transform_span,
            input_param_index,
            table,
            domain,
        });
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.transform_span.start));
    facts.dedup();
    facts
}

fn ecmascript_character_substitution(
    expression: Node<'_>,
    params: &[String],
    file: FileId,
    src: &[u8],
) -> Option<(usize, String, CharacterSubstitutionDomain, bonsai_common::Span)> {
    let call = unwrap_ecmascript_expression(expression);
    if call.kind() != "call_expression" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    if function.kind() != "member_expression" {
        return None;
    }
    let receiver = function.child_by_field_name("object")?;
    let method = function.child_by_field_name("property")?;
    let method = node_text(&method, src).trim();
    let arguments = ecmascript_call_arguments(call);

    if method == "replace" {
        let input = node_text(&receiver, src).trim();
        let input_param_index = params.iter().position(|param| param == input)?;
        let pattern = arguments.first().copied()?;
        let callback = arguments.get(1).copied()?;
        let characters = ecmascript_exact_regex_characters(pattern, src)?;
        let (table, callback_parameter) = ecmascript_map_lookup_callback(callback, src)?;
        if callback_parameter.is_empty() {
            return None;
        }
        return Some((
            input_param_index,
            table,
            CharacterSubstitutionDomain::ExactCharacters { characters },
            span_of(file, &call),
        ));
    }

    if method != "join" || receiver.kind() != "call_expression" {
        return None;
    }
    let join_separator = arguments.first().copied()?;
    if ecmascript_static_string_literal(join_separator, src).as_deref() != Some("") {
        return None;
    }
    let map_function = receiver.child_by_field_name("function")?;
    if map_function.kind() != "member_expression"
        || map_function
            .child_by_field_name("property")
            .map(|property| node_text(&property, src).trim() == "map")
            != Some(true)
    {
        return None;
    }
    let iterated = map_function.child_by_field_name("object")?;
    let input = ecmascript_spread_only_array_input(iterated, src)?;
    let input_param_index = params.iter().position(|param| param == input)?;
    let callback = ecmascript_call_arguments(receiver).first().copied()?;
    let (table, callback_parameter) = ecmascript_identity_fallback_map_callback(callback, src)?;
    if callback_parameter.is_empty() {
        return None;
    }
    Some((
        input_param_index,
        table,
        CharacterSubstitutionDomain::TableKeysWithIdentityFallback,
        span_of(file, &call),
    ))
}

fn unwrap_ecmascript_expression(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "parenthesized_expression" | "expression") && node.named_child_count() == 1 {
        node = node.named_child(0).expect("single named child");
    }
    node
}

fn ecmascript_call_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).collect()
}

fn ecmascript_spread_only_array_input<'a>(array: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    if array.kind() != "array" || array.named_child_count() != 1 {
        return None;
    }
    let spread = array.named_child(0)?;
    if spread.kind() != "spread_element" {
        return None;
    }
    let argument = spread.named_child(0)?;
    (argument.kind() == "identifier").then(|| node_text(&argument, src).trim())
}

fn ecmascript_map_lookup_callback(callback: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    let (parameter, body) = ecmascript_arrow_parts(callback, src)?;
    let (table, key) = ecmascript_subscript_parts(body, src)?;
    (key == parameter).then_some((table.to_string(), parameter.to_string()))
}

fn ecmascript_identity_fallback_map_callback(callback: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    let (parameter, body) = ecmascript_arrow_parts(callback, src)?;
    if body.kind() != "binary_expression" {
        return None;
    }
    let left = body.child_by_field_name("left")?;
    let right = body.child_by_field_name("right")?;
    if src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim)
        != Some("??")
        || node_text(&right, src).trim() != parameter
    {
        return None;
    }
    let (table, key) = ecmascript_subscript_parts(left, src)?;
    (key == parameter).then_some((table.to_string(), parameter.to_string()))
}

fn ecmascript_arrow_parts<'a>(arrow: Node<'a>, src: &'a [u8]) -> Option<(&'a str, Node<'a>)> {
    if arrow.kind() != "arrow_function" {
        return None;
    }
    let parameter_node = arrow
        .child_by_field_name("parameter")
        .or_else(|| arrow.child_by_field_name("parameters"))?;
    let parameter = if parameter_node.kind() == "identifier" {
        parameter_node
    } else {
        let mut stack = vec![parameter_node];
        let mut found = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" {
                found = Some(node);
                break;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        found?
    };
    let body = arrow.child_by_field_name("body")?;
    Some((node_text(&parameter, src).trim(), body))
}

fn ecmascript_subscript_parts<'a>(subscript: Node<'a>, src: &'a [u8]) -> Option<(&'a str, &'a str)> {
    if subscript.kind() != "subscript_expression" {
        return None;
    }
    let object = subscript.child_by_field_name("object")?;
    let index = subscript.child_by_field_name("index")?;
    if object.kind() != "identifier" || index.kind() != "identifier" {
        return None;
    }
    Some((node_text(&object, src).trim(), node_text(&index, src).trim()))
}

fn ecmascript_exact_regex_characters(regex: Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    if regex.kind() != "regex" {
        return None;
    }
    let pattern = regex.child_by_field_name("pattern")?;
    let pattern = node_text(&pattern, src);
    let inner = pattern.strip_prefix('[')?.strip_suffix(']')?;
    if inner.starts_with('^') || inner.is_empty() {
        return None;
    }
    let mut characters = Vec::new();
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        if character == '-' {
            return None;
        }
        let decoded = if character == '\\' {
            let escaped = chars.next()?;
            if escaped.is_ascii_alphanumeric() {
                return None;
            }
            escaped
        } else {
            character
        };
        characters.push(decoded.to_string());
    }
    characters.sort();
    characters.dedup();
    Some(characters)
}

fn lower_ecmascript_condition_expression(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> ConditionExpressionFact {
    if node.kind() == "parenthesized_expression" {
        if let Some(inner) = node.named_child(0) {
            return lower_ecmascript_condition_expression(inner, file, src);
        }
    }

    let span = span_of(file, &node);
    if node.kind() == "unary_expression" {
        if let Some(operand) = node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
        {
            let prefix = src
                .get(node.start_byte()..operand.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if prefix == Some("!") {
                return ConditionExpressionFact::Not {
                    span,
                    operand: Box::new(lower_ecmascript_condition_expression(operand, file, src)),
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
                    return merge_ecmascript_condition_junction(
                        span,
                        lower_ecmascript_condition_expression(left, file, src),
                        lower_ecmascript_condition_expression(right, file, src),
                        false,
                    );
                }
                Some("&&") => {
                    return merge_ecmascript_condition_junction(
                        span,
                        lower_ecmascript_condition_expression(left, file, src),
                        lower_ecmascript_condition_expression(right, file, src),
                        true,
                    );
                }
                Some("==" | "===" | "!=" | "!==") => {
                    if let Some((subject, type_name)) = ecmascript_type_test_operands(left, right, file, src)
                        .or_else(|| ecmascript_type_test_operands(right, left, file, src))
                    {
                        let type_test = ConditionExpressionFact::TypeTest {
                            span,
                            subject,
                            type_name,
                        };
                        return if matches!(operator, Some("==" | "===")) {
                            type_test
                        } else {
                            ConditionExpressionFact::Not {
                                span,
                                operand: Box::new(type_test),
                            }
                        };
                    }
                    let relation = if matches!(operator, Some("==" | "===")) {
                        ConditionEquality::Equal
                    } else {
                        ConditionEquality::NotEqual
                    };
                    return ConditionExpressionFact::Equality {
                        span,
                        relation,
                        left: ecmascript_condition_operand(left, file, src),
                        right: ecmascript_condition_operand(right, file, src),
                    };
                }
                _ => {}
            }
        }
    }

    ConditionExpressionFact::Atom { span }
}

fn ecmascript_type_test_operands(
    type_query: Node<'_>,
    type_literal: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<(ConditionOperandFact, String)> {
    if type_query.kind() != "unary_expression" {
        return None;
    }
    let subject = type_query
        .child_by_field_name("argument")
        .or_else(|| type_query.named_child(0))?;
    let operator = src
        .get(type_query.start_byte()..subject.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())?
        .trim();
    if operator != "typeof" {
        return None;
    }
    let type_name = ecmascript_static_string_literal(type_literal, src)?;
    Some((ecmascript_condition_operand(subject, file, src), type_name))
}

fn merge_ecmascript_condition_junction(
    span: bonsai_common::Span,
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

fn ecmascript_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    ConditionOperandFact {
        span: span_of(file, &node),
        value_flow: bonsai_lang_api::kit::expression_flow_from_node(node, file, src),
        static_string: ecmascript_static_string_literal(node, src),
    }
}

fn ecmascript_static_string_literal(node: Node<'_>, src: &[u8]) -> Option<String> {
    if !matches!(node.kind(), "string" | "string_literal") {
        return None;
    }
    let text = node_text(&node, src);
    let quote = text.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || text.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let inner = text.get(1..text.len().checked_sub(1)?)?;
    decode_ecmascript_string_contents(inner, quote as char)
}

fn decode_ecmascript_string_contents(inner: &str, quote: char) -> Option<String> {
    let mut output = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            if matches!(character, '\r' | '\n') {
                return None;
            }
            output.push(character);
            continue;
        }
        let escaped = chars.next()?;
        match escaped {
            '\\' => output.push('\\'),
            '\'' if quote == '\'' => output.push('\''),
            '"' if quote == '"' => output.push('"'),
            '/' => output.push('/'),
            'b' => output.push('\u{0008}'),
            'f' => output.push('\u{000c}'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'v' => output.push('\u{000b}'),
            '0' if !chars.peek().is_some_and(char::is_ascii_digit) => output.push('\0'),
            'x' => output.push(decode_ecmascript_hex(&mut chars, 2)?),
            'u' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    let mut digits = String::new();
                    for digit in chars.by_ref() {
                        if digit == '}' {
                            break;
                        }
                        if !digit.is_ascii_hexdigit() || digits.len() == 6 {
                            return None;
                        }
                        digits.push(digit);
                    }
                    if digits.is_empty() {
                        return None;
                    }
                    output.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
                } else {
                    output.push(decode_ecmascript_hex(&mut chars, 4)?);
                }
            }
            '\n' => {}
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            // ECMAScript identity escapes decode to the escaped code point.
            // Decimal/octal escapes are context-sensitive and deliberately
            // remain unknown.
            other if !other.is_ascii_digit() => output.push(other),
            _ => return None,
        }
    }
    Some(output)
}

fn decode_ecmascript_hex(
    chars: &mut std::iter::Peekable<impl Iterator<Item = char>>,
    digits: usize,
) -> Option<char> {
    let mut value = 0_u32;
    for _ in 0..digits {
        value = value.checked_mul(16)?;
        value = value.checked_add(chars.next()?.to_digit(16)?)?;
    }
    char::from_u32(value)
}

/// Type locals initialized by an ECMAScript array literal from the CST. This
/// supplies the same semantic fact a compiler obtains from `const xs = []`;
/// external standard-library summaries can then require an `Array` receiver
/// instead of matching a method spelling on arbitrary user objects.
fn apply_javascript_array_literal_types(index: &mut DeclIndex, tree: &Tree, src: &[u8], file: FileId) {
    let mut bindings = Vec::new();
    for declarator in collect_kinds(tree, &["variable_declarator"]) {
        let Some(name_node) = declarator.child_by_field_name("name") else {
            continue;
        };
        let Some(value_node) = declarator.child_by_field_name("value") else {
            continue;
        };
        if value_node.kind() != "array" || name_node.kind() != "identifier" {
            continue;
        }
        let name = node_text(&name_node, src).trim();
        if !name.is_empty() {
            bindings.push((span_of(file, &declarator), name.to_string()));
        }
    }
    for (span, name) in bindings {
        let owner = index
            .defs
            .iter()
            .enumerate()
            .filter(|(_, decl)| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && decl.span.file == span.file
                    && decl.span.start <= span.start
                    && span.end <= decl.span.end
            })
            .min_by_key(|(_, decl)| decl.span.len())
            .map(|(idx, _)| idx);
        let Some(owner) = owner else { continue };
        let binding = TypeAliasBinding {
            name,
            type_name: "Array".to_string(),
        };
        if !index.defs[owner].type_aliases.contains(&binding) {
            index.defs[owner].type_aliases.push(binding);
        }
    }
}

/// Combine ES-module `import` statements with CommonJS `require(...)` calls.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut import_specs = js_ts_imports(file, tree, src);
    import_specs.extend(js_ts_require_calls(file, tree, src));
    import_specs
}

/// Shared ES-module import parser used by both the JavaScript and
/// TypeScript adapters. Handles:
///   `import x from "y"`             — default import
///   `import { a, b as c } from "z"` — named imports + alias
///   `import * as ns from "n"`       — namespace import
pub fn js_ts_imports(file: FileId, tree: &tree_sitter::Tree, src: &[u8]) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for import_node in collect_kinds(tree, &["import_statement"]) {
        let Some(source) = import_node.child_by_field_name("source") else {
            continue;
        };
        // Prefer the inner `string_fragment` to avoid quote characters in the module path.
        let module = first_named_child_of_kind(&source, "string_fragment")
            .map(|fragment| node_text(&fragment, src).to_string())
            .unwrap_or_else(|| {
                // Older grammars expose the literal directly — strip surrounding quotes.
                node_text(&source, src)
                    .trim_matches(|c: char| matches!(c, '"' | '\''))
                    .to_string()
            });
        let module = normalize_node_builtin_scheme(&module);
        if module.is_empty() {
            continue;
        }
        // We split each import statement into multiple `ImportSpec` rows so the
        // resolver / security matcher can rewrite call sites accurately:
        //   - Module-scope base entry covers the statement itself.
        //   - `{ a as b }` renames become Module-scope (the alias `b` is a
        //     distinct local binding worth surfacing in `imports` browse).
        //   - Shorthand `{ a }` becomes Local-scope so bare `a(...)` expands
        //     to `module.a` while default browse hides it.
        let import_clause = first_named_child_of_kind(&import_node, "import_clause");
        let mut module_alias: Option<String> = None;
        let mut default_alias: Option<String> = None;
        let mut is_wildcard = false;
        let mut renames: Vec<(String, String)> = Vec::new();
        let mut shorthands: Vec<String> = Vec::new();
        if let Some(import_clause) = import_clause {
            let mut clause_cursor = import_clause.walk();
            for clause_child in import_clause.named_children(&mut clause_cursor) {
                match clause_child.kind() {
                    "identifier" => {
                        // Default import: `import Foo from "..."`.
                        default_alias = Some(node_text(&clause_child, src).to_string());
                    }
                    "namespace_import" => {
                        // `import * as ns from "..."` — single binding bound to the whole module.
                        module_alias = first_named_child_of_kind(&clause_child, "identifier")
                            .map(|ident| node_text(&ident, src).to_string());
                        is_wildcard = true;
                    }
                    "named_imports" => {
                        let mut named_cursor = clause_child.walk();
                        for specifier in clause_child.named_children(&mut named_cursor) {
                            if specifier.kind() != "import_specifier" {
                                continue;
                            }
                            let original_name = specifier
                                .child_by_field_name("name")
                                .map(|name_node| node_text(&name_node, src).to_string());
                            let local_alias = specifier
                                .child_by_field_name("alias")
                                .map(|alias_node| node_text(&alias_node, src).to_string());
                            match (original_name, local_alias) {
                                // `{ a as b }` — distinct local binding `b`.
                                (Some(orig), Some(local)) => renames.push((orig, local)),
                                // `{ a }` — local name matches the export name.
                                (Some(orig), None) => shorthands.push(orig),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module: module.clone(),
            alias: module_alias,
            is_wildcard,
            original_name: None,
            scope: ImportScope::Module,
        });
        if let Some(default_alias) = default_alias.filter(|alias| !alias.is_empty()) {
            imports.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module.clone(),
                alias: Some(default_alias),
                is_wildcard: false,
                original_name: Some("default".to_string()),
                scope: ImportScope::Module,
            });
        }
        for (original_name, local_alias) in renames {
            imports.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module.clone(),
                alias: Some(local_alias),
                is_wildcard: false,
                original_name: Some(original_name),
                scope: ImportScope::Module,
            });
        }
        for shorthand_name in shorthands {
            imports.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module.clone(),
                alias: Some(shorthand_name.clone()),
                is_wildcard: false,
                original_name: Some(shorthand_name),
                scope: ImportScope::Local,
            });
        }
    }
    imports
}

/// Surface ECMAScript `export default` and CommonJS
/// `module.exports = function ...` as an additional callable/type
/// binding named `default` in the exporting module. The original
/// declaration remains indexed by its real local name, so same-file
/// references still resolve while default imports / callable
/// CommonJS requires can target the language-level export name.
pub fn apply_js_ts_default_export_aliases(decl_index: &mut DeclIndex, tree: &Tree, src: &[u8], file: FileId) {
    let mut default_exports = Vec::new();
    for export_node in collect_kinds(tree, &["export_statement"]) {
        if !export_statement_has_default_modifier(export_node) {
            continue;
        }
        let target = export_node
            .child_by_field_name("declaration")
            .or_else(|| export_node.child_by_field_name("value"));
        let Some(target) = target else {
            continue;
        };
        if target.kind() == "identifier" {
            let name = node_text(&target, src).to_string();
            if !name.is_empty() {
                default_exports.push(DefaultExportTarget::Name(name));
            }
        } else {
            default_exports.push(DefaultExportTarget::Span(span_of(file, &target)));
        }
    }
    for assignment in collect_kinds(tree, &["assignment_expression"]) {
        let left = assignment.child_by_field_name("left");
        let right = assignment.child_by_field_name("right");
        let (Some(left), Some(right)) = (left, right) else {
            continue;
        };
        if node_text(&left, src).trim() != "module.exports" {
            continue;
        }
        if right.kind() == "identifier" {
            let name = node_text(&right, src).trim();
            if !name.is_empty() {
                default_exports.push(DefaultExportTarget::Name(name.to_string()));
            }
            continue;
        }
        default_exports.push(DefaultExportTarget::Span(span_of(file, &right)));
        if let Some(name_node) = right.child_by_field_name("name") {
            let name = node_text(&name_node, src).trim();
            if !name.is_empty() {
                default_exports.push(DefaultExportTarget::Name(name.to_string()));
            }
        }
    }
    if default_exports.is_empty() || decl_index.defs.iter().any(|decl| decl.name == "default") {
        return;
    }

    let mut next_symbol = decl_index
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .map_or(0, |raw| raw.saturating_add(1));
    let mut aliases = Vec::new();
    let mut seen_sources = Vec::new();
    for target in default_exports {
        let Some(source) = decl_index
            .defs
            .iter()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    bonsai_lang_api::DeclKind::Function
                        | bonsai_lang_api::DeclKind::Method
                        | bonsai_lang_api::DeclKind::Constructor
                        | bonsai_lang_api::DeclKind::Class
                )
            })
            .find(|decl| match &target {
                DefaultExportTarget::Span(span) => decl.span == *span,
                DefaultExportTarget::Name(name) => decl.name == *name,
            })
        else {
            continue;
        };
        if seen_sources.contains(&source.symbol) {
            continue;
        }
        seen_sources.push(source.symbol);
        let mut alias = source.clone();
        alias.symbol = SymbolId::new(next_symbol);
        next_symbol = next_symbol.saturating_add(1);
        alias.name = "default".to_string();
        alias.qualified_name = if alias.module_path.is_empty() {
            Some("default".to_string())
        } else {
            Some(format!("{}.default", alias.module_path.segments.join(".")))
        };
        aliases.push(alias);
    }
    decl_index.defs.extend(aliases);
}

/// Surface JS/TS named exports under their public export member name
/// when it differs from the local implementation name:
///
/// - `exports.name = function localName(...) { ... }`
/// - `module.exports.name = function localName(...) { ... }`
/// - `module.exports = { name: localName }`
/// - `export { localName as name }`
///
/// The shared declaration walker owns duplicate suppression for
/// same-name function expressions, so this only adds real export
/// aliases. Without these aliases, cross-file import/require calls
/// resolve only when the public export name happens to equal the local
/// function name.
pub fn apply_js_ts_commonjs_named_export_aliases(
    decl_index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let mut aliases = Vec::new();
    let mut next_symbol = decl_index
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .map_or(0, |raw| raw.saturating_add(1));
    for assignment in collect_kinds(tree, &["assignment_expression"]) {
        let left = assignment.child_by_field_name("left");
        let right = assignment.child_by_field_name("right");
        let (Some(left), Some(right)) = (left, right) else {
            continue;
        };
        let Some(export_name) = commonjs_named_export_member(node_text(&left, src)) else {
            if node_text(&left, src).trim() == "module.exports" {
                collect_commonjs_object_export_aliases(
                    decl_index,
                    &mut aliases,
                    &mut next_symbol,
                    right,
                    src,
                );
            }
            continue;
        };
        if export_name == "default" || export_name.is_empty() {
            continue;
        }
        let right_span = span_of(file, &right);
        push_named_export_alias_for_span(
            decl_index,
            &mut aliases,
            &mut next_symbol,
            export_name,
            right_span,
        );
    }
    collect_es_named_export_aliases(decl_index, &mut aliases, &mut next_symbol, tree, src);
    decl_index.defs.extend(aliases);
}

fn collect_commonjs_object_export_aliases(
    decl_index: &DeclIndex,
    aliases: &mut Vec<bonsai_lang_api::Decl>,
    next_symbol: &mut u32,
    right: Node<'_>,
    src: &[u8],
) {
    if right.kind() != "object" {
        return;
    }
    let mut cursor = right.walk();
    for child in right.named_children(&mut cursor) {
        if child.kind() != "pair" {
            continue;
        }
        let Some(key) = child.child_by_field_name("key") else {
            continue;
        };
        let Some(value) = child.child_by_field_name("value") else {
            continue;
        };
        let export_name = node_text(&key, src).trim().to_string();
        if export_name.is_empty() || export_name == "default" {
            continue;
        }
        if value.kind() == "identifier" {
            let local_name = node_text(&value, src).trim();
            push_named_export_alias_for_name(decl_index, aliases, next_symbol, export_name, local_name);
        } else {
            push_named_export_alias_for_span(
                decl_index,
                aliases,
                next_symbol,
                export_name,
                span_of(decl_index.file, &value),
            );
        }
    }
}

/// True when the parsed export statement carries ECMAScript's direct
/// `default` modifier. Named exports such as `export { value as default }`
/// contain a named `export_specifier` identifier instead and deliberately do
/// not satisfy this predicate.
fn export_statement_has_default_modifier(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() && child.kind() == "default" {
            return true;
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}

fn collect_es_named_export_aliases(
    decl_index: &DeclIndex,
    aliases: &mut Vec<bonsai_lang_api::Decl>,
    next_symbol: &mut u32,
    tree: &Tree,
    src: &[u8],
) {
    for export_node in collect_kinds(tree, &["export_statement"]) {
        let mut stack = vec![export_node];
        while let Some(current) = stack.pop() {
            if current.kind() == "export_specifier" {
                let local_name = current.child_by_field_name("name");
                let export_name = current.child_by_field_name("alias");
                if let (Some(local), Some(exported)) = (local_name, export_name) {
                    let export_name = node_text(&exported, src).trim().to_string();
                    let local_name = node_text(&local, src).trim();
                    push_named_export_alias_for_name(
                        decl_index,
                        aliases,
                        next_symbol,
                        export_name,
                        local_name,
                    );
                }
                continue;
            }
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
}

fn push_named_export_alias_for_name(
    decl_index: &DeclIndex,
    aliases: &mut Vec<bonsai_lang_api::Decl>,
    next_symbol: &mut u32,
    export_name: String,
    local_name: &str,
) {
    if export_name.is_empty() || local_name.is_empty() || export_name == local_name {
        return;
    }
    let Some(source) = decl_index.defs.iter().find(|decl| decl.name == local_name) else {
        return;
    };
    push_named_export_alias(decl_index, aliases, next_symbol, export_name, source);
}

fn push_named_export_alias_for_span(
    decl_index: &DeclIndex,
    aliases: &mut Vec<bonsai_lang_api::Decl>,
    next_symbol: &mut u32,
    export_name: String,
    source_span: bonsai_common::Span,
) {
    if export_name.is_empty() {
        return;
    }
    let Some(source) = decl_index.defs.iter().find(|decl| decl.span == source_span) else {
        return;
    };
    push_named_export_alias(decl_index, aliases, next_symbol, export_name, source);
}

fn push_named_export_alias(
    decl_index: &DeclIndex,
    aliases: &mut Vec<bonsai_lang_api::Decl>,
    next_symbol: &mut u32,
    export_name: String,
    source: &bonsai_lang_api::Decl,
) {
    if source.name == export_name {
        return;
    }
    if !matches!(
        source.kind,
        bonsai_lang_api::DeclKind::Function
            | bonsai_lang_api::DeclKind::Method
            | bonsai_lang_api::DeclKind::Constructor
            | bonsai_lang_api::DeclKind::Class
    ) {
        return;
    }
    if decl_index.defs.iter().chain(aliases.iter()).any(|decl| {
        decl.name == export_name && decl.span == source.span && decl.body_span == source.body_span
    }) {
        return;
    }
    let mut alias = source.clone();
    alias.symbol = SymbolId::new(*next_symbol);
    *next_symbol = next_symbol.saturating_add(1);
    alias.name = export_name;
    alias.qualified_name = None;
    aliases.push(alias);
}

fn commonjs_named_export_member(left: &str) -> Option<String> {
    let left = left.trim();
    let member = left
        .strip_prefix("exports.")
        .or_else(|| left.strip_prefix("module.exports."))?;
    (!member.is_empty()
        && member
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
    .then(|| member.to_string())
}

enum DefaultExportTarget {
    Span(bonsai_common::Span),
    Name(String),
}

#[derive(Clone, Debug)]
struct JsDestructureSource {
    assign_span: bonsai_common::Span,
    target: String,
    base: String,
    source: String,
}

fn rewrite_javascript_object_destructuring_sources(
    decl_index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let rewrites = collect_javascript_object_destructuring_sources(tree, src, file);
    if rewrites.is_empty() {
        return;
    }
    for decl in &mut decl_index.defs {
        let owner_span = decl.body_span.unwrap_or(decl.span);
        let relevant = rewrites
            .iter()
            .filter(|item| span_contains_or_equal(owner_span, item.assign_span))
            .cloned()
            .collect::<Vec<_>>();
        if !relevant.is_empty() {
            rewrite_destructuring_sources_in_events(&mut decl.flow_events, &relevant);
        }
    }
}

fn collect_javascript_object_destructuring_sources(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<JsDestructureSource> {
    let mut out = Vec::new();
    for declarator in collect_kinds(tree, &["variable_declarator"]) {
        let Some(pattern) = declarator.child_by_field_name("name") else {
            continue;
        };
        let Some(value) = declarator.child_by_field_name("value") else {
            continue;
        };
        if pattern.kind() != "object_pattern" {
            continue;
        }
        let base = normalize_js_member_text(node_text(&value, src));
        if base.is_empty() {
            continue;
        }
        collect_js_object_pattern_sources(pattern, &base, span_of(file, &declarator), src, &mut out);
    }
    out
}

fn collect_js_object_pattern_sources(
    pattern: Node<'_>,
    base: &str,
    assign_span: bonsai_common::Span,
    src: &[u8],
    out: &mut Vec<JsDestructureSource>,
) {
    let mut cursor = pattern.walk();
    for child in pattern.named_children(&mut cursor) {
        match child.kind() {
            "shorthand_property_identifier_pattern" => {
                let target = node_text(&child, src).trim().to_string();
                if !target.is_empty() {
                    out.push(JsDestructureSource {
                        assign_span,
                        base: base.to_string(),
                        source: format!("{base}.{target}"),
                        target,
                    });
                }
            }
            "pair_pattern" => {
                let Some(key_node) = child.child_by_field_name("key") else {
                    continue;
                };
                let Some(value_node) = child.child_by_field_name("value") else {
                    continue;
                };
                let Some(key) = js_object_field_key(key_node, src) else {
                    continue;
                };
                if let Some(target) = js_destructure_target_name(value_node, src) {
                    out.push(JsDestructureSource {
                        assign_span,
                        base: base.to_string(),
                        source: format!("{base}.{key}"),
                        target,
                    });
                }
            }
            "object_assignment_pattern" => {
                let Some(left) = child.child_by_field_name("left") else {
                    continue;
                };
                let target = node_text(&left, src).trim().to_string();
                if !target.is_empty() {
                    out.push(JsDestructureSource {
                        assign_span,
                        base: base.to_string(),
                        source: format!("{base}.{target}"),
                        target,
                    });
                }
            }
            "rest_pattern" => {}
            _ => {}
        }
    }
}

fn js_destructure_target_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            let target = node_text(&node, src).trim().to_string();
            (!target.is_empty()).then_some(target)
        }
        "assignment_pattern" => node
            .child_by_field_name("left")
            .and_then(|left| js_destructure_target_name(left, src)),
        _ => None,
    }
}

fn rewrite_destructuring_sources_in_events(events: &mut Vec<FlowEvent>, rewrites: &[JsDestructureSource]) {
    let original = std::mem::take(events);
    for mut event in original {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_destructuring_sources_in_events(then_events, rewrites);
                rewrite_destructuring_sources_in_events(else_events, rewrites);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_destructuring_sources_in_events(body, rewrites);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_destructuring_sources_in_events(body, rewrites);
                rewrite_destructuring_sources_in_events(catch_events, rewrites);
                rewrite_destructuring_sources_in_events(finally_events, rewrites);
            }
            _ => {}
        }

        let rewrite = match &event {
            FlowEvent::Assign { span, target, .. } => rewrites
                .iter()
                .find(|item| item.target == *target && spans_overlap_or_contain(*span, item.assign_span)),
            _ => None,
        };
        if let Some(rewrite) = rewrite {
            // Destructuring consumes both the aggregate and one exact field. Keep
            // those as separate events: the IDG source filter intentionally does
            // not let a structural `base` source shadow the exact `base.field`
            // source on the same event. The shared target/span interns one Write
            // node with both incoming edges.
            let mut aggregate_event = event.clone();
            set_destructuring_assignment_source(
                &mut aggregate_event,
                &rewrite.base,
                bonsai_lang_api::AssignValueKind::Destructure,
            );
            set_destructuring_assignment_source(
                &mut event,
                &rewrite.source,
                bonsai_lang_api::AssignValueKind::Compound,
            );
            events.push(aggregate_event);
        }
        events.push(event);
    }
}

fn set_destructuring_assignment_source(
    event: &mut FlowEvent,
    source: &str,
    assignment_kind: bonsai_lang_api::AssignValueKind,
) {
    let FlowEvent::Assign {
        source_name,
        source_call,
        source_call_args,
        source_names,
        value_kind,
        ..
    } = event
    else {
        return;
    };
    *source_name = Some(source.to_string());
    *source_call = None;
    source_call_args.clear();
    source_names.clear();
    source_names.push(source.to_string());
    *value_kind = Some(assignment_kind);
}

#[derive(Clone, Debug)]
struct JsObjectFieldAssigns {
    assign_span: bonsai_common::Span,
    target: String,
    fields: Vec<FlowEvent>,
}

fn inject_javascript_object_literal_field_assigns(
    decl_index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let field_assigns = collect_javascript_object_literal_field_assigns(tree, src, file);
    if field_assigns.is_empty() {
        return;
    }
    for decl in &mut decl_index.defs {
        let owner_span = decl.body_span.unwrap_or(decl.span);
        let relevant = field_assigns
            .iter()
            .filter(|item| span_contains_or_equal(owner_span, item.assign_span))
            .cloned()
            .collect::<Vec<_>>();
        if !relevant.is_empty() {
            insert_object_field_assigns_in_events(&mut decl.flow_events, &relevant);
        }
    }
}

fn collect_javascript_object_literal_field_assigns(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<JsObjectFieldAssigns> {
    let mut out = Vec::new();
    for declarator in collect_kinds(tree, &["variable_declarator"]) {
        let Some(name) = declarator.child_by_field_name("name") else {
            continue;
        };
        let Some(value) = declarator.child_by_field_name("value") else {
            continue;
        };
        if value.kind() != "object" || name.kind() != "identifier" {
            continue;
        }
        let target = node_text(&name, src).trim().to_string();
        push_javascript_object_literal_field_assigns(
            &mut out,
            span_of(file, &declarator),
            &target,
            value,
            src,
            file,
        );
    }
    for assignment in collect_kinds(tree, &["assignment_expression"]) {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if right.kind() != "object" {
            continue;
        }
        let target = normalize_js_member_text(node_text(&left, src));
        push_javascript_object_literal_field_assigns(
            &mut out,
            span_of(file, &assignment),
            &target,
            right,
            src,
            file,
        );
    }
    out
}

fn push_javascript_object_literal_field_assigns(
    out: &mut Vec<JsObjectFieldAssigns>,
    assign_span: bonsai_common::Span,
    target: &str,
    object: Node<'_>,
    src: &[u8],
    file: FileId,
) {
    if target.trim().is_empty() {
        return;
    }
    let mut fields = Vec::new();
    let mut cursor = object.walk();
    for child in object.named_children(&mut cursor) {
        match child.kind() {
            "pair" => {
                let Some(key_node) = child.child_by_field_name("key") else {
                    continue;
                };
                let Some(value_node) = child.child_by_field_name("value") else {
                    continue;
                };
                let Some(key) = js_object_field_key(key_node, src) else {
                    continue;
                };
                let sources = js_value_source_names(value_node, src);
                fields.push(FlowEvent::Assign {
                    span: span_of(file, &value_node),
                    target: format!("{target}.{key}"),
                    source_name: (sources.len() == 1).then(|| sources[0].clone()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: sources,
                    declares_new_binding: false,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                });
            }
            "shorthand_property_identifier" => {
                let key = node_text(&child, src).trim().to_string();
                if key.is_empty() {
                    continue;
                }
                fields.push(FlowEvent::Assign {
                    span: span_of(file, &child),
                    target: format!("{target}.{key}"),
                    source_name: Some(key.clone()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: vec![key],
                    declares_new_binding: false,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                });
            }
            "spread_element" => {}
            _ => {}
        }
    }
    if !fields.is_empty() {
        out.push(JsObjectFieldAssigns {
            assign_span,
            target: target.to_string(),
            fields,
        });
    }
}

fn insert_object_field_assigns_in_events(
    events: &mut Vec<FlowEvent>,
    field_assigns: &[JsObjectFieldAssigns],
) {
    let mut index = 0usize;
    while index < events.len() {
        match &mut events[index] {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_object_field_assigns_in_events(then_events, field_assigns);
                insert_object_field_assigns_in_events(else_events, field_assigns);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_object_field_assigns_in_events(body, field_assigns);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_object_field_assigns_in_events(body, field_assigns);
                insert_object_field_assigns_in_events(catch_events, field_assigns);
                insert_object_field_assigns_in_events(finally_events, field_assigns);
            }
            _ => {}
        }

        let inserts = match &events[index] {
            FlowEvent::Assign { span, target, .. } => field_assigns
                .iter()
                .filter(|item| item.target == *target && spans_overlap_or_contain(*span, item.assign_span))
                .flat_map(|item| item.fields.clone())
                .filter(|field_event| !event_list_contains_assign(events, field_event))
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        if inserts.is_empty() {
            index += 1;
            continue;
        }
        let inserted = inserts.len();
        events.splice((index + 1)..=index, inserts);
        index += inserted + 1;
    }
}

fn event_list_contains_assign(events: &[FlowEvent], candidate: &FlowEvent) -> bool {
    let FlowEvent::Assign {
        span: wanted_span,
        target: wanted_target,
        ..
    } = candidate
    else {
        return false;
    };
    events.iter().any(|event| match event {
        FlowEvent::Assign { span, target, .. } => span == wanted_span && target == wanted_target,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            event_list_contains_assign(then_events, candidate)
                || event_list_contains_assign(else_events, candidate)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            event_list_contains_assign(body, candidate)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            event_list_contains_assign(body, candidate)
                || event_list_contains_assign(catch_events, candidate)
                || event_list_contains_assign(finally_events, candidate)
        }
        _ => false,
    })
}

fn js_object_field_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let key = raw
        .strip_prefix('"')
        .and_then(|part| part.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|part| part.strip_suffix('\'')))
        .or_else(|| raw.strip_prefix('`').and_then(|part| part.strip_suffix('`')))
        .unwrap_or(raw)
        .trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(key.to_string())
}

fn js_value_source_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    collect_js_value_source_names(node, src, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_js_value_source_names(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "identifier" | "shorthand_property_identifier" => {
            push_js_source_name(out, node_text(&node, src).trim());
        }
        "member_expression" => {
            push_js_source_name(out, &normalize_js_member_text(node_text(&node, src)));
            if let Some(object) = node.child_by_field_name("object") {
                collect_js_value_source_names(object, src, out);
            }
            return;
        }
        "string" | "number" | "true" | "false" | "null" | "undefined" | "property_identifier" => return,
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_value_source_names(child, src, out);
    }
}

fn push_js_source_name(out: &mut Vec<String>, source: &str) {
    let source = source.trim();
    if source.is_empty()
        || source.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        || source.contains(['"', '\'', '`', '{', '}'])
    {
        return;
    }
    out.push(source.to_string());
}

fn normalize_js_member_text(text: &str) -> String {
    text.trim()
        .replace("?.", ".")
        .replace("?.[", ".[")
        .replace([' ', '\t', '\n', '\r'], "")
        .trim_end_matches(';')
        .to_string()
}

fn span_contains_or_equal(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && outer.end >= inner.end
}

fn spans_overlap_or_contain(left: bonsai_common::Span, right: bonsai_common::Span) -> bool {
    left.file == right.file
        && (span_contains_or_equal(left, right)
            || span_contains_or_equal(right, left)
            || (left.start <= right.end && right.start <= left.end))
}

/// CommonJS `const x = require("y")` / `const { a } = require("y")` /
/// `const { a: b } = require("y")`. Walks `call_expression` nodes whose
/// function name is `require`.
/// Normalize a Node.js builtin-module specifier by dropping the
/// explicit `node:` scheme. `require("node:child_process")` and
/// `import "node:fs/promises"` name the exact same builtins as their
/// bare forms (`child_process`, `fs/promises`); rules and the resolver
/// key on the bare name, so canonicalizing here keeps the prefixed
/// form from silently bypassing package gates and alias-based callee
/// rewrites. Non-builtin specifiers (relative paths, scoped packages)
/// are returned unchanged.
fn normalize_node_builtin_scheme(module: &str) -> String {
    module.strip_prefix("node:").unwrap_or(module).to_string()
}

pub fn js_ts_require_calls(file: FileId, tree: &tree_sitter::Tree, src: &[u8]) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for call_node in collect_kinds(tree, &["call_expression"]) {
        let Some(callee) = call_node.child_by_field_name("function") else {
            continue;
        };
        // Syntactic gate: only bare `require(...)` calls. Member calls
        // (`foo.require(...)`) and other shapes are not module imports.
        if node_text(&callee, src) != "require" {
            continue;
        }
        let Some(arguments) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        // Module path comes from the first string literal argument.
        let module = first_named_child_of_kind(&arguments, "string")
            .and_then(|string_node| first_named_child_of_kind(&string_node, "string_fragment"))
            .map(|fragment| node_text(&fragment, src).to_string())
            .unwrap_or_default();
        let module = normalize_node_builtin_scheme(&module);
        if module.is_empty() {
            continue;
        }
        // Anchor the import to the LHS binding: this is what makes a
        // bare `require()` participate in module-resolution.
        let declarator = call_node
            .parent()
            .filter(|parent| parent.kind() == "variable_declarator");
        let lhs_name_node = declarator.and_then(|vd| vd.child_by_field_name("name"));
        // Case 1: `const x = require("y")` — simple identifier binding.
        let simple_alias = lhs_name_node
            .filter(|name| name.kind() == "identifier")
            .map(|name| node_text(&name, src).to_string());
        // Case 2: `const { a: b, c } = require("y")` — destructured object pattern.
        //   - `{ a: b }` (rename) is Module-scope: `b` is a distinct local binding.
        //   - `{ a }` (shorthand) is Local-scope: bare `a(...)` expands to `module.a`,
        //     but default `imports` browse hides these to reduce noise.
        let mut rename_entries: Vec<(String, String)> = Vec::new();
        let mut shorthand_entries: Vec<String> = Vec::new();
        if let Some(object_pattern) = lhs_name_node.filter(|name| name.kind() == "object_pattern") {
            let mut pattern_cursor = object_pattern.walk();
            for pattern_child in object_pattern.named_children(&mut pattern_cursor) {
                match pattern_child.kind() {
                    "pair_pattern" => {
                        let key_node = pattern_child.child_by_field_name("key");
                        let value_node = pattern_child.child_by_field_name("value");
                        if let (Some(key), Some(value)) = (key_node, value_node) {
                            let original_name = node_text(&key, src).to_string();
                            let local_name = node_text(&value, src).to_string();
                            // Skip self-renames — same name on both sides is a shorthand.
                            if !original_name.is_empty()
                                && !local_name.is_empty()
                                && original_name != local_name
                            {
                                rename_entries.push((original_name, local_name));
                            }
                        }
                    }
                    "shorthand_property_identifier_pattern" => {
                        let name = node_text(&pattern_child, src).to_string();
                        if !name.is_empty() {
                            shorthand_entries.push(name);
                        }
                    }
                    "object_assignment_pattern" => {
                        // `{ exec = noop }` — destructure with default; treat the LHS as a shorthand.
                        if let Some(left) = pattern_child.child_by_field_name("left") {
                            let name = node_text(&left, src).to_string();
                            if !name.is_empty() {
                                shorthand_entries.push(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // Base entry: always one per `require()` call, carrying the simple binding alias if any.
        imports.push(ImportSpec {
            span: span_of(file, &call_node),
            module: module.clone(),
            alias: simple_alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        // Rename entries: one per `{ orig: local }` pair, surfaced at module scope.
        for (original_name, local_name) in rename_entries {
            imports.push(ImportSpec {
                span: span_of(file, &call_node),
                module: module.clone(),
                alias: Some(local_name),
                is_wildcard: false,
                original_name: Some(original_name),
                scope: ImportScope::Module,
            });
        }
        // Shorthand entries: one per `{ a }` binding, kept at local scope (browse hides these).
        for shorthand_name in shorthand_entries {
            imports.push(ImportSpec {
                span: span_of(file, &call_node),
                module: module.clone(),
                alias: Some(shorthand_name.clone()),
                is_wildcard: false,
                original_name: Some(shorthand_name),
                scope: ImportScope::Local,
            });
        }
    }
    imports
}

/// Walk every `class_declaration` and `class` node, harvest its
/// `class_heritage > extends_clause` base names. JS has only single
/// inheritance, but the result shape mirrors the TypeScript adapter
/// for a consistent `Decl.bases` contract.
fn collect_javascript_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    for class_node in collect_kinds(tree, &["class_declaration", "class"]) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for class_child in class_node.named_children(&mut class_cursor) {
            // Both wrapper and extends_clause shapes are accepted — grammar revisions vary.
            if matches!(class_child.kind(), "class_heritage" | "extends_clause") {
                collect_js_extends_names(class_child, src, &mut bases);
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Recursively walk a JS heritage subtree and append any base name we
/// encounter (deduped). Member expressions like `mod.Base` collapse to
/// the right-most segment so `Base` matches a class declaration.
fn collect_js_extends_names(node: Node<'_>, src: &[u8], collected_bases: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "class_heritage" | "extends_clause" => {
                // Wrapper node — descend into its children to find the actual base name.
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
            "identifier" | "member_expression" => {
                let raw_text = node_text(&current, src).to_string();
                // `a.b.Base` -> `Base`. The resolver matches on bare names.
                let canonical = raw_text
                    .rsplit('.')
                    .next()
                    .unwrap_or(raw_text.as_str())
                    .to_string();
                if !canonical.is_empty() && !collected_bases.iter().any(|b| b == &canonical) {
                    collected_bases.push(canonical);
                }
            }
            _ => {
                // Unknown wrapper (e.g. parenthesized expression) — keep descending.
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}

fn rewrite_javascript_super_constructor_invocations(index: &mut DeclIndex) {
    let class_info: HashMap<SymbolId, (String, Vec<String>)> = index
        .defs
        .iter()
        .filter(|decl| matches!(decl.kind, DeclKind::Class))
        .map(|decl| (decl.symbol, (decl.name.clone(), decl.bases.clone())))
        .collect();

    for decl in &mut index.defs {
        if !matches!(decl.kind, DeclKind::Constructor) {
            continue;
        }
        let Some(parent) = decl.parent else {
            continue;
        };
        let Some((_, bases)) = class_info.get(&parent) else {
            continue;
        };
        rewrite_javascript_super_constructor_invocations_in_events(
            &mut decl.flow_events,
            bases.first().map(String::as_str),
        );
    }
}

fn rewrite_javascript_super_constructor_invocations_in_events(
    events: &mut [FlowEvent],
    super_ctor: Option<&str>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
                ..
            } => {
                if let Some(super_ctor) = super_ctor.filter(|ctor| !ctor.is_empty()) {
                    if name.trim() == "super" {
                        name.clear();
                        name.push_str(super_ctor);
                        *receiver = Some("super".to_string());
                        receiver_types.clear();
                        *call_kind = bonsai_lang_api::CallKind::Method;
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_javascript_super_constructor_invocations_in_events(then_events, super_ctor);
                rewrite_javascript_super_constructor_invocations_in_events(else_events, super_ctor);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_javascript_super_constructor_invocations_in_events(body, super_ctor);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_javascript_super_constructor_invocations_in_events(body, super_ctor);
                rewrite_javascript_super_constructor_invocations_in_events(catch_events, super_ctor);
                rewrite_javascript_super_constructor_invocations_in_events(finally_events, super_ctor);
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct JsGetterProjection {
    property: String,
    projected_source: String,
}

pub fn apply_javascript_getter_property_sources(
    decl_index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let own_getters = collect_javascript_getter_projections(decl_index, tree, src, file);
    if own_getters.is_empty() {
        return;
    }

    let mut class_symbols = Vec::new();
    let mut class_symbol_by_name: HashMap<String, SymbolId> = HashMap::new();
    let mut base_symbols_by_class: HashMap<SymbolId, Vec<SymbolId>> = HashMap::new();
    for decl in &decl_index.defs {
        if !matches!(decl.kind, DeclKind::Class) {
            continue;
        }
        class_symbols.push(decl.symbol);
        class_symbol_by_name.insert(canonical_js_class_name(&decl.name), decl.symbol);
        if let Some(qualified) = &decl.qualified_name {
            class_symbol_by_name.insert(canonical_js_class_name(qualified), decl.symbol);
        }
    }
    for decl in &decl_index.defs {
        if !matches!(decl.kind, DeclKind::Class) {
            continue;
        }
        let bases = decl
            .bases
            .iter()
            .filter_map(|base| class_symbol_by_name.get(&canonical_js_class_name(base)).copied())
            .collect::<Vec<_>>();
        if !bases.is_empty() {
            base_symbols_by_class.insert(decl.symbol, bases);
        }
    }

    let mut getters_by_class: HashMap<SymbolId, Vec<JsGetterProjection>> = HashMap::new();
    for class_symbol in class_symbols {
        let mut projections = Vec::new();
        let mut seen_properties = HashSet::new();
        let mut visiting = HashSet::new();
        collect_getters_for_class(
            class_symbol,
            &own_getters,
            &base_symbols_by_class,
            &mut seen_properties,
            &mut visiting,
            &mut projections,
        );
        if !projections.is_empty() {
            getters_by_class.insert(class_symbol, projections);
        }
    }

    for decl in &mut decl_index.defs {
        if !matches!(decl.kind, DeclKind::Method | DeclKind::Constructor) {
            continue;
        }
        let Some(parent) = decl.parent else {
            continue;
        };
        let Some(projections) = getters_by_class.get(&parent) else {
            continue;
        };
        enrich_getter_property_sources_in_events(&mut decl.flow_events, projections);
    }
}

fn collect_javascript_getter_projections(
    decl_index: &DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> HashMap<SymbolId, Vec<JsGetterProjection>> {
    let mut by_class: HashMap<SymbolId, Vec<JsGetterProjection>> = HashMap::new();
    for method in collect_kinds(tree, &["method_definition"]) {
        if !is_javascript_getter_method(method, src) {
            continue;
        }
        let method_span = span_of(file, &method);
        let Some(decl) = decl_index.defs.iter().find(|decl| {
            decl.span == method_span && matches!(decl.kind, DeclKind::Method) && decl.parent.is_some()
        }) else {
            continue;
        };
        let Some(parent) = decl.parent else {
            continue;
        };
        let Some(projected_source) = first_simple_js_getter_return_projection(&decl.flow_events) else {
            continue;
        };
        let projection = JsGetterProjection {
            property: decl.name.clone(),
            projected_source,
        };
        let entries = by_class.entry(parent).or_default();
        if !entries.iter().any(|existing| existing == &projection) {
            entries.push(projection);
        }
    }
    by_class
}

fn is_javascript_getter_method(method: Node<'_>, src: &[u8]) -> bool {
    if method.kind() != "method_definition" {
        return false;
    }
    let Some(name) = method.child_by_field_name("name") else {
        return false;
    };
    let Some(prefix) = src.get(method.start_byte()..name.start_byte()) else {
        return false;
    };
    let Ok(prefix) = std::str::from_utf8(prefix) else {
        return false;
    };
    prefix
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .any(|token| token == "get")
}

fn first_simple_js_getter_return_projection(events: &[FlowEvent]) -> Option<String> {
    for event in events {
        match event {
            FlowEvent::Return { value_flow, .. } => {
                if let Some(projected) = value_flow.projection.as_ref().and_then(|projection| {
                    matches!(projection.base.as_str(), "this" | "super").then(|| projection.canonical_place())
                }) {
                    return Some(projected);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(projected) = first_simple_js_getter_return_projection(then_events)
                    .or_else(|| first_simple_js_getter_return_projection(else_events))
                {
                    return Some(projected);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(projected) = first_simple_js_getter_return_projection(body) {
                    return Some(projected);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(projected) = first_simple_js_getter_return_projection(body)
                    .or_else(|| first_simple_js_getter_return_projection(catch_events))
                    .or_else(|| first_simple_js_getter_return_projection(finally_events))
                {
                    return Some(projected);
                }
            }
            _ => {}
        }
    }
    None
}

fn collect_getters_for_class(
    class_symbol: SymbolId,
    own_getters: &HashMap<SymbolId, Vec<JsGetterProjection>>,
    base_symbols_by_class: &HashMap<SymbolId, Vec<SymbolId>>,
    seen_properties: &mut HashSet<String>,
    visiting: &mut HashSet<SymbolId>,
    out: &mut Vec<JsGetterProjection>,
) {
    if !visiting.insert(class_symbol) {
        return;
    }
    if let Some(getters) = own_getters.get(&class_symbol) {
        for getter in getters {
            if seen_properties.insert(getter.property.clone()) {
                out.push(getter.clone());
            }
        }
    }
    if let Some(bases) = base_symbols_by_class.get(&class_symbol) {
        for base in bases {
            collect_getters_for_class(
                *base,
                own_getters,
                base_symbols_by_class,
                seen_properties,
                visiting,
                out,
            );
        }
    }
    visiting.remove(&class_symbol);
}

fn enrich_getter_property_sources_in_events(events: &mut [FlowEvent], projections: &[JsGetterProjection]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                source_name,
                source_names,
                ..
            } => {
                if let Some(projected) = source_name
                    .as_deref()
                    .and_then(|source| projected_js_getter_source(source, projections))
                {
                    push_unique_source(source_names, projected);
                }
                enrich_getter_source_names(source_names, projections);
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    enrich_getter_sources_in_call_arg(arg, projections);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_getter_property_sources_in_events(then_events, projections);
                enrich_getter_property_sources_in_events(else_events, projections);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_getter_property_sources_in_events(body, projections);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_getter_property_sources_in_events(body, projections);
                enrich_getter_property_sources_in_events(catch_events, projections);
                enrich_getter_property_sources_in_events(finally_events, projections);
            }
            _ => {}
        }
    }
}

fn enrich_getter_sources_in_call_arg(arg: &mut CallArg, projections: &[JsGetterProjection]) {
    let mut candidates = Vec::new();
    candidates.push(arg.value_text.clone());
    if let Some(place) = arg.place.as_deref() {
        candidates.push(place.to_string());
    }
    for source in &arg.source_names {
        candidates.push(source.clone());
    }
    for candidate in candidates {
        if let Some(projected) = projected_js_getter_source(&candidate, projections) {
            push_unique_source(&mut arg.source_names, projected);
        }
    }
    enrich_getter_source_names(&mut arg.source_names, projections);
}

fn enrich_getter_source_names(source_names: &mut Vec<String>, projections: &[JsGetterProjection]) {
    let existing = source_names.clone();
    for source in existing {
        if let Some(projected) = projected_js_getter_source(&source, projections) {
            push_unique_source(source_names, projected);
        }
    }
}

fn projected_js_getter_source(source: &str, projections: &[JsGetterProjection]) -> Option<String> {
    let source = source.trim();
    for projection in projections {
        for receiver in ["this", "super"] {
            let property_read = format!("{receiver}.{}", projection.property);
            if source != property_read {
                continue;
            }
            if receiver == "this" {
                return Some(projection.projected_source.clone());
            }
            if let Some(rest) = projection.projected_source.strip_prefix("this.") {
                return Some(format!("super.{rest}"));
            }
            return Some(projection.projected_source.clone());
        }
    }
    None
}

fn push_unique_source(source_names: &mut Vec<String>, source: String) {
    if !source.trim().is_empty() && !source_names.iter().any(|existing| existing == &source) {
        source_names.push(source);
    }
}

fn canonical_js_class_name(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).trim().to_string()
}

/// Split a workspace-relative JS/TS path into module-identity segments.
/// The trailing source extension is stripped so `src/utils/log.ts` becomes
/// `["src", "utils", "log"]`. Skips path roots and parent (`..`) components.
pub fn js_ts_module_segments(path: &std::path::Path) -> Vec<String> {
    let mut segments: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if let Some(last_segment) = segments.last_mut() {
        // Strip exactly one source extension; `.tsx` is checked before `.ts`.
        for extension in [".tsx", ".ts", ".jsx", ".js", ".mjs", ".cjs"] {
            if last_segment.ends_with(extension) {
                *last_segment = last_segment.trim_end_matches(extension).to_string();
                break;
            }
        }
    }
    segments.retain(|segment| !segment.is_empty());
    segments
}

#[cfg(test)]
mod syntax_tests {
    use super::{collect_kinds, export_statement_has_default_modifier, language_from_pack, PACK_NAME};

    fn export_has_default_modifier(source: &str) -> bool {
        let language = language_from_pack(PACK_NAME).expect("javascript grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set javascript grammar");
        let tree = parser.parse(source, None).expect("parse javascript");
        let exports = collect_kinds(&tree, &["export_statement"]);
        assert_eq!(exports.len(), 1, "expected one parsed export statement");
        export_statement_has_default_modifier(exports[0])
    }

    #[test]
    fn default_export_modifier_comes_from_the_syntax_tree() {
        assert!(export_has_default_modifier("export default app;"));
        assert!(!export_has_default_modifier("export { app as default };"));
        assert!(!export_has_default_modifier("export const app = 1;"));
    }
}
