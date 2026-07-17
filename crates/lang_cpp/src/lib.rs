//! C++ language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        c_family_preproc_imports, collect_kinds, collect_param_type_aliases, first_named_child_of_kind,
        language_from_pack, node_text, parse_with, span_of, with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, AggregateLayout, DeclIndex, DeclKind, FieldWrite, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    TypeAliasBinding, TypeAliasVocabulary, Visibility,
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

pub const LANG_ID: LanguageId = LanguageId::new("cpp");
const PACK_NAME: &str = "cpp";
const CPP_CALL_KINDS: &[&str] = &["new_expression"];

/// C++ lifecycle transitions. `release` covers `unique_ptr.release()`.
/// `delete` / `delete[]` aren't `Call` events so they're not modelled here.
const CPP_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
    bonsai_lang_api::LifecycleTransition {
        call_match: "free",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "fclose",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "close",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "closedir",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "release",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "reset",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "std::move",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "move",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "pthread_mutex_unlock",
        transition: "unlocked",
        arg_index: 0,
    },
];

const HANDLER: GrammarHandler = GrammarHandler {
    call_kinds: CPP_CALL_KINDS,
    // `this` for instance methods; C++ has no `super` keyword, but
    // `Base::method()` is a qualified call that the resolver
    // already narrows by qualified-name matching, so the explicit
    // implicit-receiver list stays at `this`.
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    ..with_fn_kinds_and_implicit_receivers(&["function_definition"], &["this"], &[])
};

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
        &["cpp", "cc", "cxx", "hpp", "hh", "hxx"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Macros: same story as C — tree-sitter-cpp parses
        // `STR_CPY(...)` / `LOG(...)` / `assert(...)` as ordinary
        // call expressions and the engine narrows them by name.
        // `#define` expansion is not performed.
        LanguageCapabilities {
            macros: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            // C++ constructors are class-named; the kind-based
            // `DeclKind::Constructor` lookup is authoritative.
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &["this"],
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
            let cast_aliases = collect_cpp_cast_aliases(&tree, file, src);
            let initializer_specs = collect_cpp_initializer_field_specs(&tree, file, src);
            for decl in &mut decl_index.defs {
                if let Some(fields) = decl.parent.and_then(|parent| fields_by_parent.get(&parent)) {
                    qualify_cpp_member_expression_flows(&mut decl.flow_events, fields);
                }
                if let Some(visibility) = access_by_span.get(&decl.span).copied() {
                    decl.visibility = visibility;
                }
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                for (fn_span, binding) in &cast_aliases {
                    if *fn_span == decl.span {
                        decl.type_aliases.push(binding.clone());
                    }
                }
                // Repair catch-param bindings: the kit's generic
                // extractor picks the first identifier descendant of
                // the catch clause, which on C++ `catch (const T& e)`
                // is the type identifier rather than the binding.
                fix_cpp_catch_params(&mut decl.flow_events, &tree, src);
                // Bases only attach to class-shaped decls; skip
                // free functions, methods, vars, etc.
                if let Some(specs) = initializer_specs
                    .iter()
                    .find_map(|(span, specs)| (*span == decl.span).then_some(specs))
                {
                    for spec in specs {
                        let source_param_indices = decl
                            .params
                            .iter()
                            .enumerate()
                            .filter_map(|(idx, param)| {
                                cpp_value_mentions_param(&spec.value, param).then_some(idx)
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
        // Append `FlowEvent::Lifecycle` for recognised C++
        // resource transitions. Built on the C base set since
        // `free` / `fclose` / `close` carry over; `delete` is the
        // C++-specific addition.
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            let has_variadic_param = decl
                .params
                .iter()
                .any(|param| param == bonsai_lang_api::kit::SYNTHETIC_VARARGS_PARAM);
            bonsai_lang_api::kit::normalize_c_variadic_builtin_flow(
                &mut decl.flow_events,
                has_variadic_param,
            );
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, CPP_LIFECYCLE_TRANSITIONS);
            apply_cpp_moved_argument_places(&mut decl.flow_events);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`new Foo()` / `Foo()` / `Foo::new()` -> typed receiver) so `recv.method(...)` resolves
        // `receiver_type_in` / `[Type, method]` rules; the constructor heuristic only
        // types PascalCase callees, so language exported-function calls are unaffected.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
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

fn qualify_cpp_member_expression_flows(events: &mut [FlowEvent], fields: &std::collections::HashSet<String>) {
    for event in events {
        match event {
            FlowEvent::Return { value_flow, .. } | FlowEvent::Yield { value_flow, .. } => {
                qualify_cpp_member_expression_flow(value_flow, fields);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                qualify_cpp_member_expression_flows(then_events, fields);
                qualify_cpp_member_expression_flows(else_events, fields);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                qualify_cpp_member_expression_flows(body, fields);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                qualify_cpp_member_expression_flows(body, fields);
                qualify_cpp_member_expression_flows(catch_events, fields);
                qualify_cpp_member_expression_flows(finally_events, fields);
            }
            _ => {}
        }
    }
}

fn qualify_cpp_member_expression_flow(
    flow: &mut bonsai_lang_api::ExpressionFlow,
    fields: &std::collections::HashSet<String>,
) {
    let old_place = flow.place.clone();
    if let Some(projection) = &mut flow.projection {
        if fields.contains(&projection.base) {
            projection.path.insert(0, std::mem::take(&mut projection.base));
            projection.base = "this".to_string();
            flow.place = Some(projection.canonical_place());
        }
    } else if let Some(place) = flow.place.as_deref() {
        if fields.contains(place) {
            flow.projection = Some(bonsai_lang_api::ExpressionProjection {
                base: "this".to_string(),
                path: vec![place.to_string()],
            });
            flow.place = Some(format!("this.{place}"));
        }
    }
    if let (Some(old_place), Some(new_place)) = (old_place.as_deref(), flow.place.as_deref()) {
        if old_place != new_place {
            for source in &mut flow.source_names {
                if source == old_place {
                    source.clone_from(&new_place.to_string());
                }
            }
        }
    }
    for field in &mut flow.aggregate_fields {
        qualify_cpp_member_expression_flow(&mut field.value, fields);
    }
    for item in &mut flow.tuple_items {
        qualify_cpp_member_expression_flow(item, fields);
    }
    for spread in &mut flow.spreads {
        qualify_cpp_member_expression_flow(spread, fields);
    }
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
    value: String,
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
            let value = node_text(&value_node, src)
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim()
                .to_string();
            if field.is_empty() || value.is_empty() {
                continue;
            }
            specs.push(CppInitializerFieldSpec {
                span: span_of(file, &init),
                field,
                value,
            });
        }
        if !specs.is_empty() {
            out.push((span_of(file, &fn_node), specs));
        }
    }
    out
}

fn cpp_value_mentions_param(value: &str, param: &str) -> bool {
    let mut token = String::new();
    for ch in value.chars().chain(std::iter::once(' ')) {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }
        if token == param {
            return true;
        }
        token.clear();
    }
    false
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
