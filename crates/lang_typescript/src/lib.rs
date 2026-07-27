//! TypeScript language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    collect_modifier_visibility, collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, CallArg, CallKind, DeclIndex, DeclKind, FieldWrite, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    ModifierVocabulary, TypeAliasBinding, TypeAliasVocabulary, Visibility,
};
use tree_sitter::Node;

const TYPESCRIPT_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_declaration", "method_definition", "method_signature"],
    param_kinds: &["required_parameter", "optional_parameter"],
    name_field: "pattern",
    type_field: "type",
};

const TYPESCRIPT_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "method_definition",
        "method_signature",
        "public_field_definition",
        "abstract_method_signature",
    ],
    modifier_container_kinds: &["accessibility_modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("protected", Visibility::Protected),
        ("public", Visibility::Public),
    ],
    // TypeScript's default class-member visibility is `public`.
    default_visibility: Visibility::Public,
};
use bonsai_lang_javascript::{
    apply_javascript_getter_property_sources, apply_js_ts_commonjs_named_export_aliases,
    apply_js_ts_default_export_aliases, js_ts_imports, js_ts_module_segments, js_ts_require_calls,
    populate_ecmascript_compiler_facts, JS_TS_MODULE_RESOLUTION_EXTENSIONS,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("typescript");
const PACK_NAME: &str = "typescript";
const HANDLER: GrammarHandler = GrammarHandler {
    call_kinds: &["new_expression"],
    constructor_names: &["constructor"],
    // TypeScript exposes `abstract class Foo` under
    // `abstract_class_declaration` — the GENERIC_HANDLER default
    // only covers `class_declaration`, so without this override
    // abstract base classes are missed at decl-emission time, and
    // every subclass ends up with `decl.parent = None`. That
    // breaks Phase 3c/3d field-flow stitching: the inheritance
    // walk has no class to attach `BaseRepository` to.
    class_kinds: &[
        "class_declaration",
        "abstract_class_declaration",
        "interface_declaration",
    ],
    ..with_fn_kinds_and_implicit_receivers(
        &[
            "function_declaration",
            "method_definition",
            "method_signature",
            // Generator forms.
            "generator_function_declaration",
            "generator_function",
        ],
        &["this"],
        &[],
    )
};

#[derive(Debug, Default, Copy, Clone)]
pub struct TypeScriptAdapter;

impl TypeScriptAdapter {
    /// Construct a fresh adapter. Stateless; cheap to copy.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for TypeScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "TypeScript"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ts", "tsx"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            universal_type_names: &["any", "unknown", "object", "Object"],
            module_export_aliases: &["exports", "module.exports"],
            module_default_export_names: &["default"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
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
        // TS/JS module = workspace-relative file path with `.ts`/`.tsx` (etc.) stripped.
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
            let src = snapshot.text.as_bytes();
            apply_js_ts_default_export_aliases(&mut decl_index, &tree, src, file);
            // Phase-6 return-type extraction: `function f(): T {}` / `(): T => ...`
            // populates `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, &tree, src, &HANDLER);
            // Visibility from `public/protected/private` keywords, and parameter type aliases.
            let visibility_by_span =
                collect_modifier_visibility(tree.root_node(), file, src, &TYPESCRIPT_VOCAB);
            let type_aliases_by_span = collect_param_type_aliases(&tree, file, src, &TYPESCRIPT_TYPE_ALIASES);
            // WS2 cast typing: `const c = make() as Foo` / `const c = <Foo>make()`.
            // The cast type lives only on the initializer (the declared-type /
            // return-type paths don't see it), so capture it as a local type
            // alias so `c.method(...)` resolves `receiver_type_in` / `[Foo, m]`.
            let cast_aliases_by_span = collect_typescript_cast_aliases(&tree, file, src);
            // TypeScript constructor parameter properties are both parameters
            // and instance fields: `constructor(private svc: Service)`.
            // The generic assignment walker sees no `this.svc = svc` write,
            // so emit the equivalent precise field/type facts from the syntax.
            let parameter_properties_by_span = collect_typescript_parameter_properties(&tree, file, src);
            for decl in &mut decl_index.defs {
                if let Some(vis) = visibility_by_span.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                if let Some(aliases) = type_aliases_by_span.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(cast_aliases) = cast_aliases_by_span.get(&decl.span) {
                    decl.type_aliases.extend(cast_aliases.iter().cloned());
                }
                if let Some(parameter_properties) = parameter_properties_by_span.get(&decl.span) {
                    for (alias, field_write) in parameter_properties {
                        if !decl.type_aliases.contains(alias) {
                            decl.type_aliases.push(alias.clone());
                        }
                        if !decl.receiver_field_writes.contains(field_write) {
                            decl.receiver_field_writes.push(field_write.clone());
                        }
                    }
                }
            }
            // ECMAScript `#name` private fields/methods are syntactically marked.
            for decl in &mut decl_index.defs {
                if decl.name.starts_with('#') {
                    decl.visibility = Visibility::Private;
                }
            }
            // Per-class `bases`: `class Echo extends WebSocketHandler implements Mixin { ... }`
            // becomes `["WebSocketHandler", "Mixin"]`. The TS grammar groups extends +
            // implements under a `class_heritage` child of the class.
            let bases_by_span = collect_typescript_class_bases(&tree, file, src);
            for decl in &mut decl_index.defs {
                // Bases only make sense on type-defining declarations.
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
            apply_javascript_getter_property_sources(&mut decl_index, &tree, src, file);
            inject_typescript_graphql_root_resolver_calls(&mut decl_index, &tree, src, file);
        }
        // Recognised TypeScript lifecycle transitions — same call
        // names as JavaScript since TS shares the JS runtime surface.
        const TYPESCRIPT_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
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
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, TYPESCRIPT_LIFECYCLE_TRANSITIONS);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing
        // (`const c = new Foo()` → `c: Foo`); see the JS adapter for the
        // rationale. TypeScript shares the JS naming convention.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

#[derive(Clone, Debug)]
struct TsGraphqlRootResolver {
    name: String,
    arg_fields: Vec<String>,
}

#[derive(Clone, Debug)]
struct TsGraphqlResolverDispatch {
    call_span: bonsai_common::Span,
    arg_span: bonsai_common::Span,
    variable_values: String,
    resolvers: Vec<TsGraphqlRootResolver>,
}

fn inject_typescript_graphql_root_resolver_calls(
    decl_index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let dispatches = collect_typescript_graphql_resolver_dispatches(tree, src, file);
    if dispatches.is_empty() {
        return;
    }
    for decl in &mut decl_index.defs {
        let owner_span = decl.body_span.unwrap_or(decl.span);
        let relevant = dispatches
            .iter()
            .filter(|dispatch| span_contains_or_equal(owner_span, dispatch.call_span))
            .cloned()
            .collect::<Vec<_>>();
        if !relevant.is_empty() {
            insert_graphql_resolver_dispatches(&mut decl.flow_events, &relevant);
        }
    }
}

fn collect_typescript_graphql_resolver_dispatches(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<TsGraphqlResolverDispatch> {
    let root_resolvers = collect_typescript_graphql_root_resolvers(tree, src);
    if root_resolvers.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for call in collect_kinds(tree, &["call_expression"]) {
        if !typescript_graphql_execute_call(&call, src) {
            continue;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            continue;
        };
        let Some(config) = first_named_child_of_kind(&args, "object") else {
            continue;
        };
        let Some(root_value) = typescript_object_pair_value(config, src, "rootValue") else {
            continue;
        };
        let root_name = node_text(&root_value, src).trim();
        if root_name.is_empty()
            || !root_name
                .chars()
                .all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
        {
            continue;
        }
        let Some(variable_values) = typescript_object_pair_value(config, src, "variableValues") else {
            continue;
        };
        let variable_values_text = node_text(&variable_values, src).trim().to_string();
        if variable_values_text.is_empty() {
            continue;
        }
        let Some(resolvers) = root_resolvers.get(root_name) else {
            continue;
        };
        if resolvers.is_empty() {
            continue;
        }
        out.push(TsGraphqlResolverDispatch {
            call_span: span_of(file, &call),
            arg_span: span_of(file, &variable_values),
            variable_values: variable_values_text,
            resolvers: resolvers.clone(),
        });
    }
    out
}

fn collect_typescript_graphql_root_resolvers(
    tree: &Tree,
    src: &[u8],
) -> std::collections::HashMap<String, Vec<TsGraphqlRootResolver>> {
    let mut out = std::collections::HashMap::new();
    for declarator in collect_kinds(tree, &["variable_declarator"]) {
        let Some(name_node) = declarator.child_by_field_name("name") else {
            continue;
        };
        if name_node.kind() != "identifier" {
            continue;
        }
        let Some(value_node) = declarator.child_by_field_name("value") else {
            continue;
        };
        if value_node.kind() != "object" {
            continue;
        }
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let resolvers = typescript_object_resolvers(value_node, src);
        if !resolvers.is_empty() {
            out.insert(name, resolvers);
        }
    }
    out
}

fn typescript_object_resolvers(object: Node<'_>, src: &[u8]) -> Vec<TsGraphqlRootResolver> {
    let mut out = Vec::new();
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
                if !matches!(
                    value_node.kind(),
                    "arrow_function" | "function" | "function_expression" | "generator_function"
                ) {
                    continue;
                }
                let Some(name) = typescript_object_field_key(key_node, src) else {
                    continue;
                };
                out.push(TsGraphqlRootResolver {
                    name,
                    arg_fields: typescript_first_param_object_fields(value_node, src),
                });
            }
            "method_definition" => {
                let Some(name_node) = child.child_by_field_name("name") else {
                    continue;
                };
                let Some(name) = typescript_object_field_key(name_node, src) else {
                    continue;
                };
                out.push(TsGraphqlRootResolver {
                    name,
                    arg_fields: typescript_first_param_object_fields(child, src),
                });
            }
            _ => {}
        }
    }
    out
}

fn typescript_graphql_execute_call(call: &Node<'_>, src: &[u8]) -> bool {
    let Some(callee) = call.child_by_field_name("function") else {
        return false;
    };
    let callee_text = node_text(&callee, src).trim();
    let tail = callee_text
        .rsplit(['.', ':'])
        .find(|part| !part.trim().is_empty())
        .unwrap_or(callee_text)
        .trim();
    matches!(tail, "graphql" | "execute")
}

fn typescript_object_pair_value<'tree>(object: Node<'tree>, src: &[u8], key: &str) -> Option<Node<'tree>> {
    let mut cursor = object.walk();
    for child in object.named_children(&mut cursor) {
        if child.kind() != "pair" {
            continue;
        }
        let Some(key_node) = child.child_by_field_name("key") else {
            continue;
        };
        if typescript_object_field_key(key_node, src).as_deref() != Some(key) {
            continue;
        }
        return child.child_by_field_name("value");
    }
    None
}

fn typescript_object_field_key(node: Node<'_>, src: &[u8]) -> Option<String> {
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

fn typescript_first_param_object_fields(callable: Node<'_>, src: &[u8]) -> Vec<String> {
    let Some(params) = callable
        .child_by_field_name("parameters")
        .or_else(|| first_named_child_of_kind(&callable, "formal_parameters"))
    else {
        return Vec::new();
    };
    let mut cursor = params.walk();
    let Some(first_param) = params.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "required_parameter" | "optional_parameter" | "identifier" | "object_pattern"
        )
    }) else {
        return Vec::new();
    };
    let pattern = first_param.child_by_field_name("pattern").unwrap_or(first_param);
    let object_pattern = if pattern.kind() == "object_pattern" {
        Some(pattern)
    } else {
        first_named_child_of_kind(&pattern, "object_pattern")
    };
    let Some(object_pattern) = object_pattern else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_typescript_object_pattern_fields(object_pattern, src, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_typescript_object_pattern_fields(pattern: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    let mut cursor = pattern.walk();
    for child in pattern.named_children(&mut cursor) {
        match child.kind() {
            "shorthand_property_identifier_pattern" => {
                let field = node_text(&child, src).trim();
                if !field.is_empty() {
                    out.push(field.to_string());
                }
            }
            "pair_pattern" => {
                if let Some(key_node) = child.child_by_field_name("key") {
                    if let Some(field) = typescript_object_field_key(key_node, src) {
                        out.push(field);
                    }
                }
            }
            _ => collect_typescript_object_pattern_fields(child, src, out),
        }
    }
}

fn insert_graphql_resolver_dispatches(events: &mut Vec<FlowEvent>, dispatches: &[TsGraphqlResolverDispatch]) {
    let mut index = 0usize;
    while index < events.len() {
        match &mut events[index] {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_graphql_resolver_dispatches(then_events, dispatches);
                insert_graphql_resolver_dispatches(else_events, dispatches);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_graphql_resolver_dispatches(body, dispatches);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_graphql_resolver_dispatches(body, dispatches);
                insert_graphql_resolver_dispatches(catch_events, dispatches);
                insert_graphql_resolver_dispatches(finally_events, dispatches);
            }
            _ => {}
        }

        let inserts = match &events[index] {
            FlowEvent::Call { span, name, .. } if matches!(name.as_str(), "graphql" | "execute") => {
                dispatches
                    .iter()
                    .filter(|dispatch| spans_overlap_or_contain(*span, dispatch.call_span))
                    .flat_map(graphql_dispatch_call_events)
                    .filter(|event| !graphql_dispatch_event_exists(events, event))
                    .collect::<Vec<_>>()
            }
            _ => Vec::new(),
        };
        if inserts.is_empty() {
            index += 1;
            continue;
        }
        let inserted = inserts.len();
        let insert_at = index + 1;
        events.splice(insert_at..insert_at, inserts);
        index += inserted + 1;
    }
}

fn graphql_dispatch_call_events(dispatch: &TsGraphqlResolverDispatch) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for resolver in &dispatch.resolvers {
        let arg_text = if resolver.arg_fields.len() == 1 {
            format!("{}.{}", dispatch.variable_values, resolver.arg_fields[0])
        } else {
            dispatch.variable_values.clone()
        };
        out.push(FlowEvent::Call {
            span: dispatch.call_span,
            receiver: None,
            receiver_types: Vec::new(),
            name: resolver.name.clone(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: dispatch.arg_span,
                name: None,
                place: Some(arg_text.clone()),
                source_names: vec![dispatch.variable_values.clone(), arg_text.clone()],
                value_text: arg_text,
            }],
        });
    }
    out
}

fn graphql_dispatch_event_exists(events: &[FlowEvent], candidate: &FlowEvent) -> bool {
    let FlowEvent::Call {
        span: wanted_span,
        name: wanted_name,
        ..
    } = candidate
    else {
        return false;
    };
    events.iter().any(|event| match event {
        FlowEvent::Call { span, name, .. } => span == wanted_span && name == wanted_name,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            graphql_dispatch_event_exists(then_events, candidate)
                || graphql_dispatch_event_exists(else_events, candidate)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            graphql_dispatch_event_exists(body, candidate)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            graphql_dispatch_event_exists(body, candidate)
                || graphql_dispatch_event_exists(catch_events, candidate)
                || graphql_dispatch_event_exists(finally_events, candidate)
        }
        _ => false,
    })
}

fn span_contains_or_equal(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && outer.end >= inner.end
}

fn spans_overlap_or_contain(left: bonsai_common::Span, right: bonsai_common::Span) -> bool {
    left.file == right.file
        && (span_contains_or_equal(left, right)
            || span_contains_or_equal(right, left)
            || (left.start < right.end && right.start < left.end))
}

/// Combine ES-module imports, CommonJS `require(...)` calls, and the
/// TypeScript-only `import x = require("y")` legacy form. Delegates to
/// the JS helpers so the two adapters cannot drift on import semantics.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = js_ts_imports(file, tree, src);
    // Dedup against `import_alias`: the JS helper sees an anonymous `require("y")`
    // and would emit `alias=None` for the same module the TS-specific pass below
    // emits with `alias=Some("x")`.
    let mut require_calls = js_ts_require_calls(file, tree, src);
    let alias_call_spans = ts_import_alias_call_spans(tree);
    require_calls.retain(|spec| !span_inside_any(spec.span, &alias_call_spans));
    imports.extend(require_calls);
    // `import x = require("y")` — TS legacy form. tree-sitter-typescript wraps it
    // in `import_alias` (not `import_statement`), so the JS helper never sees it.
    imports.extend(parse_ts_import_alias(file, tree, src));
    imports
}

/// Return the byte spans of every `call_expression` that lives
/// inside an `import_alias` node. Used to dedup the JS helper's
/// anonymous emission against the TS-specific aliased emission.
fn ts_import_alias_call_spans(tree: &Tree) -> Vec<(u32, u32)> {
    let mut alias_call_spans = Vec::new();
    for alias_node in collect_kinds(tree, &["import_alias"]) {
        let mut stack = vec![alias_node];
        while let Some(current) = stack.pop() {
            if current.kind() == "call_expression" {
                let start = current.start_byte() as u32;
                let end = current.end_byte() as u32;
                alias_call_spans.push((start, end));
            }
            // Descend even past `call_expression` — nested forms are rare but possible.
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    alias_call_spans
}

/// True when `span` is byte-contained within any of the given ranges.
/// Used to suppress duplicate require-call imports that already have an
/// `import_alias` entry above them.
fn span_inside_any(span: bonsai_common::Span, ranges: &[(u32, u32)]) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| span.start >= u64::from(start) && span.end <= u64::from(end))
}

/// Parse TypeScript-only `import x = require("y")` statements. The
/// grammar wraps these in `import_alias` nodes whose `name` field
/// holds `x` and whose `value` field is a call to `require` with a
/// single string argument. Emits a single Module-scope ImportSpec
/// with `alias = Some("x")` so resolve sees `x` as an alias for
/// the `y` module.
fn parse_ts_import_alias(file: FileId, tree: &Tree, src: &[u8]) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for alias_node in collect_kinds(tree, &["import_alias"]) {
        let local_alias = alias_node
            .child_by_field_name("name")
            .map(|name_node| node_text(&name_node, src).to_string());
        // Prefer the documented `value` field; fall back to the first `call_expression`
        // named child to tolerate grammar revisions that expose the require call differently.
        let value_node = alias_node.child_by_field_name("value").or_else(|| {
            let mut cursor = alias_node.walk();
            // Bind explicitly so the cursor outlives the iterator return.
            let found = alias_node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "call_expression");
            found
        });
        let Some(value_node) = value_node else { continue };
        // The value is typically `require("...")`; pull the module path from the first string.
        let module = first_named_child_of_kind(&value_node, "string")
            .and_then(|string_node| first_named_child_of_kind(&string_node, "string_fragment"))
            .map(|fragment| node_text(&fragment, src).to_string())
            .unwrap_or_else(|| {
                // Fallback: walk for any `string_fragment` descendant. Rare, but covers
                // grammars that nest the literal under different node kinds.
                let mut stack = vec![value_node];
                while let Some(current) = stack.pop() {
                    if current.kind() == "string_fragment" {
                        return node_text(&current, src).to_string();
                    }
                    let mut cursor = current.walk();
                    for child in current.named_children(&mut cursor) {
                        stack.push(child);
                    }
                }
                String::new()
            });
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &alias_node),
            module,
            alias: local_alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Whether a declaration kind can carry a base list (`extends` / `implements`).
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// WS2 cast-expression typing. A `const c = make() as Foo` / `const c =
/// <Foo>make()` carries its type ONLY on the cast — the declared-type
/// extractor (`collect_param_type_aliases` handles params, not locals)
/// and the return-type path (`make(): Foo`) both miss it. Capture the
/// cast type as a per-enclosing-function `c -> Foo` alias so
/// `c.method(tainted)` resolves `receiver_type_in: [Foo]` / `[Foo, m]`.
///
/// Keyed by the enclosing function declaration's span (matching how
/// `collect_param_type_aliases` keys), and restricted to PascalCase
/// (class-like) types — the only shape receiver-type rules key on —
/// mirroring the C#/Java cast extractors.
fn collect_typescript_cast_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    const FN_KINDS: &[&str] = &[
        "function_declaration",
        "function_expression",
        "method_definition",
        "arrow_function",
        "generator_function_declaration",
    ];
    let mut out = std::collections::HashMap::new();
    for fn_node in collect_kinds(tree, FN_KINDS) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![fn_node];
        while let Some(node) = work.pop() {
            // A nested function owns its own locals — let its own
            // iteration scope them rather than leaking into the parent.
            if node != fn_node && FN_KINDS.contains(&node.kind()) {
                continue;
            }
            if node.kind() == "variable_declarator" {
                extend_ts_aliases_from_cast(node, src, &mut aliases);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                work.push(child);
            }
        }
        // Only PascalCase class-like types — `string`/`any`/`number` etc.
        // are useless for receiver-type matching and aliasing a local to
        // them would disturb clean-overwrite / callable-binding resolution.
        aliases.retain(|alias| {
            alias
                .type_name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
        });
        if !aliases.is_empty() {
            out.insert(span_of(file, &fn_node), aliases);
        }
    }
    out
}

/// Emit a `name -> Type` alias when a `variable_declarator`'s initializer
/// IS a cast (`x as Foo` / `<Foo>x`). Reads only the declarator's `value`
/// field, so a cast nested in a call argument (`const c = wrap(x as Foo)`)
/// does NOT mistype the local — only a cast that is the whole initializer.
fn extend_ts_aliases_from_cast(declarator: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let Some(name_node) = declarator.child_by_field_name("name") else {
        return;
    };
    // Only simple identifier bindings (`const c = ...`); destructuring
    // patterns don't bind a single receiver.
    if name_node.kind() != "identifier" {
        return;
    }
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return;
    }
    let Some(value) = declarator.child_by_field_name("value") else {
        return;
    };
    // `x as Foo` is `as_expression`; `<Foo>x` is `type_assertion`.
    if !matches!(value.kind(), "as_expression" | "type_assertion") {
        return;
    }
    let Some(type_name) = ts_cast_type_name(value, src) else {
        return;
    };
    if type_name.is_empty() {
        return;
    }
    aliases.push(TypeAliasBinding { name, type_name });
}

/// The cast's target type. For `x as Foo` the `type_identifier` is the
/// trailing child; for `<Foo>x` it is the leading child. Generic casts
/// (`as Foo<T>`) surface a `generic_type` whose `name` is the base type.
fn ts_cast_type_name(cast: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = cast.walk();
    for child in cast.named_children(&mut cursor) {
        match child.kind() {
            "type_identifier" => return Some(node_text(&child, src).trim().to_string()),
            "generic_type" => {
                if let Some(name) = child.child_by_field_name("name") {
                    return Some(node_text(&name, src).trim().to_string());
                }
            }
            // `<Foo>x` (type_assertion) nests the type under `type_arguments`.
            "type_arguments" => {
                let mut inner = child.walk();
                for ty in child.named_children(&mut inner) {
                    match ty.kind() {
                        "type_identifier" => return Some(node_text(&ty, src).trim().to_string()),
                        "generic_type" => {
                            if let Some(name) = ty.child_by_field_name("name") {
                                return Some(node_text(&name, src).trim().to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// TypeScript parameter properties are the syntax-level equivalent of:
///
///   constructor(private readonly diag: DiagService) { this.diag = diag; }
///
/// Tree-sitter exposes this as a normal constructor parameter carrying
/// an `accessibility_modifier` token rather than an assignment event. Emit
/// the same `diag -> DiagService` and `this.diag` field-write facts that a
/// handwritten assignment would have produced, but only for the syntactic
/// parameter-property forms (`public` / `private` / `protected` / `readonly`).
fn collect_typescript_parameter_properties(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<(TypeAliasBinding, FieldWrite)>> {
    let mut out = std::collections::HashMap::new();
    for ctor in collect_kinds(tree, &["method_definition"]) {
        if !typescript_method_name_is(&ctor, src, "constructor") {
            continue;
        }
        let Some(params_node) = ctor
            .child_by_field_name("parameters")
            .or_else(|| first_named_child_of_kind(&ctor, "formal_parameters"))
        else {
            continue;
        };

        let mut bindings: Vec<(TypeAliasBinding, FieldWrite)> = Vec::new();
        let mut param_index = 0usize;
        let mut cursor = params_node.walk();
        for param in params_node.named_children(&mut cursor) {
            if !matches!(param.kind(), "required_parameter" | "optional_parameter") {
                continue;
            }
            let current_index = param_index;
            param_index += 1;

            if !typescript_parameter_property_declares_field(&param, src) {
                continue;
            }
            let Some(name) = typescript_parameter_property_name(&param, src) else {
                continue;
            };
            let Some(type_name) = typescript_parameter_property_type(&param, src) else {
                continue;
            };
            if name.is_empty() || name == type_name {
                continue;
            }
            let alias = TypeAliasBinding {
                name: name.clone(),
                type_name,
            };
            let field_write = FieldWrite {
                span: span_of(file, &param),
                target: format!("this.{name}"),
                source_param_indices: vec![current_index],
            };
            let entry = (alias, field_write);
            if !bindings.contains(&entry) {
                bindings.push(entry);
            }
        }
        if !bindings.is_empty() {
            out.insert(span_of(file, &ctor), bindings);
        }
    }
    out
}

fn typescript_method_name_is(node: &Node<'_>, src: &[u8], expected: &str) -> bool {
    node.child_by_field_name("name")
        .map(|name| node_text(&name, src).trim() == expected)
        .unwrap_or(false)
}

fn typescript_parameter_property_declares_field(param: &Node<'_>, src: &[u8]) -> bool {
    let mut cursor = param.walk();
    for child in param.named_children(&mut cursor) {
        let kind = child.kind();
        if matches!(kind, "accessibility_modifier" | "readonly_modifier") || kind.contains("readonly") {
            return true;
        }
    }
    let Some(pattern) = param.child_by_field_name("pattern") else {
        return false;
    };
    if pattern.start_byte() <= param.start_byte() || pattern.start_byte() > src.len() {
        return false;
    }
    let prefix = std::str::from_utf8(&src[param.start_byte()..pattern.start_byte()]).unwrap_or_default();
    prefix
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|token| matches!(token, "public" | "private" | "protected" | "readonly"))
}

fn typescript_parameter_property_name(param: &Node<'_>, src: &[u8]) -> Option<String> {
    let pattern = param.child_by_field_name("pattern")?;
    typescript_identifier_leaf(pattern, src)
}

fn typescript_parameter_property_type(param: &Node<'_>, src: &[u8]) -> Option<String> {
    let type_node = param.child_by_field_name("type")?;
    typescript_type_name_leaf(type_node, src)
}

fn typescript_identifier_leaf(node: Node<'_>, src: &[u8]) -> Option<String> {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern" | "private_property_identifier"
    ) {
        let name = node_text(&node, src).trim().trim_start_matches('#').to_string();
        return (!name.is_empty()).then_some(name);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(name) = typescript_identifier_leaf(child, src) {
            return Some(name);
        }
    }
    None
}

fn typescript_type_name_leaf(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" | "predefined_type" | "nested_type_identifier" => {
            return canonical_ts_type_name(node_text(&node, src));
        }
        "generic_type" => {
            if let Some(name) = node.child_by_field_name("name") {
                return canonical_ts_type_name(node_text(&name, src));
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(type_name) = typescript_type_name_leaf(child, src) {
            return Some(type_name);
        }
    }
    None
}

fn canonical_ts_type_name(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_start_matches(':').trim();
    let name = canonical_ts_base_name(raw)?;
    name.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        .then_some(name)
}

/// Walk TS class / interface / abstract-class declarations and
/// collect bare base type names. Grammar shape:
///
///   `class Echo extends WebSocketHandler implements Mixin { ... }` →
///     (class_declaration name: (type_identifier)
///        (class_heritage
///           (extends_clause value: (identifier))
///           (implements_clause (type_identifier))))
///
/// `interface_declaration` uses `extends_type_clause` (multiple
/// type identifiers under one wrapper) instead of `class_heritage`.
fn collect_typescript_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &[
        "class_declaration",
        "abstract_class_declaration",
        "class",
        "interface_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for class_child in class_node.named_children(&mut class_cursor) {
            match class_child.kind() {
                // Class wrapper containing both `extends_clause` and `implements_clause`.
                "class_heritage" => {
                    collect_ts_heritage_names(class_child, src, &mut bases);
                }
                // `interface_declaration` and direct `extends_clause` children.
                "extends_type_clause" | "extends_clause" => {
                    collect_ts_heritage_names(class_child, src, &mut bases);
                }
                _ => {}
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Walk a TS heritage wrapper (class_heritage / extends_clause /
/// implements_clause / extends_type_clause) and pick out every
/// identifier-like base name. Generics → leftmost name.
fn collect_ts_heritage_names(node: Node<'_>, src: &[u8], collected_bases: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            // Wrapper kinds — descend; the actual identifier is one or more levels down.
            "extends_clause" | "implements_clause" | "extends_type_clause" | "class_heritage" => {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
            "identifier" | "type_identifier" => {
                if let Some(name) = canonical_ts_base_name(node_text(&current, src)) {
                    if !collected_bases.iter().any(|b| b == &name) {
                        collected_bases.push(name);
                    }
                }
            }
            "generic_type" => {
                // `Foo<T>` — keep `Foo` and skip `type_arguments` entirely so we
                // don't accidentally collect `T` as a base.
                if let Some(name_child) = current.child_by_field_name("name") {
                    if let Some(name) = canonical_ts_base_name(node_text(&name_child, src)) {
                        if !collected_bases.iter().any(|b| b == &name) {
                            collected_bases.push(name);
                        }
                    }
                } else {
                    // Fallback for grammars without the `name` field: take the
                    // first identifier-like child and stop.
                    let mut cursor = current.walk();
                    for child in current.named_children(&mut cursor) {
                        if matches!(child.kind(), "identifier" | "type_identifier") {
                            if let Some(name) = canonical_ts_base_name(node_text(&child, src)) {
                                if !collected_bases.iter().any(|b| b == &name) {
                                    collected_bases.push(name);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            "nested_type_identifier" | "nested_identifier" => {
                // `Foo.Bar` — `canonical_ts_base_name` keeps only the right-most segment.
                if let Some(name) = canonical_ts_base_name(node_text(&current, src)) {
                    if !collected_bases.iter().any(|b| b == &name) {
                        collected_bases.push(name);
                    }
                }
            }
            _ => {
                // Unknown wrapper — keep descending; we'd rather over-walk than miss a base.
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}

/// Reduce a heritage type expression to a bare class/interface name:
/// strips generics (`Foo<T>` -> `Foo`) and nested-type prefixes
/// (`mod.Foo` -> `Foo`). Returns `None` if nothing usable remains.
fn canonical_ts_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Drop generic argument list before any path split — `mod.Foo<T>` should yield `Foo`.
    let without_generics = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let bare = without_generics
        .rsplit('.')
        .next()
        .unwrap_or(without_generics)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}
