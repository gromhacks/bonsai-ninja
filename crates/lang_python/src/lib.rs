//! Python language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        call_arg_from_nodes, collect_kinds, language_from_pack, node_text, normalize_call_name_whitespace,
        parse_with, span_of, GENERIC_HANDLER,
    },
    AdapterContext, AdapterError, AssignmentValueIndex, CallArg, CallKind, DeclIndex, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    TypeAliasBinding, Visibility,
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
    fn_kinds: &["function_definition"],
    class_kinds: &["class_definition"],
    method_kinds: GENERIC_HANDLER.method_kinds,
    method_context_kinds: &["class_definition"],
    constructor_method_kinds: GENERIC_HANDLER.constructor_method_kinds,
    constructor_names: &["__init__"],
    if_kinds: GENERIC_HANDLER.if_kinds,
    for_kinds: GENERIC_HANDLER.for_kinds,
    foreach_kinds: GENERIC_HANDLER.foreach_kinds,
    while_kinds: GENERIC_HANDLER.while_kinds,
    do_kinds: GENERIC_HANDLER.do_kinds,
    loop_kinds: GENERIC_HANDLER.loop_kinds,
    call_kinds: GENERIC_HANDLER.call_kinds,
    assignment_kinds: GENERIC_HANDLER.assignment_kinds,
    return_kinds: GENERIC_HANDLER.return_kinds,
    throw_kinds: GENERIC_HANDLER.throw_kinds,
    lambda_kinds: GENERIC_HANDLER.lambda_kinds,
    try_kinds: GENERIC_HANDLER.try_kinds,
    catch_kinds: GENERIC_HANDLER.catch_kinds,
    finally_kinds: GENERIC_HANDLER.finally_kinds,
    break_kinds: GENERIC_HANDLER.break_kinds,
    continue_kinds: GENERIC_HANDLER.continue_kinds,
    yield_kinds: GENERIC_HANDLER.yield_kinds,
    await_kinds: GENERIC_HANDLER.await_kinds,
    defer_kinds: GENERIC_HANDLER.defer_kinds,
    using_kinds: GENERIC_HANDLER.using_kinds,
    special_forms: &[],
    method_receiver_param_index: Some(0),
    // `self` for ordinary instance methods; `super` so `super().foo()`
    // and `super(Class, self).foo()` resolve to the parent class's
    // `foo` via the engine's `resolve_super_method_candidates`. The
    // engine treats both `super` and the call form `super()` as
    // implicit-receiver markers.
    implicit_receiver_names: &["self", "super"],
    implicit_receiver_prefixes: GENERIC_HANDLER.implicit_receiver_prefixes,
    tail_expression_returns: GENERIC_HANDLER.tail_expression_returns,
    void_return_type_names: GENERIC_HANDLER.void_return_type_names,
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
            reflection: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: &["__init__"],
            bare_call_constructor_syntax: true,
            super_receiver_tokens: &["super"],
            // Python's receiver is the adapter-proven first method parameter;
            // `self` is a convention, not an implicit grammar token.
            implicit_receiver_tokens: &[],
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
            let property_fn_spans = collect_python_property_function_spans(&tree, file, src);
            let property_aliases = collect_python_property_aliases(&idx, &property_fn_spans);
            let property_aliases_by_decl = python_property_aliases_by_decl(&idx, &property_aliases);
            let assignment_values = AssignmentValueIndex::new(&idx.assignment_values);
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
                augment_python_dict_flow_events(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                    &assignment_values,
                );
                if let Some(property_aliases_for_decl) = property_aliases_by_decl.get(&decl.symbol) {
                    augment_python_property_flow_events(&mut decl.flow_events, property_aliases_for_decl);
                }
                rewrite_python_constant_reflection(&mut decl.flow_events);
                rewrite_python_generator_send(&mut decl.flow_events);
                augment_python_asyncio_to_thread_calls(&mut decl.flow_events);
            }
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
            if let Some(argument) = call_arg_from_nodes(arg, value_node, file, src, name) {
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
    if !python_span_contains(decl_span, pattern.span) {
        return false;
    }
    let Some(owner) = callable_spans
        .iter()
        .copied()
        .filter(|span| python_span_contains(*span, pattern.span))
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
) {
    for event in events.iter_mut() {
        match event {
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_python_dict_flow_events(then_events, source, assignment_values);
                augment_python_dict_flow_events(else_events, source, assignment_values);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                augment_python_dict_flow_events(body, source, assignment_values);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_python_dict_flow_events(body, source, assignment_values);
                augment_python_dict_flow_events(catch_events, source, assignment_values);
                augment_python_dict_flow_events(finally_events, source, assignment_values);
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
                for field_read in python_static_get_field_reads(rhs) {
                    synthetic.push(bonsai_lang_api::FlowEvent::Assign {
                        span: *span,
                        target: target.clone(),
                        source_name: Some(field_read.clone()),
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: vec![field_read],
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
