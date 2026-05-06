//! Java language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasBinding, Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("java");
const PACK_NAME: &str = "java";

/// Java lifecycle transitions: Closeable / Future / Lock / Disposable.
const JAVA_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
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
        call_match: "unlock",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "release",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "dispose",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "destroy",
        transition: "freed",
        arg_index: 0,
    },
];

const HANDLER: GrammarHandler = with_fn_kinds_and_implicit_receivers(
    &["method_declaration", "constructor_declaration"],
    &["this", "super"],
    &[],
);

#[derive(Debug, Default, Copy, Clone)]
pub struct JavaAdapter;

impl JavaAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for JavaAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Java"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["java"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Exceptions: the adapter populates `Throw::thrown_type` from
        // `throw new IOException(...)` and `Try::catch_types` from
        // `catch (IOException e)` (including multi-catch
        // `catch (A | B e)`). The engine seeds the catch param only
        // when at least one body throw is type-assignable; this lifts
        // the `Partial` claim to `Exact` for typed-exception flow on
        // Java code.
        // Reflection: the adapter rewrites the constant-string
        // `Class.forName("X").getMethod("Y").invoke(target, args)`
        // chain into a synthesized direct call `X.Y(args)`. Dynamic
        // forms remain unrewritten and the rule-load gate still
        // rejects rules anchored on the reflective shape.
        LanguageCapabilities {
            exceptions: bonsai_lang_api::CapabilityLevel::Exact,
            reflection: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
            return index;
        };
        let src = snapshot.text.as_bytes();
        // Populate Throw::thrown_type and Try::catch_types from the
        // parse tree before downstream resolution. Done first so the
        // type info propagates through every later mutation.
        for decl in &mut index.defs {
            populate_java_exception_types(&mut decl.flow_events, &tree, src);
            rewrite_java_reflection_chain(&mut decl.flow_events);
        }
        let field_aliases = collect_java_type_aliases(tree.root_node(), src, &["field_declaration"]);
        let method_aliases = collect_java_method_type_aliases(&tree, file, src, &field_aliases);
        for decl in &mut index.defs {
            if let Some(aliases) = method_aliases
                .iter()
                .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
            {
                decl.type_aliases = aliases.clone();
            }
        }
        // Per-class `bases`: `class C extends B implements I, J` →
        // ["B", "I", "J"]. Lets `kind: param` rules require an
        // ancestor type (`in_class: [WebSocketHandler]` matching a
        // user `class Echo extends WebSocketHandler { ... }`).
        let bases_by_span = collect_java_class_bases(&tree, file, src);
        for decl in &mut index.defs {
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
        // Java visibility from real syntax — `public`/`private`/
        // `protected` modifiers, and absence-of-modifier = package-private.
        let visibility_by_span = collect_java_visibility(tree.root_node(), file, src);
        for decl in &mut index.defs {
            if let Some(vis) = visibility_by_span.get(&decl.span).copied() {
                decl.visibility = vis;
            }
        }
        // Module path from `package com.foo.bar;` declaration.
        // When absent (default package), fall back to file-stem.
        if let Some(segments) = extract_java_package(tree.root_node(), src) {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut index, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut index, ctx);
        }
        // Append `FlowEvent::Lifecycle` for recognised Java
        // resource transitions (`Closeable.close`, `Future.cancel`,
        // `Lock.unlock`).
        for decl in &mut index.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, JAVA_LIFECYCLE_TRANSITIONS);
        }
        index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Build per-method type-alias bindings (`Foo bar` → `bar : Foo`) by
/// merging file-level field aliases with each method's local declarations.
fn collect_java_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    field_aliases: &[TypeAliasBinding],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut aliases_by_method = Vec::new();
    for method_node in collect_kinds(tree, &["method_declaration", "constructor_declaration"]) {
        // Start every method with the file's field aliases — fields are
        // visible throughout the method body.
        let mut method_aliases = field_aliases.to_vec();
        method_aliases.extend(collect_java_type_aliases(
            method_node,
            src,
            &["formal_parameter", "local_variable_declaration"],
        ));
        dedup_type_aliases(&mut method_aliases);
        aliases_by_method.push((span_of(file, &method_node), method_aliases));
    }
    aliases_by_method
}

/// Walk `root` collecting `(name, type)` aliases from every declaration
/// node whose kind matches `kinds`. The result is deduplicated.
fn collect_java_type_aliases(root: Node<'_>, src: &[u8], kinds: &[&str]) -> Vec<TypeAliasBinding> {
    let mut aliases = Vec::new();
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        if kinds.contains(&node.kind()) {
            aliases.extend(java_type_aliases_from_decl(node, src));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            work_stack.push(child);
        }
    }
    dedup_type_aliases(&mut aliases);
    aliases
}

/// Pull every `(name, type)` binding out of a single declaration node —
/// handles both `Foo bar` (single name field) and `Foo a, b, c`
/// (multiple `variable_declarator` children).
fn java_type_aliases_from_decl(node: Node<'_>, src: &[u8]) -> Vec<TypeAliasBinding> {
    let Some(type_node) = node.child_by_field_name("type") else {
        return Vec::new();
    };
    let Some(canonical_type) = canonical_java_type_name(node_text(&type_node, src)) else {
        return Vec::new();
    };
    let mut aliases = Vec::new();
    // Single-name declarations (most parameter shapes).
    if let Some(name_node) = node.child_by_field_name("name") {
        push_type_alias(&mut aliases, node_text(&name_node, src), &canonical_type);
        return aliases;
    }
    // Multi-name `Foo a, b, c;` — one `variable_declarator` per name.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            push_type_alias(&mut aliases, node_text(&name_node, src), &canonical_type);
        }
    }
    aliases
}

/// Canonicalize a Java type expression to its short, generics/array-free
/// form: `List<String>` → `List`, `int[]` → `int`, `java.util.Map` →
/// `Map`. Rejects names whose canonical form doesn't start with an
/// uppercase letter — primitives like `int` survive the strip but we
/// still want them out of the alias set.
fn canonical_java_type_name(raw: &str) -> Option<String> {
    // Strip generics and array brackets — they don't change the receiver type.
    let without_generics = raw.split('<').next().unwrap_or(raw);
    let without_arrays = without_generics.split('[').next().unwrap_or(without_generics);
    // Take the rightmost path segment as the bare type name.
    let bare_type = without_arrays
        .trim()
        .rsplit('.')
        .next()
        .unwrap_or(without_arrays)
        .trim();
    // Reject primitives and empty results — only class-like types qualify.
    if bare_type.is_empty() || !bare_type.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    Some(bare_type.to_string())
}

/// Append a type-alias binding to `aliases`, skipping empty names and
/// self-aliases (`Foo Foo`).
fn push_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    let bare_name = name.trim();
    if bare_name.is_empty() || bare_name == type_name {
        return;
    }
    aliases.push(TypeAliasBinding {
        name: bare_name.to_string(),
        type_name: type_name.to_string(),
    });
}

/// Drop duplicate `TypeAliasBinding` entries while preserving source-order.
fn dedup_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut deduped = Vec::new();
    for alias in aliases.drain(..) {
        if !deduped.contains(&alias) {
            deduped.push(alias);
        }
    }
    *aliases = deduped;
}

/// Parse Java import declarations into `ImportSpec` records.
///
/// Java import shapes:
///   `import java.sql.Connection;`      → scoped_identifier path
///   `import static java.lang.Math.PI;` → leading `static` keyword
///   `import java.util.*;`              → trailing `.*` wildcard
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for import_node in collect_kinds(tree, &["import_declaration"]) {
        // Strip the keyword chrome and the trailing semicolon. Tree-sitter
        // gives us the raw text, but the `import_declaration` doesn't
        // expose a clean module path field, so textual stripping is the
        // simplest route.
        let module_path_text = node_text(&import_node, src)
            .trim_start_matches("import ")
            .trim_start_matches("static ")
            .trim_end_matches(';')
            .trim();
        if module_path_text.is_empty() {
            continue;
        }
        let is_wildcard = module_path_text.ends_with(".*");
        let module_path = module_path_text.trim_end_matches(".*").to_string();
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module: module_path,
            alias: None,
            is_wildcard,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Walk the Java tree and map each function/class/method/constructor
/// span to its real Visibility from `modifiers` siblings. Java
/// privacy rules:
///   - `public` → Public
///   - `private` → Private
///   - `protected` → Protected
///   - no modifier → package-private (Visibility::Module)
fn collect_java_visibility(
    root: Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Visibility> {
    let mut visibility_by_span = std::collections::HashMap::new();
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        let kind = node.kind();
        let is_class_or_member_decl = matches!(
            kind,
            "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "annotation_type_declaration"
                | "record_declaration"
        );
        if is_class_or_member_decl {
            visibility_by_span.insert(span_of(file, &node), java_node_visibility(&node, src));
        }
        // Walk every child, named or not — modifiers are usually named but
        // `public`/`private` keyword tokens are anonymous.
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            work_stack.push(child);
        }
    }
    visibility_by_span
}

/// Read the `modifiers` child of a Java declaration to determine its
/// declared `Visibility`. No modifier means package-private (Module).
fn java_node_visibility(node: &Node<'_>, src: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        let mut modifier_cursor = child.walk();
        for modifier in child.children(&mut modifier_cursor) {
            match node_text(&modifier, src) {
                "public" => return Visibility::Public,
                "private" => return Visibility::Private,
                "protected" => return Visibility::Protected,
                _ => {}
            }
        }
    }
    // Java's default access is package-private — represented as Module
    // in the bonsai visibility lattice.
    Visibility::Module
}

/// Find the `package com.foo.bar;` declaration at the top of the
/// file and return its segments. Returns None for files in the
/// default (unnamed) package.
/// True for class-like decls whose `bases:` we should populate.
/// Java emits `interface_declaration`, `enum_declaration`,
/// `record_declaration`, `class_declaration`,
/// `annotation_type_declaration` — all surface as `DeclKind::Class`
/// at the kit's pass-3 (no separate Interface/Enum/Record kinds in
/// the kit's classification). See `kit.rs::class_nodes` pass 3.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk every Java class-like declaration and collect the
/// superclass + super_interfaces names. Java grammar:
///
///   `class C extends B implements I, J { ... }` →
///     superclass: (superclass (type_identifier))
///     interfaces: (super_interfaces (type_list (type_identifier) (type_identifier)))
///
/// `interface_declaration` uses `extends_interfaces` instead of
/// `superclass`. `record_declaration` only has `interfaces`.
fn collect_java_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut out = Vec::new();
    let class_kinds = &[
        "class_declaration",
        "interface_declaration",
        "record_declaration",
        "enum_declaration",
        "annotation_type_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        // `superclass` field — single parent.
        if let Some(sc) = class_node.child_by_field_name("superclass") {
            collect_java_base_names(sc, src, &mut bases);
        }
        // `interfaces` field — `super_interfaces` wrapping `type_list`.
        if let Some(ifaces) = class_node.child_by_field_name("interfaces") {
            collect_java_base_names(ifaces, src, &mut bases);
        }
        // `interface_declaration` carries `extends_interfaces`.
        if let Some(extends) = class_node.child_by_field_name("extends_interfaces") {
            collect_java_base_names(extends, src, &mut bases);
        }
        // `permits` clause from sealed classes. The matcher consults
        // Decl.bases for hierarchy resolution (e.g. `kind: param` rules
        // with `in_class:` constraints). For sealed types both
        // directions of the relationship are useful: the parent
        // declares which subtypes inherit, so emitting the permits
        // members lets cross-file rules that key on the ancestor
        // type still resolve through the sealed parent's permitted
        // subclass list.
        if let Some(permits) = class_node.child_by_field_name("permits") {
            collect_java_base_names(permits, src, &mut bases);
        }
        if !bases.is_empty() {
            out.push((span_of(file, &class_node), bases));
        }
    }
    out
}

/// Pull every `type_identifier` / `scoped_type_identifier` /
/// `generic_type` descendant of a Java parent-clause node and push
/// the canonical short name into `out`. Skips internal punctuation
/// nodes.
fn collect_java_base_names(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "type_identifier" | "scoped_type_identifier" | "generic_type" => {
                if let Some(name) = canonical_java_type_name(node_text(&n, src)) {
                    if !out.iter().any(|b| b == &name) {
                        out.push(name);
                    }
                }
            }
            _ => {}
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Walk `decl.flow_events` recursively and populate
/// `Throw::thrown_type` / `Try::catch_types` from the Java parse
/// tree by span lookup. Java syntax:
///   throw new IOException("...")  → thrown_type: "IOException"
///   throw err                     → thrown_type: None (need data-flow)
///   `try { } catch (IOException e) { } catch (A | B e) { }`
///                                 → `catch_types = vec!["IOException", "A", "B"]`
fn populate_java_exception_types(events: &mut [bonsai_lang_api::FlowEvent], tree: &Tree, src: &[u8]) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Throw {
                span, thrown_type, ..
            } => {
                if thrown_type.is_some() {
                    continue;
                }
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["throw_statement"])
                {
                    if let Some(name) = java_thrown_type_for_node(node, src) {
                        *thrown_type = Some(name);
                    }
                }
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_types,
                catch_param,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if catch_types.is_empty() {
                        *catch_types = collect_java_catch_types(node, src);
                    }
                    // The kit's generic catch_param extractor sometimes
                    // picks the type identifier instead of the variable
                    // name on Java's `catch (T name)` shape. Fix in the
                    // adapter where we have the structural context.
                    if let Some(name) = collect_java_catch_param_name(node, src) {
                        *catch_param = Some(name);
                    }
                }
                populate_java_exception_types(body, tree, src);
                populate_java_exception_types(catch_events, tree, src);
                populate_java_exception_types(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                populate_java_exception_types(then_events, tree, src);
                populate_java_exception_types(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                populate_java_exception_types(body, tree, src);
            }
            _ => {}
        }
    }
}

fn java_thrown_type_for_node(throw_node: Node<'_>, src: &[u8]) -> Option<String> {
    // throw_statement > object_creation_expression > type_identifier (or generic_type)
    let mut cursor = throw_node.walk();
    for child in throw_node.named_children(&mut cursor) {
        if child.kind() == "object_creation_expression" {
            if let Some(t) = child.child_by_field_name("type") {
                return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                    &t, src,
                )));
            }
            // Fallback: walk for first type_identifier descendant.
            let mut tcur = child.walk();
            for descendant in child.named_children(&mut tcur) {
                if matches!(
                    descendant.kind(),
                    "type_identifier" | "generic_type" | "scoped_type_identifier"
                ) {
                    return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                        &descendant,
                        src,
                    )));
                }
            }
        }
    }
    None
}

fn collect_java_catch_param_name(try_node: Node<'_>, src: &[u8]) -> Option<String> {
    // Java's `catch (T name)` parses as:
    //   catch_clause
    //     catch_formal_parameter
    //       <modifiers>?
    //       catch_type
    //         type_identifier
    //       name: identifier
    // We want the `name` field of the catch_formal_parameter.
    let mut cursor = try_node.walk();
    for child in try_node.named_children(&mut cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        let mut ccur = child.walk();
        for sub in child.named_children(&mut ccur) {
            if sub.kind() != "catch_formal_parameter" {
                continue;
            }
            if let Some(n) = sub.child_by_field_name("name") {
                return Some(node_text(&n, src).trim().to_string());
            }
            // Fallback: rightmost `identifier` (after the type).
            let mut pcur = sub.walk();
            let mut last_ident: Option<Node<'_>> = None;
            for ptype in sub.named_children(&mut pcur) {
                if ptype.kind() == "identifier" {
                    last_ident = Some(ptype);
                }
            }
            if let Some(n) = last_ident {
                return Some(node_text(&n, src).trim().to_string());
            }
        }
    }
    None
}

fn collect_java_catch_types(try_node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cursor = try_node.walk();
    for child in try_node.named_children(&mut cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        // catch_clause > catch_formal_parameter > catch_type > type_identifier (one or more)
        let mut ccur = child.walk();
        for sub in child.named_children(&mut ccur) {
            if sub.kind() != "catch_formal_parameter" {
                continue;
            }
            let mut pcur = sub.walk();
            for ptype in sub.named_children(&mut pcur) {
                if ptype.kind() == "catch_type" {
                    let mut tcur = ptype.walk();
                    for t in ptype.named_children(&mut tcur) {
                        if matches!(
                            t.kind(),
                            "type_identifier" | "generic_type" | "scoped_type_identifier"
                        ) {
                            let name = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&t, src));
                            if !name.is_empty() && !out.iter().any(|x| x == &name) {
                                out.push(name);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Rewrite Java's reflection chain `Class.forName("X").getMethod("Y")
/// .invoke(target, args...)` into a synthesized direct call to
/// `X.Y(args...)` so the resolver narrows it like a normal method
/// dispatch. Walks `flow_events` in source order, building an alias
/// map of `var → "Class"` and `var → "Class.Method"` entries from
/// constant-string `forName` / `getMethod` calls. When it sees
/// `m.invoke(target, ...args)` where `m` resolves to a known
/// "Class.Method", rewrites the Call's `name` to that target and
/// drops the leading `target` (or `null`) arg so the remaining args
/// align with the real method's parameters.
///
/// Dynamic forms (computed string args) stay unrewritten and the
/// `reflection: Unsupported` rule continues to gate them at rulepack
/// load time. This is the Java analog of P2.1's Python rewrite.
fn rewrite_java_reflection_chain(events: &mut [bonsai_lang_api::FlowEvent]) {
    use bonsai_lang_api::FlowEvent;
    use std::collections::HashMap;
    // var name -> what it points at, accumulated across the walk:
    //   "c" -> "Sink"        (after `Class<?> c = Class.forName("Sink")`)
    //   "m" -> "Sink.run"    (after `Method m = c.getMethod("run", ...)`)
    let mut reflective_alias: HashMap<String, String> = HashMap::new();
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_call_args,
                ..
            } => {
                // Only the constant-string forms are usable; the second
                // arg / dynamic forms stay unrewritten.
                let Some(callee) = source_call else { continue };
                let Some(literal_arg) = source_call_args.first() else {
                    continue;
                };
                let Some(literal_text) = strip_java_string_quotes(literal_arg) else {
                    continue;
                };
                // `Class.forName("X")` — record `target -> "X"`.
                let is_for_name = callee == "Class.forName" || callee.ends_with(".forName");
                if is_for_name {
                    reflective_alias.insert(target.clone(), literal_text);
                    continue;
                }
                // `<receiver>.getMethod("Y")` — chain only if receiver
                // is itself a Class<?> we tracked. Result: `target ->
                // "<receiver-class>.Y"`.
                if let Some(get_method_receiver) = callee.strip_suffix(".getMethod") {
                    if let Some(class_name) = reflective_alias.get(get_method_receiver) {
                        let chained = format!("{class_name}.{literal_text}");
                        reflective_alias.insert(target.clone(), chained);
                    }
                }
            }
            FlowEvent::Call {
                name, receiver, args, ..
            } => {
                // `<receiver>.invoke(target_or_null, arg1, ..)` is the
                // Java reflection escape hatch. Rewrite when the
                // receiver was bound to a known Method handle.
                let Some(receiver_name) = receiver.as_deref() else {
                    continue;
                };
                if !name.ends_with(".invoke") {
                    continue;
                }
                let Some(target_class_method) = reflective_alias.get(receiver_name) else {
                    continue;
                };
                // Rewrite the call to point at the underlying method.
                name.clone_from(target_class_method);
                // `m.invoke(target, a, b)` ⇒ `Class.Method(a, b)`:
                // drop the first arg (the receiver / `null` static
                // target) so the remaining args line up with the real
                // method's parameter list.
                if !args.is_empty() {
                    args.remove(0);
                }
                // Update `receiver` to the class part of the qualified
                // name, e.g. "Sink.run" -> Some("Sink"). The resolver
                // uses this to anchor the dispatch.
                *receiver = target_class_method
                    .rsplit_once('.')
                    .map(|(class_part, _)| class_part.to_string());
            }
            // Reflection chains can hide inside any control-flow
            // container — keep walking.
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_java_reflection_chain(then_events);
                rewrite_java_reflection_chain(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_java_reflection_chain(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_java_reflection_chain(body);
                rewrite_java_reflection_chain(catch_events);
                rewrite_java_reflection_chain(finally_events);
            }
            _ => {}
        }
    }
}

/// Strip surrounding `"..."` quotes from a Java string-literal arg-text
/// representation, returning the inner content. Returns `None` for any
/// non-literal form (variable, expression, single-quoted char, etc.).
fn strip_java_string_quotes(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        return Some(trimmed[1..trimmed.len() - 1].to_string());
    }
    None
}

fn extract_java_package(root: Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "package_declaration" {
            continue;
        }
        // package_declaration's `name` child is a `scoped_identifier`
        // (or bare `identifier` for single-segment packages).
        let mut sub = child.walk();
        for subchild in child.children(&mut sub) {
            if matches!(subchild.kind(), "scoped_identifier" | "identifier") {
                let text = node_text(&subchild, src);
                let segments: Vec<String> = text
                    .split('.')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if !segments.is_empty() {
                    return Some(segments);
                }
            }
        }
    }
    None
}
