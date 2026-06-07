//! JavaScript language adapter.
use bonsai_common::{FileId, SymbolId};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, Visibility,
};
use bonsai_lang_api::{CallArg, DeclKind, FlowEvent};
use std::collections::{HashMap, HashSet};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("javascript");
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
            constructor_method_names: &["constructor"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            apply_js_ts_commonjs_named_export_aliases(&mut decl_index, &tree, snapshot.text.as_bytes(), file);
        }
        // Module identity = workspace-relative path with the JS/TS extension stripped.
        let module_segments = ctx
            .workspace_relative_path(file)
            .map(|p| js_module_segments(&p))
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
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
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
        let text = node_text(&export_node, src).trim_start();
        if !text.starts_with("export default") {
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
        let Some(source) = decl_index.defs.iter().find(|decl| match &target {
            DefaultExportTarget::Span(span) => decl.span == *span,
            DefaultExportTarget::Name(name) => decl.name == *name,
        }) else {
            continue;
        };
        if seen_sources.contains(&source.symbol) {
            continue;
        }
        if !matches!(
            source.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
                | bonsai_lang_api::DeclKind::Class
        ) {
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

fn rewrite_destructuring_sources_in_events(events: &mut [FlowEvent], rewrites: &[JsDestructureSource]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } => {
                let Some(rewrite) = rewrites
                    .iter()
                    .find(|item| item.target == *target && spans_overlap_or_contain(*span, item.assign_span))
                else {
                    continue;
                };
                *source_name = Some(rewrite.source.clone());
                *source_call = None;
                source_call_args.clear();
                source_names.clear();
                source_names.push(rewrite.source.clone());
                *value_kind = Some(bonsai_lang_api::AssignValueKind::Compound);
            }
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
    }
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
            FlowEvent::Return {
                value_name,
                value_text,
                ..
            } => {
                if let Some(projected) = value_name
                    .as_deref()
                    .and_then(simple_js_getter_projection)
                    .or_else(|| value_text.as_deref().and_then(simple_js_getter_projection))
                {
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

fn simple_js_getter_projection(text: &str) -> Option<String> {
    let normalized = text
        .trim()
        .trim_end_matches(';')
        .replace("?.", ".")
        .replace("?.[", ".[");
    if normalized.contains(['(', ')', '{', '}', ',', ' ', '\t', '\n', '\r']) {
        return None;
    }
    let mut parts = Vec::new();
    for part in normalized.split(['.', '[', ']']) {
        let part = part.trim().trim_matches('"').trim_matches('\'').trim_matches('`');
        if part.is_empty() {
            continue;
        }
        if !part
            .chars()
            .all(|ch| ch == '_' || ch == '$' || ch == '#' || ch.is_ascii_alphanumeric())
        {
            return None;
        }
        parts.push(part.to_string());
    }
    if parts.len() < 2 || !matches!(parts.first().map(String::as_str), Some("this" | "super")) {
        return None;
    }
    Some(parts.join("."))
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
fn js_module_segments(path: &std::path::Path) -> Vec<String> {
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
