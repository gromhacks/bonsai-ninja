//! JavaScript language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("javascript");
const PACK_NAME: &str = "javascript";
const HANDLER: GrammarHandler = GrammarHandler {
    call_kinds: &["new_expression"],
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
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
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
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, JAVASCRIPT_LIFECYCLE_TRANSITIONS);
        }
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
        let mut alias: Option<String> = None;
        let mut is_wildcard = false;
        let mut renames: Vec<(String, String)> = Vec::new();
        let mut shorthands: Vec<String> = Vec::new();
        if let Some(import_clause) = import_clause {
            let mut clause_cursor = import_clause.walk();
            for clause_child in import_clause.named_children(&mut clause_cursor) {
                match clause_child.kind() {
                    "identifier" => {
                        // Default import: `import Foo from "..."`.
                        alias = Some(node_text(&clause_child, src).to_string());
                    }
                    "namespace_import" => {
                        // `import * as ns from "..."` — single binding bound to the whole module.
                        alias = first_named_child_of_kind(&clause_child, "identifier")
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
            alias,
            is_wildcard,
            original_name: None,
            scope: ImportScope::Module,
        });
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
