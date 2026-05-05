//! Scala language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasVocabulary, Visibility,
};

const SCALA_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition", "function_declaration"],
    param_kinds: &["parameter", "class_parameter"],
    name_field: "name",
    type_field: "type",
};

const SCALA_DECL_KINDS: &[&str] = &[
    "function_definition",
    "function_declaration",
    "class_definition",
    "object_definition",
    "trait_definition",
    "type_definition",
    "val_definition",
    "var_definition",
];
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("scala");
const PACK_NAME: &str = "scala";
const HANDLER: GrammarHandler =
    with_fn_kinds_and_implicit_receivers(&["function_definition"], &["this", "super"], &[]);

#[derive(Debug, Default, Copy, Clone)]
pub struct ScalaAdapter;

impl ScalaAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ScalaAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Scala"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["scala", "sc"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Pattern matching: the adapter post-processes flat `Branch`
        // events emitted for `match_expression`s into nested `Branch`
        // chains so the engine forks state per arm. Each arm's body
        // sees a fresh copy of the pre-match taint state, runs in
        // isolation, and unions back at the merge — yielding
        // path-disjoint precision instead of the over-approximate
        // "any arm's taint reaches every other arm's body."
        LanguageCapabilities {
            pattern_matching: bonsai_lang_api::CapabilityLevel::Exact,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let arm_spans = collect_scala_match_arm_spans(&tree, src, file);
            for decl in &mut idx.defs {
                bonsai_lang_api::kit::split_match_arms_in_branch_events(&mut decl.flow_events, &arm_spans);
            }
        }
        let pkg_segments = parse_with(PACK_NAME, file, ctx)
            .and_then(|(snapshot, tree)| extract_scala_package(tree.root_node(), snapshot.text.as_bytes()));
        if let Some(segments) = pkg_segments {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_scala_visibility(tree.root_node(), file, src);
            let alias_map = collect_param_type_aliases(&tree, file, src, &SCALA_TYPE_ALIASES);
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
            }
            // Per-class `bases`: `class C extends Base with Mixin` →
            // ["Base", "Mixin"]. Scala wraps every parent (extends +
            // with) under a single `extends_clause` whose `type:`
            // fields list each parent.
            let bases_by_span = collect_scala_class_bases(&tree, file, src);
            for decl in &mut idx.defs {
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
        }
        // Recognised Scala lifecycle transitions — same call names as
        // Java since the JVM library surface is shared.
        const SCALA_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
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
        ];
        for decl in &mut idx.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, SCALA_LIFECYCLE_TRANSITIONS);
        }
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Parse `import_declaration` nodes into `ImportSpec`s, one per surfaced symbol.
///
/// Scala shapes:
///   `import x.y.Z`            — straight
///   `import x.y.{A, B}`       — braced selector list
///   `import x.y.{A => B}`     — renaming alias (Scala 2)
///   `import x.y.{A as B}`     — renaming alias (Scala 3)
///   `import x.y._` / `x.y.*`  — wildcard (Scala 2 / Scala 3)
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for import_node in collect_kinds(tree, &["import_declaration"]) {
        let text = node_text(&import_node, src)
            .trim_start_matches("import ")
            .trim()
            .to_string();
        if text.is_empty() {
            continue;
        }
        let is_wildcard = text.ends_with("._") || text.ends_with(".*");
        let span = span_of(file, &import_node);
        if let Some((path, brace_body)) = text.rsplit_once(".{") {
            // Validate the path: Scala doesn't permit nested brace-list
            // groups (`{c.{X}}`), so any brace inside `path` indicates a
            // malformed source. Skip emission rather than producing an
            // ugly module string.
            if path.contains('{') || path.contains('}') {
                continue;
            }
            // Multi-entry braced selectors: `import x.y.{A, B => BB, C}`
            // emits ONE ImportSpec per selector. Splitting on ',' first
            // and then per-selector rsplit on ` => ` / ` as ` matches
            // the grammar's expansion (one binding per entry).
            let inside = brace_body.trim_end_matches('}').trim();
            let module = path.to_string();
            for raw in inside.split(',') {
                let mut entry = raw.trim().to_string();
                if entry.is_empty() {
                    continue;
                }
                // Scala 3 `given` selector: bare `given` is the
                // "all givens" wildcard; `given Foo` (with any
                // intervening whitespace) records the trait name.
                // Tokenise so multi-space variants don't fall
                // through with a literal "given  Foo" original_name.
                {
                    let tokens: Vec<&str> = entry.split_whitespace().collect();
                    if tokens.first().copied() == Some("given") {
                        if tokens.len() == 1 {
                            imports.push(ImportSpec {
                                span,
                                module: module.clone(),
                                alias: None,
                                is_wildcard: true,
                                original_name: None,
                                scope: ImportScope::Module,
                            });
                            continue;
                        }
                        // `given X` (and `given X => Y` / `given X as Y` —
                        // the rename arms below handle those after
                        // we strip the `given` token).
                        entry = tokens[1..].join(" ");
                    }
                }
                // Braced wildcard: `{Foo, *}` / `{Foo, _}` mark the
                // ImportSpec as a wildcard rather than a leaf with
                // a literal `*`/`_` original_name.
                if entry == "*" || entry == "_" {
                    imports.push(ImportSpec {
                        span,
                        module: module.clone(),
                        alias: None,
                        is_wildcard: true,
                        original_name: None,
                        scope: ImportScope::Module,
                    });
                    continue;
                }
                if entry.is_empty() {
                    continue;
                }
                // Per-selector rename: Scala 2 uses `=>`, Scala 3
                // accepts `as` as well. Try the Scala 3 form first
                // since it's the more recent convention; fall back
                // to `=>`.
                let (original, alias) = if let Some((orig, alias_text)) = entry.rsplit_once(" as ") {
                    (Some(orig.trim().to_string()), Some(alias_text.trim().to_string()))
                } else if let Some((orig, alias_text)) = entry.rsplit_once(" => ") {
                    (Some(orig.trim().to_string()), Some(alias_text.trim().to_string()))
                } else {
                    (Some(entry.clone()), None)
                };
                imports.push(ImportSpec {
                    span,
                    module: module.clone(),
                    alias,
                    is_wildcard: false,
                    original_name: original,
                    scope: ImportScope::Module,
                });
            }
            continue;
        }
        // Scala 3 top-level rename without braces: `import a.b.Foo as Bar`.
        // Scala 2 syntax requires braces; Scala 3 makes them optional.
        if let Some((path, alias)) = text.rsplit_once(" as ") {
            let alias = alias.trim();
            let (module, original) = if let Some((mod_path, last)) = path.rsplit_once('.') {
                (mod_path.to_string(), Some(last.trim().to_string()))
            } else {
                // No dotted path — entire `path` is the symbol name.
                (String::new(), Some(path.trim().to_string()))
            };
            if !alias.is_empty() {
                imports.push(ImportSpec {
                    span,
                    module,
                    alias: Some(alias.to_string()),
                    is_wildcard: false,
                    original_name: original,
                    scope: ImportScope::Module,
                });
                continue;
            }
        }
        // Bare unaliased import `import a.b.X`: keep the full
        // dotted path as `module` for parity with Java/Kotlin and
        // existing downstream resolve logic. (The cross-adapter
        // smell that flagged `original_name=Some(last_segment)`
        // was a documentation request, not a correctness fix —
        // changing the shape would invalidate downstream callers
        // that key on the fully-qualified module path.)
        let module = text.trim_end_matches("._").trim_end_matches(".*").to_string();
        imports.push(ImportSpec {
            span,
            module,
            alias: None,
            is_wildcard,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Scala-aware visibility collector that recognises scoped forms:
/// `private[X]` / `protected[X]` / `private[this]`. Maps to the
/// four-level lattice as follows:
///
/// - `private[this]` → `Private` (instance-only is the strictest)
/// - `private` (bare) → `Private`
/// - `private[X]` → `Crate` (broader scope within the same compilation unit)
/// - `protected[X]` → `Protected` (we don't have a tighter level)
/// - `protected` → `Protected`
/// - default → `Public`
///
/// Visibility comes from real syntax markers; per-language scoping
/// handling lives in the adapter.
fn collect_scala_visibility(
    root: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut visibility_by_span = std::collections::HashMap::new();
    // Iterative DFS — tree-sitter trees can be deep enough that recursion
    // would risk blowing the stack on pathological inputs.
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if SCALA_DECL_KINDS.contains(&node.kind()) {
            visibility_by_span.insert(span_of(file, &node), scala_node_visibility(node, src));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    visibility_by_span
}

/// Map a single Scala decl's `modifiers` block to the four-level visibility
/// lattice. See `collect_scala_visibility`'s doc comment for the rules.
fn scala_node_visibility(node: tree_sitter::Node<'_>, src: &[u8]) -> Visibility {
    let mut found_private = false;
    let mut found_protected = false;
    let mut scope_marker: Option<String> = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        // Walk modifier keywords; tree-sitter-scala emits keyword
        // tokens directly as children. The optional `[X]` access
        // qualifier lives next to the keyword as an `access_qualifier`
        // node (or as a bracketed identifier).
        let mut modifiers_cursor = child.walk();
        for modifier in child.children(&mut modifiers_cursor) {
            let text = node_text(&modifier, src);
            if text == "private" {
                found_private = true;
            } else if text == "protected" {
                found_protected = true;
            } else if matches!(modifier.kind(), "access_qualifier") {
                // Strip the surrounding `[ ]` to get the bare scope name.
                let qualifier_text = node_text(&modifier, src);
                let inside = qualifier_text
                    .trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .trim();
                if !inside.is_empty() {
                    scope_marker = Some(inside.to_string());
                }
            } else if text.starts_with('[') && text.ends_with(']') {
                // Older grammars emit the qualifier as a literal bracketed
                // token rather than an `access_qualifier` node.
                let inside = text.trim_start_matches('[').trim_end_matches(']').trim();
                if !inside.is_empty() {
                    scope_marker = Some(inside.to_string());
                }
            }
        }
    }
    match (found_private, found_protected, scope_marker.as_deref()) {
        // `private[this]` is the strictest form — instance-only.
        (true, _, Some("this")) => Visibility::Private,
        // `private[X]` widens to package-level within the same compilation unit.
        (true, _, Some(_)) => Visibility::Crate,
        (true, _, None) => Visibility::Private,
        (_, true, _) => Visibility::Protected,
        _ => Visibility::Public,
    }
}

/// True when the decl is a type-defining container that can carry `bases`.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Scala class / object / trait definitions and collect the
/// type names listed in `extends_clause`. Grammar shape (verified):
///
///   `class Echo extends WebSocketHandler with Mixin` →
///     (class_definition name: (identifier)
///        extend: (extends_clause type: (type_identifier) type: (type_identifier)))
///
/// `extends_clause` carries every parent (the initial `extends` plus
/// every `with` mixin) under repeating `type:` fields. Scala doesn't
/// distinguish "the super-class" vs "mixin traits" syntactically.
fn collect_scala_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_definition", "object_definition", "trait_definition"];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        // `extend:` field holds the entire `extends_clause` (extends + every with-mixin).
        let extend_node = class_node.child_by_field_name("extend");
        if let Some(extend) = extend_node {
            let mut extend_cursor = extend.walk();
            for child in extend.named_children(&mut extend_cursor) {
                let raw = node_text(&child, src);
                if let Some(name) = canonical_scala_base_name(raw) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Canonicalize a Scala base reference to a bare type name.
///
/// Strips type parameter brackets (`Foo[T]` → `Foo`) and any qualifying
/// path (`pkg.Foo` → `Foo`). Lowercase-leading names are rejected because
/// they're values (e.g. constructor-arg lists) not type references.
fn canonical_scala_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Strip type parameter brackets: `Foo[T]` → `Foo`.
    let head = trimmed.split('[').next().unwrap_or(trimmed).trim();
    // Strip qualifying path: `pkg.Foo` → `Foo`.
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    // Type names are conventionally upper-cased; reject lower-case leads
    // so we don't pick up arg expressions in `extends Foo(arg)`.
    if bare.is_empty() || !bare.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    Some(bare.to_string())
}

/// Per-arm body spans collected from every `match_expression` in the
/// file. The kit emits a single `Branch { then_events: [arm1_body...,
/// arm2_body..., ...] }` for the whole match, lumping arm bodies
/// together. We use these spans in `split_match_arms_in_branch_events`
/// to peel each arm into its own nested `Branch` so the engine forks
/// state per arm.
fn collect_scala_match_arm_spans(tree: &Tree, _src: &[u8], file: FileId) -> Vec<Vec<bonsai_common::Span>> {
    let mut spans_per_match: Vec<Vec<bonsai_common::Span>> = Vec::new();
    for match_node in collect_kinds(tree, &["match_expression"]) {
        let mut arm_body_spans: Vec<bonsai_common::Span> = Vec::new();
        let mut match_cursor = match_node.walk();
        for child in match_node.named_children(&mut match_cursor) {
            if child.kind() != "case_block" {
                continue;
            }
            let mut block_cursor = child.walk();
            for case in child.named_children(&mut block_cursor) {
                if case.kind() != "case_clause" {
                    continue;
                }
                // Scala's case_clause exposes one `body:` field per
                // statement (multi-statement arms produce multiple
                // body children). Span the union from min start to
                // max end across every named child whose role is
                // `body` so we capture the full arm scope.
                let mut min_start: Option<u64> = None;
                let mut max_end: Option<u64> = None;
                let mut case_cursor = case.walk();
                for (field_idx, body_node) in case.named_children(&mut case_cursor).enumerate() {
                    if case.field_name_for_named_child(field_idx as u32) == Some("body") {
                        let body_start = body_node.start_byte() as u64;
                        let body_end = body_node.end_byte() as u64;
                        min_start = Some(min_start.map_or(body_start, |m| m.min(body_start)));
                        max_end = Some(max_end.map_or(body_end, |m| m.max(body_end)));
                    }
                }
                if let (Some(start), Some(end)) = (min_start, max_end) {
                    arm_body_spans.push(bonsai_common::Span::new(file, start, end));
                }
            }
        }
        if !arm_body_spans.is_empty() {
            spans_per_match.push(arm_body_spans);
        }
    }
    spans_per_match
}

/// Extract the dotted package path from a file's `package_clause`, if any.
///
/// Returns the path as a list of segments (e.g. `package com.acme` →
/// `["com", "acme"]`) so callers can feed it to
/// `apply_module_path_semantic_identity`. Returns `None` for files without
/// an explicit `package` declaration.
fn extract_scala_package(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        // Look for the dotted path child; grammars vary on which named
        // kind exposes it.
        let mut clause_cursor = child.walk();
        for subchild in child.children(&mut clause_cursor) {
            if matches!(
                subchild.kind(),
                "package_identifier" | "stable_identifier" | "identifier"
            ) {
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
