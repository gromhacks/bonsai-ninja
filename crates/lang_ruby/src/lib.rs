//! Ruby language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::kit::with_fn_kinds_and_implicit_receivers;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath, Ref, RefKind,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("ruby");
const PACK_NAME: &str = "ruby";
const BASE_HANDLER: GrammarHandler =
    with_fn_kinds_and_implicit_receivers(&["method", "singleton_method"], &["self", "super"], &["@"]);
const HANDLER: GrammarHandler = GrammarHandler {
    // Ruby methods return their final expression when there is no
    // explicit `return`. Surface that terminal expression as a normal
    // Return event so the shared semantic taint summaries can model
    // wrapper methods such as `def wrap(data); new(data); end`.
    tail_expression_returns: true,
    ..BASE_HANDLER
};

#[derive(Debug, Default, Copy, Clone)]
pub struct RubyAdapter;

impl RubyAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for RubyAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Ruby"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.erb` (HTML/Ruby template blend) and `.rhtml` (legacy
        // Rails) are claimed alongside `.rb`. tree-sitter-ruby cannot
        // parse the HTML wrapper as Ruby — extract_declarations
        // pre-processes ERB files to mask HTML with whitespace
        // (preserving line numbers) and expose only the embedded
        // `<%= expr %>` / `<% stmt %>` Ruby blocks to the parser.
        &["rb", "erb", "rhtml"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            constructor_method_names: &["initialize", "new"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["self"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        // Pure Ruby files take the standard pipeline.
        let path = ctx.vfs.path(file).ok();
        let is_erb = path
            .as_ref()
            .and_then(|p| p.extension())
            .is_some_and(|ext| ext == "erb" || ext == "rhtml");
        if !is_erb {
            let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
            if let Ok(snapshot) = ctx.vfs.snapshot(file) {
                idx.refs
                    .extend(synthesize_rack_query_string_refs(snapshot.text.as_bytes(), file));
                // Apply Ruby's scope-marker visibility: `private`,
                // `protected`, `public` keywords inside a class body
                // change the default visibility of subsequent method
                // definitions. See `apply_ruby_scope_visibility` for
                // the exact contract this implements.
                apply_ruby_scope_visibility(&mut idx, snapshot.text.as_bytes(), file, ctx);
            }
            // Per-class `bases`: `class Echo < Base` → ["Base"].
            // Ruby has only single-inheritance; mixins via `include`
            // are call statements (handled by the matcher's existing
            // include path), not parent-clauses.
            if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
                let src = snapshot.text.as_bytes();
                let bases_by_span = collect_ruby_class_bases(&tree, file, src);
                for decl in &mut idx.defs {
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
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
            apply_ruby_class_semantic_identity(&mut idx);
            // Recognised Ruby lifecycle transitions. Method-style
            // `close` for files / sockets, `unlink` / `dispose` for
            // freed resources, `cancel` for async work.
            const RUBY_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
                bonsai_lang_api::LifecycleTransition {
                    call_match: "close",
                    transition: "closed",
                    arg_index: 0,
                },
                bonsai_lang_api::LifecycleTransition {
                    call_match: "unlink",
                    transition: "freed",
                    arg_index: 0,
                },
                bonsai_lang_api::LifecycleTransition {
                    call_match: "dispose",
                    transition: "freed",
                    arg_index: 0,
                },
                bonsai_lang_api::LifecycleTransition {
                    call_match: "cancel",
                    transition: "cancelled",
                    arg_index: 0,
                },
            ];
            for decl in &mut idx.defs {
                bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, RUBY_LIFECYCLE_TRANSITIONS);
            }
            // Lift `@field = ParamType` writes captured during decl
            // collection into per-method `type_aliases`, so the
            // resolver's `type_alias_for_receiver(method, "self.field")`
            // returns the constructor-supplied type without re-walking
            // sibling decls per call site.
            bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
            return idx;
        }
        // ERB files: pre-process the source so the HTML wrapper
        // becomes whitespace and only `<%= expr %>` / `<% stmt %>`
        // Ruby code remains, then run the standard pipeline against
        // the synthetic source. Whitespace masking preserves line
        // numbers so diagnostics stay accurate.
        let Some(snapshot) = ctx.vfs.snapshot(file).ok() else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        let processed = preprocess_erb(&snapshot.text);
        // Parse the processed source manually with tree-sitter-ruby.
        let Ok(lang) = language_from_pack(PACK_NAME) else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&lang).is_err() {
            return DeclIndex {
                file,
                ..Default::default()
            };
        }
        let Some(tree) = parser.parse(&processed, None) else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        // Build a DeclIndex by hand over the pre-processed source.
        // ERB expressions are module-scope Ruby snippets, so wrap
        // actionable flow events in a synthetic `__module__` decl.
        // That preserves rule constraints that depend on call args
        // (`raw @value`) instead of falling back to arg-less refs.
        let src = processed.as_bytes();
        let root = tree.root_node();
        let root_events = bonsai_lang_api::kit::walk_flow_events(root, file, src, &HANDLER, &[]);
        let has_actionable_event = root_events.iter().any(|event| {
            matches!(
                event,
                bonsai_lang_api::FlowEvent::Call { .. }
                    | bonsai_lang_api::FlowEvent::Assign { .. }
                    | bonsai_lang_api::FlowEvent::Yield { .. }
                    | bonsai_lang_api::FlowEvent::Await { .. }
            )
        });
        // Recognised Ruby lifecycle transitions. Same set used for
        // pure-Ruby files; applied to ERB module-level decls below.
        const RUBY_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "unlink",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "dispose",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
        ];
        let mut defs = if has_actionable_event {
            let module_span = span_of(file, &root);
            // Synthesized container for ERB module-level code (the
            // body of `<% %>` / `<%= %>` blocks). Module-level Ruby
            // code is implicitly public — the template renderer
            // executes it when the file is processed. Marking the
            // container `Public` means the resolver's visibility
            // filter doesn't accidentally hide its FlowEvents when
            // a future caller reaches in by name.
            vec![bonsai_lang_api::Decl {
                symbol: bonsai_common::SymbolId::new(0),
                kind: bonsai_lang_api::DeclKind::Function,
                name: "__module__".to_string(),
                qualified_name: None,
                module_path: bonsai_lang_api::ModulePath::default(),
                span: module_span,
                name_span: module_span,
                visibility: bonsai_lang_api::Visibility::Public,
                parent: None,
                body_span: Some(module_span),
                flow_events: root_events,
                has_implicit_returns: true,
                params: Vec::new(),
                param_annotations: Vec::new(),
                type_aliases: Vec::new(),
                bases: Vec::new(),
                receiver_param_index: None,
                receiver_field_writes: Vec::new(),
                implicit_receiver_names: Vec::new(),
                receiver_state_sources: Vec::new(),
                return_type: None,
            }]
        } else {
            Vec::new()
        };
        for decl in &mut defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, RUBY_LIFECYCLE_TRANSITIONS);
        }
        let mut refs = bonsai_lang_api::kit::extract_call_refs(&tree, file, src);
        refs.extend(bonsai_lang_api::kit::extract_decorators(&tree, file, src));
        refs.extend(bonsai_lang_api::kit::extract_read_write_refs(&tree, file, src));
        refs.extend(synthesize_rack_query_string_refs(src, file));
        let strings = bonsai_lang_api::kit::extract_string_literals(&tree, file, src);
        let comments = bonsai_lang_api::kit::extract_comments(&tree, file, src);
        DeclIndex {
            file,
            defs,
            refs,
            strings,
            comments,
        }
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

fn apply_ruby_class_semantic_identity(idx: &mut DeclIndex) {
    let mut classes: Vec<(Span, String, bonsai_common::SymbolId)> = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.name.clone(), decl.symbol))
        .collect();
    classes.sort_by_key(|(span, _, _)| span.end.saturating_sub(span.start));
    if classes.is_empty() {
        return;
    }
    for decl in &mut idx.defs {
        if is_class_like(decl.kind) {
            decl.module_path = ModulePath::from_segments([decl.name.clone()]);
            decl.qualified_name = Some(decl.name.clone());
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some((_, class_name, class_symbol)) = classes
            .iter()
            .filter(|(span, _, _)| span.start <= decl.span.start && span.end >= decl.span.end)
            .min_by_key(|(span, _, _)| span.end.saturating_sub(span.start))
        else {
            continue;
        };
        decl.parent = Some(*class_symbol);
        decl.module_path = ModulePath::from_segments([class_name.clone()]);
        decl.qualified_name = Some(format!("{class_name}.{}", decl.name));
    }
}

/// Apply Ruby's scope-marker visibility to method decls. Ruby's
/// `private` / `protected` / `public` keywords (used as bare
/// statements inside a class / module body) change the default
/// visibility of subsequent `def` definitions until another marker
/// flips the scope. The keyword form `private :foo, :bar` flips a
/// specific list of names rather than a scope.
///
/// Visibility comes from real syntax. The kit's modifier-vocabulary
/// path doesn't model line-scoped visibility, so this adapter walks
/// the parsed tree directly.
fn apply_ruby_scope_visibility(idx: &mut DeclIndex, src: &[u8], file: FileId, ctx: &AdapterContext<'_>) {
    let Ok(lang) = language_from_pack(PACK_NAME) else {
        return;
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return;
    }
    let _ = ctx; // ctx unused for now; reserved for future error reporting.
    let Some(tree) = parser.parse(src, None) else {
        return;
    };
    // Map (start_byte, end_byte) of each method decl in the index to
    // the span we'll patch when we find the matching tree node.
    let mut visibility_overrides: std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility> =
        std::collections::HashMap::new();
    walk_class_bodies(
        tree.root_node(),
        src,
        file,
        bonsai_lang_api::Visibility::Public,
        &mut visibility_overrides,
    );
    for decl in &mut idx.defs {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        if let Some(visibility) = visibility_overrides.get(&(decl.span.start, decl.span.end)) {
            decl.visibility = *visibility;
        }
    }
}

/// Walk the tree, find each `class` / `module` / `singleton_class`,
/// and run the scope-tracking pass over its body. Each body resets to
/// `Public` — Ruby scope markers don't bleed between sibling classes.
fn walk_class_bodies(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    file: FileId,
    inherited_scope: bonsai_lang_api::Visibility,
    out: &mut std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility>,
) {
    // Ruby tree-sitter exposes class / module / singleton bodies as
    // `body_statement` children of `class` / `module` / `singleton_class`.
    // Inside those bodies we track the current scope marker.
    match node.kind() {
        "class" | "module" | "singleton_class" => {
            let mut scope = bonsai_lang_api::Visibility::Public;
            if let Some(body) = node.child_by_field_name("body") {
                walk_body_statements(body, src, file, &mut scope, out);
            } else {
                // Fall back to scanning all named children — ts-ruby
                // grammar uses `body_statement` as a named child.
                let mut child_cursor = node.walk();
                for child in node.named_children(&mut child_cursor) {
                    if child.kind() == "body_statement" {
                        walk_body_statements(child, src, file, &mut scope, out);
                    }
                }
            }
        }
        _ => {}
    }
    // Recurse: nested classes and modules need their own scope tracking.
    let mut child_cursor = node.walk();
    for child in node.named_children(&mut child_cursor) {
        walk_class_bodies(child, src, file, inherited_scope, out);
    }
}

/// Iterate one class / module body in source order, mutating
/// `current_scope` as scope markers appear and tagging each `def` /
/// `singleton_method` with the active scope. The scope is line-relative
/// — markers only affect defs that follow them inside the same body.
fn walk_body_statements(
    body: tree_sitter::Node<'_>,
    src: &[u8],
    file: FileId,
    current_scope: &mut bonsai_lang_api::Visibility,
    out: &mut std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility>,
) {
    let mut body_cursor = body.walk();
    for stmt in body.named_children(&mut body_cursor) {
        match stmt.kind() {
            // Bare scope marker: `private` / `protected` / `public` /
            // `module_function` alone on a line flips the default for
            // subsequent defs. tree-sitter-ruby parses arg-less calls
            // to those methods as bare identifiers, not `call` nodes.
            "identifier" => {
                let text = std::str::from_utf8(&src[stmt.byte_range()]).unwrap_or("");
                match text {
                    "private" => *current_scope = bonsai_lang_api::Visibility::Private,
                    "protected" => *current_scope = bonsai_lang_api::Visibility::Protected,
                    "public" => *current_scope = bonsai_lang_api::Visibility::Public,
                    // `module_function` flips the dual-mode (private
                    // instance, public module-level). The
                    // resolver-relevant half is the public surface;
                    // model as Public.
                    "module_function" => *current_scope = bonsai_lang_api::Visibility::Public,
                    _ => {}
                }
            }
            // Modifier with arg list: `private :foo, :bar`. Tags the
            // listed methods only — does NOT flip the scope. Also
            // covers `module_function :name` (Ruby's "make `name` both
            // private instance and public module-level"), which we
            // model as a Public override on the named method, plus the
            // `attr_reader` / `attr_writer` / `attr_accessor` forms
            // which declare *new* synthetic methods that don't exist
            // as `def` decls — but if the declaration sits inside a
            // public scope region, we keep the default scope, and if
            // it sits inside a private region the kit's scope-marker
            // path already handles the surrounding visibility.
            "call" => {
                let method_node = stmt.child_by_field_name("method");
                let method_text = method_node
                    .map(|method| std::str::from_utf8(&src[method.byte_range()]).unwrap_or(""))
                    .unwrap_or("");
                let target_visibility = match method_text {
                    "private" => Some(bonsai_lang_api::Visibility::Private),
                    "protected" => Some(bonsai_lang_api::Visibility::Protected),
                    "public" => Some(bonsai_lang_api::Visibility::Public),
                    // `module_function :name` — exposes `name` as a
                    // public module-level method while keeping it
                    // private as an instance method. We tag the
                    // matching `def` Public so cross-module callers
                    // can resolve it.
                    "module_function" => Some(bonsai_lang_api::Visibility::Public),
                    _ => None,
                };
                if let Some(visibility) = target_visibility {
                    if let Some(args) = stmt.child_by_field_name("arguments") {
                        let mut arg_cursor = args.walk();
                        for arg in args.named_children(&mut arg_cursor) {
                            // Only `:name` symbols name a target; bare
                            // identifiers in the arg list are treated
                            // as locals by Ruby and ignored here.
                            if arg.kind() != "simple_symbol" {
                                continue;
                            }
                            let raw_symbol = std::str::from_utf8(&src[arg.byte_range()]).unwrap_or("");
                            let target_name = raw_symbol.trim_start_matches(':');
                            if target_name.is_empty() {
                                continue;
                            }
                            // Find a method def in this body with the
                            // same name and tag it.
                            let mut sibling_cursor = body.walk();
                            for sibling in body.named_children(&mut sibling_cursor) {
                                if sibling.kind() != "method" && sibling.kind() != "singleton_method" {
                                    continue;
                                }
                                let name_node = sibling.child_by_field_name("name");
                                let sibling_name = name_node
                                    .map(|name| std::str::from_utf8(&src[name.byte_range()]).unwrap_or(""))
                                    .unwrap_or("");
                                if sibling_name == target_name {
                                    let span = span_of(file, &sibling);
                                    out.insert((span.start, span.end), visibility);
                                }
                            }
                        }
                    }
                }
                // `module_function` with no args (bare keyword form)
                // flips the scope for subsequent defs to the dual
                // private-instance/public-module mode. From the
                // resolver's perspective the public module-level half
                // is what matters, so we treat it as a Public scope
                // flip for the rest of the body.
                if method_text == "module_function" {
                    let no_args = match stmt.child_by_field_name("arguments") {
                        None => true,
                        Some(args) => args.named_child_count() == 0,
                    };
                    if no_args {
                        *current_scope = bonsai_lang_api::Visibility::Public;
                    }
                }
            }
            "method" | "singleton_method" => {
                let span = span_of(file, &stmt);
                // Don't overwrite an explicit `private :foo` tag.
                out.entry((span.start, span.end)).or_insert(*current_scope);
            }
            _ => {}
        }
    }
}

/// True for any `DeclKind` that can carry a `bases` list. Ruby only
/// has `Class` itself, but the predicate is shared with the
/// post-processing loop and matches the shape used by the other adapters.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Ruby `class` declarations and collect the single optional
/// superclass from the `superclass:` field. Grammar shape (verified):
///
///   `class Echo < Base; … end` →
///     (class name: (constant) superclass: (superclass (constant)) body: …)
///
/// Ruby has no interfaces and no multiple inheritance. The `include
/// SomeMixin` form is a call statement inside the body, not a parent
/// clause — the matcher's existing import / include resolution path
/// handles it elsewhere.
fn collect_ruby_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_table = Vec::new();
    for class_node in collect_kinds(tree, &["class"]) {
        let class_name = class_node
            .child_by_field_name("name")
            .map(|node| node_text(&node, src).to_string())
            .unwrap_or_default();
        let mut bases: Vec<String> = Vec::new();
        if let Some(superclass_node) = class_node.child_by_field_name("superclass") {
            // `superclass` wrapper has one named child — the constant
            // / scope_resolution naming the parent.
            let mut sc_cursor = superclass_node.walk();
            for child in superclass_node.named_children(&mut sc_cursor) {
                if let Some(name) = canonical_ruby_base_name(node_text(&child, src)) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        // Header fallback for grammar variants that don't expose the
        // superclass via a labelled field.
        if bases.is_empty() {
            if let Some(name) = ruby_class_superclass_from_header(node_text(&class_node, src)) {
                bases.push(name);
            }
        }
        if !bases.is_empty() {
            bases_table.push((span_of(file, &class_node), class_name, bases));
        }
    }
    bases_table
}

/// Textual fallback that scrapes `class Foo < Bar` from the raw class
/// node text. Used only when the grammar omits the `superclass` field
/// for a parsed class — kept for resilience across tree-sitter-ruby
/// releases.
fn ruby_class_superclass_from_header(raw: &str) -> Option<String> {
    let header = raw.lines().next().unwrap_or(raw);
    let (_, rest) = header.split_once('<')?;
    let candidate = rest
        .split(|ch: char| ch.is_whitespace() || ch == ';')
        .find(|part| !part.trim().is_empty())?;
    canonical_ruby_base_name(candidate)
}

/// Strip `Foo::Bar::Baz` down to the bare tail (`Baz`). Resolver
/// lookups for inherited methods key on the unqualified class name.
fn canonical_ruby_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let bare = trimmed.rsplit("::").next().unwrap_or(trimmed).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Surface every textual occurrence of `QUERY_STRING` as a Read ref.
/// Rack passes the request query string through `env['QUERY_STRING']`,
/// and our taint sources match on the bare name; without these refs
/// the matcher has no anchor to bind the source to.
fn synthesize_rack_query_string_refs(src: &[u8], file: FileId) -> Vec<Ref> {
    let source = std::str::from_utf8(src).unwrap_or("");
    source
        .match_indices("QUERY_STRING")
        .map(|(start, text)| Ref {
            span: Span::new(
                file,
                u64::try_from(start).unwrap_or(u64::MAX),
                u64::try_from(start + text.len()).unwrap_or(u64::MAX),
            ),
            name: "QUERY_STRING".to_string(),
            kind: RefKind::Read,
            scope: None,
            resolved: None,
        })
        .collect()
}

/// Pre-process an ERB / RHTML template source: replace HTML wrapping
/// with spaces while preserving the embedded `<%= expr %>` and
/// `<% stmt %>` Ruby code blocks. The ERB tags themselves (`<%=`,
/// `<%`, `%>`) are also masked so tree-sitter-ruby sees only Ruby
/// code surrounded by whitespace.
///
/// Line breaks are preserved — every replacement is whitespace of
/// the same byte length, so column / line positions in the resulting
/// tree-sitter node match the original `.erb` source.
fn preprocess_erb(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    // Preserve all newlines first so blank-string regions still
    // carry line breaks into the masked output.
    for (byte_index, &byte) in bytes.iter().enumerate() {
        if byte == b'\n' || byte == b'\r' {
            out[byte_index] = byte;
        }
    }
    // Find each `<%` ... `%>` block and copy the Ruby chunk into the
    // masked output. Tag boundaries themselves stay as spaces so
    // tree-sitter-ruby sees only Ruby tokens.
    let mut cursor = 0;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] == b'<' && bytes[cursor + 1] == b'%' {
            // Skip optional `=` / `-` / `#` (ERB comment / silent / value).
            let tag_start = cursor;
            let mut content_start = cursor + 2;
            while content_start < bytes.len() && matches!(bytes[content_start], b'=' | b'-' | b'#') {
                content_start += 1;
            }
            // Find closing `%>`.
            let mut close_start = content_start;
            while close_start + 1 < bytes.len() {
                if bytes[close_start] == b'%' && bytes[close_start + 1] == b'>' {
                    break;
                }
                close_start += 1;
            }
            if close_start + 1 >= bytes.len() {
                // Unclosed tag — treat the rest as masked.
                break;
            }
            // Copy Ruby content [content_start..close_start] into the output.
            // ERB comments (`<%# ... %>`) — masked, not surfaced as
            // Ruby. Silent and value forms are surfaced.
            let is_comment = bytes.get(tag_start + 2).copied() == Some(b'#');
            if !is_comment {
                for content_index in content_start..close_start {
                    if bytes[content_index] != b'\n' && bytes[content_index] != b'\r' {
                        out[content_index] = bytes[content_index];
                    }
                }
            }
            // Skip past `%>` (and an optional trailing `-` for trim form).
            cursor = close_start + 2;
            if cursor < bytes.len() && bytes[cursor] == b'-' {
                cursor += 1;
            }
            continue;
        }
        cursor += 1;
    }
    // Safety: only valid-UTF8 bytes were copied (Ruby code from a
    // UTF-8 input is UTF-8). The rest is ASCII whitespace.
    match String::from_utf8(out) {
        Ok(masked) => masked,
        Err(invalid) => {
            // Fall back to lossy if a multi-byte char straddled a
            // tag boundary in a way that produced an invalid byte
            // sequence (very unlikely with the byte-level copy).
            String::from_utf8_lossy(invalid.as_bytes()).into_owned()
        }
    }
}

/// Lift every `require` / `require_relative` / `load` / `autoload`
/// call into an `ImportSpec`. Ruby has no native import keyword; these
/// method calls are the convention and the only handle the resolver has.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // tree-sitter-ruby parses each loader call as a `call` node whose
    // `method:` is the function name and whose `arguments:` carries
    // the module string.
    for call_node in collect_kinds(tree, &["call"]) {
        let Some(method_node) = call_node.child_by_field_name("method") else {
            continue;
        };
        let method = node_text(&method_node, src);
        if !matches!(method, "require" | "require_relative" | "load" | "autoload") {
            continue;
        }
        let Some(args) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        let module = first_named_child_of_kind(&args, "string")
            .and_then(|string_node| first_named_child_of_kind(&string_node, "string_content"))
            .map(|content| node_text(&content, src).to_string())
            .unwrap_or_default();
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &call_node),
            module,
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    for assignment in collect_kinds(tree, &["assignment"]) {
        if inside_ruby_executable_scope(assignment) {
            continue;
        }
        let (Some(left), Some(right)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if left.kind() != "constant" || right.kind() != "constant" {
            continue;
        }
        let alias = node_text(&left, src).trim();
        let module = node_text(&right, src).trim();
        if alias.is_empty() || module.is_empty() || alias == module {
            continue;
        }
        if imports.iter().any(|import| {
            import.alias.as_deref() == Some(alias)
                && import.module == module
                && import.original_name.is_none()
        }) {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &assignment),
            module: module.to_string(),
            alias: Some(alias.to_string()),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn inside_ruby_executable_scope(node: tree_sitter::Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "method" | "singleton_method" | "block" | "do_block"
        ) {
            return true;
        }
        parent = current.parent();
    }
    false
}
