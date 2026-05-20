//! PHP language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::kit::with_fn_kinds_and_implicit_receivers;
use bonsai_lang_api::{
    collect_modifier_visibility, collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, AssignValueKind, CallArg, CallKind, DeclIndex, DeclKind, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    ModifierVocabulary, TypeAliasVocabulary, Visibility,
};

const PHP_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition", "method_declaration"],
    param_kinds: &["simple_parameter", "property_promotion_parameter"],
    name_field: "name",
    type_field: "type",
};

const PHP_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "method_declaration",
        "property_declaration",
        "class_declaration",
        "interface_declaration",
        "trait_declaration",
        "enum_declaration",
    ],
    modifier_container_kinds: &["visibility_modifier", "modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("protected", Visibility::Protected),
        ("public", Visibility::Public),
    ],
    // PHP's default visibility for class members is `public`.
    default_visibility: Visibility::Public,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("php");
const PACK_NAME: &str = "php";
const HANDLER: GrammarHandler = with_fn_kinds_and_implicit_receivers(
    &["function_definition", "method_declaration"],
    &["$this", "this"],
    &[],
);

/// Tree-sitter adapter for PHP.
#[derive(Debug, Default, Copy, Clone)]
pub struct PhpAdapter;

impl PhpAdapter {
    /// Construct a fresh adapter; the type carries no state.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for PhpAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "PHP"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["php"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: &["__construct"],
            super_receiver_tokens: &["parent", "self"],
            implicit_receiver_tokens: &["$this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Synthesize Call FlowEvents for PHP language constructs the
        // tree-sitter grammar exposes as dedicated expression kinds
        // rather than call_expression nodes:
        //   - `include $tainted` / `include_once $tainted`
        //   - `require $tainted` / `require_once $tainted`
        //   - `` `cmd $tainted` `` (shell_command_expression)
        // Without this lowering the shipped php.eval.{include,require}_*
        // and php.cmdi.backtick rules can't match real code.
        let source = ctx
            .vfs
            .snapshot(file)
            .ok()
            .map(|snapshot| snapshot.text.to_string())
            .unwrap_or_default();
        if !source.is_empty() {
            // Reparse here rather than reuse `parse_with` — synthesis
            // walks descendants and benefits from a dedicated tree.
            if let Ok(lang) = language_from_pack(PACK_NAME) {
                let mut parser = tree_sitter::Parser::new();
                if parser.set_language(&lang).is_ok() {
                    if let Some(tree) = parser.parse(&source, None) {
                        let synthesized = synthesize_php_construct_events(&tree, source.as_bytes(), file);
                        if !synthesized.is_empty() {
                            attach_synthesized_calls_to_decls(&mut idx, synthesized);
                        }
                    }
                }
            }
        }
        // Use the `namespace Foo\Bar;` segments as the module path so
        // private symbols cross-link only inside the namespace.
        let namespace_segments = parse_with(PACK_NAME, file, ctx)
            .and_then(|(snapshot, tree)| extract_php_namespace(tree.root_node(), snapshot.text.as_bytes()));
        if let Some(segments) = namespace_segments {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            // No `namespace` declaration — fall back to file-stem.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let visibility_by_span = collect_modifier_visibility(tree.root_node(), file, src, &PHP_VOCAB);
            let aliases_by_span = collect_param_type_aliases(&tree, file, src, &PHP_TYPE_ALIASES);
            for decl in &mut idx.defs {
                if let Some(visibility) = visibility_by_span.get(&decl.span).copied() {
                    decl.visibility = visibility;
                }
                if let Some(aliases) = aliases_by_span.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
            }
            // Per-class `bases`: `class Echo extends Base implements I, J`
            // → ["Base", "I", "J"]. PHP exposes them as separate
            // `base_clause` (single) and `class_interface_clause`
            // (one or more) children of the class node.
            let bases_by_span = collect_php_class_bases(&tree, file, src);
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
        // Recognised PHP lifecycle transitions. Method-style `close`,
        // file-handle `fclose`/`pclose`, and `unset` (a language
        // construct that *may* surface as a Call depending on the
        // grammar — best-effort).
        const PHP_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "fclose",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "pclose",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "unset",
                transition: "freed",
                arg_index: 0,
            },
        ];
        for decl in &mut idx.defs {
            augment_php_qualified_source_names(&mut decl.flow_events, &source);
            bonsai_lang_api::kit::inject_callable_reference_aliases_from_source(
                &mut decl.flow_events,
                &source,
            );
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, PHP_LIFECYCLE_TRANSITIONS);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

fn augment_php_qualified_source_names(events: &mut [FlowEvent], source: &str) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                span,
                source_name,
                source_names,
                value_kind,
                ..
            } => {
                if let Some(rhs) = php_assignment_rhs_text(source, *span) {
                    if target.trim_start().starts_with('$')
                        && php_quoted_bare_callable_literal(&rhs).is_some()
                    {
                        *source_name = Some(rhs.clone());
                        *value_kind = Some(AssignValueKind::Literal);
                    }
                    for access in php_qualified_accesses(&rhs) {
                        push_unique_source(source_names, access.clone());
                        let bare = access.trim_start_matches(['$', '@', '%']).to_string();
                        push_unique_source(source_names, bare);
                    }
                }
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    for access in php_qualified_accesses(&arg.value_text) {
                        if arg.place.is_none() {
                            arg.place = Some(access.clone());
                        }
                        push_unique_source(&mut arg.source_names, access.clone());
                        let bare = access.trim_start_matches(['$', '@', '%']).to_string();
                        push_unique_source(&mut arg.source_names, bare);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_php_qualified_source_names(then_events, source);
                augment_php_qualified_source_names(else_events, source);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_php_qualified_source_names(body, source);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_php_qualified_source_names(body, source);
                augment_php_qualified_source_names(catch_events, source);
                augment_php_qualified_source_names(finally_events, source);
            }
            _ => {}
        }
    }
}

fn php_quoted_bare_callable_literal(value: &str) -> Option<&str> {
    let value = value.trim();
    let quote = value.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || value.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let inner = value.get(1..value.len().saturating_sub(1))?.trim();
    if inner.is_empty()
        || inner
            .chars()
            .any(|ch| !(ch == '_' || ch == '\\' || ch.is_ascii_alphanumeric()))
        || inner.chars().next().is_some_and(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    Some(inner)
}

fn php_assignment_rhs_text(source: &str, span: Span) -> Option<String> {
    let start = usize::try_from(span.start).ok()?.min(source.len());
    let end = usize::try_from(span.end).ok()?.min(source.len());
    if start >= end || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return None;
    }
    let statement = &source[start..end];
    let (idx, separator_len) = find_php_assignment_separator(statement)?;
    let rhs = statement[idx + separator_len..]
        .trim()
        .trim_end_matches(';')
        .trim();
    (!rhs.is_empty()).then(|| rhs.to_string())
}

fn find_php_assignment_separator(text: &str) -> Option<(usize, usize)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut chars = text.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => {
                let next = chars.peek().map(|(_, next)| *next);
                if matches!(next, Some('=' | '>')) {
                    continue;
                }
                return Some((idx, ch.len_utf8()));
            }
            _ => {}
        }
    }
    None
}

fn php_qualified_accesses(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.char_indices().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    while let Some((idx, ch)) = chars.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if !matches!(ch, '$' | '@' | '%') {
            continue;
        }
        let ident_start = idx + ch.len_utf8();
        let mut ident_end = ident_start;
        while let Some((next_idx, next_ch)) = chars.peek().copied() {
            if next_ch == '_' || next_ch.is_ascii_alphanumeric() {
                ident_end = next_idx + next_ch.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        if ident_end == ident_start {
            continue;
        }
        let mut access = text[idx..ident_end].to_string();
        let mut cursor = ident_end;
        let mut saw_field = false;
        loop {
            let rest = text[cursor..].trim_start();
            let skipped_ws = text[cursor..].len() - rest.len();
            cursor += skipped_ws;
            if let Some(after_arrow) = text[cursor..].strip_prefix("->") {
                cursor += 2;
                let Some((field, end)) = php_access_field(after_arrow) else {
                    break;
                };
                access.push('.');
                access.push_str(&field);
                cursor += end;
                saw_field = true;
                continue;
            }
            if text[cursor..].starts_with('[') {
                let Some(close) = find_php_bracket_close(text, cursor) else {
                    break;
                };
                let Some(field) = php_access_field_name(&text[cursor + 1..close]) else {
                    break;
                };
                access.push('.');
                access.push_str(&field);
                cursor = close + 1;
                saw_field = true;
                continue;
            }
            break;
        }
        if saw_field {
            push_unique_source(&mut out, access);
        }
        while chars.peek().is_some_and(|(next_idx, _)| *next_idx < cursor) {
            chars.next();
        }
    }
    out
}

fn php_access_field(text: &str) -> Option<(String, usize)> {
    if text.starts_with('{') {
        let close = find_php_bracket_close(text, 0)?;
        let field = php_access_field_name(&text[1..close])?;
        return Some((field, close + 1));
    }
    let mut end = 0usize;
    for (idx, ch) in text.char_indices() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    (end > 0).then(|| (text[..end].to_string(), end))
}

fn php_access_field_name(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_matches(['"', '\'']);
    (!trimmed.is_empty() && trimmed.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()))
        .then(|| trimmed.to_string())
}

fn find_php_bracket_close(text: &str, open: usize) -> Option<usize> {
    let open_ch = text[open..].chars().next()?;
    let close_ch = match open_ch {
        '[' => ']',
        '{' => '}',
        _ => return None,
    };
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices().skip_while(|(idx, _)| *idx < open) {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if ch == open_ch {
            depth += 1;
        } else if ch == close_ch {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn push_unique_source(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

/// Parse PHP `use`/`require`/`include` statements into `ImportSpec`s.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Two PHP import shapes:
    //   1. `use X\Y;` / `use X\Y as Z;` / `use X\{A, B};`
    //      → only `namespace_use_clause`. The outer
    //        `namespace_use_declaration` wraps one or more clauses,
    //        so collecting both kinds emits each import twice.
    //   2. `require '...';` / `require_once '...';` / `include '...';`
    //      → dedicated expression nodes (NOT call expressions)
    for clause in collect_kinds(tree, &["namespace_use_clause"]) {
        let raw = node_text(&clause, src)
            .trim_start_matches("use ")
            .trim_end_matches(';')
            .trim();
        if raw.is_empty() {
            continue;
        }
        // Split off `as Alias` if present.
        let (module_text, alias) = if let Some((module_part, alias_part)) = raw.rsplit_once(" as ") {
            (
                module_part.trim().to_string(),
                Some(alias_part.trim().to_string()),
            )
        } else {
            (raw.to_string(), None)
        };
        // Grouped import `use Foo\{A, B as BB};` lowers each member
        // to a `namespace_use_clause` whose text is just `A` / `B as
        // BB` — the `Foo\` prefix lives on the outer
        // `namespace_use_group`'s namespace child. Walk up and
        // prepend so resolve sees the fully-qualified module path.
        let qualified_module = match group_namespace_prefix(&clause, src) {
            Some(prefix) if !module_text.starts_with(&prefix) => format!("{prefix}\\{module_text}"),
            _ => module_text,
        };
        imports.push(ImportSpec {
            span: span_of(file, &clause),
            module: qualified_module,
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    for node in collect_kinds(
        tree,
        &[
            "require_expression",
            "require_once_expression",
            "include_expression",
            "include_once_expression",
        ],
    ) {
        // The argument can be a bare string or a binary expression like
        // `__DIR__ . '/foo.php'`. Surface the FIRST string descendant —
        // that matches what the user would query against.
        let module = first_string_descendant(&node, src);
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &node),
            module,
            alias: None,
            is_wildcard: true,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// For a `namespace_use_clause` nested inside `use Foo\{A, B};`,
/// return the `Foo` prefix carried by the enclosing
/// `namespace_use_group`'s namespace child. Returns `None` for
/// non-grouped `use Foo\Bar;` clauses.
fn group_namespace_prefix(clause: &tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut ancestor = clause.parent();
    while let Some(parent) = ancestor {
        if parent.kind() == "namespace_use_group" {
            // tree-sitter-php doesn't expose the prefix as a named
            // field on the enclosing `namespace_use_declaration`;
            // walk the outer declaration's named children up to the
            // group node and pick the last `namespace_name` /
            // `qualified_name` we see (handles multi-segment
            // prefixes like `Foo\Bar\{A, B}`).
            let outer = parent.parent()?;
            let mut outer_cursor = outer.walk();
            let mut last_prefix: Option<String> = None;
            for child in outer.named_children(&mut outer_cursor) {
                // Stop scanning once we reach the group itself —
                // anything past it is a member, not a prefix.
                if child.id() == parent.id() {
                    break;
                }
                if matches!(child.kind(), "namespace_name" | "qualified_name") {
                    let text = node_text(&child, src).trim_end_matches('\\').trim().to_string();
                    if !text.is_empty() {
                        last_prefix = Some(text);
                    }
                }
            }
            return last_prefix;
        }
        ancestor = parent.parent();
    }
    None
}

/// Return the source text of the first `string` literal descendant
/// (without quotes) under `node`, or an empty string if none.
fn first_string_descendant(node: &tree_sitter::Node<'_>, src: &[u8]) -> String {
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "string" {
            // Prefer the unquoted `string_content` child; otherwise
            // strip surrounding quotes manually.
            if let Some(content) = first_named_child_of_kind(&current, "string_content") {
                return node_text(&content, src).to_string();
            }
            return node_text(&current, src)
                .trim_matches(|ch: char| matches!(ch, '"' | '\''))
                .to_string();
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    String::new()
}

/// Synthesize Call FlowEvents for PHP language constructs that
/// tree-sitter exposes as dedicated expression kinds.
///
/// Mappings:
///   - include_expression           → name = "include"
///   - include_once_expression      → name = "include_once"
///   - require_expression           → name = "require"
///   - require_once_expression      → name = "require_once"
///   - shell_command_expression     → name = "shell_exec" (matches
///     the existing php.cmdi.shell_exec rule's name without needing
///     a new rule for backtick literal)
///
/// The expression's argument (the included path / shell command)
/// becomes a single positional CallArg whose `value_text` is the
/// argument's source text — typically a `variable_name` like `$t`
/// or a string literal. The taint engine reads `value_text` to
/// decide whether the argument is tainted.
fn synthesize_php_construct_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    // Pairs of (grammar kind, synthesized callee name). The callee
    // name must match what the rulepack queries against.
    const CONSTRUCT_KINDS: &[(&str, &str)] = &[
        ("include_expression", "include"),
        ("include_once_expression", "include_once"),
        ("require_expression", "require"),
        ("require_once_expression", "require_once"),
        ("shell_command_expression", "shell_exec"),
    ];
    let mut synthesized = Vec::new();
    for (kind, callee) in CONSTRUCT_KINDS {
        for node in collect_kinds(tree, &[*kind]) {
            let span = span_of(file, &node);
            let mut args: Vec<CallArg> = Vec::new();
            // For include/require the first non-keyword child is the
            // argument expression; for shell_command_expression the
            // interpolated scalars / identifiers inside become args.
            if *kind == "shell_command_expression" {
                let mut cursor = node.walk();
                let mut stack: Vec<tree_sitter::Node<'_>> = Vec::new();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
                while let Some(current) = stack.pop() {
                    // Only nodes that can carry user data become args;
                    // literal text inside the backticks is ignored.
                    if matches!(
                        current.kind(),
                        "variable_name" | "subscript_expression" | "member_access_expression"
                    ) {
                        let text = node_text(&current, src).to_string();
                        if !text.is_empty() {
                            args.push(CallArg {
                                span: span_of(file, &current),
                                name: None,
                                value_text: text,
                                place: None,
                                source_names: Vec::new(),
                            });
                        }
                    }
                    let mut child_cursor = current.walk();
                    for child in current.named_children(&mut child_cursor) {
                        stack.push(child);
                    }
                }
            } else {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    let text = node_text(&child, src).to_string();
                    if !text.is_empty() {
                        args.push(CallArg {
                            span: span_of(file, &child),
                            name: None,
                            value_text: text,
                            place: None,
                            source_names: Vec::new(),
                        });
                        // include/require has exactly one argument.
                        break;
                    }
                }
            }
            let event = FlowEvent::Call {
                span,
                name: (*callee).to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args,
            };
            synthesized.push((span, event));
        }
    }
    synthesized
}

/// Assign each synthesized call event to the smallest decl whose body
/// contains the event span.
fn attach_synthesized_calls_to_decls(idx: &mut DeclIndex, events: Vec<(Span, FlowEvent)>) {
    // PHP allows nested `function inner()` inside another function
    // body. tree-sitter-php parses both as `function_definition`, so
    // pre-order extraction yields [outer, inner]. Picking the FIRST
    // containing decl would route the synthesized event (require /
    // include / backtick) to `outer`, hiding it from `inner`'s
    // intra-taint pass. Pick the smallest containing decl instead.
    for (event_span, event) in events {
        let mut best_decl: Option<usize> = None;
        let mut best_body_len: u64 = u64::MAX;
        for (decl_idx, decl) in idx.defs.iter().enumerate() {
            let body = decl.body_span.unwrap_or(decl.span);
            if event_span.file == body.file && event_span.start >= body.start && event_span.end <= body.end {
                let body_len = body.end.saturating_sub(body.start);
                if body_len < best_body_len {
                    best_decl = Some(decl_idx);
                    best_body_len = body_len;
                }
            }
        }
        if let Some(decl_idx) = best_decl {
            idx.defs[decl_idx].flow_events.push(event);
        }
    }
}

/// True for decl kinds that can declare an `extends`/`implements`
/// list — used to gate which decls receive `bases` entries.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk PHP class / interface / trait declarations and collect bare
/// base type names. Grammar shape (verified):
///
///   `class Handler extends Base implements I, J { ... }` →
///     (class_declaration name: (name)
///        (base_clause (name))
///        (class_interface_clause (name) (name))
///        body: (declaration_list))
///
/// `interface_declaration` uses its own `interface_base_clause` (just
/// `extends`). `trait_declaration` has no parent list.
fn collect_php_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_declaration", "interface_declaration", "enum_declaration"];
    for class_node in collect_kinds(tree, class_kinds) {
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "name"))
            .or_else(|| first_named_child_of_kind(&class_node, "qualified_name"))
        else {
            continue;
        };
        let class_name = node_text(&name_node, src).trim();
        if class_name.is_empty() {
            continue;
        }
        let mut bases: Vec<String> = Vec::new();
        let mut cursor = class_node.walk();
        for child in class_node.named_children(&mut cursor) {
            match child.kind() {
                "base_clause" | "class_interface_clause" | "interface_base_clause" => {
                    let mut clause_cursor = child.walk();
                    for entry in child.named_children(&mut clause_cursor) {
                        // Children of the parent-clause are
                        // `name` / `qualified_name` identifiers in
                        // tree-sitter-php.
                        if matches!(entry.kind(), "name" | "qualified_name") {
                            let raw = node_text(&entry, src);
                            if let Some(name) = canonical_php_base_name(raw) {
                                if !bases.iter().any(|existing| existing == &name) {
                                    bases.push(name);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), class_name.to_string(), bases));
        }
    }
    bases_by_class
}

/// Strip namespace qualifiers from a base name. `\Foo\Bar` → `Bar`,
/// `Bar` → `Bar`. Returns `None` for empty input.
fn canonical_php_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('\\');
    let bare = trimmed.rsplit('\\').next().unwrap_or(trimmed).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Return the namespace path (split on `\`) of the file's
/// `namespace Foo\Bar;` declaration, or `None` if absent.
fn extract_php_namespace(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "namespace_definition" {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            let text = node_text(&name_node, src);
            let segments: Vec<String> = text
                .split('\\')
                .map(str::trim)
                .filter(|segment| !segment.is_empty())
                .map(str::to_string)
                .collect();
            if !segments.is_empty() {
                return Some(segments);
            }
        }
    }
    None
}
