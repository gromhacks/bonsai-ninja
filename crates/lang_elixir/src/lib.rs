//! Elixir language adapter.
//!
//! Elixir's `def` and `defp` are macros, not keywords — tree-sitter-elixir
//! parses them as `call` nodes whose target is the identifier `def` or
//! `defp`. We use `call` as the function-kind and filter by the target
//! identifier in the grammar handler. Constructs with `do ... end`
//! blocks (function bodies, branches, loops) all share the `do_block`
//! grammar kind.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    with_fn_kinds, AdapterContext, AdapterError, DeclIndex, GrammarHandler, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath, Ref, RefKind, Visibility,
};
use bonsai_lang_api::{AssignValueKind, FlowEvent};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("elixir");
const PACK_NAME: &str = "elixir";
// Elixir has no direct `function_definition` grammar node. Function
// definitions come through as `call` nodes with target `def` / `defp`.
// Accepting `call` as the fn-kind means the adapter treats every call
// as a potential function body; the walker then finds the actual name
// from the child identifier. This over-captures (macro calls that aren't
// definitions also match), but that's the cost of Elixir's macro-based
// syntax — precision upgrades would require a hand-rolled handler
// filtering by target.
const HANDLER: GrammarHandler = GrammarHandler {
    assignment_kinds: &["binary_operator"],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    // Elixir functions return their final expression; the kit emits a
    // `Return` for the last statement of the `do` block.
    tail_expression_returns: true,
    ..with_fn_kinds(&["call"])
};

#[derive(Debug, Default, Copy, Clone)]
pub struct ElixirAdapter;

impl ElixirAdapter {
    /// Construct a stateless Elixir adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ElixirAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Elixir"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ex", "exs"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: bonsai_lang_api::NO_SUPER_RECEIVER_TOKENS,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Elixir privacy: `defp` is module-private, `def` is public.
        // Both lower to `call` nodes whose target identifier names
        // the macro. Walk for `defp` call spans, then mark matching
        // decls private.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            decl_index.refs.extend(synthesize_elixir_request_field_reads(
                &tree,
                snapshot.text.as_bytes(),
                file,
            ));
            let module_spans = collect_elixir_module_spans(&tree, snapshot.text.as_bytes(), file);
            if module_spans.is_empty() {
                bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
            } else {
                apply_elixir_module_identity(&mut decl_index, &module_spans);
            }
            for decl in &mut decl_index.defs {
                if let Some(params) = elixir_clause_param_slots(snapshot.text.as_ref(), decl.span, &decl.name)
                {
                    decl.params = params;
                }
                bonsai_lang_api::kit::inject_callable_reference_aliases_from_source(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                );
                normalize_elixir_control_expression_assignments(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                );
            }
            let private_spans = collect_elixir_defp_spans(&tree, snapshot.text.as_bytes());
            for decl in &mut decl_index.defs {
                let body_start = decl.body_span.map(|s| s.start).unwrap_or(decl.span.start);
                let body_end = decl.body_span.map(|s| s.end).unwrap_or(decl.span.end);
                // Match either by exact body-span anchor, or by an
                // enclosing span that aligns with the decl's start —
                // the walker may have anchored to either depending on
                // whether a `do` block was seen.
                if private_spans.iter().any(|(defp_start, defp_end)| {
                    *defp_start == body_start
                        || (*defp_start >= body_start
                            && *defp_end <= body_end
                            && *defp_start == decl.span.start)
                }) {
                    decl.visibility = Visibility::Module;
                }
            }
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        }
        // Recognised Elixir lifecycle transitions. Elixir's
        // tree-sitter call names land as bare atoms (e.g.
        // `:gen_server.stop` reads as `:gen_server.stop`); the
        // matcher's call-name comparison strips the leading colon
        // when the rule key omits it. Bare `close`/`cancel` cover
        // ad-hoc resource APIs that follow the same convention.
        const ELIXIR_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: ":gen_server.stop",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: ":ets.delete",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "Process.exit",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
        ];
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, ELIXIR_LIFECYCLE_TRANSITIONS);
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

#[derive(Clone, Debug)]
struct ElixirModuleSpan {
    span: bonsai_common::Span,
    module: String,
}

fn collect_elixir_module_spans(tree: &Tree, src: &[u8], file: FileId) -> Vec<ElixirModuleSpan> {
    let mut raw = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        if call_target_text(&call_node, src).as_deref() != Some("defmodule") {
            continue;
        }
        let Some(args_node) = call_node
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call_node, "arguments"))
        else {
            continue;
        };
        let mut args_cursor = args_node.walk();
        let Some(module_node) = args_node
            .named_children(&mut args_cursor)
            .find(|child| child.kind() == "alias")
        else {
            continue;
        };
        let module = node_text(&module_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        raw.push((span_of(file, &call_node), module));
    }

    raw.sort_by_key(|(span, _)| (span.start, std::cmp::Reverse(span.end)));
    let mut resolved = Vec::new();
    for (idx, (span, module)) in raw.iter().enumerate() {
        let parent = raw
            .iter()
            .enumerate()
            .filter(|(parent_idx, (parent_span, _))| {
                *parent_idx != idx
                    && parent_span.start <= span.start
                    && parent_span.end >= span.end
                    && (parent_span.start, parent_span.end) != (span.start, span.end)
            })
            .min_by_key(|(_, (parent_span, _))| parent_span.end.saturating_sub(parent_span.start))
            .and_then(|(parent_idx, _)| resolved_module_for_raw_index(parent_idx, &raw, &resolved));
        let full_module = if module.contains('.') {
            module.clone()
        } else if let Some(parent) = parent {
            format!("{parent}.{module}")
        } else {
            module.clone()
        };
        resolved.push(ElixirModuleSpan {
            span: *span,
            module: full_module,
        });
    }
    resolved
}

fn resolved_module_for_raw_index(
    raw_idx: usize,
    raw: &[(bonsai_common::Span, String)],
    resolved: &[ElixirModuleSpan],
) -> Option<String> {
    let (span, module) = raw.get(raw_idx)?;
    resolved
        .iter()
        .find(|entry| entry.span.start == span.start && entry.span.end == span.end)
        .map(|entry| entry.module.clone())
        .or_else(|| module.contains('.').then(|| module.clone()))
}

fn apply_elixir_module_identity(idx: &mut DeclIndex, modules: &[ElixirModuleSpan]) {
    for decl in &mut idx.defs {
        let Some(module) = innermost_module_for_span(modules, decl.span) else {
            continue;
        };
        let segments: Vec<String> = module.split('.').map(str::to_string).collect();
        decl.module_path = ModulePath::from_segments(segments);
        decl.qualified_name = Some(format!("{module}.{}", decl.name));
    }
}

fn innermost_module_for_span(modules: &[ElixirModuleSpan], span: bonsai_common::Span) -> Option<&str> {
    modules
        .iter()
        .filter(|module| module.span.start <= span.start && module.span.end >= span.end)
        .min_by_key(|module| module.span.end.saturating_sub(module.span.start))
        .map(|module| module.module.as_str())
}

fn elixir_clause_param_slots(src: &str, span: bonsai_common::Span, name: &str) -> Option<Vec<String>> {
    let text = elixir_span_text(src, span)?;
    let name_start = find_elixir_clause_name(text, name)?;
    let after_name = &text[name_start + name.len()..];
    let leading_ws = after_name.len().saturating_sub(after_name.trim_start().len());
    let after_name = &after_name[leading_ws..];
    if !after_name.starts_with('(') {
        return Some(Vec::new());
    }
    let close = find_matching_elixir_delim(after_name, 0, '(', ')')?;
    let args = split_elixir_top_level_args(&after_name[1..close]);
    Some(
        args.iter()
            .enumerate()
            .map(|(idx, arg)| elixir_pattern_param_name(arg).unwrap_or_else(|| format!("_arg{idx}")))
            .collect(),
    )
}

fn find_elixir_clause_name(text: &str, name: &str) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    text.match_indices(name).find_map(|(idx, _)| {
        let before = text[..idx].chars().next_back();
        let after = text[idx + name.len()..].chars().next();
        let before_ok = before.is_none_or(|ch| !elixir_ident_char(ch));
        let after_ok = after.is_none_or(|ch| !elixir_ident_char(ch));
        (before_ok && after_ok).then_some(idx)
    })
}

fn elixir_ident_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn elixir_span_text(src: &str, span: bonsai_common::Span) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?.min(src.len());
    let end = usize::try_from(span.end).ok()?.min(src.len());
    if start >= end || !src.is_char_boundary(start) || !src.is_char_boundary(end) {
        return None;
    }
    Some(&src[start..end])
}

fn elixir_pattern_param_name(arg: &str) -> Option<String> {
    let mut token = String::new();
    for ch in arg.chars().chain(std::iter::once(' ')) {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }
        if elixir_variable_name(&token) {
            return Some(token);
        }
        token.clear();
    }
    None
}

fn elixir_variable_name(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_lowercase())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !matches!(text, "do" | "end" | "fn" | "true" | "false" | "nil")
}

fn normalize_elixir_control_expression_assignments(events: &mut [FlowEvent], src: &str) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } if source_call
                .as_deref()
                .is_some_and(elixir_control_expression_macro) =>
            {
                if let Some(branch_sources) = elixir_control_expression_value_sources(src, *span) {
                    *source_call = None;
                    source_call_args.clear();
                    *source_names = branch_sources;
                    *value_kind = Some(if source_names.is_empty() {
                        AssignValueKind::Literal
                    } else {
                        AssignValueKind::Compound
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_elixir_control_expression_assignments(then_events, src);
                normalize_elixir_control_expression_assignments(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_elixir_control_expression_assignments(body, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_elixir_control_expression_assignments(body, src);
                normalize_elixir_control_expression_assignments(catch_events, src);
                normalize_elixir_control_expression_assignments(finally_events, src);
            }
            _ => {}
        }
    }
}

fn elixir_control_expression_macro(name: &str) -> bool {
    matches!(name, "if" | "unless")
}

fn elixir_control_expression_value_sources(src: &str, span: bonsai_common::Span) -> Option<Vec<String>> {
    let text = elixir_span_text(src, span)?;
    let rhs = text.split_once('=').map_or(text, |(_, rhs)| rhs).trim();
    let body = elixir_do_else_body(rhs)?;
    let mut out = Vec::new();
    collect_elixir_branch_value_names(body.then_body, &mut out);
    if let Some(else_body) = body.else_body {
        collect_elixir_branch_value_names(else_body, &mut out);
    }
    out.sort();
    out.dedup();
    Some(out)
}

#[derive(Copy, Clone)]
struct ElixirDoElseBody<'a> {
    then_body: &'a str,
    else_body: Option<&'a str>,
}

fn elixir_do_else_body(text: &str) -> Option<ElixirDoElseBody<'_>> {
    let mut scanner = ElixirKeywordScanner::new(text);
    let mut do_end = None;
    let mut else_range = None;
    let mut end_start = None;
    let mut depth = 0usize;
    while let Some((word, start, end)) = scanner.next_word() {
        match word {
            "do" => {
                depth = depth.saturating_add(1);
                do_end.get_or_insert(end);
            }
            "else" if depth == 1 => {
                else_range = Some((start, end));
            }
            "end" if depth > 0 => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end_start = Some(start);
                    break;
                }
            }
            _ => {}
        }
    }
    let do_end = do_end?;
    let end_start = end_start?;
    let (then_end, else_body) = if let Some((else_start, else_end)) = else_range {
        (else_start, Some(text[else_end..end_start].trim()))
    } else {
        (end_start, None)
    };
    Some(ElixirDoElseBody {
        then_body: text[do_end..then_end].trim(),
        else_body,
    })
}

struct ElixirKeywordScanner<'a> {
    text: &'a str,
    offset: usize,
    quote: Option<char>,
    escaped: bool,
}

impl<'a> ElixirKeywordScanner<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            offset: 0,
            quote: None,
            escaped: false,
        }
    }

    fn next_word(&mut self) -> Option<(&'a str, usize, usize)> {
        while self.offset < self.text.len() {
            let rest = &self.text[self.offset..];
            let mut chars = rest.char_indices();
            let (_, ch) = chars.next()?;
            let ch_len = ch.len_utf8();
            if let Some(open_quote) = self.quote {
                self.offset += ch_len;
                if self.escaped {
                    self.escaped = false;
                } else if ch == '\\' {
                    self.escaped = true;
                } else if ch == open_quote {
                    self.quote = None;
                }
                continue;
            }
            if matches!(ch, '"' | '\'') {
                self.quote = Some(ch);
                self.offset += ch_len;
                continue;
            }
            if !elixir_ident_char(ch) {
                self.offset += ch_len;
                continue;
            }
            let start = self.offset;
            let mut end = self.offset + ch_len;
            for (relative_idx, next) in chars {
                if !elixir_ident_char(next) {
                    break;
                }
                end = self.offset + relative_idx + next.len_utf8();
            }
            self.offset = end;
            return Some((&self.text[start..end], start, end));
        }
        None
    }
}

fn collect_elixir_branch_value_names(text: &str, out: &mut Vec<String>) {
    let mut scanner = ElixirKeywordScanner::new(text);
    while let Some((word, _, _)) = scanner.next_word() {
        if elixir_variable_name(word) && !out.iter().any(|existing| existing == word) {
            out.push(word.to_string());
        }
    }
}

fn find_matching_elixir_delim(text: &str, open_idx: usize, open: char, close: char) -> Option<usize> {
    if !text.is_char_boundary(open_idx) || !text[open_idx..].starts_with(open) {
        return None;
    }
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices().skip_while(|(idx, _)| *idx < open_idx) {
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
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        if ch == open {
            depth = depth.saturating_add(1);
        } else if ch == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn split_elixir_top_level_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut arg_start = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
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
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(text[arg_start..idx].trim().to_string());
                arg_start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    args.push(text[arg_start..].trim().to_string());
    args
}

/// Extract `alias`, `import`, `require`, `use` directives from an Elixir
/// tree into the canonical `ImportSpec` shape.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Elixir's `alias`, `import`, `require`, `use` are all macro calls —
    // `call` nodes whose target is the corresponding identifier and whose
    // first argument is the module alias. `alias MyApp.Foo, as: F` adds
    // the alias-rename via a keywords-pair child.
    for call_node in collect_kinds(tree, &["call"]) {
        let Some(target_node) = call_node.child_by_field_name("target") else {
            continue;
        };
        let target_text = node_text(&target_node, src);
        // Filter to the four directive macros — every other call slips
        // through unchanged.
        if !matches!(target_text, "alias" | "import" | "require" | "use") {
            continue;
        }
        let Some(args_node) = call_node
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call_node, "arguments"))
        else {
            continue;
        };
        // First positional arg must be an `alias` (Elixir's name for a
        // module identifier like `MyApp.Foo`). Anything else is unsupported
        // (e.g. `import :erlang_module` atom form).
        let mut args_cursor = args_node.walk();
        let mut named_args = args_node.named_children(&mut args_cursor);
        let module_node = match named_args.next() {
            Some(arg) if arg.kind() == "alias" => arg,
            _ => continue,
        };
        let module = node_text(&module_node, src).to_string();
        // `as: F` rename appears as a keyword list: `keywords > pair { key, value }`.
        let explicit_alias = first_named_child_of_kind(&args_node, "keywords")
            .and_then(|keywords| first_named_child_of_kind(&keywords, "pair"))
            .and_then(|pair| {
                let key_node = pair.child_by_field_name("key")?;
                let key_text = node_text(&key_node, src).trim().trim_end_matches(':');
                if key_text == "as" {
                    pair.child_by_field_name("value")
                        .map(|value_node| node_text(&value_node, src).to_string())
                } else {
                    None
                }
            });
        // Elixir's `alias MyApp.AuthService` (no `as:` rename) binds
        // the leaf segment as the local name — `AuthService` becomes
        // a path head usable as `AuthService.run(x)`. When no
        // explicit `as:` is provided, mirror Elixir's binding rule
        // so the resolver knows `AuthService` resolves into the
        // workspace's `MyApp.AuthService` module.
        let alias = explicit_alias.or_else(|| match target_text {
            "alias" => module
                .rsplit('.')
                .next()
                .map(str::trim)
                .filter(|leaf| !leaf.is_empty())
                .map(str::to_string),
            _ => None,
        });
        imports.push(ImportSpec {
            span: span_of(file, &call_node),
            module: module.clone(),
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if target_text == "import" {
            imports.push(ImportSpec {
                span: span_of(file, &call_node),
                module,
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Local,
            });
        }
    }
    imports
}

/// Plug.Conn / Oban request fields read via `conn.<field>` dot access.
/// Elixir parses `conn.query_params` (no parens) as a `call` node whose
/// `target` is a `dot` — the kit's generic read/write extractor only
/// recognises member-expression node kinds, so the dotted field name is
/// never surfaced as a `Read` ref. These are the framework-supplied
/// request fields the taint sources query; the bare receiver `conn`
/// remains a separate, intentionally-disabled over-broad source.
const ELIXIR_REQUEST_FIELD_READS: &[&str] = &[
    "params",
    "query_params",
    "body_params",
    "cookies",
    "req_headers",
    "args",
];

/// Surface `conn.query_params` / `job.args`-style request-field accesses as
/// `Read` refs named after the field. Bounded to [`ELIXIR_REQUEST_FIELD_READS`]
/// so the adapter never emits a read for arbitrary `a.b` dot access — the
/// same targeted-synthesis convention Ruby (`QUERY_STRING`) and Lua (`arg`)
/// use, keeping the behavioural blast radius to exactly the field names the
/// queue/HTTP source rules bind to.
fn synthesize_elixir_request_field_reads(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    let mut refs = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        let mut target_cursor = call_node.walk();
        let target = match call_node.child_by_field_name("target") {
            Some(target) => target,
            None => match call_node.named_children(&mut target_cursor).next() {
                Some(target) => target,
                None => continue,
            },
        };
        if target.kind() != "dot" {
            continue;
        }
        // `dot` node for `recv.field` exposes the field as its last named
        // child (the leading `.` is anonymous); older grammar revisions
        // name it `right`.
        let mut field_cursor = target.walk();
        let field = match target.child_by_field_name("right") {
            Some(field) => Some(field),
            None => target.named_children(&mut field_cursor).last(),
        };
        let Some(field_node) = field else {
            continue;
        };
        if field_node.kind() != "identifier" {
            continue;
        }
        let name = node_text(&field_node, src).trim();
        if !ELIXIR_REQUEST_FIELD_READS.contains(&name) {
            continue;
        }
        refs.push(Ref {
            span: span_of(file, &field_node),
            name: name.to_string(),
            kind: RefKind::Read,
            scope: None,
            resolved: None,
        });
    }
    refs
}

fn call_target_text(call_node: &Node<'_>, src: &[u8]) -> Option<String> {
    call_node
        .child_by_field_name("target")
        .or_else(|| {
            let mut cursor = call_node.walk();
            let first = call_node.named_children(&mut cursor).next();
            first
        })
        .map(|target| node_text(&target, src).trim().to_string())
}

/// Find every `defp` call site in the tree and return its byte span.
/// Adapter uses these to mark matching decls as Visibility::Module
/// (Elixir's module-private visibility).
fn collect_elixir_defp_spans(tree: &tree_sitter::Tree, src: &[u8]) -> Vec<(u64, u64)> {
    let mut defp_spans = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        let field_target = call_node.child_by_field_name("target");
        // Prefer the `target:` field; older grammar revisions don't expose
        // it, so fall back to the first named child.
        let target_node = match field_target {
            Some(target) => target,
            None => {
                let mut call_cursor = call_node.walk();
                let first_named = call_node.named_children(&mut call_cursor).next();
                match first_named {
                    Some(first_child) => first_child,
                    None => continue,
                }
            }
        };
        let target_text = node_text(&target_node, src).trim();
        if target_text == "defp" {
            defp_spans.push((
                u64::try_from(call_node.start_byte()).unwrap_or(u64::MAX),
                u64::try_from(call_node.end_byte()).unwrap_or(u64::MAX),
            ));
        }
    }
    defp_spans
}

#[cfg(test)]
mod tests;
