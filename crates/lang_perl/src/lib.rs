//! Perl language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, CallArg, CallKind, DeclIndex, DeclKind, FlowEvent, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath,
    Ref, RefKind,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("perl");
const PACK_NAME: &str = "perl";
// Perl5 OO uses bare `package Foo;` declarations as class
// boundaries; tree-sitter-perl exposes them as `package_statement`
// nodes with a `name:` field. The grammar's `class_statement` form
// (newer perl5 OO syntax) is also surfaced for completeness.
const PERL_CLASS_KINDS: &[&str] = &["package_statement", "class_statement"];

const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &["subroutine_declaration_statement"],
    class_kinds: PERL_CLASS_KINDS,
    method_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.method_kinds,
    method_context_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.method_context_kinds,
    constructor_method_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.constructor_method_kinds,
    constructor_names: bonsai_lang_api::kit::GENERIC_HANDLER.constructor_names,
    if_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.if_kinds,
    for_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.for_kinds,
    foreach_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.foreach_kinds,
    while_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.while_kinds,
    do_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.do_kinds,
    loop_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.loop_kinds,
    call_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.call_kinds,
    assignment_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.assignment_kinds,
    return_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.return_kinds,
    throw_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.throw_kinds,
    lambda_kinds: &["anonymous_subroutine_expression"],
    try_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.try_kinds,
    catch_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.catch_kinds,
    finally_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.finally_kinds,
    break_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.break_kinds,
    continue_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.continue_kinds,
    yield_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.yield_kinds,
    await_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.await_kinds,
    defer_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.defer_kinds,
    using_kinds: bonsai_lang_api::kit::GENERIC_HANDLER.using_kinds,
    method_receiver_param_index: bonsai_lang_api::kit::GENERIC_HANDLER.method_receiver_param_index,
    implicit_receiver_names: bonsai_lang_api::kit::GENERIC_HANDLER.implicit_receiver_names,
    implicit_receiver_prefixes: bonsai_lang_api::kit::GENERIC_HANDLER.implicit_receiver_prefixes,
    tail_expression_returns: bonsai_lang_api::kit::GENERIC_HANDLER.tail_expression_returns,
};

/// Tree-sitter adapter for Perl 5.
#[derive(Debug, Default, Copy, Clone)]
pub struct PerlAdapter;

impl PerlAdapter {
    /// Construct a fresh adapter; the type carries no state.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for PerlAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Perl"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.t` is the standard Perl test-file extension — the same
        // module loader and grammar applies; without claiming it,
        // every Perl test file's calls were invisible to the index.
        &["pl", "pm", "t"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities::partial_baseline()
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        let source = ctx
            .vfs
            .snapshot(file)
            .ok()
            .map(|snapshot| snapshot.text.to_string())
            .unwrap_or_default();
        // Perl's tree-sitter grammar doesn't label subroutine
        // parameters structurally — every sub is parameterless at
        // the grammar level. Real code binds positional args via
        // `my ($a, $b) = @_;` (or shifts `$_[0]`). Scan the
        // leading flow events of each sub for that idiom and
        // synthesize `params` so entry-point inference (G5) and
        // taint seeding work.
        for decl in &mut idx.defs {
            let list_params = rewrite_perl_list_param_bindings(&mut decl.flow_events, &source);
            let inferred = list_params.unwrap_or_else(|| infer_perl_params_from_body(&decl.flow_events));
            if !inferred.is_empty() {
                decl.params = inferred;
            }
        }
        // Synthesize Call FlowEvents for `qx//` and backtick `` `cmd` ``
        // expressions. tree-sitter-perl parses both as `command_string`
        // nodes with no `Call` exposure of their own, so the
        // `perl.cmdi.qx_backticks` rule (kind: call, callee.name: qx)
        // can't match real code without this lowering. The interpolated
        // scalars inside become CallArgs so the matcher can evaluate
        // arg-shape constraints and the taint engine can see them as
        // tainted-arg call sites.
        if !source.is_empty() {
            if let Ok(lang) = language_from_pack(PACK_NAME) {
                let mut parser = tree_sitter::Parser::new();
                if parser.set_language(&lang).is_ok() {
                    if let Some(tree) = parser.parse(&source, None) {
                        idx.refs
                            .extend(synthesize_perl_source_refs(source.as_bytes(), file));
                        let mut calls = synthesize_qx_call_events(&tree, source.as_bytes(), file);
                        calls.extend(synthesize_method_call_events(&tree, source.as_bytes(), file));
                        calls.extend(synthesize_builtin_call_events(&tree, source.as_bytes(), file));
                        calls.extend(synthesize_builtin_expression_arg_call_events(
                            &tree,
                            source.as_bytes(),
                            file,
                        ));
                        calls.extend(synthesize_match_regex_call_events(&tree, source.as_bytes(), file));
                        calls.extend(synthesize_coderef_invocation_events(source.as_bytes(), file));
                        if !calls.is_empty() {
                            attach_synthesized_calls_to_decls(&mut idx, calls);
                        }
                    }
                }
            }
        }
        for decl in &mut idx.defs {
            rewrite_perl_call_arg_texts(&mut decl.flow_events, &source);
            normalize_perl_hash_deref_flow_events(&mut decl.flow_events, &source);
            augment_perl_collection_flow_events(&mut decl.flow_events, &source);
        }
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        apply_perl_package_semantic_identity(&mut idx);
        // Perl convention: subroutines starting with `_` are
        // module-private. Mark those Visibility::Module so the
        // resolver refuses cross-package calls to internal helpers.
        for decl in &mut idx.defs {
            if decl.name.starts_with('_') {
                decl.visibility = bonsai_lang_api::Visibility::Module;
            }
        }
        // Per-package `bases`: Perl5 has no syntactic
        // `extends`/`implements` — class hierarchy is set by
        // `use base 'Parent::Class'` / `use parent 'Foo'` calls
        // inside the package body. Walk every `use_statement` in
        // the file and assign the named parents to the package
        // decl that contains them. Bare-tail (right-most segment of
        // `Foo::Bar`) is the bases entry.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let bases_by_span = collect_perl_class_bases(&tree, file, src, &idx);
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
        // Recognised Perl lifecycle transitions. Perl is procedural;
        // method calls (`$fh->close`) land bare. `undef $x` is the
        // idiomatic Perl free, surfaced as a call to `undef`.
        const PERL_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "undef",
                transition: "freed",
                arg_index: 0,
            },
        ];
        for decl in &mut idx.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, PERL_LIFECYCLE_TRANSITIONS);
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

fn apply_perl_package_semantic_identity(idx: &mut DeclIndex) {
    let mut packages: Vec<(Span, String, bonsai_common::SymbolId)> = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.name.clone(), decl.symbol))
        .collect();
    packages.sort_by_key(|(span, _, _)| span.start);
    if packages.is_empty() {
        return;
    }
    for decl in &mut idx.defs {
        if is_class_like(decl.kind) {
            let module_path = ModulePath::from_segments([decl.name.clone()]);
            decl.module_path = module_path;
            decl.qualified_name = Some(decl.name.clone());
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some((_, package_name, package_symbol)) = packages
            .iter()
            .filter(|(span, _, _)| span.start <= decl.span.start)
            .max_by_key(|(span, _, _)| span.start)
        else {
            continue;
        };
        decl.parent = Some(*package_symbol);
        decl.module_path = ModulePath::from_segments([package_name.clone()]);
        decl.qualified_name = Some(format!("{package_name}::{}", decl.name));
    }
}

/// Augment Assign events with extra `source_names` so collection
/// transforms (`map`/`grep`/`sort`) and `push @arr, $tainted` calls
/// surface the underlying collection in taint flow.
///
/// Recurses into branches, loops, defers, using-blocks and try/catch
/// bodies so deeply-nested transforms still get their sources.
fn augment_perl_collection_flow_events(events: &mut Vec<FlowEvent>, source: &str) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_names,
                ..
            } => {
                if let Some(rhs) = assignment_rhs_text(source, *span) {
                    add_perl_collection_transform_sources(target, &rhs, source_names);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_perl_collection_flow_events(then_events, source);
                augment_perl_collection_flow_events(else_events, source);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_perl_collection_flow_events(body, source);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_perl_collection_flow_events(body, source);
                augment_perl_collection_flow_events(catch_events, source);
                augment_perl_collection_flow_events(finally_events, source);
            }
            _ => {}
        }
    }

    // Second pass: lower `push @arr, $x` calls into a synthetic
    // Assign event so taint flowing into `$x` propagates to `@arr`.
    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let push_assignment = perl_push_assignment(&event);
        rewritten.push(event);
        if let Some(assign) = push_assignment {
            rewritten.push(assign);
        }
    }
    *events = rewritten;
}

/// Rewrite Perl hash-deref expressions like `$h->{k}` into the
/// dotted form `$h.k` so the resolver and taint engine treat them as
/// member accesses rather than opaque text.
///
/// Recurses into nested control-flow event lists; merges adjacent
/// Assigns that share a span (the grammar can split a single
/// hash-deref assignment into multiple events).
fn normalize_perl_hash_deref_flow_events(events: &mut Vec<FlowEvent>, source: &str) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call_args,
                source_names,
                ..
            } => {
                if let Some(name) = source_name {
                    *name = normalize_perl_hash_deref_text(name);
                }
                for arg in source_call_args {
                    *arg = normalize_perl_hash_deref_text(arg);
                }
                for name in source_names.iter_mut() {
                    *name = normalize_perl_hash_deref_text(name);
                }
                if let Some(rhs) = assignment_rhs_text(source, *span) {
                    add_perl_hash_deref_sources(&rhs, source_names);
                }
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    // Rewrite call arguments only — `value_text` and
                    // `place` should stay in sync.
                    if let Some(access) = perl_hash_deref_access(&arg.value_text) {
                        arg.value_text.clone_from(&access);
                        arg.place = Some(access);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_hash_deref_flow_events(then_events, source);
                normalize_perl_hash_deref_flow_events(else_events, source);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_hash_deref_flow_events(body, source);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_hash_deref_flow_events(body, source);
                normalize_perl_hash_deref_flow_events(catch_events, source);
                normalize_perl_hash_deref_flow_events(finally_events, source);
            }
            _ => {}
        }
    }

    // Second pass: collapse a hash-deref Assign plus any later
    // same-span Assigns into a single normalized Assign.
    let mut rewritten = Vec::with_capacity(events.len());
    let mut event_idx = 0usize;
    while event_idx < events.len() {
        let Some((span, target, rhs)) = perl_hash_deref_assignment(&events[event_idx], source) else {
            rewritten.push(events[event_idx].clone());
            event_idx += 1;
            continue;
        };

        let mut source_name = None;
        let mut source_call = None;
        let mut source_call_args = Vec::new();
        let mut source_names = Vec::new();
        // Walk forward absorbing every Assign that shares this span.
        while event_idx < events.len() {
            let FlowEvent::Assign {
                span: next_span,
                source_name: next_source_name,
                source_call: next_source_call,
                source_call_args: next_source_call_args,
                source_names: next_source_names,
                ..
            } = &events[event_idx]
            else {
                break;
            };
            if *next_span != span {
                break;
            }
            if source_name.is_none() {
                // Drop any source_name that's actually the LHS itself
                // — these are extractor noise from hash-deref shapes.
                source_name = next_source_name
                    .as_deref()
                    .map(normalize_perl_hash_deref_text)
                    .filter(|name| !perl_source_name_is_lhs_artifact(name, &target));
            }
            if source_call.is_none() {
                source_call.clone_from(next_source_call);
            }
            if source_call_args.is_empty() {
                source_call_args = next_source_call_args
                    .iter()
                    .map(|arg| normalize_perl_hash_deref_text(arg))
                    .collect();
            }
            for name in next_source_names {
                let normalized = normalize_perl_hash_deref_text(name);
                if !perl_source_name_is_lhs_artifact(&normalized, &target) {
                    push_unique_string(&mut source_names, normalized);
                }
            }
            event_idx += 1;
        }

        // Final pass: also surface every sigil'd identifier in the
        // textual RHS so taint sees both the variable and its bare
        // form (`$x` and `x`).
        for name in perl_sigiled_identifiers(&rhs, ['$', '@', '%']) {
            push_unique_string(&mut source_names, name.clone());
            push_unique_string(
                &mut source_names,
                name.trim_start_matches(['$', '@', '%']).to_string(),
            );
        }

        rewritten.push(FlowEvent::Assign {
            span,
            target,
            source_name,
            source_call,
            source_call_args,
            source_names,
        });
    }
    *events = rewritten;
}

/// If `event` is an Assign whose LHS is a hash-deref expression,
/// return the canonical span/target/rhs triple; otherwise `None`.
fn perl_hash_deref_assignment(event: &FlowEvent, source: &str) -> Option<(Span, String, String)> {
    let FlowEvent::Assign { span, .. } = event else {
        return None;
    };
    let (lhs, rhs) = assignment_lhs_rhs_text(source, *span)?;
    let target = perl_hash_deref_access(&lhs)?;
    Some((*span, target, rhs))
}

/// When the LHS of `@arr = map { ... } @other` is a collection and
/// the RHS is a `map`/`grep`/`sort` form, register every sigil'd
/// collection identifier in the RHS as an extra taint source.
fn add_perl_collection_transform_sources(target: &str, rhs: &str, source_names: &mut Vec<String>) {
    let target = target.trim();
    // Only collections (arrays, hashes) get this treatment.
    if !target.starts_with(['@', '%']) {
        return;
    }
    let rhs_trimmed = rhs.trim_start();
    // Match the four canonical forms with optional whitespace before
    // the block. Keeps us conservative — a user-defined `map_*` sub
    // wouldn't trigger.
    if !(rhs_trimmed.starts_with("map ")
        || rhs_trimmed.starts_with("map{")
        || rhs_trimmed.starts_with("grep ")
        || rhs_trimmed.starts_with("grep{")
        || rhs_trimmed.starts_with("sort "))
    {
        return;
    }
    for collection in perl_sigiled_identifiers(rhs, ['@', '%']) {
        push_unique_string(source_names, collection.clone());
        push_unique_string(
            source_names,
            collection.trim_start_matches(['@', '%']).to_string(),
        );
    }
}

/// If `event` is a `push @arr, $val` call, synthesize an Assign that
/// flows the value(s) into `@arr`. Returns `None` for any other
/// shape.
fn perl_push_assignment(event: &FlowEvent) -> Option<FlowEvent> {
    let FlowEvent::Call { span, name, args, .. } = event else {
        return None;
    };
    if name != "push" || args.len() < 2 {
        return None;
    }
    let target = args.first()?.value_text.trim();
    // First arg must be the target array — sanity gate.
    if !target.starts_with('@') {
        return None;
    }
    let mut source_names = Vec::new();
    for arg in args.iter().skip(1) {
        let value = arg.value_text.trim();
        if value.is_empty() {
            continue;
        }
        push_unique_string(&mut source_names, value.to_string());
        // Surface both the sigil'd and bare forms so the taint engine
        // matches against either spelling.
        if value.starts_with(['$', '@', '%']) {
            push_unique_string(
                &mut source_names,
                value.trim_start_matches(['$', '@', '%']).to_string(),
            );
        }
    }
    (!source_names.is_empty()).then(|| FlowEvent::Assign {
        span: *span,
        target: target.to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names,
    })
}

/// Return the trimmed RHS text of an assignment whose textual range
/// is `span`. Wraps `assignment_lhs_rhs_text` and drops the trailing
/// semicolon.
fn assignment_rhs_text(source: &str, span: Span) -> Option<String> {
    let (_, rhs) = assignment_lhs_rhs_text(source, span)?;
    Some(rhs.trim().trim_end_matches(';').trim().to_string())
}

/// Split the source text at `span` into `(lhs, rhs)` around the
/// top-level `=` (or `=>`). Returns `None` when the span is invalid
/// or no separator is found.
fn assignment_lhs_rhs_text(source: &str, span: Span) -> Option<(String, String)> {
    let start = usize::try_from(span.start).ok()?.min(source.len());
    let end = usize::try_from(span.end).ok()?.min(source.len());
    if start >= end || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return None;
    }
    let statement = &source[start..end];
    let (separator_idx, separator_len) = find_top_level_assignment_separator(statement)?;
    Some((
        statement[..separator_idx].trim().to_string(),
        statement[separator_idx + separator_len..].trim().to_string(),
    ))
}

/// Normalize a hash-deref expression to dotted form, falling back to
/// the trimmed input when the text isn't a deref.
fn normalize_perl_hash_deref_text(text: &str) -> String {
    perl_hash_deref_access(text).unwrap_or_else(|| text.trim().to_string())
}

fn add_perl_hash_deref_sources(text: &str, source_names: &mut Vec<String>) {
    for access in perl_hash_deref_accesses(text) {
        push_unique_string(source_names, access.clone());
        let bare = access.trim_start_matches(['$', '@', '%']).to_string();
        push_unique_string(source_names, bare);
    }
}

fn perl_hash_deref_accesses(text: &str) -> Vec<String> {
    let mut accesses = Vec::new();
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

        let access_end = extend_perl_deref_end(text, ident_end);
        if access_end <= ident_end {
            continue;
        }
        if let Some(access) = perl_hash_deref_access(&text[idx..access_end]) {
            push_unique_string(&mut accesses, access);
        }
        while chars.peek().is_some_and(|(next_idx, _)| *next_idx < access_end) {
            chars.next();
        }
    }

    accesses
}

/// Convert `$h->{k}` / `$h{k}` / `@arr->{k}` style hash-deref text
/// into the canonical `$h.k` form. Returns `None` for any other
/// shape (so callers can skip non-deref text).
fn perl_hash_deref_access(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_end_matches(';').trim();
    let mut cursor = 0usize;
    let sigil = trimmed[cursor..].chars().next()?;
    // Must start with a Perl sigil — otherwise it's not a deref.
    if !matches!(sigil, '$' | '@' | '%') {
        return None;
    }
    cursor += sigil.len_utf8();
    let ident_start = cursor;
    while let Some(ch) = trimmed[cursor..].chars().next() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            cursor += ch.len_utf8();
        } else {
            break;
        }
    }
    // Need at least one identifier char after the sigil.
    if cursor == ident_start {
        return None;
    }
    let base = &trimmed[..cursor];
    cursor = skip_ascii_ws(trimmed, cursor);
    // Optional `->` arrow before `{`.
    if trimmed[cursor..].starts_with("->") {
        cursor += 2;
        cursor = skip_ascii_ws(trimmed, cursor);
    }
    if !trimmed[cursor..].starts_with('{') {
        return None;
    }
    let close_end = skip_balanced_perl_braces(trimmed, cursor);
    if close_end <= cursor + 1
        || close_end > trimmed.len()
        || trimmed.as_bytes().get(close_end - 1).copied() != Some(b'}')
    {
        return None;
    }
    let field = perl_hash_field_name(&trimmed[cursor + 1..close_end - 1])?;
    cursor = skip_ascii_ws(trimmed, close_end);
    // Reject anything trailing — `$h->{k}->[0]` etc. — so we don't
    // mis-collapse multi-level accesses.
    (cursor == trimmed.len()).then(|| format!("{base}.{field}"))
}

/// Advance `idx` past any ASCII whitespace bytes in `text`.
fn skip_ascii_ws(text: &str, mut idx: usize) -> usize {
    while idx < text.len() && text.as_bytes()[idx].is_ascii_whitespace() {
        idx += 1;
    }
    idx
}

/// Validate and unquote a hash key. Accepts bareword identifiers
/// (matching `[A-Za-z_][A-Za-z0-9_]*`) optionally wrapped in single
/// or double quotes; returns `None` otherwise.
fn perl_hash_field_name(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Strip matching surrounding quotes if present.
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|part| part.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|part| part.strip_suffix('\''))
        })
        .unwrap_or(trimmed)
        .trim();
    // Reject anything that isn't a simple identifier — `$h->{$k}` and
    // `$h->{a-b}` shouldn't collapse to a dotted form.
    if unquoted.is_empty()
        || unquoted
            .chars()
            .next()
            .is_some_and(|ch| !(ch == '_' || ch.is_ascii_alphabetic()))
        || !unquoted.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(unquoted.to_string())
}

/// True if `name` is just a re-spelling of the LHS `target` (or its
/// base / field). Used to drop extractor noise where the same span
/// reports the LHS as one of its `source_names`.
fn perl_source_name_is_lhs_artifact(name: &str, target: &str) -> bool {
    let target = target.trim();
    let Some((base, field)) = target.rsplit_once('.') else {
        return false;
    };
    let bare_base = base.trim_start_matches(['$', '@', '%']);
    let bare_target = target.trim_start_matches(['$', '@', '%']);
    let normalized = normalize_perl_hash_deref_text(name);
    // Collapse `->` and `{}`/`}` shapes so we compare canonical forms.
    let collapsed = normalized
        .replace("->", ".")
        .replace(['{', '}'], "")
        .trim_matches('.')
        .to_string();
    [name.trim(), normalized.as_str(), collapsed.as_str()]
        .iter()
        .any(|candidate| {
            !candidate.is_empty()
                && (*candidate == target
                    || *candidate == bare_target
                    || *candidate == base
                    || *candidate == bare_base
                    || *candidate == field)
        })
}

/// Find the `=` (or `=>`) that separates LHS from RHS in `text`,
/// skipping over braces/brackets/quotes. Returns `(byte_idx, len)`
/// where `len` is 1 for `=` and 2 for `=>`. `==` is skipped.
fn find_top_level_assignment_separator(text: &str) -> Option<(usize, usize)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
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
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => {
                let next_ch = iter.peek().map(|(_, next)| *next);
                // Fat-comma: `=>` is also a valid assignment separator.
                if matches!(next_ch, Some('>')) {
                    return Some((idx, 2));
                }
                // `==` is a comparison, not assignment.
                if matches!(next_ch, Some('=')) {
                    continue;
                }
                return Some((idx, 1));
            }
            _ => {}
        }
    }
    None
}

/// Scan `text` for sigil'd identifiers (e.g. `$x`, `@arr`, `%h`)
/// matching any of `sigils`, ignoring matches inside string
/// literals. Returns each unique identifier (with sigil) in source
/// order.
fn perl_sigiled_identifiers(text: &str, sigils: impl IntoIterator<Item = char>) -> Vec<String> {
    let sigils = sigils.into_iter().collect::<Vec<_>>();
    let mut identifiers = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
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
        if !sigils.contains(&ch) {
            continue;
        }
        let mut end = idx + ch.len_utf8();
        while let Some((next_idx, next_ch)) = chars.peek().copied() {
            if next_ch == '_' || next_ch.is_ascii_alphanumeric() {
                chars.next();
                end = next_idx + next_ch.len_utf8();
            } else {
                break;
            }
        }
        // Bare sigil with no name (`$$` etc.) — skip.
        if end > idx + ch.len_utf8() {
            push_unique_string(&mut identifiers, text[idx..end].to_string());
        }
    }
    identifiers
}

/// Append `value` to `out` only if it's non-empty and not already
/// present. Linear-scan dedup is fine here because the call sites
/// produce O(few) names per event.
fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

/// Walk every Call event and rewrite its arg `value_text` so that
/// (a) string literals include their surrounding quotes, and
/// (b) sigil'd variables with deref tails (`$h->{k}`, `$h{k}`) cover
/// the full expression.
///
/// Recurses into nested control-flow event lists so deeply-nested
/// calls get the same treatment.
fn rewrite_perl_call_arg_texts(events: &mut [FlowEvent], source: &str) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    let start = usize::try_from(arg.span.start).unwrap_or(usize::MAX);
                    let end = usize::try_from(arg.span.end).unwrap_or(usize::MAX);
                    if start == usize::MAX || end > source.len() || start > end {
                        continue;
                    }
                    let bytes = source.as_bytes();
                    // String literal check: the byte just before the
                    // span and the byte AT the span end form a matched
                    // quote pair (the grammar exposes the inner
                    // content).
                    if start > 0
                        && end < bytes.len()
                        && matches!(bytes[start - 1], b'\'' | b'"' | b'`')
                        && bytes[start - 1] == bytes[end]
                    {
                        arg.value_text = source[start - 1..=end].to_string();
                        arg.place = None;
                        continue;
                    }
                    // Locate the sigil. The grammar sometimes places
                    // the span at the sigil and sometimes one byte
                    // past it, so check both.
                    let sigil_start = if matches!(bytes.get(start), Some(b'$' | b'@' | b'%')) {
                        Some(start)
                    } else if start > 0 && matches!(bytes[start - 1], b'$' | b'@' | b'%') {
                        Some(start - 1)
                    } else {
                        None
                    };
                    if let Some(sigil_start) = sigil_start {
                        // Extend through any chained `->{k}` / `{k}`
                        // accesses so the full deref shows up in the
                        // arg text.
                        let extended_end = extend_perl_deref_end(source, end);
                        arg.value_text = source[sigil_start..extended_end].to_string();
                        arg.place = Some(arg.value_text.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_perl_call_arg_texts(then_events, source);
                rewrite_perl_call_arg_texts(else_events, source);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_perl_call_arg_texts(body, source);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_perl_call_arg_texts(body, source);
                rewrite_perl_call_arg_texts(catch_events, source);
                rewrite_perl_call_arg_texts(finally_events, source);
            }
            _ => {}
        }
    }
}

/// Starting at `end`, advance past any chained `->{k}`, `->ident`, or
/// bare `{k}` deref tails and return the new end byte.
fn extend_perl_deref_end(source: &str, mut end: usize) -> usize {
    loop {
        let rest = &source[end..];
        if let Some(after_arrow) = rest.strip_prefix("->") {
            end += 2;
            // `->{` opens a balanced brace deref.
            if after_arrow.starts_with('{') {
                end = skip_balanced_perl_braces(source, end);
                continue;
            }
            // `->ident` consumes the identifier characters.
            while let Some(ch) = source[end..].chars().next() {
                if ch == '_' || ch.is_ascii_alphanumeric() {
                    end += ch.len_utf8();
                } else {
                    break;
                }
            }
            continue;
        }
        // Bare `{k}` after a variable (no arrow needed).
        if rest.starts_with('{') {
            end = skip_balanced_perl_braces(source, end);
            continue;
        }
        return end;
    }
}

/// Walk forward from `open` (which must point at `{`) to its matching
/// `}` and return the byte index just past the close brace. Tolerates
/// nested braces and skips over quoted strings.
fn skip_balanced_perl_braces(source: &str, open: usize) -> usize {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut cursor = open;
    while cursor < source.len() {
        let ch = source[cursor..].chars().next().expect("valid char boundary");
        cursor += ch.len_utf8();
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
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return cursor;
                }
            }
            _ => {}
        }
    }
    source.len()
}

/// Replace `my ($a, $b) = @_;` style list-context destructures with
/// one explicit Assign per bound variable so taint sees each parameter
/// individually, and report the bound names back as the inferred
/// parameter list.
///
/// Returns `None` when no list binding is found (callers fall back to
/// `infer_perl_params_from_body`).
fn rewrite_perl_list_param_bindings(events: &mut Vec<FlowEvent>, source: &str) -> Option<Vec<String>> {
    let mut rewritten = Vec::with_capacity(events.len());
    let mut inferred_params = None;
    let mut event_idx = 0;
    while event_idx < events.len() {
        let Some((span, vars)) = perl_list_binding_at(&events[event_idx], source) else {
            rewritten.push(events[event_idx].clone());
            event_idx += 1;
            continue;
        };
        // First binding wins — that's the canonical positional list.
        if inferred_params.is_none() {
            inferred_params = Some(vars.clone());
        }
        // Skip any subsequent same-span Assigns the extractor emitted
        // for this binding.
        while event_idx < events.len() {
            match &events[event_idx] {
                FlowEvent::Assign { span: next_span, .. } if *next_span == span => event_idx += 1,
                _ => break,
            }
        }
        // Replace the original Assigns with one Assign per variable
        // so each parameter has its own taint seed.
        for var in vars {
            let bare = var.trim_start_matches(['$', '@', '%']).to_string();
            rewritten.push(FlowEvent::Assign {
                span,
                target: var.clone(),
                source_name: None,
                source_call: None,
                source_call_args: Vec::new(),
                source_names: vec![var, bare],
            });
        }
    }
    *events = rewritten;
    inferred_params
}

/// If `event` is a `my (...) = @_;` destructure, return the span and
/// the list of bound variable names (with sigils preserved).
fn perl_list_binding_at(event: &FlowEvent, source: &str) -> Option<(bonsai_common::Span, Vec<String>)> {
    let FlowEvent::Assign {
        span, source_names, ..
    } = event
    else {
        return None;
    };
    // The extractor surfaces `_` / `@_` in source_names whenever the
    // RHS references the implicit args array.
    if !source_names.iter().any(|name| name == "_" || name == "@_") {
        return None;
    }
    let vars = source
        .get(span.start as usize..span.end as usize)
        .and_then(|text| {
            // Must be a list-context binding against `@_`.
            if !text.contains("@_") {
                return None;
            }
            let start = text.find('(')?;
            let end = text[start + 1..].find(')')? + start + 1;
            let vars = text[start + 1..end]
                .split(',')
                .map(str::trim)
                .filter(|part| part.starts_with(['$', '@', '%']))
                .map(str::to_string)
                .collect::<Vec<_>>();
            if vars.is_empty() {
                None
            } else {
                Some(vars)
            }
        })
        .unwrap_or_else(|| {
            // Fallback for shapes where the source slice is missing —
            // synthesize from `source_names`, normalizing to `$name`
            // and reversing because `source_names` is right-to-left
            // in stack order.
            let mut vars = source_names
                .iter()
                .filter(|name| name.as_str() != "_" && name.as_str() != "@_")
                .map(|name| {
                    if name.starts_with('$') {
                        name.clone()
                    } else {
                        format!("${name}")
                    }
                })
                .collect::<Vec<_>>();
            vars.reverse();
            vars
        });
    if vars.is_empty() {
        None
    } else {
        Some((*span, vars))
    }
}

/// Walk the leading flow events of a Perl sub looking for the
/// canonical positional-arg binding patterns:
///
///   my ($a, $b) = @_;   — list-context destructure
///   my $a = shift;      — sequential shift
///   my $a = `$_[0]`;    — explicit positional index
///
/// Returns the parameter names (with `$` sigil preserved) in the
/// order they bind, so G5 entry-point seeding and the taint seed
/// match how Perl code actually declares its params.
fn infer_perl_params_from_body(events: &[FlowEvent]) -> Vec<String> {
    let mut params: Vec<String> = Vec::new();
    for event in events {
        let FlowEvent::Assign {
            target,
            source_name,
            source_names,
            ..
        } = event
        else {
            // Only look at the contiguous prefix of Assigns — any
            // non-Assign event marks the end of the parameter-
            // binding prologue (call/branch/loop/try/return/throw,
            // plus yield/await/defer/using/break/continue all imply
            // the prologue is over).
            break;
        };
        // Shape 1: `my $a = shift` — target is a sigil'd var, RHS
        // references `shift` or `@_`.
        let rhs_mentions_args = source_name
            .as_deref()
            .is_some_and(|s| s == "shift" || s == "@_" || s.starts_with("$_["))
            || source_names
                .iter()
                .any(|n| n == "shift" || n == "@_" || n == "_" || n.starts_with("_["));
        if !target.is_empty()
            && rhs_mentions_args
            && target.starts_with('$')
            && !params.iter().any(|p| p == target)
        {
            params.push(target.clone());
        }
    }
    params
}

/// Synthesize `Ref` records for Perl's implicit taint sources
/// (`@ARGV`, `%ENV`, `STDIN`). The grammar doesn't expose a dedicated
/// node for these, so a textual scan is the simplest reliable
/// surface.
fn synthesize_perl_source_refs(src: &[u8], file: FileId) -> Vec<Ref> {
    let source = std::str::from_utf8(src).unwrap_or("");
    let mut refs = Vec::new();
    // (literal-to-find, canonical-name) pairs — the canonical name
    // is what taint rules query against.
    for (needle, name) in [
        ("$ARGV", "ARGV"),
        ("@ARGV", "ARGV"),
        ("$ENV", "ENV"),
        ("%ENV", "ENV"),
        ("STDIN", "STDIN"),
    ] {
        for (start, _) in source.match_indices(needle) {
            refs.push(Ref {
                span: Span::new(
                    file,
                    u64::try_from(start).unwrap_or(u64::MAX),
                    u64::try_from(start + needle.len()).unwrap_or(u64::MAX),
                ),
                name: name.to_string(),
                kind: RefKind::Read,
                scope: None,
                resolved: None,
            });
        }
    }
    refs
}

/// Parse Perl `use Foo;` and `require Foo;` statements into
/// `ImportSpec` records.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Perl `use_statement` is a dedicated grammar node:
    //   `use Foo;`              → module: package "Foo"
    //   `use Foo qw(a b);`      → module + quoted_word_list (export list)
    //   `use Foo ();`           → module + stub_expression (no exports)
    //   `use parent 'Bar';`     → module: parent + bareword string
    // Per-symbol import lists (qw(a b)) aren't represented in ImportSpec;
    // they're captured implicitly by the fact that the module is in scope.
    for use_node in collect_kinds(tree, &["use_statement"]) {
        let Some(module_node) = use_node.child_by_field_name("module") else {
            continue;
        };
        let module = node_text(&module_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &use_node),
            module,
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    // `require Some::Module;` is a dedicated `require_expression` wrapping
    // a `bareword`. Different from PHP's require — no string literal,
    // just a module name.
    for require_node in collect_kinds(tree, &["require_expression"]) {
        let mut cursor = require_node.walk();
        let Some(first_child) = require_node.named_children(&mut cursor).next() else {
            continue;
        };
        // Accept either bareword module names or string literals
        // (`require 'module.pl'` is a runtime path-load form).
        let module = match first_child.kind() {
            "bareword" => node_text(&first_child, src).to_string(),
            "string" | "string_literal" => node_text(&first_child, src)
                .trim_matches(|ch: char| matches!(ch, '"' | '\''))
                .to_string(),
            _ => continue,
        };
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &require_node),
            module,
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Walk the parse tree for `command_string` nodes (the tree-sitter
/// shape covering both `qx//` quote-like operators and backtick
/// `` `cmd` ``) and synthesize a `FlowEvent::Call` for each one.
/// The synthesized call is named `qx` so the shipped
/// `perl.cmdi.qx_backticks` rule (callee.name: qx) matches.
///
/// Each interpolated scalar variable inside the command string
/// becomes a `CallArg` whose `value_text` is the variable text
/// (`$tainted`). Plain literal command strings (no interpolation)
/// also surface as a Call but with an empty arg list — the rule
/// still matches at the call kind, but the taint engine has
/// nothing to flow into so the finding is correctly silent.
fn synthesize_qx_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for command_node in collect_kinds(tree, &["command_string"]) {
        let span = span_of(file, &command_node);
        let mut args: Vec<CallArg> = Vec::new();
        // The interpolated parts live under the `content` /
        // `string_content` child as `scalar` nodes. Walk
        // descendants so sigils inside nested expressions surface.
        let mut cursor = command_node.walk();
        let mut stack: Vec<tree_sitter::Node<'_>> = Vec::new();
        for child in command_node.named_children(&mut cursor) {
            stack.push(child);
        }
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "scalar" | "array" | "hash") {
                let text = node_text(&node, src).to_string();
                if !text.is_empty() {
                    args.push(CallArg {
                        span: span_of(file, &node),
                        name: None,
                        value_text: text.clone(),
                        place: None,
                        source_names: Vec::new(),
                    });
                }
            }
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                stack.push(child);
            }
        }
        let event = FlowEvent::Call {
            span,
            name: "qx".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args,
        };
        events.push((span, event));
    }
    events
}

/// Synthesize Call events for `$obj->method(args)` invocations.
/// tree-sitter-perl exposes them as `method_call_expression` rather
/// than `call_expression`, so the generic call extraction misses
/// them.
fn synthesize_method_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(tree, &["method_call_expression"]) {
        let Some(invocant) = call_node.child_by_field_name("invocant") else {
            continue;
        };
        let Some(method) = call_node.child_by_field_name("method") else {
            continue;
        };
        // Strip the sigil so the receiver is a plain identifier.
        let receiver = node_text(&invocant, src)
            .trim()
            .trim_start_matches(['$', '@', '%']);
        let method_name = node_text(&method, src).trim();
        if receiver.is_empty() || method_name.is_empty() {
            continue;
        }
        let args = call_node
            .child_by_field_name("arguments")
            .map(|arguments| perl_list_args(&arguments, src, file))
            .unwrap_or_default();
        let span = span_of(file, &call_node);
        events.push((
            span,
            FlowEvent::Call {
                span,
                name: format!("{receiver}->{method_name}"),
                receiver: Some(receiver.to_string()),
                receiver_types: Vec::new(),
                // Perl convention: `Class->new` is the constructor.
                call_kind: if method_name == "new" {
                    CallKind::Constructor
                } else {
                    CallKind::Method
                },
                args,
            },
        ));
    }
    events
}

/// Convert a Perl argument-list node into `CallArg`s. Recognises
/// `key => value` fat-comma pairs as named args; everything else
/// becomes a positional arg.
fn perl_list_args(node: &tree_sitter::Node<'_>, src: &[u8], file: FileId) -> Vec<CallArg> {
    // Single-value forms (`$x`, `'lit'`, `42`) wrap the argument
    // directly — emit a one-element CallArg list.
    if perl_node_is_single_arg(node.kind()) {
        let value_text = node_text(node, src).trim().to_string();
        if value_text.is_empty() {
            return Vec::new();
        }
        return vec![CallArg {
            span: span_of(file, node),
            name: None,
            value_text,
            place: None,
            source_names: Vec::new(),
        }];
    }

    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    let mut args = Vec::new();
    let mut child_idx = 0;
    while child_idx < children.len() {
        let child = children[child_idx];
        // Detect fat-comma named args: `key => value` pairs.
        if matches!(child.kind(), "bareword" | "autoquoted_bareword") && child_idx + 1 < children.len() {
            let next = children[child_idx + 1];
            // Look at the bytes between the two children to spot the
            // `=>` operator the grammar leaves anonymous.
            let gap = std::str::from_utf8(&src[child.end_byte()..next.start_byte()]).unwrap_or("");
            if gap.contains("=>") {
                let text = std::str::from_utf8(&src[child.start_byte()..next.end_byte()])
                    .unwrap_or("")
                    .trim()
                    .to_string();
                args.push(CallArg {
                    span: Span::new(
                        file,
                        u64::try_from(child.start_byte()).unwrap_or(u64::MAX),
                        u64::try_from(next.end_byte()).unwrap_or(u64::MAX),
                    ),
                    name: Some(node_text(&child, src).trim().to_string()),
                    value_text: text,
                    place: None,
                    source_names: Vec::new(),
                });
                child_idx += 2;
                continue;
            }
        }
        let value_text = node_text(&child, src).trim().to_string();
        if !value_text.is_empty() {
            args.push(CallArg {
                span: span_of(file, &child),
                name: None,
                value_text,
                place: None,
                source_names: Vec::new(),
            });
        }
        child_idx += 1;
    }
    args
}

/// True if `kind` represents a single-value expression node — used to
/// decide whether an argument list wraps one value or many.
fn perl_node_is_single_arg(kind: &str) -> bool {
    matches!(
        kind,
        "scalar"
            | "array"
            | "hash"
            | "number"
            | "integer"
            | "float"
            | "string"
            | "string_literal"
            | "command_string"
            | "bareword"
            | "autoquoted_bareword"
    )
}

/// Synthesize Call events for `rand` / `stat` builtins parsed by
/// tree-sitter-perl as `func1op_call_expression`. The shipped rules
/// expect them as named function calls.
fn synthesize_builtin_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(tree, &["func1op_call_expression"]) {
        let text = node_text(&call_node, src).trim();
        // Only handle the small set of builtins the rulepack queries.
        // Match `name`, `name(...)`, or `name <ws>...` shapes.
        // Builtins surfaced as named Call events. `close` / `read` /
        // `unlink` feed the lifecycle injector; `rand` / `stat` feed
        // the rulepack.
        let Some(name) = ["rand", "stat", "close", "read", "unlink"]
            .into_iter()
            .find(|name| {
                text == *name
                    || text.strip_prefix(*name).is_some_and(|rest| {
                        rest.starts_with('(') || rest.chars().next().is_some_and(char::is_whitespace)
                    })
            })
        else {
            continue;
        };
        let mut args = Vec::new();
        let mut cursor = call_node.walk();
        let mut stack: Vec<tree_sitter::Node<'_>> = call_node.named_children(&mut cursor).collect();
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "scalar" | "array" | "hash") {
                let value_text = node_text(&node, src).trim().to_string();
                if !value_text.is_empty() {
                    args.push(CallArg {
                        span: span_of(file, &node),
                        name: None,
                        value_text,
                        place: None,
                        source_names: Vec::new(),
                    });
                }
            }
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                stack.push(child);
            }
        }
        events.push((
            span_of(file, &call_node),
            FlowEvent::Call {
                span: span_of(file, &call_node),
                name: name.to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args,
            },
        ));
    }
    events
}

/// Synthesize Call events for `system "cmd $arg"` / `eval "code"`
/// where the argument is a binary string-concatenation expression.
/// The grammar wraps these as `function_call_expression`s but the
/// arguments don't surface through the generic call extraction.
fn synthesize_builtin_expression_arg_call_events(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for call_node in collect_kinds(tree, &["function_call_expression"]) {
        let Some(function_node) = call_node.child_by_field_name("function") else {
            continue;
        };
        let name = node_text(&function_node, src).trim();
        // Only `system` and `eval` are interesting here — others
        // already lower correctly through the generic extraction.
        if !matches!(name, "system" | "eval") {
            continue;
        }
        let Some(arguments) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        // Restrict to string-concat expressions; literal-only calls
        // already have no taint surface.
        if arguments.kind() != "binary_expression" {
            continue;
        }
        let value_text = node_text(&arguments, src).trim().to_string();
        if value_text.is_empty() {
            continue;
        }
        let span = span_of(file, &call_node);
        events.push((
            span,
            FlowEvent::Call {
                span,
                name: name.to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: vec![CallArg {
                    span: span_of(file, &arguments),
                    name: None,
                    value_text,
                    place: None,
                    source_names: Vec::new(),
                }],
            },
        ));
    }
    events
}

/// Synthesize a Call event named `m` for each `match_regexp` node so
/// regex-based rules can match on the pattern text.
fn synthesize_match_regex_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for match_node in collect_kinds(tree, &["match_regexp"]) {
        let Some(content) = match_node.child_by_field_name("content") else {
            continue;
        };
        let value_text = node_text(&content, src).trim().to_string();
        let span = span_of(file, &match_node);
        events.push((
            span,
            FlowEvent::Call {
                span,
                name: "m".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: vec![CallArg {
                    span: span_of(file, &content),
                    name: None,
                    value_text,
                    place: None,
                    source_names: Vec::new(),
                }],
            },
        ));
    }
    events
}

/// Detect coderef invocations (`$cb->(...)` / `&$cb(...)`) by textual
/// search and emit a Call event so taint sees them as call sites. The
/// grammar's `method_call_expression` shape doesn't fire for
/// arrow-with-parens-only forms.
fn synthesize_coderef_invocation_events(src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    let mut search_idx = 0usize;
    while search_idx + 3 <= src.len() {
        let Some(relative_arrow) = find_bytes(&src[search_idx..], b"->(") else {
            break;
        };
        let arrow_idx = search_idx + relative_arrow;
        let Some((name_start, name_end)) = perl_coderef_name_before_arrow(src, arrow_idx) else {
            // No identifier before the arrow — skip past it.
            search_idx = arrow_idx + 2;
            continue;
        };
        let Some(close) = find_matching_perl_paren(src, arrow_idx + 2) else {
            // Unbalanced parens — skip and keep scanning.
            search_idx = arrow_idx + 2;
            continue;
        };
        let name = String::from_utf8_lossy(&src[name_start..name_end])
            .trim()
            .to_string();
        if name.is_empty() {
            search_idx = close + 1;
            continue;
        }
        let call_end = close + 1;
        let span = Span::new(
            file,
            u64::try_from(name_start).unwrap_or(u64::MAX),
            u64::try_from(call_end).unwrap_or(u64::MAX),
        );
        events.push((
            span,
            FlowEvent::Call {
                span,
                name,
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: perl_text_args(src, arrow_idx + 3, close, file),
            },
        ));
        search_idx = call_end;
    }
    events
}

/// Naive byte-window search for `needle` inside `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Locate the identifier (with optional sigil) immediately preceding
/// `arrow` in `src`. Used to find the coderef name in `$cb->(...)`.
fn perl_coderef_name_before_arrow(src: &[u8], arrow: usize) -> Option<(usize, usize)> {
    let mut end = arrow;
    while end > 0 && src[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 {
        let byte = src[start - 1];
        if byte == b'_' || byte.is_ascii_alphanumeric() {
            start -= 1;
        } else {
            break;
        }
    }
    // No identifier before arrow — bail.
    if start == end {
        return None;
    }
    // Include the sigil if it directly precedes the name.
    if start > 0 && matches!(src[start - 1], b'$' | b'@' | b'%') {
        start -= 1;
    }
    Some((start, end))
}

/// Find the byte index of the `)` that matches `(` at `open`, or
/// `None` if unbalanced. Skips quoted segments.
fn find_matching_perl_paren(src: &[u8], open: usize) -> Option<usize> {
    if src.get(open).copied() != Some(b'(') {
        return None;
    }
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for (idx, &byte) in src.iter().enumerate().skip(open) {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == open_quote {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'(' => depth += 1,
            b')' => {
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

/// Split the byte range `start..end` of `src` on top-level commas
/// into `CallArg`s, trimming whitespace and skipping empty pieces.
fn perl_text_args(src: &[u8], start: usize, end: usize, file: FileId) -> Vec<CallArg> {
    if start >= end || end > src.len() {
        return Vec::new();
    }
    let mut args = Vec::new();
    let mut arg_start = start;
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for idx in start..=end {
        // Treat the end as a virtual comma so the final arg is flushed.
        let byte = if idx == end { b',' } else { src[idx] };
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == open_quote {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                let mut part_start = arg_start;
                let mut part_end = idx;
                // Trim leading/trailing whitespace from the piece.
                while part_start < part_end && src[part_start].is_ascii_whitespace() {
                    part_start += 1;
                }
                while part_end > part_start && src[part_end - 1].is_ascii_whitespace() {
                    part_end -= 1;
                }
                if part_start < part_end {
                    let value_text = String::from_utf8_lossy(&src[part_start..part_end]).to_string();
                    args.push(CallArg {
                        span: Span::new(
                            file,
                            u64::try_from(part_start).unwrap_or(u64::MAX),
                            u64::try_from(part_end).unwrap_or(u64::MAX),
                        ),
                        name: None,
                        // Sigil'd args double as `place`s for taint.
                        place: value_text
                            .starts_with(['$', '@', '%'])
                            .then(|| value_text.clone()),
                        value_text,
                        source_names: Vec::new(),
                    });
                }
                arg_start = idx + 1;
            }
            _ => {}
        }
    }
    args
}

/// Attach each synthesized (span, event) pair to the decl whose
/// body contains it. Pick the SMALLEST containing decl — Perl
/// supports nested `sub { ... }` blocks inside an outer sub, so
/// picking the first match would silently route synthetic events
/// (qx// shell-out etc.) to the outer sub. If no enclosing decl
/// exists (top-level qx// in a script body), the event is dropped
/// — the rulepack's qx rule already requires a sub context for
/// the finding to chain to a source. Linear walk over decls — Perl
/// files rarely have more than a handful of subs, so
/// O(events × decls) is fine.
fn attach_synthesized_calls_to_decls(idx: &mut DeclIndex, events: Vec<(Span, FlowEvent)>) {
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

/// True for decl kinds that represent Perl-style class-like
/// constructs — used to gate which decls receive `bases` entries.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk every Perl `use_statement` whose module is `base` /
/// `parent` / `mro` and collect the string-literal arguments as
/// parent class names. Each `use base 'Foo::Bar';` adds `Bar` (the
/// right-most `::` segment of the literal). Multiple parents are
/// supported via `use base ('A', 'B');` or `use base qw(A B);`.
///
/// The collected bases are keyed by the smallest-containing class
/// decl span — for files with a single `package` and a few `use base`
/// lines that's the package decl, but a single `.pm` file can
/// declare multiple packages so we attach to the smallest match.
fn collect_perl_class_bases(
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
    idx: &DeclIndex,
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    use std::collections::HashMap;
    // Parse `use base/parent/mro 'X';` statements anywhere in the file.
    let mut bases_by_decl: HashMap<bonsai_common::Span, Vec<String>> = HashMap::new();
    for use_node in collect_kinds(tree, &["use_statement"]) {
        let Some(module_node) = use_node.child_by_field_name("module") else {
            continue;
        };
        let module = node_text(&module_node, src).trim();
        // Only the inheritance pragmas register parents.
        if !matches!(module, "base" | "parent" | "mro" | "parent::versioned") {
            continue;
        }
        // The use-statement's args follow the module name: walk all
        // descendant `string_content` nodes (covers single and double
        // quoted literals plus `qw(...)` words).
        let mut bases: Vec<String> = Vec::new();
        let mut stack: Vec<tree_sitter::Node<'_>> = vec![use_node];
        while let Some(node) = stack.pop() {
            // Skip the module-name node itself — we only want args.
            if node.id() == module_node.id() {
                continue;
            }
            match node.kind() {
                "string_content" | "bareword" | "interpolation_string_content" => {
                    let raw = node_text(&node, src).trim();
                    // `qw(A B C)` content is a single text node;
                    // split on whitespace to get each parent name.
                    for piece in raw.split_whitespace() {
                        if let Some(name) = canonical_perl_base_name(piece) {
                            if !bases.iter().any(|existing| existing == &name) {
                                bases.push(name);
                            }
                        }
                    }
                }
                _ => {
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        stack.push(child);
                    }
                }
            }
        }
        if bases.is_empty() {
            continue;
        }
        // Find the smallest class-decl span that contains this
        // use_statement; attach the bases there.
        let use_span = span_of(file, &use_node);
        let mut best_decl: Option<(usize, u64)> = None;
        for (decl_idx, decl) in idx.defs.iter().enumerate() {
            if !is_class_like(decl.kind) {
                continue;
            }
            let body = decl.body_span.unwrap_or(decl.span);
            if use_span.file == body.file && use_span.start >= body.start && use_span.end <= body.end {
                let body_len = body.end.saturating_sub(body.start);
                if best_decl.is_none_or(|(_, prev_len)| body_len < prev_len) {
                    best_decl = Some((decl_idx, body_len));
                }
            }
        }
        if let Some((decl_idx, _)) = best_decl {
            let entry = bases_by_decl.entry(idx.defs[decl_idx].span).or_default();
            for name in bases {
                if !entry.iter().any(|existing| existing == &name) {
                    entry.push(name);
                }
            }
        }
    }
    bases_by_decl.into_iter().collect()
}

/// Strip Perl namespace separators (`::`) from a base name, returning
/// just the rightmost segment. Rejects flag-style arguments (e.g.
/// `-norequire`) and empty inputs.
fn canonical_perl_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches(|ch: char| matches!(ch, '\'' | '"'));
    if trimmed.is_empty() {
        return None;
    }
    // Skip `-norequire` / `-no_isa` style flags occasionally passed
    // before module names.
    if trimmed.starts_with('-') {
        return None;
    }
    let bare = trimmed.rsplit("::").next().unwrap_or(trimmed).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}
