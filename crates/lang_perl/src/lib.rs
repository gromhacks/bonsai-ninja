//! Perl language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, foreach_binding_assigns_from_text, language_from_pack, node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, CallArg, CallKind, DeclIndex, DeclKind, FieldWrite, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    ModulePath, Ref, RefKind, TypeAliasBinding,
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
    constructor_names: &["new"],
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
        LanguageCapabilities {
            constructor_method_names: &["new"],
            // Perl uses `SUPER::` (case-sensitive) for super-class
            // dispatch, but the syntactic receiver token preceding
            // `::method` is `SUPER`.
            super_receiver_tokens: &["SUPER"],
            implicit_receiver_tokens: &["$self"],
            ..LanguageCapabilities::partial_baseline()
        }
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
                        calls.extend(synthesize_map_grep_topic_call_events(
                            &tree,
                            source.as_bytes(),
                            file,
                        ));
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
            normalize_perl_simple_scalar_renames(&mut decl.flow_events, &source);
            augment_perl_collection_flow_events(&mut decl.flow_events, &source);
            inject_perl_coderef_aliases(&mut decl.flow_events, &source);
            normalize_perl_eval_exception_flow_events(&mut decl.flow_events, &source);
            // L1: lower `die` to Throw across the WHOLE sub body, not
            // just inside an `eval {}; if ($@)` region. This seeds a
            // native `try { die $x; } catch ($e) { ... }` body (the
            // kit builds the Try + catch_param; we make the die a
            // Throw inside it) and models cross-procedural propagation
            // of an uncaught top-level `die`. The lowering is
            // idempotent: a `die` Call left in place by the eval
            // normalization (which already emitted its Throw) is
            // recognised by the Throw that immediately precedes it and
            // is NOT lowered a second time.
            let body = std::mem::take(&mut decl.flow_events);
            decl.flow_events = lower_perl_die_calls_to_throws(body);
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
        for decl in &mut idx.defs {
            mark_perl_method_receiver_param(decl);
            enrich_perl_bless_receiver_field_writes(decl, &source);
            let mut aliases = collect_perl_bless_type_aliases(&decl.flow_events);
            dedup_perl_type_aliases(&mut aliases);
            for alias in aliases {
                if !decl.type_aliases.contains(&alias) {
                    decl.type_aliases.push(alias);
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
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, PERL_LIFECYCLE_TRANSITIONS);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`new Foo()` / `Foo()` / `Foo::new()` -> typed receiver) so `recv.method(...)` resolves
        // `receiver_type_in` / `[Type, method]` rules; the constructor heuristic only
        // types PascalCase callees, so language exported-function calls are unaffected.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

fn enrich_perl_bless_receiver_field_writes(decl: &mut bonsai_lang_api::Decl, source: &str) {
    if decl.name != "new" || decl.params.len() < 2 {
        return;
    }
    let Some(text) = source.get(decl.span.start as usize..decl.span.end as usize) else {
        return;
    };
    let Some(receiver) = decl.params.first().cloned() else {
        return;
    };
    let mut writes = Vec::new();
    for hash_body in perl_bless_hash_bodies(text) {
        for field_init in split_perl_top_level(hash_body, ',') {
            let Some((field, value)) = field_init.split_once("=>") else {
                continue;
            };
            let field = perl_hash_key_name(field);
            if field.is_empty() {
                continue;
            }
            let value = value.trim();
            let Some(source_idx) = decl
                .params
                .iter()
                .position(|param| perl_param_matches_value(param, value))
            else {
                continue;
            };
            writes.push(FieldWrite {
                span: decl.span,
                target: format!("{receiver}.{field}"),
                source_param_indices: vec![source_idx],
            });
        }
    }
    if writes.is_empty() {
        return;
    }
    decl.receiver_field_writes.extend(writes);
    decl.receiver_field_writes
        .sort_by_key(|write| (write.span.start, write.target.clone()));
    decl.receiver_field_writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
}

fn perl_bless_hash_bodies(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find("bless") {
        rest = &rest[pos + "bless".len()..];
        let Some(open) = rest.find('{') else {
            continue;
        };
        let after_open = &rest[open + 1..];
        let Some(close) = find_matching_perl_brace(after_open) else {
            continue;
        };
        out.push(&after_open[..close]);
        rest = &after_open[close + 1..];
    }
    out
}

fn find_matching_perl_brace(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(quote_ch) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote_ch {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '{' => depth += 1,
            '}' if depth == 0 => return Some(idx),
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn split_perl_top_level(text: &str, delimiter: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(quote_ch) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote_ch {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth = depth.saturating_sub(1),
            _ if ch == delimiter && depth == 0 => {
                out.push(text[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    out.push(text[start..].trim());
    out
}

fn perl_hash_key_name(raw: &str) -> String {
    raw.trim()
        .trim_matches(|ch| matches!(ch, '\'' | '"' | '$' | '{' | '}' | ' '))
        .to_string()
}

fn perl_param_matches_value(param: &str, value: &str) -> bool {
    let param = param.trim();
    let value = value.trim();
    if value == param {
        return true;
    }
    let param_bare = param.trim_start_matches('$');
    let value_bare = value.trim_start_matches('$');
    !param_bare.is_empty() && param_bare == value_bare
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

fn mark_perl_method_receiver_param(decl: &mut bonsai_lang_api::Decl) {
    if decl.receiver_param_index.is_some() {
        return;
    }
    let Some(first_param) = decl.params.first().map(String::as_str) else {
        return;
    };
    // Perl method dispatch passes the invocant as the first @_ item.
    // The conventional bindings are `$self` for instance methods and
    // `$class` for class methods; mark only those explicit shapes so
    // ordinary package functions keep positional argument binding.
    if matches!(first_param, "$self" | "self" | "$class" | "class") {
        decl.receiver_param_index = Some(0);
    }
}

fn collect_perl_bless_type_aliases(events: &[FlowEvent]) -> Vec<TypeAliasBinding> {
    let mut out = Vec::new();
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_call: Some(source_call),
                source_call_args,
                ..
            } if source_call == "bless" => {
                if let Some(type_name) = source_call_args
                    .get(1)
                    .and_then(|arg| canonical_perl_base_name(arg))
                {
                    push_perl_type_alias(&mut out, target, &type_name);
                    let sigiled = format!("${target}");
                    push_perl_type_alias(&mut out, &sigiled, &type_name);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                out.extend(collect_perl_bless_type_aliases(then_events));
                out.extend(collect_perl_bless_type_aliases(else_events));
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                out.extend(collect_perl_bless_type_aliases(body));
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                out.extend(collect_perl_bless_type_aliases(body));
                out.extend(collect_perl_bless_type_aliases(catch_events));
                out.extend(collect_perl_bless_type_aliases(finally_events));
            }
            _ => {}
        }
    }
    out
}

fn push_perl_type_alias(out: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    let name = name.trim();
    let type_name = type_name.trim();
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    out.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

fn dedup_perl_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
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
        let foreach_assignments = perl_foreach_binding_assignments(&event, source);
        let push_assignment = perl_push_assignment(&event);
        rewritten.extend(foreach_assignments);
        rewritten.push(event);
        if let Some(assign) = push_assignment {
            rewritten.push(assign);
        }
    }
    *events = rewritten;
}

fn perl_foreach_binding_assignments(event: &FlowEvent, source: &str) -> Vec<FlowEvent> {
    let FlowEvent::Loop { span, .. } = event else {
        return Vec::new();
    };
    let Some(text) = source_span_text(source, *span) else {
        return Vec::new();
    };
    foreach_binding_assigns_from_text(*span, text)
}

/// Add exact callable-alias facts for Perl coderef assignments such
/// as `my $cb = \&helper;`.
///
/// The generic assignment walker sees the same statement, but the
/// declaration wrapper can add unrelated operands to `source_names`.
/// A clean synthetic alias keeps callback resolution semantic: it is
/// emitted only when the RHS is Perl's explicit subroutine-reference
/// syntax and the LHS contains one scalar binding.
fn inject_perl_coderef_aliases(events: &mut Vec<FlowEvent>, source: &str) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_perl_coderef_aliases(then_events, source);
                inject_perl_coderef_aliases(else_events, source);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_perl_coderef_aliases(body, source);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_perl_coderef_aliases(body, source);
                inject_perl_coderef_aliases(catch_events, source);
                inject_perl_coderef_aliases(finally_events, source);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let alias = perl_coderef_alias_assignment(&event, source);
        rewritten.push(event);
        if let Some(alias) = alias {
            rewritten.push(alias);
        }
    }
    *events = rewritten;
}

fn perl_coderef_alias_assignment(event: &FlowEvent, source: &str) -> Option<FlowEvent> {
    let FlowEvent::Assign { span, target, .. } = event else {
        return None;
    };
    let (lhs, rhs) = assignment_lhs_rhs_text(source, *span)?;
    let target = perl_coderef_lhs_target(&lhs)
        .or_else(|| target.trim().starts_with('$').then(|| target.trim().to_string()))?;
    let source_name = perl_coderef_rhs_source(&rhs)?;
    Some(FlowEvent::Assign {
        span: *span,
        target,
        source_name: Some(source_name),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    })
}

fn perl_coderef_lhs_target(lhs: &str) -> Option<String> {
    let vars = perl_sigiled_identifiers(lhs, ['$']);
    if vars.len() != 1 {
        return None;
    }
    vars.into_iter().next()
}

fn perl_coderef_rhs_source(rhs: &str) -> Option<String> {
    let trimmed = rhs.trim().trim_end_matches(';').trim();
    let rest = trimmed.strip_prefix("\\&")?.trim_start();
    let mut end = 0usize;
    for (idx, ch) in rest.char_indices() {
        if ch == '_' || ch == ':' || ch.is_ascii_alphanumeric() {
            end = idx + ch.len_utf8();
            continue;
        }
        break;
    }
    if end == 0 {
        return None;
    }
    let name = rest[..end].trim();
    if name.is_empty() {
        return None;
    }
    let suffix = rest[end..].trim();
    if !suffix.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// Lower Perl's exception idiom `eval { die ... }; if ($@) { ... }`
/// into a structural Try/Throw region. Tree-sitter-perl exposes the
/// eval block's body as ordinary calls and the `$@` handler as an
/// unrelated branch, so downstream taint cannot otherwise connect the
/// thrown value to the handler binding.
fn normalize_perl_eval_exception_flow_events(events: &mut Vec<FlowEvent>, source: &str) {
    let eval_blocks = perl_eval_block_ranges(source);
    if eval_blocks.is_empty() {
        return;
    }
    rewrite_perl_eval_exception_regions(events, source, &eval_blocks);
}

#[derive(Clone, Copy, Debug)]
struct PerlEvalBlockRange {
    start: usize,
    body_start: usize,
    body_end: usize,
}

fn perl_eval_block_ranges(source: &str) -> Vec<PerlEvalBlockRange> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut search = 0usize;
    while search + 4 <= bytes.len() {
        let Some(relative) = find_bytes(&bytes[search..], b"eval") else {
            break;
        };
        let start = search + relative;
        let after_eval = start + 4;
        if !perl_keyword_boundary(bytes, start, after_eval) {
            search = after_eval;
            continue;
        }
        let mut open = after_eval;
        while open < bytes.len() && bytes[open].is_ascii_whitespace() {
            open += 1;
        }
        if bytes.get(open).copied() != Some(b'{') {
            search = after_eval;
            continue;
        }
        let body_start = open + 1;
        let Some(close_relative) = find_matching_perl_brace(&source[body_start..]) else {
            search = after_eval;
            continue;
        };
        let body_end = body_start + close_relative;
        out.push(PerlEvalBlockRange {
            start,
            body_start,
            body_end,
        });
        search = body_end.saturating_add(1);
    }
    out
}

fn perl_keyword_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).and_then(|idx| bytes.get(idx)).copied();
    let after = bytes.get(end).copied();
    !before.is_some_and(perl_identifier_byte) && !after.is_some_and(perl_identifier_byte)
}

fn perl_identifier_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn rewrite_perl_eval_exception_regions(
    events: &mut Vec<FlowEvent>,
    source: &str,
    eval_blocks: &[PerlEvalBlockRange],
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_perl_eval_exception_regions(then_events, source, eval_blocks);
                rewrite_perl_eval_exception_regions(else_events, source, eval_blocks);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_perl_eval_exception_regions(body, source, eval_blocks);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_perl_eval_exception_regions(body, source, eval_blocks);
                rewrite_perl_eval_exception_regions(catch_events, source, eval_blocks);
                rewrite_perl_eval_exception_regions(finally_events, source, eval_blocks);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    let mut idx = 0usize;
    while idx < events.len() {
        let Some(block) = event_span(&events[idx])
            .and_then(|span| {
                eval_blocks
                    .iter()
                    .find(|block| span_inside_eval_body(span, **block))
            })
            .copied()
        else {
            rewritten.push(events[idx].clone());
            idx += 1;
            continue;
        };

        let mut body_end = idx;
        while body_end < events.len() {
            let Some(span) = event_span(&events[body_end]) else {
                break;
            };
            if !span_inside_eval_body(span, block) {
                break;
            }
            body_end += 1;
        }
        if body_end == idx || body_end >= events.len() {
            rewritten.extend(events[idx..body_end].iter().cloned());
            idx = body_end;
            continue;
        }

        let FlowEvent::Branch {
            span: branch_span,
            condition,
            then_events,
            ..
        } = &events[body_end]
        else {
            rewritten.extend(events[idx..body_end].iter().cloned());
            idx = body_end;
            continue;
        };
        if !perl_condition_is_dollar_at(condition.as_deref()) {
            rewritten.extend(events[idx..body_end].iter().cloned());
            idx = body_end;
            continue;
        }

        let mut body = events[idx..body_end].to_vec();
        body = lower_perl_die_calls_to_throws(body);
        let (catch_param, catch_events) = perl_dollar_at_catch_events(then_events, source);
        let file = branch_span.file;
        let try_span = Span::new(
            file,
            u64::try_from(block.start).unwrap_or(branch_span.start),
            branch_span.end,
        );
        rewritten.push(FlowEvent::Try {
            span: try_span,
            body,
            catch_events,
            finally_events: Vec::new(),
            catch_param,
            catch_types: Vec::new(),
        });
        idx = body_end + 1;
    }
    *events = rewritten;
}

fn event_span(event: &FlowEvent) -> Option<Span> {
    Some(event.span())
}

fn span_inside_eval_body(span: Span, block: PerlEvalBlockRange) -> bool {
    let Ok(start) = usize::try_from(span.start) else {
        return false;
    };
    let Ok(end) = usize::try_from(span.end) else {
        return false;
    };
    start >= block.body_start && end <= block.body_end
}

fn perl_condition_is_dollar_at(condition: Option<&str>) -> bool {
    condition
        .map(str::trim)
        .is_some_and(|condition| matches!(condition, "$@" | "($@)"))
}

fn lower_perl_die_calls_to_throws(events: Vec<FlowEvent>) -> Vec<FlowEvent> {
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                call_kind,
                args,
            } if name == "die" => {
                // Idempotency guard: if the event we just emitted is
                // already the Throw lowered from THIS die (same span
                // start, since `perl_die_throw_span` preserves the
                // call's start byte), this `die` Call is the residual
                // kept by a prior lowering pass. Re-lowering it would
                // emit a duplicate Throw, so pass it through unchanged.
                let already_lowered = matches!(
                    out.last(),
                    Some(FlowEvent::Throw { span: throw_span, .. })
                        if throw_span.start == span.start && throw_span.file == span.file
                );
                if already_lowered {
                    out.push(FlowEvent::Call {
                        span,
                        name,
                        receiver,
                        receiver_types,
                        call_kind,
                        args,
                    });
                } else {
                    out.push(FlowEvent::Throw {
                        span: perl_die_throw_span(span, &args),
                        value_name: perl_die_value_name(&args),
                        thrown_type: None,
                    });
                    out.push(FlowEvent::Call {
                        span,
                        name,
                        receiver,
                        receiver_types,
                        call_kind,
                        args,
                    });
                }
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => out.push(FlowEvent::Branch {
                span,
                condition,
                then_events: lower_perl_die_calls_to_throws(then_events),
                else_events: lower_perl_die_calls_to_throws(else_events),
            }),
            FlowEvent::Loop {
                span,
                loop_kind,
                body,
            } => out.push(FlowEvent::Loop {
                span,
                loop_kind,
                body: lower_perl_die_calls_to_throws(body),
            }),
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_types,
            } => out.push(FlowEvent::Try {
                span,
                body: lower_perl_die_calls_to_throws(body),
                catch_events: lower_perl_die_calls_to_throws(catch_events),
                finally_events: lower_perl_die_calls_to_throws(finally_events),
                catch_param,
                catch_types,
            }),
            FlowEvent::Defer { span, body } => out.push(FlowEvent::Defer {
                span,
                body: lower_perl_die_calls_to_throws(body),
            }),
            FlowEvent::Using { span, body } => out.push(FlowEvent::Using {
                span,
                body: lower_perl_die_calls_to_throws(body),
            }),
            other => out.push(other),
        }
    }
    out
}

fn perl_die_throw_span(span: Span, args: &[CallArg]) -> Span {
    let end = args
        .iter()
        .map(|arg| arg.span.end)
        .max()
        .unwrap_or(span.end)
        .max(span.end);
    Span::new(span.file, span.start, end)
}

fn perl_die_value_name(args: &[CallArg]) -> Option<String> {
    let arg = args.first()?;
    if let Some(place) = arg
        .place
        .as_deref()
        .map(str::trim)
        .filter(|place| !place.is_empty())
    {
        return Some(place.to_string());
    }
    if let Some(source) = arg
        .source_names
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .find(|source| !source.is_empty())
    {
        return Some(source.to_string());
    }
    let value = arg.value_text.trim();
    if perl_sigiled_identifiers(value, ['$', '@', '%'])
        .first()
        .is_some_and(|identifier| identifier == value)
    {
        return Some(value.to_string());
    }
    (!value.is_empty() && value.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()))
        .then(|| value.to_string())
}

fn perl_dollar_at_catch_events(events: &[FlowEvent], source: &str) -> (Option<String>, Vec<FlowEvent>) {
    let mut aliases = Vec::new();
    for event in events {
        if let FlowEvent::Assign { span, target, .. } = event {
            if perl_assignment_rhs_is_dollar_at(source, *span) {
                push_unique_string(&mut aliases, target.clone());
            }
        }
    }
    let catch_param = aliases
        .iter()
        .find(|alias| alias.starts_with('$'))
        .cloned()
        .or_else(|| aliases.first().cloned())
        .or_else(|| Some("$@".to_string()));

    let catch_events = events
        .iter()
        .filter(|event| {
            !matches!(
                event,
                FlowEvent::Assign { span, .. } if perl_assignment_rhs_is_dollar_at(source, *span)
            )
        })
        .cloned()
        .collect();
    (catch_param, catch_events)
}

fn perl_assignment_rhs_is_dollar_at(source: &str, span: Span) -> bool {
    assignment_rhs_text(source, span)
        .map(|rhs| rhs.trim().trim_end_matches(';').trim() == "$@")
        .unwrap_or(false)
}

/// Rewrite exact Perl scalar/array/hash renames (`my $y = $x`) from
/// generic compound-token assignments into `source_name` assignments.
/// This keeps true compound/deref RHSs (`$obj->{k}`, `$x . $y`,
/// function calls) on the broader `source_names` path while making the
/// simple rename case exact.
fn normalize_perl_simple_scalar_renames(events: &mut [FlowEvent], source: &str) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } => {
                if source_call.is_some() || !source_call_args.is_empty() {
                    continue;
                }
                if let Some(rhs) =
                    assignment_rhs_text(source, *span).and_then(|rhs| perl_exact_variable_rhs(&rhs))
                {
                    *source_name = Some(rhs);
                    source_names.clear();
                    *value_kind = None;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_perl_simple_scalar_renames(then_events, source);
                normalize_perl_simple_scalar_renames(else_events, source);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_perl_simple_scalar_renames(body, source);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_perl_simple_scalar_renames(body, source);
                normalize_perl_simple_scalar_renames(catch_events, source);
                normalize_perl_simple_scalar_renames(finally_events, source);
            }
            _ => {}
        }
    }
}

fn perl_exact_variable_rhs(rhs: &str) -> Option<String> {
    let rhs = rhs.trim().trim_end_matches(';').trim();
    if rhs == "@_" || rhs == "$@" {
        return None;
    }
    let vars = perl_sigiled_identifiers(rhs, ['$', '@', '%']);
    if vars.len() == 1 && vars[0] == rhs {
        return Some(vars[0].clone());
    }
    None
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
                for arg in &mut *args {
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
            declares_new_binding: false,
            value_kind: None,
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
        declares_new_binding: false,
        value_kind: None,
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

fn split_perl_assignment_text(text: &str) -> Option<(&str, &str)> {
    let (separator_idx, separator_len) = find_top_level_assignment_separator(text)?;
    Some((
        text[..separator_idx].trim(),
        text[separator_idx + separator_len..].trim(),
    ))
}

fn source_span_text(source: &str, span: Span) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?.min(source.len());
    let end = usize::try_from(span.end).ok()?.min(source.len());
    if start >= end || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return None;
    }
    source.get(start..end)
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
                for arg in &mut *args {
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
                combine_perl_fat_comma_call_args(args, source);
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

fn combine_perl_fat_comma_call_args(args: &mut Vec<CallArg>, source: &str) {
    if args.len() < 2 {
        return;
    }
    let mut combined = Vec::with_capacity(args.len());
    let mut idx = 0usize;
    while idx < args.len() {
        if idx + 1 < args.len() && perl_args_have_fat_comma_between(&args[idx], &args[idx + 1], source) {
            let key = args[idx].value_text.trim().to_string();
            let value = &args[idx + 1];
            let start = usize::try_from(args[idx].span.start).unwrap_or(usize::MAX);
            let end = usize::try_from(value.span.end).unwrap_or(usize::MAX);
            let value_text = if start != usize::MAX && end <= source.len() && start <= end {
                source[start..end].trim().to_string()
            } else {
                format!("{key} => {}", value.value_text.trim())
            };
            combined.push(CallArg {
                span: Span::new(args[idx].span.file, args[idx].span.start, value.span.end),
                name: (!key.is_empty()).then_some(key),
                value_text,
                place: value.place.clone(),
                source_names: value.source_names.clone(),
            });
            idx += 2;
        } else {
            combined.push(args[idx].clone());
            idx += 1;
        }
    }
    *args = combined;
}

fn perl_args_have_fat_comma_between(left: &CallArg, right: &CallArg, source: &str) -> bool {
    if left.span.file != right.span.file || left.span.end > right.span.start {
        return false;
    }
    let start = usize::try_from(left.span.end).unwrap_or(usize::MAX);
    let end = usize::try_from(right.span.start).unwrap_or(usize::MAX);
    if start == usize::MAX || end > source.len() || start > end {
        return false;
    }
    let key = left.value_text.trim();
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric() || ch == ':')
        && source[start..end].contains("=>")
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
                declares_new_binding: false,
                value_kind: None,
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
        .or_else(|| {
            source
                .get(span.start as usize..span.end as usize)
                .and_then(|text| {
                    if !text.contains("@_") {
                        return None;
                    }
                    let (lhs, rhs) = split_perl_assignment_text(text)?;
                    if !rhs.contains("@_") {
                        return None;
                    }
                    let vars = perl_sigiled_identifiers(lhs, ['$', '@', '%'])
                        .into_iter()
                        .filter(|var| var != "@_")
                        .collect::<Vec<_>>();
                    if vars.is_empty() {
                        None
                    } else {
                        Some(vars)
                    }
                })
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
    // Per-symbol import lists (`qw(a b)`) are resolver-local bindings:
    // `a()` should resolve to `Foo::a` without making every bare `a`
    // in the workspace eligible.
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
            module: module.clone(),
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if !is_perl_inheritance_pragma(&module) {
            for exported in perl_use_qw_imports(&use_node, src) {
                imports.push(ImportSpec {
                    span: span_of(file, &use_node),
                    module: module.clone(),
                    alias: None,
                    is_wildcard: false,
                    original_name: Some(exported),
                    scope: ImportScope::Local,
                });
            }
        }
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

fn perl_use_qw_imports(use_node: &tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = use_node.walk();
    for child in use_node.named_children(&mut cursor) {
        if child.kind() != "quoted_word_list" {
            continue;
        }
        collect_qw_words(child, src, &mut out);
    }
    out
}

fn is_perl_inheritance_pragma(module: &str) -> bool {
    matches!(module, "base" | "parent" | "mro" | "parent::versioned")
}

fn collect_qw_words(node: tree_sitter::Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if matches!(
        node.kind(),
        "string_content" | "bareword" | "interpolation_string_content"
    ) {
        for word in node_text(&node, src).split_whitespace() {
            let word = word.trim();
            if word.is_empty() || out.iter().any(|seen| seen == word) {
                continue;
            }
            out.push(word.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_qw_words(child, src, out);
    }
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

/// Perl's `map { ... } @items` / `grep { ... } @items` binds each
/// element to the implicit topic variable `$_` inside the callback
/// block. The generic walker sees calls inside the block (`step($_)`)
/// but does not have a scoped variable binding for `$_`. Instead of
/// globally tainting `$_`, synthesize a parallel callback call whose
/// topic argument is the mapped collection expression.
fn synthesize_map_grep_topic_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut events = Vec::new();
    for map_node in collect_kinds(tree, &["map_grep_expression"]) {
        let Some(callback) = map_node.child_by_field_name("callback") else {
            continue;
        };
        let Some(list) = map_node.child_by_field_name("list") else {
            continue;
        };
        let list_span = span_of(file, &list);
        let source_names = perl_collection_source_names(node_text(&list, src));
        let Some(primary_source) = source_names.first().cloned() else {
            continue;
        };
        for call_node in descendant_nodes_of_kind(callback, "function_call_expression") {
            let Some(function) = call_node.child_by_field_name("function") else {
                continue;
            };
            let name = node_text(&function, src).trim().to_string();
            if name.is_empty() {
                continue;
            }
            let Some(arguments) = call_node.child_by_field_name("arguments") else {
                continue;
            };
            let mut args = perl_list_args(&arguments, src, file);
            let mut rewrote_topic_arg = false;
            for arg in &mut args {
                if perl_arg_uses_topic_var(&arg.value_text) {
                    arg.span = list_span;
                    arg.value_text.clone_from(&primary_source);
                    arg.place = Some(primary_source.clone());
                    arg.source_names.clone_from(&source_names);
                    rewrote_topic_arg = true;
                }
            }
            if !rewrote_topic_arg {
                continue;
            }
            let span = span_of(file, &call_node);
            events.push((
                span,
                FlowEvent::Call {
                    span,
                    name,
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args,
                },
            ));
        }
    }
    events
}

fn descendant_nodes_of_kind<'tree>(
    root: tree_sitter::Node<'tree>,
    kind: &str,
) -> Vec<tree_sitter::Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node != root && node.kind() == kind {
            out.push(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    out
}

fn perl_collection_source_names(text: &str) -> Vec<String> {
    let mut source_names = Vec::new();
    for name in perl_sigiled_identifiers(text, ['$', '@', '%']) {
        push_unique_string(&mut source_names, name.clone());
        push_unique_string(
            &mut source_names,
            name.trim_start_matches(['$', '@', '%']).to_string(),
        );
    }
    source_names
}

fn perl_arg_uses_topic_var(text: &str) -> bool {
    text.split(|ch: char| !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()))
        .any(|part| matches!(part, "$_" | "_"))
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
            // L8: `method_call_expression` is in COMMON_CALL_KINDS, so
            // the kit already emitted a Call for `$obj->method(...)`
            // (carrying source_names + a receiver this synth lacks).
            // Drop the synth duplicate when the kit's Call for the
            // same node is already present: its name-span is CONTAINED
            // in this synth's whole-call-node span and it shares the
            // same name + receiver. We only drop when a real match is
            // found, so a node the kit somehow missed still keeps its
            // synth Call.
            if perl_synth_call_duplicates_kit_call(&idx.defs[decl_idx].flow_events, event_span, &event) {
                continue;
            }
            idx.defs[decl_idx].flow_events.push(event);
        }
    }
}

/// True when `event` is a synthesized `$obj->method(...)` Call that
/// the kit already emitted for the same node. The kit's Call uses the
/// `method`-identifier span (a name-span), which falls inside this
/// synth event's whole-`method_call_expression` span, and carries the
/// same `name`/`receiver`. Matching on overlap (CONTAINS) rather than
/// identical spans is required because the two spans deliberately
/// differ. Recurses into nested bodies since a kit Call inside an
/// `if`/`while`/`try` lands in a child event list.
fn perl_synth_call_duplicates_kit_call(existing: &[FlowEvent], synth_span: Span, event: &FlowEvent) -> bool {
    let FlowEvent::Call {
        name: synth_name,
        receiver: synth_receiver,
        call_kind,
        ..
    } = event
    else {
        return false;
    };
    // Only the method-call synth produces `receiver->method` names
    // with a Method/Constructor kind; qx/builtin synths are Functions.
    if !matches!(call_kind, CallKind::Method | CallKind::Constructor) || !synth_name.contains("->") {
        return false;
    }
    perl_flow_has_contained_call(existing, synth_span, synth_name, synth_receiver.as_deref())
}

fn perl_flow_has_contained_call(
    events: &[FlowEvent],
    synth_span: Span,
    synth_name: &str,
    synth_receiver: Option<&str>,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span, name, receiver, ..
            } => {
                let contained = span.file == synth_span.file
                    && span.start >= synth_span.start
                    && span.end <= synth_span.end;
                if contained && name == synth_name && receiver.as_deref() == synth_receiver {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if perl_flow_has_contained_call(then_events, synth_span, synth_name, synth_receiver)
                    || perl_flow_has_contained_call(else_events, synth_span, synth_name, synth_receiver)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if perl_flow_has_contained_call(body, synth_span, synth_name, synth_receiver) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if perl_flow_has_contained_call(body, synth_span, synth_name, synth_receiver)
                    || perl_flow_has_contained_call(catch_events, synth_span, synth_name, synth_receiver)
                    || perl_flow_has_contained_call(finally_events, synth_span, synth_name, synth_receiver)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
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
        // use_statement; attach the bases there. If the grammar
        // models `package Foo;` as a statement rather than a
        // container, fall back to the package range ending at the
        // next package statement.
        let use_span = span_of(file, &use_node);
        if let Some(decl_idx) = perl_class_decl_for_span(use_span, idx, file, src.len()) {
            push_perl_bases(&mut bases_by_decl, idx.defs[decl_idx].span, bases);
        }
    }
    collect_perl_isa_assignment_bases(src, file, idx, &mut bases_by_decl);
    bases_by_decl.into_iter().collect()
}

fn perl_class_decl_for_span(span: Span, idx: &DeclIndex, file: FileId, source_len: usize) -> Option<usize> {
    let mut best_decl: Option<(usize, u64)> = None;
    for (decl_idx, decl) in idx.defs.iter().enumerate() {
        if !is_class_like(decl.kind) {
            continue;
        }
        let body = decl.body_span.unwrap_or(decl.span);
        if span.file == body.file && span.start >= body.start && span.end <= body.end {
            let body_len = body.end.saturating_sub(body.start);
            if best_decl.is_none_or(|(_, prev_len)| body_len < prev_len) {
                best_decl = Some((decl_idx, body_len));
            }
        }
    }
    if let Some((decl_idx, _)) = best_decl {
        return Some(decl_idx);
    }
    perl_package_ranges(idx, file, source_len)
        .into_iter()
        .find_map(|(decl_idx, range)| {
            (span.file == range.file && span.start >= range.start && span.end <= range.end)
                .then_some(decl_idx)
        })
}

fn perl_package_ranges(idx: &DeclIndex, file: FileId, source_len: usize) -> Vec<(usize, Span)> {
    let mut packages: Vec<(usize, Span)> = idx
        .defs
        .iter()
        .enumerate()
        .filter(|(_, decl)| is_class_like(decl.kind) && decl.span.file == file)
        .map(|(idx, decl)| (idx, decl.span))
        .collect();
    packages.sort_by_key(|(_, span)| span.start);
    let file_end = u64::try_from(source_len).unwrap_or(u64::MAX);
    let mut ranges = Vec::new();
    for pos in 0..packages.len() {
        let (decl_idx, span) = packages[pos];
        let end = packages
            .get(pos + 1)
            .map(|(_, next_span)| next_span.start)
            .unwrap_or(file_end);
        ranges.push((decl_idx, Span::new(file, span.start, end)));
    }
    ranges
}

fn collect_perl_isa_assignment_bases(
    src: &[u8],
    file: FileId,
    idx: &DeclIndex,
    bases_by_decl: &mut std::collections::HashMap<bonsai_common::Span, Vec<String>>,
) {
    let source = std::str::from_utf8(src).unwrap_or("");
    for (decl_idx, range) in perl_package_ranges(idx, file, src.len()) {
        let start = usize::try_from(range.start)
            .unwrap_or(usize::MAX)
            .min(source.len());
        let end = usize::try_from(range.end).unwrap_or(usize::MAX).min(source.len());
        if start >= end {
            continue;
        }
        let bases = perl_isa_bases_from_text(&source[start..end]);
        if !bases.is_empty() {
            push_perl_bases(bases_by_decl, idx.defs[decl_idx].span, bases);
        }
    }
}

fn perl_isa_bases_from_text(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(relative) = source[offset..].find("@ISA") {
        let isa_start = offset + relative;
        let after_isa = &source[isa_start + "@ISA".len()..];
        let Some(eq_pos) = after_isa.find('=') else {
            offset = isa_start + "@ISA".len();
            continue;
        };
        let rhs = &after_isa[eq_pos + 1..];
        let stmt_len = rhs.find(';').unwrap_or(rhs.len());
        collect_perl_isa_rhs_bases(&rhs[..stmt_len], &mut out);
        offset = isa_start + "@ISA".len() + eq_pos + 1 + stmt_len;
    }
    out
}

fn collect_perl_isa_rhs_bases(rhs: &str, out: &mut Vec<String>) {
    let mut offset = 0;
    while let Some(relative) = rhs[offset..].find("qw") {
        let qw_start = offset + relative;
        let after_qw = rhs[qw_start + 2..].trim_start();
        if let Some(content) = after_qw.strip_prefix('(').and_then(|rest| rest.split(')').next()) {
            for piece in content.split_whitespace() {
                push_perl_base_name(out, piece);
            }
        }
        offset = qw_start + 2;
    }

    let bytes = rhs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote != b'\'' && quote != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        i = start;
        while i < bytes.len() && bytes[i] != quote {
            if bytes[i] == b'\\' {
                i = i.saturating_add(1);
            }
            i += 1;
        }
        if i <= bytes.len() {
            push_perl_base_name(out, &rhs[start..i]);
        }
        i = i.saturating_add(1);
    }

    for token in rhs.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':')) {
        if matches!(token, "" | "qw" | "ISA" | "our" | "my") {
            continue;
        }
        push_perl_base_name(out, token);
    }
}

fn push_perl_bases(
    bases_by_decl: &mut std::collections::HashMap<bonsai_common::Span, Vec<String>>,
    decl_span: Span,
    bases: Vec<String>,
) {
    let entry = bases_by_decl.entry(decl_span).or_default();
    for name in bases {
        if !entry.iter().any(|existing| existing == &name) {
            entry.push(name);
        }
    }
}

fn push_perl_base_name(out: &mut Vec<String>, raw: &str) {
    if let Some(name) = canonical_perl_base_name(raw) {
        if !out.iter().any(|existing| existing == &name) {
            out.push(name);
        }
    }
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

#[cfg(test)]
mod tests;
