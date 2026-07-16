//! Taint-source seed derivation.
//!
//! Converts a source `RuleMatch` into the set of seed tokens the taint
//! engine starts from: AST event seed targets (assign / output-arg /
//! callback-param bindings), qualified-read
//! descendant aliases, and the strict source-text matcher that gates
//! text-only seeding.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn collect_source_seed_targets(
    events: &[bonsai_lang_api::FlowEvent],
    src: &RuleMatch,
    source_output_args: &[usize],
    source_callback_args: &[SourceCallbackArgSemantics],
    allow_text_only_source_match: bool,
    out: &mut TokenSet,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_names,
                source_call_args,
                value_kind,
                ..
            } => {
                let source_text_matches = source_name
                    .as_deref()
                    .is_some_and(|n| security_text_matches_source_strict(n, &src.match_text))
                    || source_call
                        .as_deref()
                        .is_some_and(|n| security_text_matches_source_strict(n, &src.match_text))
                    || source_names
                        .iter()
                        .any(|n| security_text_matches_source_strict(n, &src.match_text))
                    || source_call_args
                        .iter()
                        .any(|n| security_text_matches_source_strict(n, &src.match_text));
                let source_site_matches = span_contains(*span, src.span)
                    || spans_overlap(*span, src.span)
                    || (allow_text_only_source_match && source_text_matches);
                if source_site_matches {
                    if !source_output_args.is_empty() {
                        seed_source_output_text_args(out, source_call_args, source_output_args);
                        continue;
                    }
                    let source_is_call_input = source_call.is_some()
                        && matches!(value_kind, Some(AssignValueKind::CallResult))
                        && !source_call
                            .as_deref()
                            .is_some_and(|n| security_text_matches_source_strict(n, &src.match_text))
                        && (source_names
                            .iter()
                            .any(|n| security_text_matches_source_strict(n, &src.match_text))
                            || source_call_args
                                .iter()
                                .any(|n| security_text_matches_source_strict(n, &src.match_text)));
                    let skip_target_seed = assign_is_callback_parameter_binding(
                        target,
                        source_name.as_deref(),
                        source_call.as_deref(),
                        source_names,
                        *value_kind,
                    );
                    if !skip_target_seed && !source_is_call_input && !target.is_empty() {
                        insert_taint_aliases(out, target);
                        if source_names_contain_descendant_of_source(source_names, &src.match_text) {
                            insert_descendant_taint_aliases(out, target);
                        }
                    }
                    let _ = source_call;
                    if let Some(source_name) = source_name.as_deref() {
                        if security_text_matches_source_strict(source_name, &src.match_text) {
                            insert_taint_aliases(out, source_name);
                        }
                    }
                    seed_descendant_aliases_for_qualified_source_reads(out, source_names, &src.match_text);
                    // Tighter match here than `security_text_matches_source`:
                    // when the source rule matches a qualified callee
                    // like `os.getenv`, the assignment's `source_names`
                    // includes both the tail (`getenv`) and the
                    // receiver (`os`). The receiver IS NOT a source
                    // term — adding it taints every `os.<other>` call
                    // in the same function (Task #279). Only seed
                    // entries that are equal to the source text or a
                    // proper qualified-tail of it.
                    for name in source_names {
                        if security_text_matches_source_strict(name, &src.match_text) {
                            insert_taint_aliases(out, name);
                        }
                    }
                    for name in source_call_args {
                        if security_text_matches_source_strict(name, &src.match_text) {
                            insert_taint_aliases(out, name);
                        }
                    }
                    if target_is_destructuring_pattern(target) {
                        for name in source_names {
                            insert_taint_aliases(out, name);
                        }
                    }
                }
            }
            FlowEvent::Call {
                span,
                name,
                receiver,
                args,
                ..
            } => {
                // Receiver-only match (e.g. receiver `os` matching source
                // text `os.getenv` via substring containment) was over-
                // broad: any call whose receiver was the same module
                // got its arg places seeded as if the call itself were
                // the source. That conflated `os.execute(CONST_OK)`
                // with the source seed of `os.getenv(...)` in the same
                // function — a Lua intra-fn precision regression
                // (Task #279). Match name OR span overlap only; the
                // receiver alone isn't enough to identify the source
                // site.
                let text_only_call_match = security_text_matches_source_strict(name, &src.match_text);
                let call_matches = span_contains(*span, src.span)
                    || spans_overlap(*span, src.span)
                    || (allow_text_only_source_match && text_only_call_match);
                let _ = receiver;
                if call_matches && !source_output_args.is_empty() {
                    seed_source_output_call_args(out, args, source_output_args);
                }
                // Callback-source delivery is an IDG edge from this exact
                // source call's anchored CallRet to the compiler-resolved
                // callback parameter. Do not re-parse the callback argument's
                // rendering to rediscover lambda parameters here.
                if call_matches
                    && source_output_args.is_empty()
                    && source_callback_args.is_empty()
                    && !name.is_empty()
                {
                    insert_taint_aliases(out, name);
                }
                // A source READ used *directly* as (or inside) an
                // argument of this call — e.g. `exec(req.params.x)`,
                // `exec(req.params.x + "-a")`. Here the call is NOT the
                // source: its callee name (`exec`) and its event span
                // (just the callee token) neither match nor overlap the
                // source read span, so none of the `call_matches` seeding
                // above fires and the split-assign form
                // (`t = req.params.x; exec(t)`) is the only shape that
                // seeds. Seed the matching source carriers from the
                // argument that fully contains the source span, exactly
                // as the Assign branch seeds `source_names` — the
                // `span_contains(arg.span, src.span)` gate localises to
                // the argument holding the source read (so a source
                // *call*, whose match span spans the whole call and is
                // therefore wider than any single arg, never trips this)
                // and the strict source-text filter keeps sibling
                // operands (`a` in `exec(a + req.params.x)`) untainted.
                if source_output_args.is_empty() && source_callback_args.is_empty() {
                    seed_source_arg_reads(out, args, src);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_source_seed_targets(
                    then_events,
                    src,
                    source_output_args,
                    source_callback_args,
                    allow_text_only_source_match,
                    out,
                );
                collect_source_seed_targets(
                    else_events,
                    src,
                    source_output_args,
                    source_callback_args,
                    allow_text_only_source_match,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_source_seed_targets(
                    body,
                    src,
                    source_output_args,
                    source_callback_args,
                    allow_text_only_source_match,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_source_seed_targets(
                    body,
                    src,
                    source_output_args,
                    source_callback_args,
                    allow_text_only_source_match,
                    out,
                );
                collect_source_seed_targets(
                    catch_events,
                    src,
                    source_output_args,
                    source_callback_args,
                    allow_text_only_source_match,
                    out,
                );
                collect_source_seed_targets(
                    finally_events,
                    src,
                    source_output_args,
                    source_callback_args,
                    allow_text_only_source_match,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn assign_is_callback_parameter_binding(
    target: &str,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_names: &[String],
    value_kind: Option<AssignValueKind>,
) -> bool {
    source_name.is_none()
        && source_call.is_none()
        && matches!(
            value_kind,
            Some(AssignValueKind::Compound | AssignValueKind::Unknown)
        )
        && source_names.iter().any(|name| name == target)
        && source_names
            .iter()
            .any(|name| matches!(name.as_str(), "function" | "async"))
}

fn seed_source_output_text_args(out: &mut TokenSet, args: &[String], source_output_args: &[usize]) {
    for &index in source_output_args {
        let Some(text) = args.get(index).map(|value| value.trim()) else {
            continue;
        };
        if text.is_empty() || source_seed_text_is_literal(text) {
            continue;
        }
        insert_taint_aliases(out, text);
        insert_descendant_taint_aliases(out, text);
    }
}

/// Seed the taint source when the matched source read is used
/// *directly* as a call argument (`sink(req.params.x)`), rather than
/// first bound to a local (`t = req.params.x; sink(t)`). Only the
/// argument whose span fully contains the source match span is
/// considered, and within it only carriers that strictly match the
/// source text (plus their qualified descendants) are seeded — this is
/// the argument-position analogue of the `FlowEvent::Assign` branch's
/// `source_names` seeding, and it inherits that branch's precision:
/// sibling operands of a compound argument (`a` in `sink(a + req.x)`)
/// never match the source text and so stay untainted.
fn seed_source_arg_reads(out: &mut TokenSet, args: &[bonsai_lang_api::CallArg], src: &RuleMatch) {
    for arg in args {
        if !span_contains(arg.span, src.span) {
            continue;
        }
        seed_descendant_aliases_for_qualified_source_reads(out, &arg.source_names, &src.match_text);
        if let Some(place) = arg.place.as_deref() {
            if security_text_matches_source_strict(place, &src.match_text) {
                insert_taint_aliases(out, place);
                insert_descendant_taint_aliases(out, place);
            }
        }
        for name in &arg.source_names {
            if security_text_matches_source_strict(name, &src.match_text) {
                insert_taint_aliases(out, name);
            }
        }
    }
}

fn seed_source_output_call_args(
    out: &mut TokenSet,
    args: &[bonsai_lang_api::CallArg],
    source_output_args: &[usize],
) {
    for &index in source_output_args {
        let Some(arg) = args.get(index) else {
            continue;
        };
        let Some(text) = arg.place.as_deref().map(str::trim) else {
            continue;
        };
        if text.is_empty() || source_seed_text_is_literal(text) {
            continue;
        }
        insert_taint_aliases(out, text);
        insert_descendant_taint_aliases(out, text);
    }
}

fn source_seed_text_is_literal(text: &str) -> bool {
    let text = text.trim();
    if text.len() < 2 {
        return false;
    }
    let Some(first) = text.chars().next() else {
        return false;
    };
    let Some(last) = text.chars().last() else {
        return false;
    };
    matches!(first, '"' | '\'' | '`') && first == last
}

pub(super) fn seed_descendant_aliases_for_qualified_source_reads(
    out: &mut TokenSet,
    source_names: &[String],
    source_text: &str,
) {
    let source_normalised = security_normalise_qualified_text(source_text);
    for name in source_names {
        let normalised = security_normalise_qualified_text(name);
        if !source_normalised.is_empty()
            && source_normalised.contains('.')
            && (normalised == source_normalised
                || normalised
                    .strip_prefix(source_normalised.as_str())
                    .is_some_and(|rest| rest.starts_with('.')))
        {
            insert_descendant_taint_aliases(out, source_text);
            insert_descendant_taint_aliases(out, &source_normalised);
            continue;
        }
        let Some((base, _)) = normalised.split_once('.') else {
            continue;
        };
        if source_base_matches(base, source_text) {
            insert_descendant_taint_aliases(out, base);
            insert_descendant_taint_aliases(out, source_text);
        }
    }
}

fn source_names_contain_descendant_of_source(source_names: &[String], source_text: &str) -> bool {
    let source = security_normalise_qualified_text(source_text);
    if source.is_empty() {
        return false;
    }
    source_names.iter().any(|name| {
        let name = security_normalise_qualified_text(name);
        name.strip_prefix(source.as_str())
            .is_some_and(|rest| rest.starts_with('.') && rest.len() > 1)
    })
}

fn source_base_matches(base: &str, source_text: &str) -> bool {
    security_text_matches_source_strict(base, source_text)
        || security_text_matches_source_strict(
            strip_security_sigils(base),
            strip_security_sigils(source_text),
        )
}

fn strip_security_sigils(text: &str) -> &str {
    text.trim().trim_start_matches(&['$', '@', '%'][..])
}

fn target_is_destructuring_pattern(target: &str) -> bool {
    let target = target.trim();
    target.contains(',')
        || target.starts_with('[')
        || target.starts_with('(')
        || target.starts_with('{')
        || target.contains(":=")
}

pub(super) fn insert_taint_aliases(out: &mut TokenSet, text: &str) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    out.insert(trimmed.to_string());
    let normalised = security_normalise_qualified_text(trimmed);
    if normalised != trimmed {
        out.insert(normalised);
    }
}

pub(super) fn insert_descendant_taint_aliases(out: &mut TokenSet, text: &str) {
    let mut aliases = TokenSet::default();
    insert_taint_aliases(&mut aliases, text);
    for alias in aliases {
        if alias.is_empty() || alias.contains('*') {
            continue;
        }
        out.insert(alias.clone());
        out.insert(format!("{alias}.*"));
    }
}

/// Source seeding uses strict identity only. Receiver substring
/// matching (`os` as a match for `os.getenv`) taints every sibling
/// member on the same object/module, so source expansion is limited
/// to equality, normalized equality, or exact qualified-tail equality.
pub(super) fn security_text_matches_source_strict(text: &str, source_text: &str) -> bool {
    let text = text.trim();
    let source_text = source_text.trim();
    if text.is_empty() || source_text.is_empty() {
        return false;
    }
    if text == source_text {
        return true;
    }
    let text_norm = security_normalise_qualified_text(text);
    let src_norm = security_normalise_qualified_text(source_text);
    if text_norm == src_norm {
        return true;
    }
    // Tail match: `getenv` matches `os.getenv` (one is a suffix of
    // the other when split on `.` / `:`). Do not tail-match
    // multi-segment receiver chains such as `request.headers.get`:
    // the tail `get` is generic and would conflate sibling framework
    // sources like `request.args.get` and `request.headers.get`.
    if source_qualified_segment_count(source_text) > 2 {
        return false;
    }
    let text_tail = text.rsplit(&['.', ':'][..]).next().unwrap_or(text);
    let src_tail = source_text.rsplit(&['.', ':'][..]).next().unwrap_or(source_text);
    text_tail == src_tail && !text_tail.is_empty()
}

fn source_qualified_segment_count(text: &str) -> usize {
    let normalized = security_normalise_qualified_text(text);
    normalized
        .split(&['.', ':'][..])
        .filter(|part| !part.trim().is_empty())
        .count()
}

fn security_normalise_qualified_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_brackets = false;
    let mut chars = text.trim().chars().peekable();
    while matches!(chars.peek(), Some('&' | '*')) {
        chars.next();
    }
    while let Some(c) = chars.next() {
        match c {
            '-' if matches!(chars.peek(), Some('>')) => {
                chars.next();
                out.push('.');
            }
            '[' => {
                in_brackets = true;
                out.push('.');
            }
            ']' => in_brackets = false,
            '\'' | '"' if in_brackets => {}
            _ => out.push(c),
        }
    }
    out.trim_matches('.').to_string()
}
