//! Assign-chain propagation pass.
//!
//! The reachability pass answers "is the source's name visible
//! anywhere on the chain?" — a blunt but honest proxy. Assign-chain
//! sharpens that by following
//! `FlowEvent::Assign { target, source_name  }` edges transitively:
//! if `y = source()` and later `z = y`, then `z` is tainted because
//! `y` was tainted. The `source_name` field on every assignment is
//! the bridge — adapters already populate it wherever the RHS is a
//! simple identifier.
//!
//! ## Semantics
//!
//! Assign-chain is **monotonic**: a name becomes tainted when an
//! assignment pulls from a tainted source, and stays tainted for the
//! rest of the walk. Reassignment-from-clean (`x = 5` after
//! `x = recv()`) does NOT remove taint — that's the intraprocedural
//! pass's CFG-aware job, which needs block ordering to distinguish
//! live data from overwritten data. Monotonic assign-chain is deliberately conservative:
//! for security work false positives beat false negatives, and the
//! intraprocedural pass is the layer that reclaims precision.
//!
//! The walker is an **in-order pass over the flow-event tree**. It
//! recurses into `Branch` / `Loop` / `Try` / `Defer` / `Using`
//! bodies and unions the taint sets coming out of each. Loop bodies
//! iterate to a fixed point so loop-carried assignment taint is visible
//! to later checks.
//!
//! ## API
//!
//! `assign_chain_taints(seed, events)` returns the full set of
//! identifiers that become tainted starting from `seed` after
//! walking `events`. Callers check `.contains(target)` themselves to
//! answer "does this specific name end up tainted?".
//!
//! The function is intraprocedural within a single flow-event tree;
//! the interprocedural pass handles cross-call propagation via the
//! resolved call graph.

use crate::{
    text::{
        is_quoted_literal, normalise_qualified_text, qualified_access_bases, text_looks_qualified,
        value_bearing_identifier_text,
    },
    TokenSet,
};
use bonsai_lang_api::FlowEvent;

/// Compute the set of identifiers tainted after walking `events`
/// in source order, starting from `seed`. Monotonic — the returned
/// set is always a superset of `seed`.
///
/// For each `FlowEvent::Assign { target, source_name: Some(src)  }`,
/// if `src` is already in the taint set, `target` is added. Nested
/// constructs (`Branch`, `Loop`, `Try`, `Defer`, `Using`) recurse and
/// union their results back into the caller's taint set.
///
/// Tokens that come out of the RHS as compound expressions
/// (`x + 1`, `f(x)`, etc.) produce `source_name = None` in most
/// adapters today — assign-chain skips those conservatively rather
/// than trying to regex-parse them. The intraprocedural pass will
/// enrich this via expression-level flow.
#[must_use]
pub fn assign_chain_taints(seed: &TokenSet, events: &[FlowEvent]) -> TokenSet {
    let mut tainted = seed.clone();
    walk_events(events, &mut tainted);
    tainted
}

/// Convenience predicate: does `target` end up tainted given the
/// starting `seed`? Shorthand for `assign_chain_taints(...).contains(target)`.
#[must_use]
pub fn target_is_tainted(seed: &TokenSet, target: &str, events: &[FlowEvent]) -> bool {
    assign_chain_taints(seed, events).contains(target)
}

/// True when the try-body contains a `Throw { value_name: Some(n) }`
/// whose `n` is in the current tainted set. Signals to the caller
/// that the catch region should be entered with its binding seeded
/// as tainted (G8 — exception-flow taint). Recurses through nested
/// control flow so throws buried inside branches/loops/inner tries
/// are still detected.
fn throw_taints_catch(events: &[FlowEvent], tainted: &TokenSet) -> bool {
    for event in events {
        match event {
            // Direct throw of a tainted value — the trigger we're looking for.
            FlowEvent::Throw {
                value_name: Some(thrown_name),
                ..
            } if !thrown_name.is_empty() && tainted.contains(thrown_name) => return true,
            // Recurse into branch arms; either arm carrying a tainted throw is enough.
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if throw_taints_catch(then_events, tainted) || throw_taints_catch(else_events, tainted) => {
                return true;
            }
            FlowEvent::Loop { body, .. } if throw_taints_catch(body, tainted) => return true,
            // Nested try/catch/finally regions can also harbour the throw.
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } if throw_taints_catch(body, tainted)
                || throw_taints_catch(catch_events, tainted)
                || throw_taints_catch(finally_events, tainted) =>
            {
                return true;
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. }
                if throw_taints_catch(body, tainted) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Walk flow events in order, mutating `tainted` in place. Assignment
/// RHS checks short-circuit after the first successful target insert;
/// the pass is set-based, so the remaining checks cannot change the
/// answer for that assignment.
///
/// Separate helper (not a closure) so recursion into nested constructs is
/// straightforward.
fn walk_events(events: &[FlowEvent], tainted: &mut TokenSet) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                if target.is_empty() {
                    continue;
                }
                if let Some(source) = source_name.as_deref() {
                    if text_is_tainted(source, tainted) {
                        insert_target_taint(tainted, target);
                        if rhs_has_descendant_shape(source_names) {
                            insert_descendant_target_taint(tainted, target);
                        }
                        continue;
                    }
                }
                // G1 — assign-chain is monotonic: if ANY tainted arg
                // is a positional arg of a call-RHS, optimistically
                // taint the target. The interprocedural pass tightens
                // this via function summaries; assign-chain favours
                // over-approximation (security bias).
                if source_call_args
                    .iter()
                    .any(|arg| !arg.is_empty() && text_is_tainted(arg, tainted))
                {
                    insert_target_taint(tainted, target);
                    if rhs_has_descendant_shape(source_names) {
                        insert_descendant_target_taint(tainted, target);
                    }
                    continue;
                }
                // Pass through descendant taint without promoting the
                // whole target — keeps `obj.*` precision when only a
                // subtree of the call's argument was wildcard-tainted.
                if source_call_args
                    .iter()
                    .any(|arg| !arg.is_empty() && actual_has_descendant_taint(arg, tainted))
                {
                    insert_descendant_target_taint(tainted, target);
                    continue;
                }
                if source_call
                    .as_deref()
                    .is_some_and(|callee| text_is_tainted(callee, tainted))
                {
                    insert_target_taint(tainted, target);
                    if rhs_has_descendant_shape(source_names) {
                        insert_descendant_target_taint(tainted, target);
                    }
                    continue;
                }
                // G2 — compound RHS operand taint. `y = prefix +
                // tainted` / `y = obj.field` / `y = f"{x} {y}"` /
                // `y = cond ? a : b`. Adapter surfaces every bare
                // identifier in the RHS as `source_names`.
                let qualified_bases = qualified_source_bases(source_names);
                if source_names.iter().any(|name| {
                    // Skip the qualified-access base (e.g. `obj` in `obj.field`):
                    // its presence in the operand list is structural, not a taint signal.
                    !name.is_empty()
                        && !qualified_bases.contains(&canonical_bare_name(name))
                        && text_is_tainted(name, tainted)
                }) {
                    insert_target_taint(tainted, target);
                    if rhs_has_descendant_shape(source_names) {
                        insert_descendant_target_taint(tainted, target);
                    }
                    continue;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                // Monotonic taint makes branch join trivial: walk
                // both arms against the *same* starting set, then
                // union the results. Either arm that taints a name
                // propagates it out.
                let mut then_taints = tainted.clone();
                walk_events(then_events, &mut then_taints);
                let mut else_taints = tainted.clone();
                walk_events(else_events, &mut else_taints);
                tainted.extend(then_taints);
                tainted.extend(else_taints);
            }
            FlowEvent::Loop { body, .. } => {
                // Iterate loop bodies to a fixed point. The transfer
                // function is monotonic over a finite set of source
                // names emitted by adapters, so convergence is quick
                // and avoids assuming a fixed number of back-edge
                // passes is enough for every loop shape.
                loop {
                    let before = tainted.len();
                    walk_events(body, tainted);
                    if tainted.len() == before {
                        break;
                    }
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                walk_events(body, tainted);
                // G8: if any `throw tainted` appeared in the body AND
                // the catch region has a declared binding, seed that
                // binding as tainted for the catch walk. This is how
                // `throw user_input; catch (e) { sink(e) }` propagates
                // through the exception handler. `throw_taints_body`
                // checks the body we just walked for any Throw whose
                // `value_name` is currently tainted.
                if let Some(param) = catch_param.as_deref() {
                    if throw_taints_catch(body, tainted) && !param.is_empty() {
                        tainted.insert(param.to_string());
                    }
                }
                walk_events(catch_events, tainted);
                walk_events(finally_events, tainted);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_events(body, tainted);
            }
            // Calls don't taint the caller's scope directly in
            // assign-chain. A tainted argument → tainted callee
            // parameter is the interprocedural pass's job.
            // A tainted return value written back to a variable shows
            // up as a later Assign event (assuming the adapter
            // populated source_name with the callee name — not
            // always the case).
            _ => {}
        }
    }
}

/// True when `text` references any tainted identifier — by direct
/// match, by qualified-access wildcard match (e.g. `obj.*`), by
/// receiver-method projection (`tainted.method(...)`), or by any
/// bare identifier token appearing outside string literals.
fn text_is_tainted(text: &str, tainted: &TokenSet) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if tainted.contains(trimmed) {
        return true;
    }
    let normalised = normalise_qualified_text(trimmed);
    if receiver_method_projection_is_tainted(trimmed, tainted) {
        return true;
    }
    // Wildcard seeds like `obj.*` only match qualified accesses,
    // never bare identifiers — guard the cheap shape check first.
    if text_looks_qualified(trimmed) && qualified_wildcard_seed_matches(&normalised, tainted) {
        return true;
    }
    let qualified_bases = qualified_access_bases(trimmed);
    identifier_tokens_outside_strings(&value_bearing_identifier_text(trimmed))
        .iter()
        .any(|token| {
            // Skip the base of any qualified access — its presence is structural,
            // and wildcard seeds were already checked above.
            !qualified_bases.iter().any(|base| base == token) && tainted.contains(token.as_str())
        })
}

/// True when `text`'s value comes from a wildcard-tainted ancestor
/// (`obj.*` seeded → `obj.field` matches). Distinct from
/// [`text_is_tainted`] because the call site must promote only the
/// descendant projection, not the whole assigned target.
fn actual_has_descendant_taint(text: &str, tainted: &TokenSet) -> bool {
    let normalised = normalise_qualified_text(text.trim());
    !normalised.is_empty() && qualified_wildcard_seed_matches(&normalised, tainted)
}

/// Insert `target` directly into the tainted set. Trivial wrapper kept
/// for parity with [`insert_descendant_target_taint`] so call sites
/// read symmetrically.
fn insert_target_taint(tainted: &mut TokenSet, target: &str) {
    tainted.insert(target.to_string());
}

/// Insert `target.*` (the wildcard descendant form) into the tainted
/// set. Skips qualified targets and already-wildcarded targets so we
/// don't generate `obj.field.*` or `obj.*.*` from re-entry.
fn insert_descendant_target_taint(tainted: &mut TokenSet, target: &str) {
    let target = normalise_qualified_text(target).trim().to_string();
    if target.is_empty() || text_looks_qualified(&target) || target.ends_with(".*") {
        return;
    }
    tainted.insert(format!("{target}.*"));
}

/// True when the RHS surface contains at least two distinct bare
/// identifiers — the heuristic that distinguishes a "constructed"
/// value (which warrants `target.*` propagation) from a single-name
/// alias (which doesn't).
fn rhs_has_descendant_shape(source_names: &[String]) -> bool {
    let mut distinct = Vec::new();
    for name in source_names {
        let name = name.trim();
        if name.is_empty() || is_quoted_literal(name) {
            continue;
        }
        let canonical = canonical_bare_name(name);
        if canonical.is_empty() || distinct.iter().any(|existing| existing == &canonical) {
            continue;
        }
        distinct.push(canonical);
    }
    distinct.len() > 1
}

/// True when any seed in `tainted` is a wildcard form (`prefix.*`)
/// that matches `normalised_text` either exactly at the prefix or as
/// a strict descendant (`prefix.field`, `prefix.a.b`).
fn qualified_wildcard_seed_matches(normalised_text: &str, tainted: &TokenSet) -> bool {
    tainted.iter().any(|seed| {
        let Some(prefix) = seed.strip_suffix(".*") else {
            return false;
        };
        let prefix = normalise_qualified_text(prefix);
        !prefix.is_empty()
            && (normalised_text == prefix
                || normalised_text
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('.')))
    })
}

/// True when `text` contains a `receiver.method(...)` shape whose
/// receiver is tainted. Catches `tainted.format(...)` patterns where
/// the call expression as a whole isn't a tracked identifier but the
/// receiver alone propagates taint.
fn receiver_method_projection_is_tainted(text: &str, tainted: &TokenSet) -> bool {
    for open_paren in text.match_indices('(').map(|(idx, _)| idx) {
        let before_call = text[..open_paren].trim_end();
        // Walk back to the start of the callee expression. `char_indices`
        // keeps us on UTF-8 boundaries — `rfind` would slice mid-char on
        // non-ASCII text (e.g. an em dash) and panic.
        let start = before_call
            .char_indices()
            .rev()
            .find(|&(_, c)| {
                !(c == '.'
                    || c == '_'
                    || c == '$'
                    || c == '@'
                    || c == '%'
                    || c == ']'
                    || c == '['
                    || c == '\''
                    || c == '"'
                    || c.is_ascii_alphanumeric())
            })
            .map_or(0, |(idx, c)| idx + c.len_utf8());
        let candidate = before_call[start..].trim();
        let Some((receiver, method)) = candidate.rsplit_once('.') else {
            continue;
        };
        if receiver.trim().is_empty() || method.trim().is_empty() {
            continue;
        }
        let receiver = normalise_qualified_text(receiver);
        if !receiver.is_empty()
            && (tainted.contains(&receiver) || qualified_wildcard_seed_matches(&receiver, tainted))
        {
            return true;
        }
    }
    false
}

/// Collect every qualified-access base (the leftmost identifier of
/// each `a.b.c` form) appearing in `source_names`. Used to mask
/// structural occurrences of identifiers from the bare-token taint
/// check so `obj.field` doesn't taint a target via `obj` alone.
fn qualified_source_bases(source_names: &[String]) -> ahash::AHashSet<String> {
    let mut bases = ahash::AHashSet::new();
    for source in source_names {
        for base in qualified_access_bases(source) {
            bases.insert(base);
        }
    }
    bases
}

/// Strip qualifier sigils (`$`, `@`, `%`) and surrounding whitespace
/// to produce the canonical bare identifier form used for set
/// membership and de-duplication.
fn canonical_bare_name(text: &str) -> String {
    normalise_qualified_text(text)
        .trim_start_matches(&['$', '@', '%'][..])
        .trim()
        .to_string()
}

/// Lex `text` into identifier tokens, skipping content that lies
/// inside single, double, or backtick string literals. Used so a
/// stray `tainted` substring inside a quoted string doesn't masquerade
/// as a real identifier reference.
pub(crate) fn identifier_tokens_outside_strings(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
            // Inside a string literal: only watch for the closing quote and escape sequences.
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        if matches!(c, '\'' | '"' | '`') {
            // Flush any in-progress identifier before entering the string region.
            push_identifier_token(&mut tokens, &mut current);
            quote = Some(c);
            continue;
        }
        if c == '_' || c.is_ascii_alphanumeric() {
            current.push(c);
        } else {
            push_identifier_token(&mut tokens, &mut current);
        }
    }
    push_identifier_token(&mut tokens, &mut current);
    tokens
}

/// Push the in-progress buffer onto `tokens` as an identifier, but
/// only when it starts with a letter or underscore. Numeric-leading
/// runs are discarded — they're literal fragments, not identifiers.
fn push_identifier_token(tokens: &mut Vec<String>, current: &mut String) {
    if current
        .chars()
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
    {
        tokens.push(std::mem::take(current));
    } else {
        current.clear();
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::{FileId, Span};

    /// Build an `Assign` event. Span is a throwaway — assign-chain
    /// doesn't use it — but the types require one.
    fn assign(target: &str, source: Option<&str>) -> FlowEvent {
        FlowEvent::Assign {
            span: Span::new(FileId::INVALID, 0, 0),
            target: target.to_string(),
            source_name: source.map(str::to_string),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
                    declares_new_binding: false,
            value_kind: None,
        }
    }

    fn call(name: &str) -> FlowEvent {
        FlowEvent::Call {
            span: Span::new(FileId::INVALID, 0, 0),
            name: name.to_string(),
            receiver: None,
            call_kind: bonsai_lang_api::CallKind::Function,
            args: Vec::new(),
            receiver_types: Vec::new(),
        }
    }

    fn assign_call_args(target: &str, callee: &str, args: &[&str]) -> FlowEvent {
        FlowEvent::Assign {
            span: Span::new(FileId::INVALID, 0, 0),
            target: target.to_string(),
            source_name: None,
            source_call: Some(callee.to_string()),
            source_call_args: args.iter().map(|arg| (*arg).to_string()).collect(),
            source_names: Vec::new(),
                    declares_new_binding: false,
            value_kind: None,
        }
    }

    fn branch(then_events: Vec<FlowEvent>, else_events: Vec<FlowEvent>) -> FlowEvent {
        FlowEvent::Branch {
            span: Span::new(FileId::INVALID, 0, 0),
            condition: None,
            then_events,
            else_events,
        }
    }

    fn loop_body(body: Vec<FlowEvent>) -> FlowEvent {
        FlowEvent::Loop {
            span: Span::new(FileId::INVALID, 0, 0),
            loop_kind: bonsai_lang_api::LoopKind::While,
            body,
        }
    }

    fn try_event(
        body: Vec<FlowEvent>,
        catch_events: Vec<FlowEvent>,
        finally_events: Vec<FlowEvent>,
    ) -> FlowEvent {
        FlowEvent::Try {
            span: Span::new(FileId::INVALID, 0, 0),
            body,
            catch_events,
            finally_events,
            catch_param: None,
            catch_types: Vec::new(),
        }
    }

    fn seed(names: &[&str]) -> TokenSet {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    #[test]
    fn seed_alone_is_returned_unchanged_for_empty_events() {
        let out = assign_chain_taints(&seed(&["recv"]), &[]);
        assert!(out.contains("recv"));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn direct_assignment_propagates_taint() {
        // `x = recv()` — if recv is tainted, x becomes tainted.
        let events = vec![assign("x", Some("recv"))];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("x"), "x should be tainted from recv");
    }

    #[test]
    fn two_hop_assignment_chain_propagates() {
        // x = recv(); y = x; z = y; — all three derived names tainted.
        let events = vec![
            assign("x", Some("recv")),
            assign("y", Some("x")),
            assign("z", Some("y")),
        ];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("x"));
        assert!(out.contains("y"));
        assert!(out.contains("z"));
    }

    #[test]
    fn call_argument_expression_tokens_propagate_to_target() {
        let events = vec![
            assign("routed", Some("envelope")),
            assign_call_args(
                "valid",
                "Try",
                &["envelope.copy(cmd = routed, user = user, length = routed.length)"],
            ),
        ];
        let out = assign_chain_taints(&seed(&["envelope"]), &events);
        assert!(out.contains("routed"));
        assert!(out.contains("valid"));
    }

    #[test]
    fn call_callee_expression_tokens_propagate_to_target() {
        let events = vec![
            assign("routed", Some("envelope")),
            FlowEvent::Assign {
                span: Span::new(FileId::INVALID, 0, 0),
                target: "valid".to_string(),
                source_name: None,
                source_call: Some(
                    "(|| -> Result<Envelope, &str> { Ok(Envelope { cmd: routed.clone() }) })().unwrap_or_else"
                        .to_string(),
                ),
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            },
        ];
        let out = assign_chain_taints(&seed(&["envelope"]), &events);
        assert!(out.contains("routed"));
        assert!(out.contains("valid"));
    }

    #[test]
    fn multiline_closure_argument_tokens_propagate_to_target() {
        let events = vec![
            assign("routed", Some("envelope")),
            assign_call_args(
                "valid",
                "(|| -> Result<Envelope, &str> { Ok(Envelope { cmd: routed.clone() }) })().unwrap_or_else",
                &["|_| Envelope {\n        kind: envelope.kind.clone(),\n        cmd: routed.clone(),\n        user: user.clone(),\n        length: routed.len(),\n        extras: envelope.extras.clone(),\n    }"],
            ),
        ];
        let out = assign_chain_taints(&seed(&["envelope"]), &events);
        assert!(out.contains("routed"));
        assert!(out.contains("valid"));
    }

    #[test]
    fn chain_breaks_when_source_is_not_tainted() {
        // x = recv(); y = other; z = y; — x tainted, y/z not.
        let events = vec![
            assign("x", Some("recv")),
            assign("y", Some("other")),
            assign("z", Some("y")),
        ];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("x"));
        assert!(!out.contains("y"));
        assert!(!out.contains("z"));
    }

    #[test]
    fn source_name_none_does_not_taint_target() {
        // Compound RHS expressions (`x + 1`, `f(y)`) leave
        // source_name = None in most adapters — assign-chain
        // conservatively skips them. The intraprocedural pass can
        // enrich with expression-level flow.
        let events = vec![assign("x", None)];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(!out.contains("x"));
    }

    #[test]
    fn assignment_from_seed_into_empty_target_is_ignored() {
        // Malformed adapter output — empty target. Assign-chain
        // just skips.
        let events = vec![assign("", Some("recv"))];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert_eq!(out.len(), 1, "only the seed should be present");
    }

    #[test]
    fn monotonic_reassignment_does_not_clear_taint() {
        // x = recv(); x = 5; — assign-chain keeps x tainted. The
        // intraprocedural pass's CFG-ordered propagation is what
        // clears taint on reassignment-from-clean; assign-chain is
        // monotonic.
        let events = vec![
            assign("x", Some("recv")),
            assign("x", None), // reassign from compound expression / literal
        ];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("x"), "assign-chain is monotonic — x stays tainted");
    }

    #[test]
    fn branch_joins_taint_from_both_arms() {
        // if c: y = x else: y = q — y tainted in at least the `then`
        // arm, so the join contains y.
        let events = vec![
            assign("x", Some("recv")),
            branch(vec![assign("y", Some("x"))], vec![assign("y", Some("q"))]),
        ];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("y"), "branch join must union taint");
    }

    #[test]
    fn branch_taint_from_one_arm_doesnt_require_both() {
        // Only the then-arm taints — still propagates because the
        // branch join is a union. Security semantics: if ANY path
        // taints a name, treat it as tainted.
        let events = vec![
            assign("x", Some("recv")),
            branch(vec![assign("y", Some("x"))], vec![]),
        ];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("y"));
    }

    #[test]
    fn loop_body_taints_propagate_out() {
        // for i in items: x = recv(); y = x; — y tainted after the
        // loop because the body runs at least once (conservatively).
        let events = vec![loop_body(vec![assign("x", Some("recv")), assign("y", Some("x"))])];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("x"));
        assert!(out.contains("y"));
    }

    #[test]
    fn try_catch_finally_all_contribute_taint() {
        // Each region walked; any assignment in any region
        // contributes to the union.
        let events = vec![try_event(
            vec![assign("a", Some("recv"))],
            vec![assign("b", Some("recv"))],
            vec![assign("c", Some("recv"))],
        )];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("a"));
        assert!(out.contains("b"));
        assert!(out.contains("c"));
    }

    #[test]
    fn target_is_tainted_predicate_matches_full_set() {
        let events = vec![assign("x", Some("recv")), assign("y", Some("x"))];
        let seed_set = seed(&["recv"]);
        assert!(target_is_tainted(&seed_set, "x", &events));
        assert!(target_is_tainted(&seed_set, "y", &events));
        assert!(!target_is_tainted(&seed_set, "z", &events));
    }

    #[test]
    fn call_events_do_not_taint_caller_scope() {
        // A tainted-argument call is the interprocedural pass's
        // territory. Assign-chain on its own shouldn't infer
        // cross-function taint.
        let events = vec![call("sink"), assign("x", Some("recv"))];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("x"));
        assert_eq!(
            out.len(),
            2,
            "only seed + x should be tainted; call doesn't add anything"
        );
    }

    #[test]
    fn multiple_seeds_all_propagate_independently() {
        // Two sources, two derived names — each chain taints its own
        // target without cross-contaminating the other.
        let events = vec![
            assign("a", Some("src1")),
            assign("b", Some("src2")),
            assign("c", Some("unrelated")),
        ];
        let out = assign_chain_taints(&seed(&["src1", "src2"]), &events);
        assert!(out.contains("a"));
        assert!(out.contains("b"));
        assert!(!out.contains("c"));
    }

    #[test]
    fn nested_branches_preserve_ordering_within_arms() {
        // Outer branch whose then-arm contains an inner branch;
        // taint should propagate through the inner structure.
        let events = vec![
            assign("x", Some("recv")),
            branch(vec![branch(vec![assign("y", Some("x"))], vec![])], vec![]),
        ];
        let out = assign_chain_taints(&seed(&["recv"]), &events);
        assert!(out.contains("y"));
    }
}
