//! Intraprocedural taint over a function CFG.
//!
//! Assign-chain walks flow events in a single in-order pass with
//! monotonic taint (once tainted, always tainted). The intraprocedural
//! pass upgrades that to a proper forward dataflow over the function's
//! CFG, tracking taint state per basic block with worklist iteration
//! to a fixed point.
//!
//! Two things this pass buys over assign-chain:
//!
//! 1. **Reassignment clears taint.** `x = recv(); x = 5; sink(x)` —
//!    assign-chain keeps `x` tainted because it never removes. The
//!    intraprocedural pass tracks that the second assignment
//!    overwrites with a clean value and clears `x` from the taint
//!    set before the `sink(x)` step.
//! 2. **Ordering.** Taint propagates along the CFG's edges, not a
//!    tree walk, so branch and loop joins are handled consistently.
//!
//! ## Non-goals (interprocedural pass handles these)
//!
//! - Cross-function propagation (tainted arg → tainted parameter in
//!   callee scope). The interprocedural pass drives the resolved call
//!   graph for that.
//! - Interprocedural return summaries. This pass uses a conservative
//!   local call-RHS heuristic; the `inter` pass resolves callees and
//!   applies function return summaries.
//!
//! ## Algorithm
//!
//! Standard forward dataflow:
//!
//! - Initial state: `entry_in = sources`, every other block's `in = {}`.
//! - For each block in the worklist: `in = ⋃ predecessors.out`.
//! - `out = transfer(events, in)` — apply each event's effect in order.
//! - If `out` changed: push every successor back onto the worklist.
//!
//! Monotonic per-event transfer operations are:
//! - `Assign { target, source = tainted id }` → add `target`.
//! - `Assign { target, source = other / None }` → clear `target`
//!   (semantic overwrite: the previous value no longer reaches the
//!   target unless the RHS exposes a tainted operand).

use crate::TokenSet;
use ahash::{AHashMap, AHashSet};
use bonsai_cfg::Cfg;
use bonsai_common::{BasicBlockId, FileId, Span};
use bonsai_diagnostics::{Diagnostic, Severity};
use bonsai_lang_api::FlowEvent;
use std::collections::VecDeque;

/// Configuration driving an intraprocedural analysis run.
#[derive(Clone, Debug, Default)]
pub struct TaintConfig {
    /// Identifier names that start tainted at the function's entry.
    pub sources: TokenSet,
    /// Compatibility field retained for callers that still pass a
    /// sanitizer list. Sanitizers are classification evidence, not a
    /// taint-transfer input, so this set does not alter propagation.
    pub sanitizers: TokenSet,
    /// Optional worklist iteration cap. When unset, the cap is derived
    /// from CFG size by multiplying the basic-block count by 8 (with a
    /// floor of 16); see `DEFAULT_WORKLIST_CAP_MULTIPLIER` and
    /// `MIN_WORKLIST_CAP` in this module.
    pub worklist_cap: Option<u32>,
}

pub(crate) const DEFAULT_WORKLIST_CAP_MULTIPLIER: u32 = 8;
pub(crate) const MIN_WORKLIST_CAP: u32 = 16;

/// Per-block taint state after the fixed point converges. Callers
/// typically ask "is identifier X tainted at basic block B?" via
/// [`IntraTaintResult::is_tainted_at_entry`] or directly via
/// [`IntraTaintResult::block_in`].
#[derive(Clone, Debug, Default)]
pub struct IntraTaintResult {
    /// Taint set on entry to each basic block. Keyed by
    /// [`BasicBlockId`].
    pub block_in: AHashMap<BasicBlockId, TokenSet>,
    /// Taint set on exit from each basic block (after the block's
    /// events transfer).
    pub block_out: AHashMap<BasicBlockId, TokenSet>,
    /// How many worklist iterations the analysis took. Exposed for
    /// tests and performance validation; never affects semantics.
    pub iterations: u32,
    /// True when the worklist hit its safety cap before converging.
    /// Realistically shouldn't happen on sane programs —
    /// the cap exists to protect against pathological adapter output.
    pub saturated: bool,
    /// Diagnostics emitted for CFG shapes that force defensive
    /// analysis behavior. These are not parse diagnostics; they flag
    /// analyzer/adapter invariants that should be investigated.
    pub diagnostics: Vec<Diagnostic>,
}

impl IntraTaintResult {
    /// True when `name` appears in the taint state on entry to `block`
    /// (i.e. before the block's events execute).
    #[must_use]
    pub fn is_tainted_at_entry(&self, block: BasicBlockId, name: &str) -> bool {
        self.block_in
            .get(&block)
            .is_some_and(|state| state.contains(name))
    }

    /// True when `name` appears in the taint state on exit from `block`
    /// (i.e. after every event in the block has been transferred).
    #[must_use]
    pub fn is_tainted_at_exit(&self, block: BasicBlockId, name: &str) -> bool {
        self.block_out
            .get(&block)
            .is_some_and(|state| state.contains(name))
    }
}

use crate::text::{
    is_quoted_literal, normalise_qualified_text, qualified_access_bases, text_looks_qualified,
    value_bearing_identifier_text,
};

/// Run the intraprocedural analysis on a function's CFG.
///
/// Worklist iteration until convergence or a safety cap is reached
/// (explicit [`TaintConfig::worklist_cap`] when set, otherwise a CFG-size
/// derived cap). Every block visited at least
/// once; blocks whose `in` state changes force their successors back
/// onto the worklist.
#[must_use]
pub fn intraprocedural_taint(cfg: &Cfg, config: &TaintConfig) -> IntraTaintResult {
    let predecessors = build_predecessor_map(cfg);
    let diagnostics = entry_predecessor_diagnostics(cfg, &predecessors);
    let safety_cap = config.worklist_cap.unwrap_or_else(|| {
        (cfg.blocks.len() as u32)
            .saturating_mul(DEFAULT_WORKLIST_CAP_MULTIPLIER)
            .max(MIN_WORKLIST_CAP)
    });

    // Per-block in / out states. Start with every block empty and
    // the entry's in = sources.
    let mut block_in: AHashMap<BasicBlockId, TokenSet> = AHashMap::new();
    let mut block_out: AHashMap<BasicBlockId, TokenSet> = AHashMap::new();
    for block in &cfg.blocks {
        block_in.insert(block.id, TokenSet::default());
        block_out.insert(block.id, TokenSet::default());
    }
    block_in.insert(cfg.entry, config.sources.clone());

    let mut worklist: VecDeque<BasicBlockId> = VecDeque::new();
    worklist.push_back(cfg.entry);
    let mut enqueued: AHashSet<BasicBlockId> = AHashSet::new();
    enqueued.insert(cfg.entry);

    let mut iterations: u32 = 0;
    let mut saturated = false;
    while let Some(block_id) = worklist.pop_front() {
        enqueued.remove(&block_id);
        iterations += 1;
        // Safety cap: bail out before pathological adapter output spirals.
        if iterations > safety_cap {
            saturated = true;
            break;
        }

        let new_in = if block_id == cfg.entry {
            // Entry block's `in` always equals the sources. Joining
            // from predecessors here would dilute the seed if any
            // back-edge reaches the entry (shouldn't happen for
            // well-formed CFGs but is cheap to guard against).
            config.sources.clone()
        } else {
            // Forward-dataflow join: union every predecessor's `out`.
            let mut joined = TokenSet::default();
            if let Some(preds) = predecessors.get(&block_id) {
                for pred in preds {
                    if let Some(pred_out) = block_out.get(pred) {
                        joined.extend(pred_out.iter().cloned());
                    }
                }
            }
            joined
        };

        let Some(block) = cfg.block(block_id) else {
            continue;
        };
        let mut new_out = new_in.clone();
        transfer_events(&block.events, &mut new_out, config);

        block_in.insert(block_id, new_in);

        // Successors only need re-visiting when this block's exit state changed.
        let changed = block_out.get(&block_id).is_none_or(|prev| prev != &new_out);
        block_out.insert(block_id, new_out);

        if changed {
            for successor in &block.successors {
                // `enqueued.insert` doubles as a presence check — skip if already queued.
                if enqueued.insert(*successor) {
                    worklist.push_back(*successor);
                }
            }
        }
    }

    IntraTaintResult {
        block_in,
        block_out,
        iterations,
        saturated,
        diagnostics,
    }
}

/// Build a `successor → [predecessors]` map from the CFG's forward
/// edges. A helper the forward dataflow needs but the CFG itself
/// doesn't expose.
fn build_predecessor_map(cfg: &Cfg) -> AHashMap<BasicBlockId, Vec<BasicBlockId>> {
    let mut predecessors: AHashMap<BasicBlockId, Vec<BasicBlockId>> = AHashMap::new();
    for block in &cfg.blocks {
        for successor in &block.successors {
            predecessors.entry(*successor).or_default().push(block.id);
        }
    }
    predecessors
}

/// Emit a warning when the CFG entry block has incoming edges. The
/// dataflow contract says entry's `in` is always the configured
/// sources; if the CFG builder produced a back-edge or fallthrough
/// targeting entry, joining predecessor outputs would dilute that
/// seed. We surface the situation as a diagnostic rather than
/// silently changing semantics — the analysis itself stays
/// conservative (entry's seed is preserved).
fn entry_predecessor_diagnostics(
    cfg: &Cfg,
    predecessors: &AHashMap<BasicBlockId, Vec<BasicBlockId>>,
) -> Vec<Diagnostic> {
    let Some(preds) = predecessors.get(&cfg.entry).filter(|preds| !preds.is_empty()) else {
        return Vec::new();
    };
    let span = cfg
        .block(cfg.entry)
        .map_or_else(|| Span::empty(FileId::INVALID, 0), |block| block.span);
    let mut diagnostic = Diagnostic::new(
        span,
        Severity::Warning,
        format!(
            "CFG entry block has {} predecessor edge(s); intraprocedural taint keeps entry seeds and ignores predecessor output",
            preds.len()
        ),
    )
    .with_code("taint-entry-predecessor");
    diagnostic
        .notes
        .push("entry predecessors indicate an adapter or CFG-builder invariant drift".to_string());
    diagnostic
        .notes
        .push("propagation remains conservative by keeping the configured entry seed set".to_string());
    vec![diagnostic]
}

/// Apply the per-event taint transfer to `state` for every event in
/// a single basic block (in order). The CFG builder guarantees that
/// a block's `events` vec contains only straight-line events (Call,
/// Assign, Yield, Await, and terminal Return/Throw/Break/Continue).
/// Nested `Branch` / `Loop` / `Try` regions are structural and
/// handled at the CFG level, not here.
#[allow(clippy::single_match)] // preserved as `match` for parity with sibling event-walks
fn transfer_events(events: &[FlowEvent], state: &mut TokenSet, _config: &TaintConfig) {
    for (event_index, event) in events.iter().enumerate() {
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
                if assignment_has_precise_field_projection(events, event_index, event) {
                    remove_target_and_descendant_taint(state, target);
                    continue;
                }
                if let Some(callee) = source_call.as_deref() {
                    // Self-contained intra-pass heuristic for
                    // return-taint: if ANY positional arg at the call
                    // site is already tainted, assume the return
                    // inherits it. Security-conservative and matches
                    // `y = transform(tainted) → y tainted`. The full
                    // summary-driven version in the interprocedural
                    // pass narrows this for cross-function precision.
                    if state.contains(callee)
                        || text_is_tainted(callee, state)
                        || source_call_args
                            .iter()
                            .any(|arg| !arg.is_empty() && text_is_tainted(arg, state))
                    {
                        insert_target_taint(state, target);
                        if rhs_has_descendant_shape(source_names) {
                            insert_descendant_target_taint(state, target);
                        }
                        continue;
                    }
                    // No tainted operand at the call site, but the target
                    // is already tainted and the adapter gave us no extra
                    // RHS evidence — leave state alone rather than clearing.
                    if source_names.is_empty() && state.contains(target) {
                        continue;
                    }
                }
                // G2: compound-expression RHS. When the adapter
                // surfaced operand identifiers in `source_names` (e.g.
                // `y = prefix + tainted` → `source_names: ["prefix",
                // "tainted"]`), propagate taint from any tainted
                // operand to the target.
                if !source_names.is_empty() {
                    let qualified_bases = qualified_source_bases(source_names);
                    let any_tainted = source_names.iter().any(|name| {
                        // Skip the structural base of qualified accesses to avoid
                        // spurious matches against `obj` in `obj.field`.
                        !name.is_empty()
                            && !qualified_bases.contains(&canonical_bare_name(name))
                            && strict_operand_is_tainted(name, state)
                    });
                    if any_tainted {
                        insert_target_taint(state, target);
                        if rhs_has_descendant_shape(source_names) {
                            insert_descendant_target_taint(state, target);
                        }
                        continue;
                    }
                }
                match source_name.as_deref() {
                    Some(src) if strict_operand_is_tainted(src, state) => insert_target_taint(state, target),
                    Some(src) if copy_mapped_descendant_taint(state, target, src) => {}
                    Some(_) | None => {
                        // Semantic overwrite: assigning a value with
                        // no tainted operands kills the target's
                        // previous taint. Source rules that model
                        // external input seed the assigned target
                        // directly; preserving here incorrectly
                        // reports `x = tainted; x = "constant";
                        // sink(x)`.
                        state.remove(target);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Add `target` to the taint state. Also inserts the bare-stripped
/// form (without `$`, `@`, `%` sigils) so propagation against PHP /
/// Perl / Ruby variables matches both the sigil and bare flavours.
fn insert_target_taint(state: &mut TokenSet, target: &str) {
    let target = normalise_target_text(target);
    if target.is_empty() {
        return;
    }
    state.insert(target.clone());
    // Sigil-stripped form lets `$foo` and `foo` both be queried later.
    let bare = target.trim_start_matches(&['$', '@', '%'][..]);
    if bare != target && !bare.is_empty() {
        state.insert(bare.to_string());
    }
}

/// Insert the wildcard-descendant form `target.*` into the taint
/// state. Skips qualified or already-wildcarded targets so we never
/// double-suffix or generate `obj.field.*`.
fn insert_descendant_target_taint(state: &mut TokenSet, target: &str) {
    let target = normalise_target_text(target);
    if target.is_empty() || text_looks_qualified(&target) || target.ends_with(".*") {
        return;
    }
    state.insert(format!("{target}.*"));
}

fn strict_operand_is_tainted(text: &str, state: &TokenSet) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || is_quoted_literal(trimmed) {
        return false;
    }
    if state.contains(trimmed) {
        return true;
    }
    let sigil_stripped = trimmed.trim_start_matches(&['$', '@', '%'][..]);
    if sigil_stripped != trimmed && state.contains(sigil_stripped) {
        return true;
    }
    if receiver_method_projection_is_tainted(trimmed, state) {
        return true;
    }
    let normalised = normalise_qualified_text(trimmed);
    let collapsed_to_base = text_looks_qualified(trimmed) && !text_looks_qualified(&normalised);
    if normalised != trimmed && !collapsed_to_base && state.contains(&normalised) {
        return true;
    }
    text_looks_qualified(trimmed) && qualified_wildcard_seed_matches(&normalised, state)
}

fn assignment_has_precise_field_projection(
    events: &[FlowEvent],
    event_index: usize,
    event: &FlowEvent,
) -> bool {
    let FlowEvent::Assign { target, span, .. } = event else {
        return false;
    };
    let base = normalise_target_text(target);
    if base.is_empty() || text_looks_qualified(&base) {
        return false;
    }
    let prefix = format!("{base}.");
    events.iter().enumerate().any(|(idx, candidate)| {
        if idx == event_index {
            return false;
        }
        let FlowEvent::Assign {
            target: candidate_target,
            span: candidate_span,
            ..
        } = candidate
        else {
            return false;
        };
        if candidate_span != span {
            return false;
        }
        normalise_target_text(candidate_target).starts_with(&prefix)
    })
}

fn copy_mapped_descendant_taint(state: &mut TokenSet, target: &str, actual_text: &str) -> bool {
    let target = normalise_target_text(target);
    let actual = normalise_target_text(actual_text);
    if target.is_empty()
        || actual.is_empty()
        || text_looks_qualified(&target)
        || text_looks_qualified(&actual)
        || !is_bare_identifier_text(&actual)
    {
        return false;
    }
    let mut changed = false;
    let wildcard = format!("{actual}.*");
    for seed in state.clone() {
        let seed = normalise_qualified_text(&seed);
        if seed == wildcard {
            let before = state.len();
            insert_descendant_target_taint(state, &target);
            changed |= state.len() != before;
            continue;
        }
        let Some(tail) = seed.strip_prefix(actual.as_str()) else {
            continue;
        };
        if !tail.starts_with('.') {
            continue;
        }
        let before = state.len();
        insert_target_taint(state, &format!("{target}{tail}"));
        changed |= state.len() != before;
    }
    changed
}

fn remove_target_and_descendant_taint(state: &mut TokenSet, target: &str) {
    let target = normalise_target_text(target);
    if target.is_empty() {
        return;
    }
    state.remove(&target);
    state.remove(&format!("{target}.*"));
    let prefix = format!("{target}.");
    state.retain(|seed| {
        let normalised = normalise_qualified_text(seed);
        !seed.starts_with(&prefix) && !normalised.starts_with(&prefix)
    });
}

fn is_bare_identifier_text(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty() && text.chars().all(is_identifier_byteish)
}

fn is_identifier_byteish(ch: char) -> bool {
    ch == '_' || ch == '$' || ch == '@' || ch == '%' || ch.is_ascii_alphanumeric()
}

/// True when the RHS surface contains at least two distinct bare
/// identifiers — the gate that promotes a target to wildcard
/// descendant taint (`target.*`) for "constructed" values vs. plain
/// aliasing.
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

/// Strip pointer / reference prefixes (`*`, `&`) from a target after
/// general qualified-text normalisation. Used so `*raw` and `&raw`
/// alias to the same `raw` identifier in the state.
fn normalise_target_text(target: &str) -> String {
    normalise_qualified_text(target)
        .trim_start_matches(bonsai_common::REFERENCE_SIGILS)
        .trim()
        .to_string()
}

/// True when `text` references any tainted identifier — by direct
/// match, qualified-access prefix, wildcard seed (`obj.*`), receiver
/// method projection, or any bare identifier token outside string
/// literals.
fn text_is_tainted(text: &str, state: &TokenSet) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if tainted_receiver_access(trimmed, state) {
        return true;
    }
    if receiver_method_projection_is_tainted(trimmed, state) {
        return true;
    }
    if state.contains(trimmed) {
        return true;
    }
    let normalised = normalise_qualified_text(trimmed);
    // Detect when normalisation collapsed a qualified expression down to its base
    // — e.g. `obj[x]` → `obj`. We don't want that degenerate match to leak
    // taint via the bare `obj` token; the caller's wildcard / qualified checks handle it.
    let collapsed_to_base = (trimmed.contains('.') || trimmed.contains('[') || trimmed.contains("->"))
        && !(normalised.contains('.') || normalised.contains('[') || normalised.contains("->"));
    if normalised != trimmed && !collapsed_to_base && state.contains(&normalised) {
        return true;
    }
    state_qualified_token_matches_text(&normalised, state)
        || state_qualified_token_matches_text(trimmed, state)
        || {
            let qualified_bases = qualified_access_bases(trimmed);
            identifier_tokens_outside_strings(&value_bearing_identifier_text(trimmed))
                .iter()
                .any(|token| {
                    // Skip qualified-access bases — those are structural and
                    // would over-match if treated as bare references.
                    !qualified_bases.iter().any(|base| base == token) && state.contains(token.as_str())
                })
        }
}

/// Collect the leftmost identifier of every qualified access in
/// `source_names`. Used to mask structural `obj` occurrences when
/// scanning bare RHS operands for taint.
fn qualified_source_bases(source_names: &[String]) -> ahash::AHashSet<String> {
    let mut bases = ahash::AHashSet::new();
    for source in source_names {
        for base in qualified_access_bases(source) {
            bases.insert(base);
        }
    }
    bases
}

/// Strip qualifier sigils and whitespace to produce the canonical
/// bare-identifier form used for de-duplication and set membership.
fn canonical_bare_name(text: &str) -> String {
    normalise_qualified_text(text)
        .trim_start_matches(&['$', '@', '%'][..])
        .trim()
        .to_string()
}

/// True when `text` matches the BASE of any qualified seed in
/// `state`. Catches `obj` references when the tracked seed is
/// `obj.field`. Mirrors the inter helper: base only, never the tail,
/// so a qualified seed (`obj.field`) does not promote an unrelated
/// bare local named `field` (M5 precision parity).
fn state_qualified_token_matches_text(text: &str, state: &TokenSet) -> bool {
    if text.is_empty() {
        return false;
    }
    state.iter().any(|seed| {
        let normalised = normalise_qualified_text(seed);
        if !normalised.contains('.') {
            return false;
        }
        let mut parts = normalised.split('.');
        let base = parts.next().unwrap_or_default();
        text == base
    })
}

/// True when `text` is itself a qualified access whose receiver is
/// tainted — either via wildcard seed (`obj.*`) or explicit qualified
/// seed prefix matching.
fn tainted_receiver_access(text: &str, state: &TokenSet) -> bool {
    let normalised = normalise_qualified_text(text);
    if qualified_wildcard_seed_matches(&normalised, state) {
        return true;
    }
    state.iter().any(|seed| {
        if !text_looks_qualified(seed) {
            return false;
        }
        let seed = normalise_qualified_text(seed);
        !seed.is_empty()
            && (normalised == seed
                || normalised
                    .strip_prefix(seed.as_str())
                    .is_some_and(|rest| rest.starts_with('.')))
    })
}

/// True when `text` contains a `receiver.method(...)` call shape and
/// the receiver is tainted. Catches `tainted.format(...)` patterns
/// where the call expression as a whole isn't a tracked identifier
/// but the receiver alone propagates taint.
fn receiver_method_projection_is_tainted(text: &str, state: &TokenSet) -> bool {
    for open_paren in text.match_indices('(').map(|(idx, _)| idx) {
        let before_call = text[..open_paren].trim_end();
        // Walk back from the `(` over identifier-ish characters to find the
        // start of the callee expression. char_indices keeps us on UTF-8 boundaries.
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
            && (state.contains(&receiver) || qualified_wildcard_seed_matches(&receiver, state))
        {
            return true;
        }
    }
    false
}

/// True when any seed in `state` is the wildcard form `prefix.*` and
/// `normalised_text` matches that prefix exactly or is a strict
/// descendant (`prefix.field`, `prefix.a.b`).
fn qualified_wildcard_seed_matches(normalised_text: &str, state: &TokenSet) -> bool {
    state.iter().any(|seed| {
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

/// Lex `text` into identifier tokens, skipping content inside single,
/// double, or backtick string literals. Lets a tainted identifier
/// inside a quoted string not be treated as a real reference.
fn identifier_tokens_outside_strings(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
            // Inside a string — only watch for the closing quote / escapes.
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
            // Flush the in-progress identifier before entering string scope.
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

/// Flush `current` as an identifier — but only when it starts with a
/// letter or underscore. Numeric-leading runs are literal fragments,
/// not identifiers, so they're discarded.
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
#[path = "intra_tests.rs"]
mod tests;
