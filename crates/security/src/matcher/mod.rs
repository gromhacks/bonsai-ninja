//! Match a rule against the workspace's browse facts.
//!
//! The matcher is **purely fact-level**: it never walks the tracer, never
//! builds chains, and never calls the resolver directly. Call-chain
//! enumeration and taint filtering are the job of `bonsai_inspect` via
//! [`crate::compile`]. The matcher just tells callers *which facts* in the
//! workspace look like a source / sink / sanitizer.

use crate::rule::{ArgTaintedSpec, ConstraintKind, MatchKind, Rule, RuleTarget};
use ahash::{AHashMap, AHashSet};
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{AliasTarget, CallArg, CallKind, Decl, DeclKind, FlowEvent, RefKind, TypeAliasBinding};
use bonsai_taint::{TaintedCall, TaintedCallKind};
use bonsai_workspace::Workspace;
use regex::Regex;
use std::{cell::RefCell, sync::Arc};

/// Current matcher policy fingerprint. The dataflow sidecar stores
/// this value so matcher-policy upgrades invalidate cached graph
/// projections that downstream security reports depend on.
pub const MATCHER_POLICY_FINGERPRINT: u128 = bonsai_common::MATCHER_POLICY_FINGERPRINT;

/// One rule the runtime matcher dropped at preparation time. Surfaced
/// in [`crate::report::SecurityReport`] so users see *why* a rule
/// failed instead of having to grep `tracing::warn` output. Per
/// `docs/security-spec.mdx`: pack-validate's `disabled_reason` field
/// captures static schema problems; this counterpart captures the
/// per-run failures the matcher detects after rules have already
/// loaded (e.g., a regex that compiled in the schema test but blew
/// up against this workspace's compiled regex flags).
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct RuntimeDisabledRule {
    pub rule_id: String,
    pub reason: String,
}

thread_local! {
    static RUNTIME_DISABLED_RULES: RefCell<Vec<RuntimeDisabledRule>> = const { RefCell::new(Vec::new()) };
}

/// Capture every runtime-disabled rule produced inside `analyze` and
/// return them. Calling this resets the collector for the current
/// thread so subsequent calls capture only new disablements.
#[must_use]
pub fn drain_runtime_disabled_rules() -> Vec<RuntimeDisabledRule> {
    RUNTIME_DISABLED_RULES.with(|slot| std::mem::take(&mut *slot.borrow_mut()))
}

/// Push one disablement record into the per-thread collector, skipping
/// duplicates. Called from prep paths (regex compile, constraint
/// regex compile) when a rule cannot be made runnable for this run.
fn record_runtime_disabled_rule(rule_id: &str, reason: impl Into<String>) {
    let entry = RuntimeDisabledRule {
        rule_id: rule_id.to_string(),
        reason: reason.into(),
    };
    RUNTIME_DISABLED_RULES.with(|slot| {
        let mut slot = slot.borrow_mut();
        // De-dup: a rule can fail prep multiple times within one
        // analysis run when reused across worker threads.
        if !slot.iter().any(|existing| existing == &entry) {
            slot.push(entry);
        }
    });
}

/// One rule match — the specific fact + location that triggered.
#[derive(Clone, Debug)]
pub struct RuleMatch {
    pub rule_id: String,
    pub language: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    /// Exact fact span in the indexed file. Renderers use line/column,
    /// but taint consumers need the byte span to correlate a rule hit
    /// with the precise call/write event instead of only the enclosing
    /// function.
    pub span: Span,
    pub match_text: String,
    /// The enclosing function's display name, when resolvable.
    pub enclosing_fn: Option<String>,
}

/// Taint facts scoped to one interprocedural source graph. The matcher
/// uses this only for `arg_tainted`; keeping the verdict cache on the
/// view prevents one source graph's tainted argument set from affecting
/// another graph.
pub struct InterTaintView<'a> {
    calls_by_span: AHashMap<Span, Vec<&'a TaintedCall>>,
    calls: Vec<&'a TaintedCall>,
    /// `Mutex` instead of `RefCell` so the view is `Sync` — required
    /// when the matcher's outer file loop runs in parallel via
    /// rayon. Cache reads are short and contention-free in practice
    /// (most ruleset+file combinations miss or hit at most once),
    /// so the lock is not a measurable cost.
    verdict_cache: parking_lot::Mutex<AHashMap<(String, FileId, u64, u64), bool>>,
}

type CalleeCallsView<'a> = (
    std::borrow::Cow<'a, [CallFact]>,
    Option<std::collections::HashMap<String, AliasTarget>>,
    Option<&'a std::collections::HashMap<String, AliasTarget>>,
);

impl<'a> InterTaintView<'a> {
    /// Build a view over the engine's tainted-call records. Pre-bins
    /// calls by span so the hot lookup path in `arg_is_tainted` is
    /// O(1) on the common (single-span) case.
    #[must_use]
    pub fn new(calls: &'a [TaintedCall]) -> Self {
        let mut calls_by_span: AHashMap<Span, Vec<&'a TaintedCall>> = AHashMap::new();
        for call in calls {
            calls_by_span.entry(call.call_span).or_default().push(call);
        }
        Self {
            calls_by_span,
            calls: calls.iter().collect(),
            verdict_cache: parking_lot::Mutex::new(AHashMap::new()),
        }
    }

    /// Check the per-rule cached verdict for a span, if any.
    fn cached_verdict(&self, rule_id: &str, span: Span) -> Option<bool> {
        self.verdict_cache
            .lock()
            .get(&(rule_id.to_string(), span.file, span.start, span.end))
            .copied()
    }

    /// Cache a verdict. Only positive verdicts are stored — a `false`
    /// verdict often hinges on context that may shift between calls
    /// (e.g. assignment-text presence), so caching it would risk
    /// returning stale `false`s.
    fn store_verdict(&self, rule_id: &str, span: Span, verdict: bool) {
        if !verdict {
            return;
        }
        self.verdict_cache
            .lock()
            .insert((rule_id.to_string(), span.file, span.start, span.end), verdict);
    }

    /// True when the engine recorded the indexed arg (or matching
    /// keyword arg) of the call at `span` as tainted on the current
    /// source's graph. Falls back to overlapping-span scan when no
    /// exact span match exists.
    #[must_use]
    pub fn arg_is_tainted(
        &self,
        span: Span,
        args: &[CallArg],
        spec: &ArgTaintedSpec,
        allow_synthetic_write: bool,
    ) -> bool {
        let Some(index) = resolve_arg_tainted_index(args, spec) else {
            return false;
        };
        let arg_value = args.get(index).map(|arg| arg.value_text.trim());
        // Hot path: span-equality lookup against pre-binned calls.
        if self.calls_by_span.get(&span).is_some_and(|calls| {
            calls
                .iter()
                .any(|call| tainted_call_has_arg(call, index, arg_value, true, allow_synthetic_write))
        }) {
            return true;
        }
        // Fallback: overlap-only check for cross-line / multi-call
        // expressions where the matcher and engine spans diverge.
        self.calls.iter().any(|call| {
            spans_overlap(span, call.call_span)
                && tainted_call_has_arg(call, index, arg_value, false, allow_synthetic_write)
        })
    }

    /// True when any syntactic call-site argument at `span` is
    /// recorded as tainted on the current source's graph. This is for
    /// APIs whose dangerous payload can live in any argument slot;
    /// APIs with a specific dangerous operand should use
    /// `arg_tainted` instead.
    #[must_use]
    pub fn any_arg_is_tainted(&self, span: Span, args: &[CallArg], allow_synthetic_write: bool) -> bool {
        (0..args.len()).any(|index| {
            let spec = ArgTaintedSpec {
                index: Some(index as u32),
                kw: None,
            };
            self.arg_is_tainted(span, args, &spec, allow_synthetic_write)
        })
    }

    /// True when the engine recorded the call receiver at `span` as
    /// tainted on the current source graph. This covers receiver-state
    /// APIs such as `tainted.!` and `target.delegatecall("")`, where
    /// the dangerous operand is not a syntactic argument.
    #[must_use]
    pub fn receiver_is_tainted(&self, span: Span) -> bool {
        if self.calls_by_span.get(&span).is_some_and(|calls| {
            calls
                .iter()
                .any(|call| call.kind == TaintedCallKind::Call && call.tainted_receiver.is_some())
        }) {
            return true;
        }
        self.calls.iter().any(|call| {
            call.kind == TaintedCallKind::Call
                && call.tainted_receiver.is_some()
                && spans_overlap(span, call.call_span)
        })
    }
}

/// True when the engine's `TaintedCall` carries an arg at `index`
/// (when index-matching is allowed) OR an arg whose textual identity
/// matches the syntactic arg the matcher is looking at, OR the
/// receiver carries the arg's identifier.
fn tainted_call_has_arg(
    call: &TaintedCall,
    index: usize,
    arg_value: Option<&str>,
    allow_index_match: bool,
    allow_synthetic_write: bool,
) -> bool {
    if call.kind != TaintedCallKind::Call && !(allow_synthetic_write && call.kind == TaintedCallKind::Write) {
        return false;
    }
    call.tainted_args.iter().any(|tainted| {
        (allow_index_match && tainted.index == index)
            || arg_value.is_some_and(|value| arg_matches_tainted_value(value, &tainted.value_text))
    }) || call
        .tainted_receiver
        .as_deref()
        .is_some_and(|receiver| arg_value.is_some_and(|value| arg_matches_tainted_receiver(value, receiver)))
}

/// Compare the matcher's arg text against an engine-recorded tainted
/// value. Exact equality first; falls back to "the tainted value is a
/// simple identifier referenced inside the larger argument expression"
/// (e.g. tainted `x` referenced in `f(x.y)`).
fn arg_matches_tainted_value(arg_value: &str, tainted_value: &str) -> bool {
    let arg_value = arg_value.trim();
    let tainted_value = tainted_value.trim();
    if arg_value.is_empty() || tainted_value.is_empty() {
        return false;
    }
    if arg_value == tainted_value {
        return true;
    }
    !quoted_literal(arg_value)
        && is_simple_identifier(tainted_value)
        && expression_contains_identifier(arg_value, tainted_value)
}

/// True when the matcher's arg expression names the same identifier
/// that the engine recorded as a tainted receiver (e.g. arg
/// expression `req` against tainted receiver `req.body`). Quoted
/// string literals are rejected — they can't be identifier hits.
fn arg_matches_tainted_receiver(arg_value: &str, receiver: &str) -> bool {
    let arg_value = arg_value.trim();
    if arg_value.is_empty() || quoted_literal(arg_value) {
        return false;
    }
    if is_simple_identifier(arg_value) {
        return expression_contains_identifier(receiver, arg_value);
    }
    receiver.contains(arg_value)
}

/// True when `value` starts with a string-literal quote character.
/// Used to reject literal args from receiver-identifier matching.
fn quoted_literal(value: &str) -> bool {
    matches!(value.as_bytes().first(), Some(b'"' | b'\'' | b'`'))
}

/// True when `expr` references `needle` as a standalone identifier
/// token. Splits on non-identifier chars so `x.y` contains both `x`
/// and `y` but not `xy`.
fn expression_contains_identifier(expr: &str, needle: &str) -> bool {
    expr.split(|ch: char| !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()))
        .any(|token| token == needle)
}

/// True when two spans share at least one byte. File ids must match —
/// cross-file spans never overlap even if their byte ranges happen
/// to coincide.
fn spans_overlap(a: Span, b: Span) -> bool {
    a.file == b.file && a.start < b.end && b.start < a.end
}

/// Scan every file for rule matches. Language-aware: a rule only runs
/// against files whose adapter matches the rule's `language` field.
/// Single-rule wrapper around the batch API — kept for unit tests
/// and narrow callers.
pub fn match_rule_against_facts(ws: &Workspace, rule: &Rule) -> Vec<RuleMatch> {
    match_rules_against_facts(ws, &[rule])
}

/// Batch-match rules against workspace facts. This is the fast path for
/// `security sources` / `sinks` / `sanitizers`: walk each indexed file's
/// facts once, then test the selected rules against those facts. The
/// older one-rule API above is kept for unit tests and narrow callers.
#[must_use]
pub fn match_rules_against_facts(ws: &Workspace, rules: &[&Rule]) -> Vec<RuleMatch> {
    match_rules_against_facts_with_progress(ws, rules, || {})
}

/// Batch matcher with a per-file progress callback.
pub fn match_rules_against_facts_with_progress<F>(
    ws: &Workspace,
    rules: &[&Rule],
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        ConstraintMode::Strict,
        None,
    )
}

/// Match one rule with access to the engine's tainted-call view.
/// Used by sink-side constraint evaluation when the rule includes
/// `arg_tainted` constraints — without the view, `arg_tainted` has
/// nothing to consult and rejects every site.
pub(crate) fn match_rule_against_facts_with_taint_view(
    ws: &Workspace,
    rule: &Rule,
    taint_view: &InterTaintView<'_>,
) -> Vec<RuleMatch> {
    let mut on_file_done = || {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        &[rule],
        &mut on_file_done,
        ConstraintMode::Strict,
        Some(taint_view),
    )
}

/// Re-evaluate `rule` against the workspace with taint context, and
/// return whether the specific `expected` hit (rule_id + span) still
/// passes. Used by chain-aware finding assembly to recheck sink
/// constraints once the source's taint graph is known.
pub(crate) fn rule_match_passes_constraints_with_taint_view(
    ws: &Workspace,
    rule: &Rule,
    expected: &RuleMatch,
    taint_view: &InterTaintView<'_>,
) -> bool {
    let Some(prepared) = PreparedRule::new(rule) else {
        return false;
    };
    if let Some(verdict) =
        exact_rule_match_passes_constraints_at_expected_hit(ws, &prepared, expected, taint_view)
    {
        return verdict;
    }
    match_rule_against_facts_with_taint_view(ws, rule, taint_view)
        .into_iter()
        .any(|hit| hit.rule_id == expected.rule_id && hit.span == expected.span)
}

fn exact_rule_match_passes_constraints_at_expected_hit(
    ws: &Workspace,
    prepared: &PreparedRule<'_>,
    expected: &RuleMatch,
    taint_view: &InterTaintView<'_>,
) -> Option<bool> {
    // Taint-analysis already has the exact endpoint span from the
    // constraint-agnostic sink scan. Rebuild the same per-fact
    // constraint context for supported endpoint kinds instead of
    // scanning the whole workspace for one `(rule, span)` verdict.
    if prepared.rule.language != expected.language || prepared.rule.id != expected.rule_id {
        return Some(false);
    }
    match prepared.rule.match_spec.kind {
        MatchKind::Call | MatchKind::New => Some(call_rule_match_passes_constraints_at_expected_hit(
            ws, prepared, expected, taint_view,
        )),
        MatchKind::Write => Some(write_rule_match_passes_constraints_at_expected_hit(
            ws, prepared, expected, taint_view,
        )),
        MatchKind::Read | MatchKind::Return | MatchKind::Param | MatchKind::Missing => None,
    }
}

fn call_rule_match_passes_constraints_at_expected_hit(
    ws: &Workspace,
    prepared: &PreparedRule<'_>,
    expected: &RuleMatch,
    taint_view: &InterTaintView<'_>,
) -> bool {
    let file = expected.span.file;
    let global = ws.db().global_index();
    let file_packages = file_package_set(ws, file);
    let bundle = decl_match_facts_for(ws, file);
    let constructor_names = if prepared.rule.match_spec.kind == MatchKind::New {
        collect_constructor_names(global.as_ref())
    } else {
        AHashSet::new()
    };

    for decl in global.decls_in(file) {
        if expected
            .enclosing_fn
            .as_ref()
            .is_some_and(|name| name != &decl.name)
        {
            continue;
        }
        let Some(facts) = bundle.by_decl_span.get(&decl.span) else {
            continue;
        };
        for call in facts.calls.iter().filter(|call| call.span == expected.span) {
            let Some(matched_callee) = callee_or_alias_matches(
                &call.callee,
                &call.receiver_types,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
                &facts.alias_map,
            ) else {
                continue;
            };
            if !prepared.call_context_allows(
                &call.callee,
                &call.receiver_types,
                &facts.alias_map,
                file_packages.as_ref(),
            ) {
                continue;
            }
            if prepared.rule.match_spec.kind == MatchKind::New
                && call.call_kind != CallKind::Constructor
                && !constructor_name_matches(&call.callee, &constructor_names)
            {
                continue;
            }
            let receiver_call_count =
                receiver_method_key(&call.callee).and_then(|key| facts.receiver_counts.get(&key).copied());
            if constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &matched_callee,
                args: &call.args,
                receiver_types: &call.receiver_types,
                span: call.span,
                call_origin: Some(call.origin),
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count,
                assignment_texts: Some(&facts.assignment_map),
                mode: ConstraintMode::Strict,
                taint_view: Some(taint_view),
                enclosing_decorators: Some(facts.decl_decorators.as_slice()),
                alias_chains: Some(&facts.alias_chains),
                runtime_types: Some(&facts.runtime_types),
                lifecycle_transitions: Some(&facts.lifecycle_transitions),
            }) {
                return true;
            }
        }
    }
    false
}

fn write_rule_match_passes_constraints_at_expected_hit(
    ws: &Workspace,
    prepared: &PreparedRule<'_>,
    expected: &RuleMatch,
    taint_view: &InterTaintView<'_>,
) -> bool {
    let file = expected.span.file;
    let global = ws.db().global_index();
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let file_packages = file_package_set(ws, file);
    let alias_map = file_alias_map(ws, file);

    for decl in global.decls_in(file) {
        if expected
            .enclosing_fn
            .as_ref()
            .is_some_and(|name| name != &decl.name)
        {
            continue;
        }
        for (target, span) in collect_writes(&decl.flow_events) {
            if span != expected.span {
                continue;
            }
            if !callee_matches(
                &target,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
            ) {
                continue;
            }
            if !prepared.call_context_allows(&target, &[], &alias_map, file_packages.as_ref()) {
                continue;
            }
            let args = write_args_from_source_text(source_text.as_deref(), span);
            if constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &target,
                args: &args,
                receiver_types: &[],
                span,
                call_origin: Some(CallFactOrigin::SyntheticWrite),
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count: None,
                assignment_texts: None,
                mode: ConstraintMode::Strict,
                taint_view: Some(taint_view),
                enclosing_decorators: None,
                alias_chains: None,
                runtime_types: None,
                lifecycle_transitions: None,
            }) {
                return true;
            }
        }
    }

    let Some(idx) = ws.db().decl_index(file) else {
        return false;
    };
    for r in &idx.refs {
        if r.kind != RefKind::Write || r.span != expected.span {
            continue;
        }
        if !callee_matches(
            &r.name,
            prepared.name,
            prepared.attribute,
            prepared.regex.as_ref(),
        ) {
            continue;
        }
        let args = write_args_from_source_text(source_text.as_deref(), r.span);
        if constraints_pass(ConstraintEval {
            rule_id: &prepared.rule.id,
            callee: &r.name,
            args: &args,
            receiver_types: &[],
            span: r.span,
            call_origin: Some(CallFactOrigin::SyntheticWrite),
            constraints: &prepared.rule.constraints.0,
            constraint_regexes: &prepared.constraint_regexes,
            receiver_call_count: None,
            assignment_texts: None,
            mode: ConstraintMode::Strict,
            taint_view: Some(taint_view),
            enclosing_decorators: None,
            alias_chains: None,
            runtime_types: None,
            lifecycle_transitions: None,
        }) {
            return true;
        }
    }
    false
}

fn write_args_from_source_text(source_text: Option<&str>, span: Span) -> Vec<CallArg> {
    source_text
        .and_then(|text| text.get(span.start as usize..span.end as usize))
        .map(|value_text| {
            vec![CallArg {
                span,
                name: None,
                place: None,
                source_names: Vec::new(),
                value_text: value_text.to_string(),
            }]
        })
        .unwrap_or_default()
}

pub(crate) fn rule_example_has_arg_index(ws: &Workspace, rule: &Rule, wanted_index: u32) -> bool {
    let Some(prepared) = PreparedRule::new(rule) else {
        return false;
    };
    let wanted_index = wanted_index as usize;
    let db = ws.db();
    let global = db.global_index();
    let constructor_names = if rule.match_spec.kind == MatchKind::New {
        collect_constructor_names(global.as_ref())
    } else {
        AHashSet::new()
    };

    for file in global.all_files() {
        let Some(adapter) = ws.db().adapter_for(file) else {
            continue;
        };
        if adapter.language_id().as_str() != rule.language {
            continue;
        }
        match rule.match_spec.kind {
            MatchKind::Call | MatchKind::New => {
                if matching_call_has_arg_index(ws, file, &prepared, &constructor_names, wanted_index) {
                    return true;
                }
            }
            MatchKind::Write => {
                if wanted_index == 0 && matching_write_exists(ws, file, &prepared) {
                    return true;
                }
            }
            // Missing-kind rules don't surface arg evidence — they fire on
            // absence of a call, not on a specific call site.
            MatchKind::Read | MatchKind::Return | MatchKind::Param | MatchKind::Missing => {}
        }
    }
    false
}

/// Matcher mode used by taint-analysis for sink endpoint discovery. The
/// semantic taint graph is authoritative for whether user-controlled
/// data reaches a sink, so sink-side constraints are ignored in this
/// mode.
pub(crate) fn match_rules_against_facts_for_taint_with_progress<F>(
    ws: &Workspace,
    rules: &[&Rule],
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        ConstraintMode::TaintEndpoint,
        None,
    )
}

/// Sink-inventory matcher: ignores `arg_tainted` constraints (the
/// inventory lists every potential sink site, regardless of whether
/// the current workspace has data flowing into it). All other
/// constraints still apply.
pub(crate) fn match_rules_against_facts_for_sink_inventory(
    ws: &Workspace,
    rules: &[&Rule],
) -> Vec<RuleMatch> {
    let mut on_file_done = || {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        ConstraintMode::SinkInventory,
        None,
    )
}

fn match_rules_against_facts_with_progress_and_mode<F>(
    ws: &Workspace,
    rules: &[&Rule],
    on_file_done: &mut F,
    mode: ConstraintMode,
    taint_view: Option<&InterTaintView<'_>>,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    use rayon::prelude::*;
    let db = ws.db();
    let global = db.global_index();
    let prepared: Vec<PreparedRule<'_>> = rules.iter().filter_map(|rule| PreparedRule::new(rule)).collect();
    if prepared.is_empty() {
        return Vec::new();
    }
    let constructor_names = if prepared.iter().any(|r| r.rule.match_spec.kind == MatchKind::New) {
        collect_constructor_names(global.as_ref())
    } else {
        AHashSet::new()
    };
    // Each `scan_file_rules` writes only to its own per-file Vec —
    // no shared state across files — so file-level work is
    // embarrassingly parallel. `par_iter` distributes files across
    // rayon's pool; per-thread match Vecs are flat-mapped at the
    // join. Match collection order is non-deterministic across
    // runs, but downstream callers already invoke `sort_matches` on
    // the returned Vec before emission to keep finding ids stable.
    let files: Vec<_> = global.all_files().collect();
    let total = files.len();
    let out: Vec<RuleMatch> = files
        .par_iter()
        .flat_map_iter(|&file| {
            let mut file_out: Vec<RuleMatch> = Vec::new();
            if let Some(adapter) = ws.db().adapter_for(file) {
                let language = adapter.language_id();
                let file_rules: Vec<&PreparedRule<'_>> = prepared
                    .iter()
                    .filter(|rule| rule.rule.language == language.as_str())
                    .collect();
                if !file_rules.is_empty() {
                    scan_file_rules(
                        ws,
                        file,
                        &file_rules,
                        &constructor_names,
                        mode,
                        taint_view,
                        &mut file_out,
                    );
                }
            }
            file_out
        })
        .collect();
    // Drain progress ticks after the parallel work completes.
    // `on_file_done` is `FnMut` and not Sync; a per-tick callback
    // mid-scan would force serialisation. Bulk-replaying the count
    // here keeps the progress UI in sync without sacrificing the
    // parallel speedup.
    for _ in 0..total {
        on_file_done();
    }
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConstraintMode {
    Strict,
    SinkInventory,
    TaintEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)] // deliberate `*Call` suffix — describes call-site origin
enum CallFactOrigin {
    RealCall,
    NestedReceiverCall,
    AssignmentSourceCall,
    SyntheticWrite,
}

#[derive(Clone, Debug)]
struct CallFact {
    callee: String,
    span: Span,
    args: Vec<CallArg>,
    receiver_types: Vec<String>,
    call_kind: CallKind,
    origin: CallFactOrigin,
}

impl ConstraintMode {
    /// True when only `arg_tainted` constraints should be skipped.
    /// Sink-inventory and initial taint-endpoint matching preserve
    /// structural constraints (arg counts, namespace, regexes, etc.)
    /// but cannot consult the per-source taint view yet. The
    /// source-specific taint pass rechecks arg-taint constraints
    /// before emitting a finding.
    fn ignore_arg_tainted(self) -> bool {
        matches!(self, Self::SinkInventory | Self::TaintEndpoint)
    }
}

struct PreparedRule<'a> {
    rule: &'a Rule,
    name: Option<&'a str>,
    attribute: Option<&'a Vec<String>>,
    regex: Option<Regex>,
    base_name_in: &'a [String],
    requires_call_package_signal: bool,
    constraint_regexes: Vec<Option<Regex>>,
    /// The rule's `packages` ∪ `imports` ∪ `modules`, in the
    /// canonical ecosystem-name form the rule pack uses. Borrowed
    /// from the rule (never owned) so this stays cheap.
    package_signals: Vec<&'a str>,
}

impl<'a> PreparedRule<'a> {
    fn new(rule: &'a Rule) -> Option<Self> {
        let target = match rule.match_spec.kind {
            // Missing rules use `callee` as the *expected* target — when
            // it doesn't appear on a path, the rule fires.
            MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
            MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
                rule.match_spec.target.as_ref()
            }
        }?;
        let mut package_signals: Vec<&str> = Vec::new();
        for signal in rule
            .packages
            .iter()
            .chain(rule.imports.iter())
            .chain(rule.modules.iter())
        {
            if !package_signals.contains(&signal.as_str()) {
                package_signals.push(signal.as_str());
            }
        }
        let requires_call_package_signal = rule_requires_call_package_signal(rule);
        let regex = match target.regex.as_deref() {
            Some(pattern) => match Regex::new(pattern) {
                Ok(regex) => Some(regex),
                Err(error) => {
                    tracing::warn!(
                        rule_id = %rule.id,
                        field = "match.callee.regex/match.target.regex",
                        regex = %pattern,
                        %error,
                        "invalid rule target regex; rule disabled for this analysis run"
                    );
                    record_runtime_disabled_rule(
                        &rule.id,
                        format!("invalid match target regex `{pattern}`: {error}"),
                    );
                    return None;
                }
            },
            None => None,
        };
        let constraint_regexes = compile_constraint_regexes(&rule.id, &rule.constraints.0)?;
        Some(Self {
            rule,
            name: target.name.as_deref(),
            attribute: target.attribute.as_ref(),
            regex,
            base_name_in: target.base_name_in.as_slice(),
            requires_call_package_signal,
            constraint_regexes,
            package_signals,
        })
    }

    fn base_name_allows(&self, text: &str) -> bool {
        if self.base_name_in.is_empty() {
            return true;
        }
        let Some(base) = match_base_name(text) else {
            return false;
        };
        self.base_name_in.iter().any(|want| want == base)
    }

    fn call_context_allows(
        &self,
        callee: &str,
        receiver_types: &[String],
        alias_map: &std::collections::HashMap<String, AliasTarget>,
        file_packages: &AHashSet<String>,
    ) -> bool {
        if !self.requires_call_package_signal {
            return true;
        }
        let mut candidates = Vec::new();
        push_unique_package_candidate(&mut candidates, callee);
        let push_target = |out: &mut Vec<String>, target: &AliasTarget| {
            push_alias_target_package_candidate(out, target);
            // `var = pkg.Type(...)` binds `var → Type{Type}` via the
            // flow-event aliaser, but the bare type name alone won't
            // satisfy `import_matches_package(Type, pkg)`. If `Type`
            // itself is a `from pkg import Type` alias, chase that
            // second hop so the gate sees `pkg`.
            if let AliasTarget::Type { type_name } = target {
                if let Some(chained) = alias_map.get(type_name) {
                    push_alias_target_package_candidate(out, chained);
                }
            }
        };
        for receiver_type in receiver_types {
            push_unique_package_candidate(&mut candidates, receiver_type);
            // Strip pointer / reference sigils that adapters keep on
            // typed parameters — Go's `*gin.Context`, Rust's
            // `&str` / `&mut Foo`, C++'s `Foo*`. Without this, the
            // alias-chain lookup fails on a punctuation-prefixed key
            // and the package gate misses receiver-typed methods.
            let stripped: String = receiver_type
                .trim_matches(bonsai_common::REFERENCE_SIGILS)
                .to_string();
            push_unique_package_candidate(&mut candidates, &stripped);
            if let Some(target) = alias_map.get(receiver_type) {
                push_target(&mut candidates, target);
            }
            if stripped != *receiver_type {
                if let Some(target) = alias_map.get(&stripped) {
                    push_target(&mut candidates, target);
                }
            }
            // Also chase the head of a qualified receiver type
            // (`gin.Context` → `gin`, `Poco::Net::Context` → `Poco`),
            // which is how adapters surface package alias bindings.
            if let Some((head, _)) = split_call_head_tail(&stripped) {
                if let Some(target) = alias_map.get(head) {
                    push_target(&mut candidates, target);
                }
            }
            if let Some(receiver_tail) = receiver_path_tail(receiver_type).strip_prefix("new ") {
                if let Some(target) = alias_map.get(receiver_tail) {
                    push_target(&mut candidates, target);
                }
            } else if let Some(target) = alias_map.get(receiver_path_tail(receiver_type)) {
                push_target(&mut candidates, target);
            }
        }
        if let Some(target) = alias_map.get(callee) {
            push_target(&mut candidates, target);
        }
        if let Some((head, _)) = split_call_head_tail(callee) {
            if let Some(target) = alias_map.get(head) {
                push_target(&mut candidates, target);
            }
        }
        let file_level_package_evidence_allowed = self.file_level_package_evidence_allowed();
        let allowed = self.package_signals.iter().any(|signal| {
            (file_level_package_evidence_allowed && file_packages.contains(*signal))
                || candidates
                    .iter()
                    .any(|candidate| crate::pkg::import_matches_package(candidate, signal))
        });
        allowed
    }

    fn file_level_package_evidence_allowed(&self) -> bool {
        if self.rule.match_spec.kind == MatchKind::Param {
            return true;
        }
        match self.rule.kind {
            crate::rule::RuleKind::Source => true,
            crate::rule::RuleKind::Sanitizer => false,
            crate::rule::RuleKind::Sink => {
                if is_lifecycle_audit_pair_sink(self.rule) {
                    return true;
                }
                let target = match self.rule.match_spec.kind {
                    MatchKind::Call | MatchKind::New | MatchKind::Missing => {
                        self.rule.match_spec.callee.as_ref()
                    }
                    MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
                        self.rule.match_spec.target.as_ref()
                    }
                };
                let receiver_agnostic_call_regex = self.rule.match_spec.kind == MatchKind::Call
                    && target
                        .and_then(|target| target.regex.as_deref())
                        .is_some_and(regex_prefix_is_receiver_agnostic)
                    && target.is_none_or(|target| target.base_name_in.is_empty());
                !receiver_agnostic_call_regex
            }
        }
    }
}

fn is_lifecycle_audit_pair_sink(rule: &Rule) -> bool {
    if rule.kind != crate::rule::RuleKind::Sink {
        return false;
    }
    matches!(
        rule.tag.as_deref(),
        Some("race" | "memory-safety" | "resource-leak")
    ) || rule.category.as_deref() == Some("source-independent")
}

fn is_lifecycle_state_sink(rule: &Rule) -> bool {
    rule.kind == crate::rule::RuleKind::Sink
        && matches!(
            rule.tag.as_deref(),
            Some("race" | "memory-safety" | "resource-leak")
        )
}

fn split_call_head_tail(callee: &str) -> Option<(&str, &str)> {
    let trimmed = callee.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .split_once("::")
        .or_else(|| trimmed.split_once('.'))
        .or_else(|| trimmed.split_once(':'))
}

fn annotation_name_matches(actual: &str, expected: &str) -> bool {
    let actual = normalize_annotation_name(actual);
    let expected = normalize_annotation_name(expected);
    if actual.eq_ignore_ascii_case(expected) {
        return true;
    }
    annotation_tail(actual).eq_ignore_ascii_case(annotation_tail(expected))
}

fn normalize_annotation_name(value: &str) -> &str {
    let value = value.trim().trim_start_matches('@');
    value
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(value)
        .trim()
}

fn annotation_tail(value: &str) -> &str {
    value
        .rsplit(['.', ':', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(value)
}

fn push_alias_target_package_candidate(out: &mut Vec<String>, target: &AliasTarget) {
    match target {
        AliasTarget::Member { module, .. } | AliasTarget::Namespace { module } => {
            push_unique_package_candidate(out, module);
        }
        AliasTarget::Type { type_name } => push_unique_package_candidate(out, type_name),
    }
}

fn push_unique_package_candidate(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && !out.iter().any(|existing| existing == value) {
        out.push(value.to_string());
    }
}

fn match_base_name(text: &str) -> Option<&str> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let end = text.find(['.', '[', '-', ':', '(']).unwrap_or(text.len());
    let base = text[..end].trim();
    (!base.is_empty()).then_some(base)
}

fn scan_file_rules(
    ws: &Workspace,
    file: FileId,
    rules: &[&PreparedRule<'_>],
    constructor_names: &AHashSet<String>,
    mode: ConstraintMode,
    taint_view: Option<&InterTaintView<'_>>,
    out: &mut Vec<RuleMatch>,
) {
    let active_rules: Vec<&PreparedRule<'_>> = rules.to_vec();
    let call_rules: Vec<&PreparedRule<'_>> = active_rules
        .iter()
        .copied()
        .filter(|r| matches!(r.rule.match_spec.kind, MatchKind::Call | MatchKind::New))
        .collect();
    let read_rules: Vec<&PreparedRule<'_>> = active_rules
        .iter()
        .copied()
        .filter(|r| r.rule.match_spec.kind == MatchKind::Read)
        .collect();
    let write_rules: Vec<&PreparedRule<'_>> = active_rules
        .iter()
        .copied()
        .filter(|r| r.rule.match_spec.kind == MatchKind::Write)
        .collect();
    let param_rules: Vec<&PreparedRule<'_>> = active_rules
        .iter()
        .copied()
        .filter(|r| r.rule.match_spec.kind == MatchKind::Param)
        .collect();
    let return_rules: Vec<&PreparedRule<'_>> = active_rules
        .iter()
        .copied()
        .filter(|r| r.rule.match_spec.kind == MatchKind::Return)
        .collect();
    let missing_rules: Vec<&PreparedRule<'_>> = active_rules
        .iter()
        .copied()
        .filter(|r| r.rule.match_spec.kind == MatchKind::Missing)
        .collect();

    if !call_rules.is_empty() {
        scan_calls_batch(ws, file, &call_rules, constructor_names, mode, taint_view, out);
    }
    if !read_rules.is_empty() {
        scan_refs_batch(ws, file, &read_rules, RefKind::Read, out);
        scan_flow_reads_batch(ws, file, &read_rules, out);
    }
    if !write_rules.is_empty() {
        scan_writes_batch(ws, file, &write_rules, mode, taint_view, out);
        scan_ref_writes_batch(ws, file, &write_rules, mode, taint_view, out);
    }
    if !param_rules.is_empty() {
        scan_params_batch(ws, file, &param_rules, out);
    }
    if !return_rules.is_empty() {
        scan_returns_batch(ws, file, &return_rules, out);
    }
    if !missing_rules.is_empty() {
        scan_missing_batch(ws, file, &missing_rules, mode, taint_view, out);
    }
}

fn scan_returns_batch(ws: &Workspace, file: FileId, rules: &[&PreparedRule<'_>], out: &mut Vec<RuleMatch>) {
    let global = ws.db().global_index();
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    for decl in global.decls_in(file) {
        let mut returns = Vec::new();
        collect_return_sites(&decl.flow_events, &mut returns);
        for (span, value_text, value_name) in returns {
            let span_text = source_text
                .as_deref()
                .and_then(|text| text.get(span.start as usize..span.end as usize))
                .unwrap_or("");
            for prepared in rules {
                let Some(match_text) =
                    return_rule_match(prepared, value_text.as_deref(), value_name.as_deref(), span_text)
                else {
                    continue;
                };
                let span = canonical_flow_read_match_span(ws, file, span, &match_text);
                let (file_path, line, col) = resolve_span(ws, file, span);
                out.push(RuleMatch {
                    rule_id: prepared.rule.id.clone(),
                    language: prepared.rule.language.clone(),
                    file: file_path,
                    line,
                    column: col,
                    span,
                    match_text,
                    enclosing_fn: Some(decl.name.clone()),
                });
            }
        }
    }
}

fn return_rule_match(
    prepared: &PreparedRule<'_>,
    value_text: Option<&str>,
    value_name: Option<&str>,
    span_text: &str,
) -> Option<String> {
    if prepared.name == Some("return") {
        return Some(
            value_text
                .or(value_name)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("return")
                .to_string(),
        );
    }
    if let Some(regex) = prepared.regex.as_ref() {
        for candidate in [value_text, value_name, Some(span_text)].into_iter().flatten() {
            if regex.is_match(candidate) {
                return Some(candidate.trim().to_string());
            }
        }
    }
    if let Some(name) = prepared.name {
        if value_name == Some(name) || value_text.is_some_and(|value| value.trim() == name) {
            return Some(name.to_string());
        }
    }
    None
}

fn scan_params_batch(ws: &Workspace, file: FileId, rules: &[&PreparedRule<'_>], out: &mut Vec<RuleMatch>) {
    let global = ws.db().global_index();
    let file_packages = file_package_set(ws, file);
    let alias_map = file_alias_map(ws, file);
    for decl in global.decls_in(file) {
        for (idx, param) in decl.params.iter().enumerate() {
            // T204: per-param annotations are parallel-indexed with
            // `params`. Empty if the adapter doesn't surface them.
            let param_anns: &[String] = decl.param_annotations.get(idx).map(Vec::as_slice).unwrap_or(&[]);
            for prepared in rules {
                // Enclosing-class / enclosing-method gates run
                // before the shape match so we never even consider
                // a param on the wrong host. Both lists default to
                // empty (no constraint applied); when populated,
                // require an exact match.
                let target = prepared.rule.match_spec.target.as_ref();
                if !decl_target_context_allows(global.as_ref(), Some(decl), target, Some(idx)) {
                    continue;
                }
                let want_annotation = target.and_then(|t| t.annotation.as_deref());
                let matched = if let Some(want) = want_annotation {
                    // Annotation-mode rule: the param matches if any of
                    // its surfaced annotations equals the rule's
                    // requested name (case-insensitive prefix-tolerant
                    // — `RequestParam` matches `@RequestParam`).
                    param_anns.iter().any(|a| annotation_name_matches(a, want))
                } else {
                    callee_matches(param, prepared.name, prepared.attribute, prepared.regex.as_ref())
                };
                if !matched {
                    continue;
                }
                // Package gate — same one calls/reads/writes use. A
                // param rule with `packages: [django]` should only
                // fire on files importing django, not on any file
                // with a same-named parameter.
                if !prepared.call_context_allows(param, &[], &alias_map, file_packages.as_ref()) {
                    continue;
                }
                let (file_path, line, col, span) = param_decl_site(ws, file, decl, param)
                    .or_else(|| first_param_read_site(ws, file, decl, param))
                    .unwrap_or_else(|| {
                        let (file_path, line, col) = resolve_span(ws, file, decl.name_span);
                        (file_path, line, col, decl.name_span)
                    });
                out.push(RuleMatch {
                    rule_id: prepared.rule.id.clone(),
                    language: prepared.rule.language.clone(),
                    file: file_path,
                    line,
                    column: col,
                    span,
                    match_text: param.clone(),
                    enclosing_fn: Some(decl.name.clone()),
                });
            }
        }
    }
}

fn param_decl_site(
    ws: &Workspace,
    file: FileId,
    decl: &bonsai_lang_api::Decl,
    param: &str,
) -> Option<(String, u32, u32, Span)> {
    let snapshot = ws.db().vfs().snapshot(file).ok()?;
    let text = snapshot.text.as_ref();
    let start = decl.span.start.min(decl.span.end) as usize;
    let mut upper_bounds = Vec::new();
    if let Some(body) = decl.body_span {
        upper_bounds.push(body.start);
    }
    if let Some(first_event) = first_flow_event_start(&decl.flow_events) {
        upper_bounds.push(first_event);
    }
    upper_bounds.push(decl.span.end);
    let Some(body_start) = upper_bounds
        .into_iter()
        .filter(|bound| *bound > decl.span.start)
        .map(|bound| bound.min(decl.span.end) as usize)
        .filter(|bound| *bound <= text.len() && *bound > start)
        .min()
    else {
        return None;
    };
    let signature = text.get(start..body_start)?;
    let mut best_start = None;
    for (offset, _) in signature.match_indices(param) {
        let absolute = start + offset;
        let end = absolute + param.len();
        if identifier_boundary(text, absolute, end) {
            best_start = Some(absolute);
        }
    }
    let absolute_start = best_start?;
    let span = Span::new(file, absolute_start as u64, (absolute_start + param.len()) as u64);
    let (file_path, line, col) = resolve_span(ws, file, span);
    Some((file_path, line, col, span))
}

fn first_flow_event_start(events: &[FlowEvent]) -> Option<u64> {
    events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { span, .. }
            | FlowEvent::Assign { span, .. }
            | FlowEvent::Return { span, .. }
            | FlowEvent::Throw { span, .. }
            | FlowEvent::Break { span, .. }
            | FlowEvent::Continue { span, .. }
            | FlowEvent::Yield { span, .. }
            | FlowEvent::Await { span, .. }
            | FlowEvent::Lifecycle { span, .. } => Some(span.start),
            FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } => Some(
                [
                    Some(span.start),
                    first_flow_event_start(then_events),
                    first_flow_event_start(else_events),
                ]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(span.start),
            ),
            FlowEvent::Loop { span, body, .. }
            | FlowEvent::Defer { span, body }
            | FlowEvent::Using { span, body, .. } => Some(
                [Some(span.start), first_flow_event_start(body)]
                    .into_iter()
                    .flatten()
                    .min()
                    .unwrap_or(span.start),
            ),
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                ..
            } => Some(
                [
                    Some(span.start),
                    first_flow_event_start(body),
                    first_flow_event_start(catch_events),
                    first_flow_event_start(finally_events),
                ]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(span.start),
            ),
        })
        .min()
}

fn identifier_boundary(text: &str, start: usize, end: usize) -> bool {
    fn is_ident_byte(byte: u8) -> bool {
        byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric()
    }
    let before_ok = start == 0 || !is_ident_byte(text.as_bytes()[start - 1]);
    let after_ok = end >= text.len() || !is_ident_byte(text.as_bytes()[end]);
    before_ok && after_ok
}

fn first_param_read_site(
    ws: &Workspace,
    file: FileId,
    decl: &bonsai_lang_api::Decl,
    param: &str,
) -> Option<(String, u32, u32, Span)> {
    let idx = ws.db().decl_index(file)?;
    let body = decl.body_span.unwrap_or(decl.span);
    let min_start = body.start.max(decl.name_span.end);
    let read = idx
        .refs
        .iter()
        .filter(|reference| reference.kind == RefKind::Read)
        .filter(|reference| reference.span.start >= min_start && reference.span.start < body.end)
        .filter(|reference| {
            reference.scope.is_none_or(|scope| scope == decl.symbol)
                && read_name_mentions_param(&reference.name, param)
        })
        .min_by_key(|reference| (reference.span.start, reference.span.end));
    if let Some(reference) = read {
        let (file_path, line, col) = resolve_span(ws, file, reference.span);
        return Some((file_path, line, col, reference.span));
    }

    let mut reads = Vec::new();
    collect_flow_read_sites(&decl.flow_events, &mut reads);
    reads
        .into_iter()
        .filter(|(span, tokens)| {
            span.start >= min_start && span.start < body.end && tokens_read_param(tokens, param)
        })
        .min_by_key(|(span, _)| (span.start, span.end))
        .map(|(span, _)| {
            let (file_path, line, col) = resolve_span(ws, file, span);
            (file_path, line, col, span)
        })
}

fn read_name_mentions_param(name: &str, param: &str) -> bool {
    split_read_token(name)
        .iter()
        .any(|token| normalize_param_name(token) == normalize_param_name(param))
}

fn tokens_read_param(tokens: &[String], param: &str) -> bool {
    tokens
        .iter()
        .any(|token| normalize_param_name(token) == normalize_param_name(param))
}

fn decl_target_context_allows(
    global: &bonsai_index::GlobalIndex,
    decl: Option<&Decl>,
    target: Option<&RuleTarget>,
    param_index: Option<usize>,
) -> bool {
    let Some(target) = target else {
        return true;
    };
    if target.decl_kind_in.is_empty()
        && target.visibility_in.is_empty()
        && target.in_class.is_empty()
        && target.in_method.is_empty()
        && (param_index.is_none() || target.param_index_in.is_empty())
    {
        return true;
    }
    let Some(decl) = decl else {
        return false;
    };
    if !target.decl_kind_in.is_empty() && !target.decl_kind_in.iter().any(|want| want == &decl.kind) {
        return false;
    }
    if !target.visibility_in.is_empty() && !target.visibility_in.iter().any(|want| want == &decl.visibility) {
        return false;
    }
    if !target.in_method.is_empty() && !target.in_method.iter().any(|want| want == &decl.name) {
        return false;
    }
    if let Some(idx) = param_index {
        if !target.param_index_in.is_empty() && !target.param_index_in.iter().any(|want| *want == idx as u32)
        {
            return false;
        }
    }
    if target.in_class.is_empty() {
        return true;
    }

    let enclosing_class = decl.parent.and_then(|sym| global.decl_of(sym)).filter(|p| {
        matches!(
            p.kind,
            DeclKind::Class | DeclKind::Struct | DeclKind::Interface | DeclKind::Trait
        )
    });
    let Some(enclosing_class) = enclosing_class else {
        return false;
    };
    target.in_class.iter().any(|want| want == &enclosing_class.name)
        || enclosing_class
            .bases
            .iter()
            .any(|base| target.in_class.iter().any(|want| want == base))
}

fn scan_calls_batch(
    ws: &Workspace,
    file: FileId,
    rules: &[&PreparedRule<'_>],
    constructor_names: &AHashSet<String>,
    mode: ConstraintMode,
    taint_view: Option<&InterTaintView<'_>>,
    out: &mut Vec<RuleMatch>,
) {
    let global = ws.db().global_index();
    let file_packages = file_package_set(ws, file);
    let import_aliases = file_alias_map(ws, file);
    let decls = global.decls_in(file);
    let bundle = decl_match_facts_for(ws, file);
    let mut decl_call_keys: AHashSet<(String, u64)> = AHashSet::new();

    for decl in decls {
        let fn_name = decl.name.clone();
        let Some(facts) = bundle.by_decl_span.get(&decl.span).cloned() else {
            continue;
        };
        for call in &facts.calls {
            decl_call_keys.insert((call.callee.clone(), call.span.start));
            for prepared in rules {
                if !decl_target_context_allows(
                    global.as_ref(),
                    Some(decl),
                    prepared.rule.match_spec.callee.as_ref(),
                    None,
                ) {
                    continue;
                }
                let Some(matched_callee) = callee_or_alias_matches(
                    &call.callee,
                    &call.receiver_types,
                    prepared.name,
                    prepared.attribute,
                    prepared.regex.as_ref(),
                    &facts.alias_map,
                ) else {
                    continue;
                };
                if !prepared.base_name_allows(&matched_callee) {
                    continue;
                }
                if !base_receiver_type_allows(prepared, Some(decl), &matched_callee) {
                    continue;
                }
                if !prepared.call_context_allows(
                    &call.callee,
                    &call.receiver_types,
                    &facts.alias_map,
                    file_packages.as_ref(),
                ) {
                    continue;
                }
                let receiver_call_count = receiver_method_key(&call.callee)
                    .and_then(|key| facts.receiver_counts.get(&key).copied());
                if !constraints_pass(ConstraintEval {
                    rule_id: &prepared.rule.id,
                    callee: &matched_callee,
                    args: &call.args,
                    receiver_types: &call.receiver_types,
                    span: call.span,
                    call_origin: Some(call.origin),
                    constraints: &prepared.rule.constraints.0,
                    constraint_regexes: &prepared.constraint_regexes,
                    receiver_call_count,
                    assignment_texts: Some(&facts.assignment_map),
                    mode,
                    taint_view,
                    enclosing_decorators: Some(facts.decl_decorators.as_slice()),
                    alias_chains: Some(&facts.alias_chains),
                    runtime_types: Some(&facts.runtime_types),
                    lifecycle_transitions: Some(&facts.lifecycle_transitions),
                }) {
                    continue;
                }
                if prepared.rule.match_spec.kind == MatchKind::New
                    && call.call_kind != CallKind::Constructor
                    && !constructor_name_matches(&call.callee, constructor_names)
                {
                    continue;
                }
                let (file_path, line, col) = resolve_span(ws, file, call.span);
                out.push(RuleMatch {
                    rule_id: prepared.rule.id.clone(),
                    language: prepared.rule.language.clone(),
                    file: file_path,
                    line,
                    column: col,
                    span: call.span,
                    match_text: call.callee.clone(),
                    enclosing_fn: Some(fn_name.clone()),
                });
            }
        }
    }

    let Some(idx) = ws.db().decl_index(file) else {
        return;
    };
    // Build a span-sorted index over the file's decls so the
    // per-ref enclosing-fn lookup is O(log decls) instead of the
    // previous O(refs × decls) linear scan. On large workspace
    // files (Redis main.c, big TypeScript compilation units) the
    // linear path dominated this batch; the binary search returns
    // the same decl because function bodies don't overlap and the
    // rightmost body whose start <= ref.span.start IS the
    // innermost containing one.
    // Workspace-cached binary-search index (built once per
    // `(FileId, version)`), shared across the 4 matcher passes
    // and across `cmd_security` subcommands. Replaces the prior
    // per-batch local builder.
    let enclosing_entries = ws.enclosing_index().entries_for(ws.db(), file);
    for r in &idx.refs {
        if r.kind != RefKind::Call || decl_call_keys.contains(&(r.name.clone(), r.span.start)) {
            continue;
        }
        let enclosing_fn = ws
            .enclosing_index()
            .enclosing_name(ws.db(), file, r.span.start)
            .or_else(|| {
                // Fast fallback when the entry is already built;
                // partition_point preserves the prior matcher
                // semantics (innermost match by binary search).
                if enclosing_entries.is_empty() {
                    return None;
                }
                let partition = enclosing_entries.partition_point(|e| e.start <= r.span.start);
                if partition == 0 {
                    return None;
                }
                let entry = &enclosing_entries[partition - 1];
                if r.span.start < entry.end {
                    Some(entry.name.clone())
                } else {
                    None
                }
            });
        for prepared in rules {
            if mode == ConstraintMode::Strict && !prepared.rule.constraints.0.is_empty() {
                continue;
            }
            let Some(matched_callee) = callee_or_alias_matches(
                &r.name,
                &[],
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
                &import_aliases,
            ) else {
                continue;
            };
            if !prepared.base_name_allows(&matched_callee) {
                continue;
            }
            if !prepared.call_context_allows(&r.name, &[], &import_aliases, file_packages.as_ref()) {
                continue;
            }
            if !constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &matched_callee,
                args: &[],
                receiver_types: &[],
                span: r.span,
                call_origin: None,
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count: None,
                assignment_texts: None,
                mode,
                taint_view,
                enclosing_decorators: None,
                alias_chains: None,
                runtime_types: None,
                lifecycle_transitions: None,
            }) {
                continue;
            }
            if prepared.rule.match_spec.kind == MatchKind::New
                && !constructor_name_matches(&r.name, constructor_names)
            {
                continue;
            }
            let (file_path, line, col) = resolve_span(ws, file, r.span);
            out.push(RuleMatch {
                rule_id: prepared.rule.id.clone(),
                language: prepared.rule.language.clone(),
                file: file_path,
                line,
                column: col,
                span: r.span,
                match_text: r.name.clone(),
                enclosing_fn: enclosing_fn.clone(),
            });
        }
    }
}

/// Fire each Missing rule on every function-shaped decl in `file`
/// where the expected callee is absent. Cross-procedural reach is
/// opt-in via `match.search_depth`.
fn scan_missing_batch(
    ws: &Workspace,
    file: FileId,
    rules: &[&PreparedRule<'_>],
    mode: ConstraintMode,
    taint_view: Option<&InterTaintView<'_>>,
    out: &mut Vec<RuleMatch>,
) {
    let global = ws.db().global_index();
    let file_packages = file_package_set(ws, file);
    let import_aliases = file_alias_map(ws, file);
    let bundle = decl_match_facts_for(ws, file);

    for decl in global.decls_in(file) {
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some(facts) = bundle.by_decl_span.get(&decl.span).cloned() else {
            continue;
        };
        let target_span = if decl.name_span.start != decl.name_span.end {
            decl.name_span
        } else {
            decl.span
        };

        for prepared in rules {
            // Empty args because Missing fires on a decl, not a
            // call — arg-shape constraints will short-circuit false.
            if !constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: "",
                args: &[],
                receiver_types: &[],
                span: target_span,
                call_origin: None,
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count: None,
                assignment_texts: Some(&facts.assignment_map),
                mode,
                taint_view,
                enclosing_decorators: Some(facts.decl_decorators.as_slice()),
                alias_chains: Some(&facts.alias_chains),
                runtime_types: Some(&facts.runtime_types),
                lifecycle_transitions: Some(&facts.lifecycle_transitions),
            }) {
                continue;
            }

            // Does any call inside this decl (or — when
            // `search_depth > 0` — any transitively reachable
            // callee, capped at depth 4) match the rule's
            // expected target callee? The intra-procedural check
            // Cross-proc BFS only runs when the rule opts in via
            // `match.search_depth > 0`.
            let target_present =
                facts.calls.iter().any(|call| {
                    callee_or_alias_matches(
                        &call.callee,
                        &call.receiver_types,
                        prepared.name,
                        prepared.attribute,
                        prepared.regex.as_ref(),
                        &facts.alias_map,
                    )
                    .is_some()
                        && prepared.call_context_allows(
                            &call.callee,
                            &call.receiver_types,
                            &facts.alias_map,
                            file_packages.as_ref(),
                        )
                }) || missing_target_in_reachable_callees(ws, file, decl, prepared, &import_aliases);
            if target_present {
                continue;
            }

            let (file_path, line, col) = resolve_span(ws, file, target_span);
            out.push(RuleMatch {
                rule_id: prepared.rule.id.clone(),
                language: prepared.rule.language.clone(),
                file: file_path,
                line,
                column: col,
                span: target_span,
                match_text: decl.name.clone(),
                enclosing_fn: Some(decl.name.clone()),
            });
        }
    }
}

/// BFS the entry decl's reachable callees up to the rule's
/// `search_depth` (capped at `MISSING_SEARCH_DEPTH_CAP`) looking
/// for the expected target. Used by the Missing walker only when
/// the rule opts into cross-procedural reach.
const MISSING_SEARCH_DEPTH_CAP: u32 = 4;

fn missing_target_in_reachable_callees(
    ws: &Workspace,
    file: FileId,
    entry: &bonsai_lang_api::Decl,
    prepared: &PreparedRule<'_>,
    import_aliases: &std::collections::HashMap<String, AliasTarget>,
) -> bool {
    if prepared.rule.match_spec.kind != MatchKind::Missing {
        return false;
    }
    let max_depth = prepared
        .rule
        .match_spec
        .search_depth
        .min(MISSING_SEARCH_DEPTH_CAP);
    if max_depth == 0 {
        return false;
    }
    let global = ws.db().global_index();
    let mut visited: AHashSet<bonsai_common::SymbolId> = AHashSet::new();
    let mut frontier: AHashSet<bonsai_common::SymbolId> = AHashSet::new();

    // Seed: direct callees of the entry decl. Export aliases come
    // from the entry's adapter so JS/TS `module.exports.X` assignments
    // count as published callees, while languages without an
    // export-by-assignment convention pass an empty slice.
    let entry_export_aliases = ws
        .db()
        .adapter_for(file)
        .map(|adapter| adapter.capabilities().module_export_aliases)
        .unwrap_or(&[]);
    collect_callee_symbols(
        ws,
        &entry.flow_events,
        &global,
        entry,
        import_aliases,
        entry_export_aliases,
        &mut frontier,
    );

    for _depth in 0..max_depth {
        if frontier.is_empty() {
            break;
        }
        let mut next: AHashSet<bonsai_common::SymbolId> = AHashSet::new();
        for symbol in &frontier {
            if !visited.insert(*symbol) {
                continue;
            }
            let Some(callee_decl) = global.decl_of(*symbol) else {
                continue;
            };
            // Per-callee aliases / packages so child resolutions
            // use the callee's own imports, not the entry's. The
            // workspace-cached `decl_match_facts_for(ws, callee_file)`
            // returns Arc-shared `DeclMatchFacts` keyed on
            // `(FileId, version, content_hash)`; using it instead
            // of inlining `collect_calls` /
            // `extend_alias_map_with_declared_types` /
            // `enrich_call_fact_receiver_types` per callee
            // collapses Missing-rule BFS cost to one cache hit
            // per (file, decl) pair across the whole search.
            let callee_file = global.declaring_file(callee_decl.symbol).unwrap_or(file);
            let callee_file_packages = file_package_set(ws, callee_file);
            let callee_bundle = decl_match_facts_for(ws, callee_file);
            // Bundle covers every decl in the file; index by
            // span. Fallback: if the cache layer didn't
            // materialise this decl (rare — adapters that emit
            // a decl with no flow_events skip it), fall through
            // to the prior inline shape.
            let callee_facts = callee_bundle.by_decl_span.get(&callee_decl.span).cloned();
            let (calls_view, callee_alias_owned, callee_alias_borrow): CalleeCallsView<'_> =
                if let Some(facts) = &callee_facts {
                    (
                        std::borrow::Cow::Borrowed(facts.calls.as_slice()),
                        None,
                        Some(&facts.alias_map),
                    )
                } else {
                    let mut callee_alias = file_alias_map(ws, callee_file);
                    extend_alias_map_with_declared_types(&mut callee_alias, &callee_decl.type_aliases);
                    bonsai_lang_api::extend_alias_map_with_flow_events(
                        &mut callee_alias,
                        &callee_decl.flow_events,
                    );
                    let mut calls = collect_calls(&callee_decl.flow_events);
                    enrich_call_fact_receiver_types(&mut calls, &callee_decl.type_aliases);
                    (std::borrow::Cow::Owned(calls), Some(callee_alias), None)
                };
            let callee_alias_ref = callee_alias_borrow
                .unwrap_or_else(|| callee_alias_owned.as_ref().expect("alias map populated"));
            for call in calls_view.iter() {
                if callee_or_alias_matches(
                    &call.callee,
                    &call.receiver_types,
                    prepared.name,
                    prepared.attribute,
                    prepared.regex.as_ref(),
                    callee_alias_ref,
                )
                .is_some()
                    && prepared.call_context_allows(
                        &call.callee,
                        &call.receiver_types,
                        callee_alias_ref,
                        callee_file_packages.as_ref(),
                    )
                {
                    return true;
                }
            }
            let callee_export_aliases = ws
                .db()
                .adapter_for(callee_file)
                .map(|adapter| adapter.capabilities().module_export_aliases)
                .unwrap_or(&[]);
            collect_callee_symbols(
                ws,
                &callee_decl.flow_events,
                &global,
                callee_decl,
                callee_alias_ref,
                callee_export_aliases,
                &mut next,
            );
        }
        frontier = next;
    }
    false
}

fn matching_call_has_arg_index(
    ws: &Workspace,
    file: FileId,
    prepared: &PreparedRule<'_>,
    constructor_names: &AHashSet<String>,
    wanted_index: usize,
) -> bool {
    let global = ws.db().global_index();
    let file_packages = file_package_set(ws, file);
    let import_aliases = file_alias_map(ws, file);
    for decl in global.decls_in(file) {
        let mut alias_map = import_aliases.clone();
        extend_alias_map_with_declared_types(&mut alias_map, &decl.type_aliases);
        bonsai_lang_api::extend_alias_map_with_flow_events(&mut alias_map, &decl.flow_events);
        let mut calls = collect_calls(&decl.flow_events);
        enrich_call_fact_receiver_types(&mut calls, &decl.type_aliases);
        for call in calls {
            if call.origin != CallFactOrigin::RealCall || call.args.get(wanted_index).is_none() {
                continue;
            }
            if callee_or_alias_matches(
                &call.callee,
                &call.receiver_types,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
                &alias_map,
            )
            .is_none()
            {
                continue;
            }
            if !prepared.call_context_allows(
                &call.callee,
                &call.receiver_types,
                &alias_map,
                file_packages.as_ref(),
            ) {
                continue;
            }
            if prepared.rule.match_spec.kind == MatchKind::New
                && call.call_kind != CallKind::Constructor
                && !constructor_name_matches(&call.callee, constructor_names)
            {
                continue;
            }
            return true;
        }
    }
    false
}

/// Build a `local_name -> AliasTarget` map for a file by consulting
/// the cached `ImportIndex` — the same structure that powers the
/// `imports` browse command and the resolver's alias rewrite. The
/// canonical helper lives in `lang_api::kit::alias_map_from_imports`
/// so every consumer of alias resolution goes through a single path;
/// this function just bridges the workspace DB lookup to that helper.
/// No extra parse, no duplicate grammar-specific code.
fn file_alias_map(ws: &Workspace, file: FileId) -> std::collections::HashMap<String, AliasTarget> {
    let Some(imports) = ws.db().import_index(file) else {
        return std::collections::HashMap::new();
    };
    bonsai_lang_api::kit::alias_map_from_imports(&imports)
}

// Process-level shared cache (parking_lot::RwLock) keyed on
// `(FileId, version, content_hash)`. Earlier this was a
// `thread_local!` which meant rayon work-stealing across the 4
// matcher passes (sources / sinks / sanitizers / pattern_sinks)
// rebuilt the same file's package set on every worker that hadn't
// seen it. The shared cache hits ~100% across all passes once a
// file has been visited once.
//
// Cross-workspace correctness: the key includes content_hash, so a
// byte-identical file in two workspaces returns the same package
// set (which is correct — the package set is purely a function of
// the file's import declarations).
type FilePackageSetMap = AHashMap<(FileId, u64, u64, u64), Arc<AHashSet<String>>>;
static FILE_PACKAGE_SET_CACHE: std::sync::LazyLock<parking_lot::RwLock<FilePackageSetMap>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));

/// Build the set of canonical package names imported by `file`.
/// Pre-enumerates every prefix shape an import target could match
/// against the rule's signal needles (exact, `.h`-stripped, and
/// progressive `/`, `.`, `:`, `\`-separated prefixes) so the
/// match-time gate can do `set.contains(rule_signal)` in O(1).
fn file_package_set(ws: &Workspace, file: FileId) -> Arc<AHashSet<String>> {
    let workspace_packages = if workspace_manifest_package_context_allowed(ws, file) {
        ws.db().workspace_root().map(|root| {
            let language = ws
                .db()
                .adapter_for(file)
                .map(|adapter| adapter.language_id().as_str())
                .unwrap_or("");
            crate::deps::workspace_dependency_packages_for_language(&root, language)
        })
    } else {
        None
    };
    let workspace_package_fingerprint = workspace_packages
        .as_ref()
        .map(|packages| packages.fingerprint)
        .unwrap_or(0);
    let (version, text_hash) = ws.db().vfs().snapshot(file).map_or((0, 0), |snapshot| {
        (
            snapshot.version,
            package_cache_content_hash(snapshot.text.as_bytes()),
        )
    });
    let key = (file, version, text_hash, workspace_package_fingerprint);
    // Drop the read guard at the `;` before any potential write
    // upgrade — parking_lot RwLocks are non-reentrant.
    let cached = FILE_PACKAGE_SET_CACHE.read().get(&key).cloned();
    if let Some(hit) = cached {
        return hit;
    }
    let mut out: AHashSet<String> = AHashSet::new();
    if let Some(imports) = ws.db().import_index(file) {
        for spec in &imports.imports {
            insert_import_target_prefixes(&mut out, &spec.module);
            if let Some(stripped) = spec
                .module
                .strip_suffix(".h")
                .or_else(|| spec.module.strip_suffix(".hpp"))
                .or_else(|| spec.module.strip_suffix(".hxx"))
            {
                insert_import_target_prefixes(&mut out, stripped);
            }
        }
    }
    if let Some(workspace_packages) = workspace_packages {
        out.extend(workspace_packages.packages.iter().cloned());
    }
    let out = Arc::new(out);
    let mut write = FILE_PACKAGE_SET_CACHE.write();
    if write.len() >= 4096 {
        write.clear();
    }
    write.entry(key).or_insert_with(|| out.clone()).clone()
}

fn workspace_manifest_package_context_allowed(ws: &Workspace, file: FileId) -> bool {
    let Some(adapter) = ws.db().adapter_for(file) else {
        return false;
    };
    if adapter.language_id().as_str() != "ruby" {
        return false;
    }
    let Ok(path) = ws.vfs().path(file) else {
        return false;
    };
    let path = path.to_string_lossy();
    matches!(
        std::path::Path::new(path.as_ref())
            .extension()
            .and_then(|ext| ext.to_str()),
        Some("erb" | "rhtml" | "haml" | "slim")
    )
}

fn package_cache_content_hash(bytes: &[u8]) -> u64 {
    bonsai_hash::fnv1a_bytes64(bytes)
}

/// Per-decl derived facts shared across the matcher's call-shaped
/// scan passes (`scan_calls_batch`, `scan_missing_batch`). Every
/// field is a pure function of the decl's `flow_events` plus
/// adapter type-aliases plus the decl's source text, so caching by
/// `(FileId, version, text_hash)` is sound. Without this cache the
/// 4-pass matcher recomputes the same `collect_calls` /
/// `collect_assignment_texts` / etc. for every rule pass — for
/// OWASP ~110k redundant per-decl walks per analysis run.
struct DeclMatchFacts {
    alias_map: std::collections::HashMap<String, AliasTarget>,
    calls: Vec<CallFact>,
    receiver_counts: AHashMap<String, u32>,
    assignment_map: AHashMap<String, String>,
    decl_decorators: Vec<String>,
    alias_chains: AHashMap<String, String>,
    runtime_types: Vec<RuntimeTypeNarrowing>,
    lifecycle_transitions: Vec<(Span, String, String)>,
}

/// Bundle of per-decl facts for one file, keyed by `decl.span` (the
/// stable identifier for a decl within a file).
struct FileDeclFactsBundle {
    by_decl_span: AHashMap<Span, Arc<DeclMatchFacts>>,
}

// Process-level shared cache (parking_lot::RwLock) keyed on
// `(FileId, version, content_hash)`. Earlier this was a
// `thread_local!` which meant rayon work-stealing across the 4
// matcher passes (sources / sinks / sanitizers / pattern_sinks)
// rebuilt the same file's per-decl bundle on every worker that
// hadn't seen it yet — expected reuse rate ~25%. The shared
// cache approaches 100% reuse across passes.
//
// Cross-workspace correctness: bundle is purely a function of
// `decl.flow_events` + adapter capabilities + source text, all
// folded into the cache key's `content_hash`. Two workspaces that
// open byte-identical files share the cache hit (correct).
//
// Note: `collect_decl_decorator_names` consults `ws` to walk the
// adapter for decorator extraction. The workspace handle leaves
// no state in the cached bundle other than what's derived from
// `decl.flow_events` + content_hash, so two workspaces with
// byte-identical files produce byte-identical bundles.
type FileDeclFactsMap = AHashMap<(FileId, u64, u64), Arc<FileDeclFactsBundle>>;
static DECL_FACTS_CACHE: std::sync::LazyLock<parking_lot::RwLock<FileDeclFactsMap>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));

/// Return the per-decl matcher fact bundle for `file`. Builds the
/// bundle on miss; cached on `(file, version, text_hash)` so source
/// edits naturally invalidate.
fn decl_match_facts_for(ws: &Workspace, file: FileId) -> Arc<FileDeclFactsBundle> {
    let (version, text_hash) = ws.db().vfs().snapshot(file).map_or((0, 0), |snap| {
        (snap.version, package_cache_content_hash(snap.text.as_bytes()))
    });
    let key = (file, version, text_hash);
    let cached = DECL_FACTS_CACHE.read().get(&key).cloned();
    if let Some(hit) = cached {
        return hit;
    }
    let global = ws.db().global_index();
    let import_aliases = file_alias_map(ws, file);
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let mut by_decl_span: AHashMap<Span, Arc<DeclMatchFacts>> = AHashMap::new();
    for decl in global.decls_in(file) {
        let mut alias_map = import_aliases.clone();
        extend_alias_map_with_declared_types(&mut alias_map, &decl.type_aliases);
        bonsai_lang_api::extend_alias_map_with_flow_events(&mut alias_map, &decl.flow_events);
        let mut calls = collect_calls(&decl.flow_events);
        enrich_call_fact_receiver_types(&mut calls, &decl.type_aliases);
        let receiver_counts = receiver_method_call_counts(&calls);
        let assignment_map = collect_assignment_texts(&decl.flow_events, source_text.as_deref());
        let decl_decorators = collect_decl_decorator_names(ws, file, decl.span);
        let alias_chains = collect_must_alias_pairs(&decl.flow_events);
        let runtime_types = collect_runtime_type_narrowings(&decl.flow_events);
        let lifecycle_transitions = collect_lifecycle_transitions(&decl.flow_events);
        by_decl_span.insert(
            decl.span,
            Arc::new(DeclMatchFacts {
                alias_map,
                calls,
                receiver_counts,
                assignment_map,
                decl_decorators,
                alias_chains,
                runtime_types,
                lifecycle_transitions,
            }),
        );
    }
    let bundle = Arc::new(FileDeclFactsBundle { by_decl_span });
    let mut write = DECL_FACTS_CACHE.write();
    if write.len() >= 1024 {
        write.clear();
    }
    write.entry(key).or_insert_with(|| bundle.clone()).clone()
}

fn insert_import_target_prefixes(out: &mut AHashSet<String>, module: &str) {
    if module.is_empty() {
        return;
    }
    out.insert(module.to_string());
    for sep in ['/', '.', ':', '\\'] {
        let mut prefix = String::new();
        let mut saw_component = false;
        for part in module.split(sep).filter(|part| !part.is_empty()) {
            if !prefix.is_empty() {
                prefix.push(sep);
            }
            prefix.push_str(part);
            saw_component = true;
            out.insert(prefix.clone());
        }
        if saw_component && sep == ':' && module.contains("::") {
            out.insert(module.split("::").next().unwrap_or(module).to_string());
        }
    }
}

/// Extended `callee_matches` that ALSO accepts a match against the
/// alias-expanded form of a bare call. Two expansion shapes:
///
/// - Member binding (`const { exec } = require("child_process")`):
///   `exec(x)` → `child_process.exec(x)`; the local name IS the
///   module member, so we prefix with `module.` and keep the rest
///   of the callee chain verbatim after the local.
/// - Namespace binding (`const cp = require("child_process")`):
///   `cp.exec(x)` → `child_process.exec(x)`; the local name IS the
///   module, so we replace the `local.` prefix with `module.`.
///
/// Both shapes feed the same `callee_matches` check against the rule
/// target, so a rule written as
/// `callee.attribute: [child_process, exec]` fires for both forms.
///
/// True when a regex target starts with a receiver-agnostic local
/// identifier prefix such as `^[A-Za-z_$][A-Za-z0-9_$]*\.`. These
/// rules are useful for dynamic languages, but must be gated by
/// adapter-surfaced import/package context rather than local variable
/// names.
pub(crate) fn rule_regex_requires_package_signal(rule: &Rule) -> bool {
    let target = match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
            rule.match_spec.target.as_ref()
        }
    };
    target
        .and_then(|target| target.regex.as_deref())
        .is_some_and(regex_prefix_is_receiver_agnostic)
        && (!rule.packages.is_empty() || !rule.imports.is_empty() || !rule.modules.is_empty())
}

fn rule_requires_call_package_signal(rule: &Rule) -> bool {
    if rule.packages.is_empty() && rule.imports.is_empty() && rule.modules.is_empty() {
        return false;
    }
    if is_lifecycle_state_sink(rule) {
        return false;
    }
    if matches!(
        rule.kind,
        crate::rule::RuleKind::Source | crate::rule::RuleKind::Sink
    ) || rule.match_spec.kind == MatchKind::Param
    {
        return true;
    }
    let target = match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
            rule.match_spec.target.as_ref()
        }
    };
    let Some(target) = target else {
        return false;
    };
    target
        .regex
        .as_deref()
        .is_some_and(regex_prefix_is_receiver_agnostic)
        || (rule.match_spec.kind == MatchKind::New && target.name.is_some())
}

fn regex_prefix_is_receiver_agnostic(regex: &str) -> bool {
    let rest = regex.trim().strip_prefix('^').unwrap_or(regex);
    rest.starts_with("[A-Za-z_")
        && rest.contains("]*\\.")
        && (rest.contains("A-Za-z0-9_") || rest.contains("a-zA-Z0-9_"))
}

fn callee_or_alias_matches(
    callee: &str,
    receiver_types: &[String],
    name: Option<&str>,
    attribute: Option<&Vec<String>>,
    regex: Option<&Regex>,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Option<String> {
    if callee_matches_with_receiver_types(callee, receiver_types, name, attribute, regex) {
        return Some(callee.to_string());
    }
    if alias_map.is_empty() {
        return None;
    }
    let bare = callee.split(&['.', ':'][..]).next()?;
    let target = alias_map.get(bare)?;
    let tail = &callee[bare.len()..];
    let expanded = match target {
        AliasTarget::Member { module, member } => {
            // `exec(x)` + member=exec → `child_process.exec(x)`.
            // `exec.sub(x)` + member=exec → `child_process.exec.sub(x)`.
            format!("{module}.{member}{tail}")
        }
        AliasTarget::Namespace { module } => {
            // `cp.exec(x)` + module=child_process → `child_process.exec(x)`.
            // `cp(x)` (bare module call) + module=child_process →
            // `child_process(x)` — unusual but valid.
            format!("{module}{tail}")
        }
        AliasTarget::Type { type_name } => {
            // `f.readBytes()` + type=File → `File.readBytes()`.
            // Receiver-type resolution: instance variables bound to
            // a constructor call surface here so attribute-chain
            // rules like `[File, readText]` / `[Logger, info]` /
            // `[HttpClient, GetStringAsync]` match the real-world
            // call shape `<recv>.<method>(...)`.
            format!("{type_name}{tail}")
        }
    };
    if callee_matches_with_receiver_types(&expanded, receiver_types, name, attribute, regex) {
        return Some(expanded);
    }
    // Type-binding case is the only path where receiver case can
    // legitimately diverge from the rule's spelling (Python rules
    // use `[cursor, execute]` lowercase while Java rules use
    // `[Statement, execute]` PascalCase). The factory-method
    // inference produces a canonical case-preserving binding; this
    // fallback also tries a Title-cased and a lower-cased rewrite
    // so the Python lowercase and Java PascalCase rule conventions
    // both fire on inferred-receiver-type chains.
    if let AliasTarget::Type { type_name } = target {
        if type_name.is_empty() {
            return None;
        }
        // The `is_empty()` guard at the top of the block already
        // proved `type_name` has at least one char, so `chars.next()`
        // can't return `None` here. We still handle the `None` arm
        // explicitly (returning `None` from the helper) so a future
        // refactor that removes the empty check fails gracefully
        // instead of panicking in production.
        let mut chars = type_name.chars();
        let first = chars.next()?;
        let alt: String = if first.is_ascii_uppercase() {
            format!("{}{}{}", first.to_ascii_lowercase(), chars.as_str(), tail)
        } else {
            format!("{}{}{}", first.to_ascii_uppercase(), chars.as_str(), tail)
        };
        if callee_matches_with_receiver_types(&alt, receiver_types, name, attribute, regex) {
            return Some(alt);
        }
    }
    None
}

fn scan_refs_batch(
    ws: &Workspace,
    file: FileId,
    rules: &[&PreparedRule<'_>],
    want_kind: RefKind,
    out: &mut Vec<RuleMatch>,
) {
    let Some(idx) = ws.db().decl_index(file) else {
        return;
    };
    let global = ws.db().global_index();
    let decls = global.decls_in(file);
    let file_packages = file_package_set(ws, file);
    let alias_map = file_alias_map(ws, file);
    for r in &idx.refs {
        if r.kind != want_kind {
            continue;
        }
        let enclosing_decl = decls.iter().find(|d| {
            let body = d.body_span.unwrap_or(d.span);
            r.span.start >= body.start && r.span.start < body.end
        });
        for prepared in rules {
            if !decl_target_context_allows(
                global.as_ref(),
                enclosing_decl,
                prepared.rule.match_spec.target.as_ref(),
                None,
            ) {
                continue;
            }
            if !callee_matches(
                &r.name,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
            ) {
                continue;
            }
            if !prepared.base_name_allows(&r.name) {
                continue;
            }
            if !base_param_index_allows(prepared, enclosing_decl, &r.name) {
                continue;
            }
            if !base_receiver_type_allows(prepared, enclosing_decl, &r.name) {
                continue;
            }
            // Receiver-agnostic read regexes (`^[A-Za-z_]\w*\.body$`)
            // would otherwise fire on any `<ident>.body` shape across
            // every workspace file — koa's request_body matching
            // every aws-lambda example is the canonical regression.
            // The package-signal gate is the same one that
            // call-shaped rules use; reads need it just as much.
            if !prepared.call_context_allows(&r.name, &[], &alias_map, file_packages.as_ref()) {
                continue;
            }
            let (file_path, line, col) = resolve_span(ws, file, r.span);
            let enclosing_fn = enclosing_decl.map(|d| d.name.clone());
            out.push(RuleMatch {
                rule_id: prepared.rule.id.clone(),
                language: prepared.rule.language.clone(),
                file: file_path,
                line,
                column: col,
                span: r.span,
                match_text: r.name.clone(),
                enclosing_fn,
            });
        }
    }
}

fn scan_flow_reads_batch(
    ws: &Workspace,
    file: FileId,
    rules: &[&PreparedRule<'_>],
    out: &mut Vec<RuleMatch>,
) {
    let global = ws.db().global_index();
    let file_packages = file_package_set(ws, file);
    let alias_map = file_alias_map(ws, file);
    for decl in global.decls_in(file) {
        let mut reads = Vec::new();
        collect_flow_read_sites(&decl.flow_events, &mut reads);
        for (span, tokens) in reads {
            for prepared in rules {
                if !decl_target_context_allows(
                    global.as_ref(),
                    Some(decl),
                    prepared.rule.match_spec.target.as_ref(),
                    None,
                ) {
                    continue;
                }
                let Some(match_text) = flow_read_rule_match(prepared, &tokens) else {
                    continue;
                };
                if !base_param_index_allows(prepared, Some(decl), &match_text) {
                    continue;
                }
                if !base_receiver_type_allows(prepared, Some(decl), &match_text) {
                    continue;
                }
                // Same package-signal gate that `scan_refs_batch`
                // applies; without it a receiver-agnostic read
                // regex would fire on any file regardless of the
                // imports it actually pulls in.
                if !prepared.call_context_allows(&match_text, &[], &alias_map, file_packages.as_ref()) {
                    continue;
                }
                let span = canonical_flow_read_match_span(ws, file, span, &match_text);
                if out
                    .iter()
                    .any(|existing| existing.rule_id == prepared.rule.id && existing.span == span)
                {
                    continue;
                }
                let (file_path, line, col) = resolve_span(ws, file, span);
                out.push(RuleMatch {
                    rule_id: prepared.rule.id.clone(),
                    language: prepared.rule.language.clone(),
                    file: file_path,
                    line,
                    column: col,
                    span,
                    match_text,
                    enclosing_fn: Some(decl.name.clone()),
                });
            }
        }
    }
}

fn flow_read_rule_match(prepared: &PreparedRule<'_>, tokens: &[String]) -> Option<String> {
    if let Some(name) = prepared.name {
        if tokens
            .iter()
            .any(|token| token == name && prepared.base_name_allows(token))
        {
            return Some(name.to_string());
        }
    }
    if let Some(attr) = prepared.attribute {
        let joined = attr.join(".");
        if prepared.base_name_allows(&joined)
            && attr.iter().all(|part| tokens.iter().any(|token| token == part))
        {
            return Some(joined);
        }
    }
    if let Some(regex) = prepared.regex.as_ref() {
        if let Some(token) = tokens
            .iter()
            .find(|token| regex.is_match(token) && prepared.base_name_allows(token))
        {
            return Some(token.clone());
        }
        if let Some(attr) = prepared.attribute {
            let joined = attr.join(".");
            if regex.is_match(&joined) && prepared.base_name_allows(&joined) {
                return Some(joined);
            }
        }
    }
    None
}

fn base_param_index_allows(
    prepared: &PreparedRule<'_>,
    decl: Option<&bonsai_lang_api::Decl>,
    match_text: &str,
) -> bool {
    let Some(target) = rule_primary_target(prepared.rule) else {
        return true;
    };
    if target.base_param_index_in.is_empty() {
        return true;
    }
    let Some(decl) = decl else {
        return false;
    };
    let Some(base) = match_base_name(match_text) else {
        return false;
    };
    target
        .base_param_index_in
        .iter()
        .any(|idx| decl.params.get(*idx as usize).is_some_and(|param| param == base))
}

fn base_receiver_type_allows(
    prepared: &PreparedRule<'_>,
    decl: Option<&bonsai_lang_api::Decl>,
    match_text: &str,
) -> bool {
    let Some(target) = rule_primary_target(prepared.rule) else {
        return true;
    };
    if target.receiver_type_in.is_empty() {
        return true;
    }
    let Some(decl) = decl else {
        return false;
    };
    let Some(base) = match_base_name(match_text) else {
        return false;
    };
    decl.type_aliases
        .iter()
        .filter(|alias| alias.name == base)
        .any(|alias| receiver_type_matches_wanted(&alias.type_name, &target.receiver_type_in))
}

fn receiver_type_matches_wanted(actual: &str, wanted: &[String]) -> bool {
    wanted
        .iter()
        .any(|want| actual == want || actual.rsplit('.').next() == Some(want.as_str()))
}

fn rule_primary_target(rule: &Rule) -> Option<&RuleTarget> {
    match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
            rule.match_spec.target.as_ref()
        }
    }
}

/// Flow-read facts are often attached to the enclosing expression that
/// exposed the read (`const q = req.query`, `sink(req.query)`). When a
/// source rule matches a specific token inside that expression, report
/// the token span rather than the wrapper span so source endpoints point
/// at the attacker-controlled read instead of an assignment target.
fn canonical_flow_read_match_span(ws: &Workspace, file: FileId, span: Span, match_text: &str) -> Span {
    let match_text = match_text.trim();
    if match_text.is_empty() || match_text.contains(',') {
        return span;
    }
    let Ok(snapshot) = ws.vfs().snapshot(file) else {
        return span;
    };
    let source = snapshot.text.as_ref();
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > source.len() {
        return span;
    }
    let raw = &source[start..end];
    let preferred_start = raw.find('=').map_or(0, |idx| idx + 1);
    let offset = raw[preferred_start..]
        .find(match_text)
        .map(|idx| preferred_start + idx)
        .or_else(|| raw.find(match_text));
    let Some(offset) = offset else {
        return span;
    };
    let match_start = span.start.saturating_add(offset as u64);
    Span::new(
        file,
        match_start,
        match_start.saturating_add(match_text.len() as u64),
    )
}

fn collect_return_sites(events: &[FlowEvent], out: &mut Vec<(Span, Option<String>, Option<String>)>) {
    for event in events {
        match event {
            FlowEvent::Return {
                span,
                value_text,
                value_name,
            } => out.push((*span, value_text.clone(), value_name.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_return_sites(then_events, out);
                collect_return_sites(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_return_sites(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_return_sites(body, out);
                collect_return_sites(catch_events, out);
                collect_return_sites(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_flow_read_sites(events: &[FlowEvent], out: &mut Vec<(Span, Vec<String>)>) {
    for event in events {
        match event {
            FlowEvent::Call {
                span, receiver, args, ..
            } => {
                let mut tokens = Vec::new();
                if let Some(receiver) = receiver {
                    tokens.extend(split_read_token(receiver));
                }
                for arg in args {
                    tokens.extend(split_read_token(&arg.value_text));
                    if let Some(place) = &arg.place {
                        tokens.extend(split_read_token(place));
                    }
                }
                if !tokens.is_empty() {
                    out.push((*span, tokens));
                }
            }
            FlowEvent::Assign {
                span,
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                let mut tokens = Vec::new();
                if let Some(source_name) = source_name {
                    tokens.extend(split_read_token(source_name));
                }
                for name in source_names {
                    tokens.extend(split_read_token(name));
                }
                for arg in source_call_args {
                    tokens.extend(split_read_token(arg));
                }
                if !tokens.is_empty() {
                    out.push((*span, tokens));
                }
            }
            FlowEvent::Return {
                span,
                value_text,
                value_name,
                ..
            } => {
                let mut tokens = Vec::new();
                if let Some(value_text) = value_text {
                    tokens.extend(split_return_read_token(value_text));
                }
                if let Some(value_name) = value_name {
                    tokens.extend(split_read_token(value_name));
                }
                if !tokens.is_empty() {
                    out.push((*span, tokens));
                }
            }
            FlowEvent::Throw {
                span,
                value_name,
                thrown_type: None,
            } => {
                if let Some(value_name) = value_name {
                    out.push((*span, split_read_token(value_name)));
                }
            }
            FlowEvent::Yield { span, value_text } => {
                if let Some(value_text) = value_text {
                    out.push((*span, split_read_token(value_text)));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_flow_read_sites(then_events, out);
                collect_flow_read_sites(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_flow_read_sites(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_flow_read_sites(body, out);
                collect_flow_read_sites(catch_events, out);
                collect_flow_read_sites(finally_events, out);
            }
            _ => {}
        }
    }
}

/// Tokenize an expression into identifier tokens. Splits on every
/// non-identifier char so `obj.field[i]` yields `[obj, field, i]`.
/// Used by `flow_read_rule_match` to detect read-rule hits inside
/// argument expressions.
fn split_read_token(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
        .filter_map(|part| {
            let part = part.trim().trim_start_matches('$');
            (!part.is_empty()).then(|| part.to_string())
        })
        .collect()
}

/// Tokenize a `return EXPR` value. When the expression is a call,
/// returns its ARGUMENT tokens instead of the function name — a
/// `return f(x.y)` should expose `x` / `y` as the read tokens, not
/// `f`. Falls back to `split_read_token` for non-call returns.
fn split_return_read_token(value: &str) -> Vec<String> {
    let value = value.trim();
    if let Some((_, args)) = receiver_call_with_args(value, Span::new(FileId::new(0), 0, 0)) {
        return args
            .iter()
            .flat_map(|arg| split_read_token(&arg.value_text))
            .collect();
    }
    split_read_token(value)
}

fn collect_assignment_texts(events: &[FlowEvent], source_text: Option<&str>) -> AHashMap<String, String> {
    let mut out = AHashMap::new();
    collect_assignment_texts_into(events, source_text, &mut out);
    out
}

fn collect_assignment_texts_into(
    events: &[FlowEvent],
    source_text: Option<&str>,
    out: &mut AHashMap<String, String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                span,
                ..
            } => {
                if target.is_empty() {
                    continue;
                }
                if let Some(rhs_text) = assignment_rhs_text(
                    source_text,
                    *span,
                    target,
                    source_name.as_deref(),
                    source_call.as_deref(),
                    source_call_args,
                    source_names,
                ) {
                    out.insert(target.clone(), rhs_text);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assignment_texts_into(then_events, source_text, out);
                collect_assignment_texts_into(else_events, source_text, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assignment_texts_into(body, source_text, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assignment_texts_into(body, source_text, out);
                collect_assignment_texts_into(catch_events, source_text, out);
                collect_assignment_texts_into(finally_events, source_text, out);
            }
            _ => {}
        }
    }
}

/// Extract a textual RHS for an `Assign` flow event, used when an
/// `arg_matches_regex` constraint follows the assignment to its
/// expression. Prefers the verbatim source slice (`x = expr`); falls
/// back to reconstructing from the structured `source_call` /
/// `source_name` / `source_names` fields when the source text isn't
/// available.
fn assignment_rhs_text(
    source_text: Option<&str>,
    span: Span,
    target: &str,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
) -> Option<String> {
    if let Some(source_text) = source_text {
        if let Some(raw) = source_text.get(span.start as usize..span.end as usize) {
            let mut rhs = raw.trim();
            if let Some(eq) = rhs.find('=') {
                rhs = rhs[eq + 1..].trim();
                rhs = rhs.trim_matches(|ch: char| ch == ';' || ch == ',');
                if !rhs.is_empty() {
                    // Trailing `)` without a matching `(` indicates
                    // we sliced into a partial call expression; drop
                    // the orphan paren so the regex sees a clean RHS.
                    if rhs.ends_with(')') && rhs.rfind('(').is_none() {
                        rhs = rhs.trim_end_matches(')');
                    }
                    return Some(rhs.to_string());
                }
            }
        }
    }
    // Reconstruct from structured fields when the raw text isn't
    // available (cached spans, snapshot races).
    if let Some(source_call) = source_call {
        if source_call_args.is_empty() {
            return Some(source_call.to_string());
        }
        return Some(format!("{source_call}({})", source_call_args.join(", ")));
    }
    if let Some(source_name) = source_name {
        return Some(source_name.to_string());
    }
    if !source_names.is_empty() {
        return Some(source_names.join(", "));
    }
    if target.is_empty() {
        return None;
    }
    None
}

/// Build the candidate text list a regex constraint should evaluate
/// against `arg`. Always includes the arg's verbatim text; when
/// `follow_assignments` is true and the arg is a bare identifier,
/// recursively follows local assignment chains so a constraint
/// matching `^http://` still fires on `let url = "http://..."; f(url)`.
/// Bounded by `depth` to prevent runaway recursion on cyclic
/// assignments.
fn arg_regex_texts(
    arg: &CallArg,
    assignment_texts: Option<&AHashMap<String, String>>,
    depth: usize,
    follow_assignments: bool,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if depth == 0 {
        return candidates;
    }
    let base = arg.value_text.trim();
    if !base.is_empty() {
        candidates.push(base.to_string());
    }
    if !follow_assignments || depth <= 1 || !is_simple_identifier(base) {
        return candidates;
    }
    let Some(assignment_texts) = assignment_texts else {
        return candidates;
    };
    let Some(assignment) = assignment_texts.get(base) else {
        return candidates;
    };
    if assignment.trim().is_empty() || assignment == base {
        return candidates;
    }
    let nested = arg_regex_texts(
        &CallArg {
            span: arg.span,
            name: arg.name.clone(),
            place: arg.place.clone(),
            source_names: arg.source_names.clone(),
            value_text: assignment.clone(),
        },
        Some(assignment_texts),
        depth.saturating_sub(1),
        follow_assignments,
    );
    candidates.extend(nested);
    candidates
}

/// True when `text` is a single identifier token (alpha / `_` / `$`
/// start; alnum / `_` / `$` body). Used to detect arg expressions
/// that might match a tainted value's identifier directly.
fn is_simple_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    // Pull the first char and short-circuit when the input is empty.
    // Folding the empty check into the iterator avoids the
    // safe-by-construction unwrap that earlier versions used.
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Layer adapter-emitted type-alias bindings (`Decl.type_aliases`)
/// onto an existing alias map. Existing entries are preserved so
/// import-derived aliases beat type-derived ones when both fire on
/// the same local name.
fn extend_alias_map_with_declared_types(
    alias_map: &mut std::collections::HashMap<String, AliasTarget>,
    aliases: &[TypeAliasBinding],
) {
    for alias in aliases {
        alias_map
            .entry(alias.name.clone())
            .or_insert_with(|| AliasTarget::Type {
                type_name: alias.type_name.clone(),
            });
    }
}

fn scan_writes_batch(
    ws: &Workspace,
    file: FileId,
    rules: &[&PreparedRule<'_>],
    mode: ConstraintMode,
    taint_view: Option<&InterTaintView<'_>>,
    out: &mut Vec<RuleMatch>,
) {
    let global = ws.db().global_index();
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let file_packages = file_package_set(ws, file);
    let alias_map = file_alias_map(ws, file);
    for decl in global.decls_in(file) {
        let writes = collect_writes(&decl.flow_events);
        for (target, span) in writes {
            let args = source_text
                .as_deref()
                .and_then(|text| text.get(span.start as usize..span.end as usize))
                .map(|value_text| {
                    vec![CallArg {
                        span,
                        name: None,
                        place: None,
                        source_names: Vec::new(),
                        value_text: value_text.to_string(),
                    }]
                })
                .unwrap_or_default();
            for prepared in rules {
                if !callee_matches(
                    &target,
                    prepared.name,
                    prepared.attribute,
                    prepared.regex.as_ref(),
                ) {
                    continue;
                }
                if !prepared.base_name_allows(&target) {
                    continue;
                }
                // Same package-signal gate the call/read scanners use —
                // a receiver-agnostic write target like
                // `^[A-Za-z_$]\w*\.headers$` would otherwise fire on
                // any file regardless of the rule's `packages` list.
                if !prepared.call_context_allows(&target, &[], &alias_map, file_packages.as_ref()) {
                    continue;
                }
                if !constraints_pass(ConstraintEval {
                    rule_id: &prepared.rule.id,
                    callee: &target,
                    args: &args,
                    receiver_types: &[],
                    span,
                    call_origin: Some(CallFactOrigin::SyntheticWrite),
                    constraints: &prepared.rule.constraints.0,
                    constraint_regexes: &prepared.constraint_regexes,
                    receiver_call_count: None,
                    assignment_texts: None,
                    mode,
                    taint_view,
                    enclosing_decorators: None,
                    alias_chains: None,
                    runtime_types: None,
                    lifecycle_transitions: None,
                }) {
                    continue;
                }
                let (file_path, line, col) = resolve_span(ws, file, span);
                out.push(RuleMatch {
                    rule_id: prepared.rule.id.clone(),
                    language: prepared.rule.language.clone(),
                    file: file_path,
                    line,
                    column: col,
                    span,
                    match_text: target.clone(),
                    enclosing_fn: Some(decl.name.clone()),
                });
            }
        }
    }
}

fn scan_ref_writes_batch(
    ws: &Workspace,
    file: FileId,
    rules: &[&PreparedRule<'_>],
    mode: ConstraintMode,
    taint_view: Option<&InterTaintView<'_>>,
    out: &mut Vec<RuleMatch>,
) {
    let Some(idx) = ws.db().decl_index(file) else {
        return;
    };
    let global = ws.db().global_index();
    let decls = global.decls_in(file);
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let file_packages = file_package_set(ws, file);
    let alias_map = file_alias_map(ws, file);
    for r in &idx.refs {
        if r.kind != RefKind::Write {
            continue;
        }
        let args = source_text
            .as_deref()
            .and_then(|text| text.get(r.span.start as usize..r.span.end as usize))
            .map(|value_text| {
                vec![CallArg {
                    span: r.span,
                    name: None,
                    place: None,
                    source_names: Vec::new(),
                    value_text: value_text.to_string(),
                }]
            })
            .unwrap_or_default();
        for prepared in rules {
            if !callee_matches(
                &r.name,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
            ) {
                continue;
            }
            if !prepared.base_name_allows(&r.name) {
                continue;
            }
            if !prepared.call_context_allows(&r.name, &[], &alias_map, file_packages.as_ref()) {
                continue;
            }
            if !constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &r.name,
                args: &args,
                receiver_types: &[],
                span: r.span,
                call_origin: Some(CallFactOrigin::SyntheticWrite),
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count: None,
                assignment_texts: None,
                mode,
                taint_view,
                enclosing_decorators: None,
                alias_chains: None,
                runtime_types: None,
                lifecycle_transitions: None,
            }) {
                continue;
            }
            if out
                .iter()
                .any(|existing| existing.rule_id == prepared.rule.id && existing.span == r.span)
            {
                continue;
            }
            let (file_path, line, col) = resolve_span(ws, file, r.span);
            let enclosing_fn = decls
                .iter()
                .find(|d| {
                    let body = d.body_span.unwrap_or(d.span);
                    r.span.start >= body.start && r.span.start < body.end
                })
                .map(|d| d.name.clone());
            out.push(RuleMatch {
                rule_id: prepared.rule.id.clone(),
                language: prepared.rule.language.clone(),
                file: file_path,
                line,
                column: col,
                span: r.span,
                match_text: r.name.clone(),
                enclosing_fn,
            });
        }
    }
}

fn matching_write_exists(ws: &Workspace, file: FileId, prepared: &PreparedRule<'_>) -> bool {
    let global = ws.db().global_index();
    for decl in global.decls_in(file) {
        for (target, _) in collect_writes(&decl.flow_events) {
            if callee_matches(
                &target,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
            ) {
                return true;
            }
        }
    }

    let Some(idx) = ws.db().decl_index(file) else {
        return false;
    };
    for r in &idx.refs {
        if r.kind == RefKind::Write
            && callee_matches(
                &r.name,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
            )
        {
            return true;
        }
    }
    false
}

/// Decorator name segments attached to `decl_span`, used by the
/// `EnclosingDecoratorIn` constraint and Missing walker scoping.
/// Each dotted segment is emitted so rules can match the framework-
/// stable tail (`route`, `post`) regardless of receiver spelling.
fn collect_decl_decorator_names(ws: &Workspace, file: FileId, decl_span: Span) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(idx) = ws.db().decl_index(file) else {
        return out;
    };
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    for r in &idx.refs {
        if r.kind != RefKind::Decorator {
            continue;
        }
        if r.span.end > decl_span.start {
            continue;
        }
        // Mirror `detect_framework_decorator`: only count decorators
        // sitting just before the decl head.
        if decl_span.start.saturating_sub(r.span.end) > 512 {
            continue;
        }
        if !decorator_is_attached_to_decl(ws, file, r.span, decl_span) {
            continue;
        }
        for segment in decorator_name_segments(&r.name) {
            if !out.contains(&segment) {
                out.push(segment);
            }
        }
        // Some grammars expose only the leftmost identifier as the
        // ref name (Python `@app.route` → "app"). Splice the source
        // span to recover the dotted callee.
        if let Some(text) = source_text.as_deref() {
            let start = r.span.start as usize;
            let end = r.span.end as usize;
            if start < text.len() && end <= text.len() && start < end {
                let raw = &text[start..end];
                let head = raw
                    .trim_start_matches('@')
                    .split(|c: char| c == '(' || c.is_whitespace())
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(',');
                for segment in decorator_name_segments(head) {
                    if !out.contains(&segment) {
                        out.push(segment);
                    }
                }
            }
        }
    }
    out
}

/// Split a qualified decorator name into its segments.
/// `app.route` → `["app.route", "app", "route"]`. The full form
/// is kept first so exact-match rules still hit.
fn decorator_name_segments(raw: &str) -> Vec<String> {
    let trimmed = raw.trim().trim_start_matches('@').trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut segments: Vec<String> = vec![trimmed.to_string()];
    for sep in bonsai_common::QUALIFIED_NAME_SEPARATORS {
        if !trimmed.contains(sep) {
            continue;
        }
        for part in trimmed.split(sep) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if !segments.iter().any(|existing| existing == part) {
                segments.push(part.to_string());
            }
        }
    }
    segments
}

/// Intra-procedural must-alias map for the `MustAlias` constraint.
/// Only simple renames (`y = x`) qualify; compound RHS (`y = x + 1`,
/// `y = f(x)`) is not aliasing. Transitive chains are folded once.
fn collect_must_alias_pairs(events: &[FlowEvent]) -> AHashMap<String, String> {
    let mut pairs: AHashMap<String, String> = AHashMap::new();
    let mut order: Vec<(String, String)> = Vec::new();
    fn walk(events: &[FlowEvent], order: &mut Vec<(String, String)>) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    target,
                    source_name,
                    source_call,
                    source_names,
                    ..
                } => {
                    if let Some(src) = source_name {
                        if source_call.is_none() && !target.is_empty() && !src.is_empty() {
                            // Reject when `source_names` carries an extra operand —
                            // that means the RHS was compound, not a simple rename.
                            let extra_operands = source_names.iter().any(|n| n != src && !n.is_empty());
                            if !extra_operands {
                                order.push((target.clone(), src.clone()));
                            }
                        }
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    walk(then_events, order);
                    walk(else_events, order);
                }
                FlowEvent::Loop { body, .. } => walk(body, order),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(body, order);
                    walk(catch_events, order);
                    walk(finally_events, order);
                }
                _ => {}
            }
        }
    }
    walk(events, &mut order);
    // Fold each (target, src) so target points to src's root.
    // Depth-cap guards against pathological cycles.
    for (target, src) in order {
        let mut root = src;
        let mut depth = 0usize;
        while depth < 32 {
            match pairs.get(&root) {
                Some(next) if next != &root => {
                    root.clone_from(next);
                    depth += 1;
                }
                _ => break,
            }
        }
        pairs.insert(target, root);
    }
    pairs
}

/// CFG-aware runtime-type narrowing for `RequiresRuntimeType`.
/// `name` was narrowed to `type_name` inside `[start, end)` — the
/// then-branch of a type-test guard. Outside the range the
/// narrowing is dropped (merge widens to top).
#[derive(Clone, Debug)]
struct RuntimeTypeNarrowing {
    name: String,
    type_name: String,
    start: u64,
    end: u64,
}

/// Collect narrowings from type-test guards (`instanceof`,
/// `isinstance`, `_ is X`, `typeof _ === "X"`). Else-arm
/// narrowings are not modelled — negation handling is follow-up.
fn collect_runtime_type_narrowings(events: &[FlowEvent]) -> Vec<RuntimeTypeNarrowing> {
    let mut narrowings: Vec<RuntimeTypeNarrowing> = Vec::new();
    fn walk(events: &[FlowEvent], narrowings: &mut Vec<RuntimeTypeNarrowing>) {
        for event in events {
            match event {
                FlowEvent::Branch {
                    condition,
                    then_events,
                    else_events,
                    ..
                } => {
                    if let Some(cond) = condition {
                        if let Some((name, ty)) = parse_type_test(cond) {
                            if let Some((start, end)) = events_span(then_events) {
                                narrowings.push(RuntimeTypeNarrowing {
                                    name,
                                    type_name: ty,
                                    start,
                                    end,
                                });
                            }
                        }
                    }
                    walk(then_events, narrowings);
                    walk(else_events, narrowings);
                }
                FlowEvent::Loop { body, .. } => walk(body, narrowings),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(body, narrowings);
                    walk(catch_events, narrowings);
                    walk(finally_events, narrowings);
                }
                _ => {}
            }
        }
    }
    walk(events, &mut narrowings);
    narrowings
}

/// Smallest enclosing `[start, end)` byte range that covers every
/// event in `events`. Returns `None` for an empty list.
fn events_span(events: &[FlowEvent]) -> Option<(u64, u64)> {
    fn flow_span(event: &FlowEvent) -> (u64, u64) {
        let span = match event {
            FlowEvent::Call { span, .. }
            | FlowEvent::Branch { span, .. }
            | FlowEvent::Loop { span, .. }
            | FlowEvent::Assign { span, .. }
            | FlowEvent::Return { span, .. }
            | FlowEvent::Throw { span, .. }
            | FlowEvent::Try { span, .. }
            | FlowEvent::Break { span, .. }
            | FlowEvent::Continue { span, .. }
            | FlowEvent::Yield { span, .. }
            | FlowEvent::Await { span, .. }
            | FlowEvent::Defer { span, .. }
            | FlowEvent::Using { span, .. }
            | FlowEvent::Lifecycle { span, .. } => span,
        };
        (span.start, span.end)
    }
    let mut start: Option<u64> = None;
    let mut end: Option<u64> = None;
    for event in events {
        let (s, e) = flow_span(event);
        start = Some(start.map_or(s, |cur| cur.min(s)));
        end = Some(end.map_or(e, |cur| cur.max(e)));
    }
    Some((start?, end?))
}

/// Narrowed type for `name` at byte position `call_span_start`,
/// or `None` if no narrowing covers it. Tightest enclosing range
/// wins so nested type tests refine outer ones.
fn runtime_type_at(narrowings: &[RuntimeTypeNarrowing], name: &str, call_span_start: u64) -> Option<String> {
    let mut chosen: Option<&RuntimeTypeNarrowing> = None;
    for n in narrowings {
        if n.name != name {
            continue;
        }
        if call_span_start < n.start || call_span_start >= n.end {
            continue;
        }
        match chosen {
            None => chosen = Some(n),
            Some(existing) => {
                let existing_width = existing.end.saturating_sub(existing.start);
                let candidate_width = n.end.saturating_sub(n.start);
                if candidate_width < existing_width {
                    chosen = Some(n);
                }
            }
        }
    }
    chosen.map(|n| n.type_name.clone())
}

/// Parse a type-test guard. Recognises `x instanceof Foo`,
/// `isinstance(x, Foo)`, `x is Foo`, and `typeof x === "Foo"`.
/// Bare-identifier subjects only — dotted access is rejected
/// because the engine doesn't bind narrowings on member access yet.
fn parse_type_test(condition: &str) -> Option<(String, String)> {
    let cond = condition.trim();
    // x instanceof Foo
    if let Some((lhs, rhs)) = cond.split_once(" instanceof ") {
        let name = lhs.trim();
        let ty = rhs
            .trim()
            .trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
        if !name.is_empty() && is_simple_ident(name) && !ty.is_empty() && is_simple_ident(ty) {
            return Some((name.to_string(), ty.to_string()));
        }
    }
    // isinstance(x, Foo) — strip optional 'not ' / leading paren
    if let Some(after) = cond.strip_prefix("isinstance(") {
        if let Some(close) = after.find(')') {
            let inner = &after[..close];
            if let Some((arg, ty)) = inner.split_once(',') {
                let name = arg.trim();
                let ty = ty.trim();
                if is_simple_ident(name) && is_simple_ident(ty) {
                    return Some((name.to_string(), ty.to_string()));
                }
            }
        }
    }
    // x is Foo (C#, Kotlin, Swift, Rust pattern)
    if let Some((lhs, rhs)) = cond.split_once(" is ") {
        let name = lhs.trim();
        let ty = rhs
            .trim()
            .trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
        if !name.is_empty() && is_simple_ident(name) && !ty.is_empty() && is_simple_ident(ty) {
            return Some((name.to_string(), ty.to_string()));
        }
    }
    // typeof x === "string" / typeof x == 'string'
    if let Some(rest) = cond.strip_prefix("typeof ") {
        for sep in [" === ", " == "] {
            if let Some((lhs, rhs)) = rest.split_once(sep) {
                let name = lhs.trim();
                let ty = rhs.trim().trim_matches(|c: char| c == '"' || c == '\'');
                if is_simple_ident(name) && !ty.is_empty() {
                    return Some((name.to_string(), ty.to_string()));
                }
            }
        }
    }
    None
}

fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Lifecycle transitions for the `RequiresState` constraint,
/// ordered by source span so the matcher can scan up to a given
/// call site without seeing later transitions. Empty when the
/// adapter doesn't yet emit `FlowEvent::Lifecycle` for the language.
fn collect_lifecycle_transitions(events: &[FlowEvent]) -> Vec<(Span, String, String)> {
    let mut out: Vec<(Span, String, String)> = Vec::new();
    fn walk(events: &[FlowEvent], out: &mut Vec<(Span, String, String)>) {
        for event in events {
            match event {
                FlowEvent::Lifecycle {
                    span,
                    name,
                    transition,
                } => {
                    if name.is_empty() || transition.is_empty() {
                        continue;
                    }
                    out.push((*span, name.clone(), transition.clone()));
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    walk(then_events, out);
                    walk(else_events, out);
                }
                FlowEvent::Loop { body, .. } => walk(body, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(body, out);
                    walk(catch_events, out);
                    walk(finally_events, out);
                }
                FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                    walk(body, out);
                }
                _ => {}
            }
        }
    }
    walk(events, &mut out);
    out.sort_by_key(|(span, _, _)| span.start);
    out
}

/// Latest transition for `name` whose span ends before
/// `call_span_start`. Branch-insensitive: lexical order is the
/// only ordering guarantee.
fn lifecycle_state_at(
    transitions: &[(Span, String, String)],
    name: &str,
    call_span_start: u64,
) -> Option<String> {
    let mut state: Option<&str> = None;
    for (span, n, t) in transitions {
        // Sorted ascending; once we pass the call site we can stop.
        if span.end > call_span_start {
            break;
        }
        if n == name {
            state = Some(t.as_str());
        }
    }
    state.map(str::to_string)
}

/// call site, including nested receiver calls and assignment-source
/// calls. The de-shadow pass at the end drops assignment-source
/// duplicates that already appear as real calls — without it, a
/// `let x = f(y)` assignment generates two CallFacts for `f(y)` and
/// `f` matches twice.
fn collect_calls(events: &[FlowEvent]) -> Vec<CallFact> {
    let mut calls = Vec::new();
    collect_calls_into(events, &mut calls);
    drop_shadowed_assignment_call_facts(&mut calls);
    calls
}

fn enrich_call_fact_receiver_types(calls: &mut [CallFact], aliases: &[TypeAliasBinding]) {
    if aliases.is_empty() {
        return;
    }
    for call in calls {
        let Some(receiver) = call_receiver_text(&call.callee) else {
            continue;
        };
        for alias in aliases {
            if alias.name == receiver || receiver_root_name(receiver).as_deref() == Some(alias.name.as_str())
            {
                push_unique_string(&mut call.receiver_types, alias.type_name.clone());
            }
        }
    }
}

fn call_receiver_text(callee: &str) -> Option<&str> {
    let callee = callee.trim();
    for sep in bonsai_common::QUALIFIED_NAME_SEPARATORS {
        let Some((receiver, _)) = callee.rsplit_once(sep) else {
            continue;
        };
        let receiver = receiver.trim();
        if !receiver.is_empty() {
            return Some(receiver);
        }
    }
    None
}

fn receiver_root_name(receiver: &str) -> Option<String> {
    let receiver = receiver
        .trim()
        .trim_start_matches(bonsai_common::ALL_NAME_PUNCTUATION);
    let root = receiver
        .split(['.', ':', '\\', '[', '('])
        .next()
        .unwrap_or(receiver)
        .trim();
    if root.is_empty() || root == receiver {
        return None;
    }
    Some(root.to_string())
}

fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

/// Tally how often each `receiver\0method` pair appears in the call
/// list, ignoring assignment-source duplicates. Drives the
/// `SameReceiverCallCountAtLeast` constraint (e.g. "this rule only
/// fires when the same receiver was called ≥ 2 times in scope").
fn receiver_method_call_counts(calls: &[CallFact]) -> AHashMap<String, u32> {
    let mut counts = AHashMap::new();
    for call in calls {
        if call.origin == CallFactOrigin::AssignmentSourceCall {
            continue;
        }
        let Some(key) = receiver_method_key(&call.callee) else {
            continue;
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

/// Build the `receiver\0method` key for a qualified callee, or
/// `None` for bare unqualified names. Tries every supported
/// qualifier separator (`.`, `::`, `->`, `:`, `\`).
fn receiver_method_key(callee: &str) -> Option<String> {
    let callee = callee.trim();
    for sep in bonsai_common::QUALIFIED_NAME_SEPARATORS {
        let Some((receiver, method)) = callee.rsplit_once(sep) else {
            continue;
        };
        let receiver = receiver.trim();
        let method = method.trim();
        if receiver.is_empty() || method.is_empty() {
            continue;
        }
        return Some(format!("{receiver}\0{method}"));
    }
    None
}

fn collect_calls_into(events: &[FlowEvent], out: &mut Vec<CallFact>) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                span,
                receiver,
                args,
                receiver_types,
                call_kind,
                ..
            } => {
                out.push(CallFact {
                    callee: name.clone(),
                    span: *span,
                    args: args.clone(),
                    receiver_types: receiver_types.clone(),
                    call_kind: *call_kind,
                    origin: CallFactOrigin::RealCall,
                });
                if let Some(receiver) = receiver.as_deref() {
                    if let Some((callee, nested_args)) = receiver_call_with_args(receiver, *span) {
                        out.push(CallFact {
                            callee,
                            span: *span,
                            args: nested_args,
                            receiver_types: Vec::new(),
                            call_kind: CallKind::Function,
                            origin: CallFactOrigin::NestedReceiverCall,
                        });
                    }
                }
            }
            FlowEvent::Assign {
                span,
                source_call: Some(name),
                source_call_args,
                source_names,
                ..
            } => {
                out.push(CallFact {
                    callee: name.clone(),
                    span: *span,
                    args: source_call_args
                        .iter()
                        .map(|value_text| CallArg {
                            span: *span,
                            name: None,
                            value_text: value_text.clone(),
                            place: None,
                            source_names: source_names.clone(),
                        })
                        .collect(),
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    origin: CallFactOrigin::AssignmentSourceCall,
                });
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_calls_into(then_events, out);
                collect_calls_into(else_events, out);
            }
            FlowEvent::Loop { body, .. } => collect_calls_into(body, out),
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_calls_into(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_calls_into(body, out);
                collect_calls_into(catch_events, out);
                collect_calls_into(finally_events, out);
            }
            _ => {}
        }
    }
}

/// Drop synthetic `AssignmentSourceCall` facts that duplicate a real
/// call already in the list. A `let x = f(y)` assignment surfaces
/// `f(y)` twice (once from the call event, once from the assignment
/// event); de-shadowing keeps the more informative real call.
fn drop_shadowed_assignment_call_facts(calls: &mut Vec<CallFact>) {
    let real_calls: Vec<(String, Span)> = calls
        .iter()
        .filter(|call| {
            matches!(
                call.origin,
                CallFactOrigin::RealCall | CallFactOrigin::NestedReceiverCall
            )
        })
        .map(|call| (call.callee.clone(), call.span))
        .collect();
    calls.retain(|call| {
        if call.origin != CallFactOrigin::AssignmentSourceCall {
            return true;
        }
        !real_calls
            .iter()
            .any(|(callee, span)| call_names_match(callee, &call.callee) && spans_overlap(*span, call.span))
    });
}

/// True when two callee names refer to the same call. Exact match
/// first; falls back to tail equality to handle adapters that emit
/// `Class.method` in one event but `method` in another.
fn call_names_match(left: &str, right: &str) -> bool {
    left == right
        || left
            .rsplit(['.', ':', '\\'])
            .next()
            .is_some_and(|left_tail| right.rsplit(['.', ':', '\\']).next() == Some(left_tail))
}

fn receiver_call_with_args(receiver: &str, span: Span) -> Option<(String, Vec<CallArg>)> {
    let receiver = receiver.trim();
    let close = receiver.rfind(')')?;
    if receiver[close + 1..].trim().is_empty() {
        let open = matching_open_paren(receiver, close)?;
        let callee = receiver[..open].trim();
        if callee.is_empty() {
            return None;
        }
        let args = split_balanced_args(&receiver[open + 1..close])
            .into_iter()
            .map(|value_text| CallArg {
                span,
                name: None,
                value_text,
                place: None,
                source_names: Vec::new(),
            })
            .collect();
        return Some((callee.to_string(), args));
    }
    None
}

fn callee_matches_with_receiver_types(
    callee: &str,
    receiver_types: &[String],
    name: Option<&str>,
    attribute: Option<&Vec<String>>,
    regex: Option<&Regex>,
) -> bool {
    if callee_matches(callee, name, attribute, regex) {
        return true;
    }
    if regex.is_some() {
        return false;
    }
    attribute.is_some_and(|attr| receiver_type_attribute_matches(callee, receiver_types, attr))
}

fn receiver_type_attribute_matches(callee: &str, receiver_types: &[String], attr: &[String]) -> bool {
    if receiver_types.is_empty() || attr.len() < 2 {
        return false;
    }
    let normalized = normalize_callee_for_matching(callee);
    let Some(method) = attr.last() else {
        return false;
    };
    if !callee_tail_matches(&normalized, method) {
        return false;
    }
    receiver_types.iter().any(|actual| {
        (0..attr.len() - 1)
            .any(|start| type_name_matches_attribute_prefix(actual, &attr[start..attr.len() - 1]))
    })
}

fn type_name_matches_attribute_prefix(actual: &str, expected: &[String]) -> bool {
    if expected.is_empty() {
        return false;
    }
    let actual = normalize_type_name_for_match(actual);
    let expected_dot = expected.join(".");
    let expected_colon = expected.join("::");
    let expected_backslash = expected.join("\\");
    [expected_dot, expected_colon, expected_backslash]
        .into_iter()
        .any(|expected| {
            let expected = normalize_type_name_for_match(&expected);
            actual == expected
                || actual.ends_with(&format!(".{expected}"))
                || actual.ends_with(&format!("::{expected}"))
                || actual.ends_with(&format!("\\{expected}"))
                || receiver_path_tail(&actual) == receiver_path_tail(&expected)
        })
}

fn receiver_type_matches_any(actual: &[String], expected: &[String]) -> bool {
    actual.iter().any(|actual| {
        expected
            .iter()
            .any(|expected| type_name_matches_attribute_prefix(actual, std::slice::from_ref(expected)))
    })
}

fn normalize_type_name_for_match(value: &str) -> String {
    let mut out = value
        .trim()
        .trim_start_matches(bonsai_common::IDENTIFIER_SIGILS)
        .trim_start_matches(bonsai_common::REFERENCE_SIGILS)
        .to_string();
    if let Some(stripped) = out.strip_suffix("()") {
        out = stripped.trim().to_string();
    }
    out
}

fn normalize_callee_for_matching(callee: &str) -> String {
    let mut normalized = callee
        .trim_start_matches(bonsai_common::IDENTIFIER_SIGILS)
        .replace("()", "");
    if let Some(stripped) = normalized.strip_prefix("new ") {
        normalized = stripped.to_string();
    }
    if normalized.contains('{') {
        let mut out = String::with_capacity(normalized.len());
        let mut depth: i32 = 0;
        for ch in normalized.chars() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    if depth > 0 {
                        depth -= 1;
                    }
                }
                _ => {
                    if depth == 0 {
                        out.push(ch);
                    }
                }
            }
        }
        normalized = out;
    }
    normalized
}

fn callee_tail_matches(normalized: &str, method: &str) -> bool {
    normalized == method
        || normalized.ends_with(&format!(".{method}"))
        || normalized.ends_with(&format!("::{method}"))
        || normalized.ends_with(&format!("->{method}"))
        || normalized.ends_with(&format!("\\{method}"))
        || normalized.ends_with(&format!(":{method}"))
}

/// Find the byte offset of the `(` that opens the call ending at
/// `close`. Walks backwards counting paren depth so nested calls
/// `f(g(h))` resolve to the outermost open paren.
fn matching_open_paren(text: &str, close: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    for idx in (0..=close).rev() {
        match bytes[idx] {
            b')' => depth = depth.saturating_add(1),
            b'(' => {
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

/// Split a call's argument text on top-level commas, ignoring commas
/// inside parens / brackets / braces / strings. Used to recover an
/// argument list from raw source text when the adapter only emits
/// the receiver expression.
fn split_balanced_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if let Some(open_quote) = quote {
            // Inside a string literal — track escapes and the closing
            // quote, but ignore everything else.
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                quote = Some(ch);
                current.push(ch);
            }
            '(' => {
                paren_depth = paren_depth.saturating_add(1);
                current.push(ch);
            }
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                current.push(ch);
            }
            '[' => {
                bracket_depth = bracket_depth.saturating_add(1);
                current.push(ch);
            }
            ']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                current.push(ch);
            }
            '{' => {
                brace_depth = brace_depth.saturating_add(1);
                current.push(ch);
            }
            '}' => {
                brace_depth = brace_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                let value = current.trim();
                if !value.is_empty() {
                    args.push(value.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let value = current.trim();
    if !value.is_empty() {
        args.push(value.to_string());
    }
    args
}

fn collect_writes(events: &[FlowEvent]) -> Vec<(String, Span)> {
    let mut out = Vec::new();
    collect_writes_into(events, &mut out);
    out
}

fn collect_writes_into(events: &[FlowEvent], out: &mut Vec<(String, Span)>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, span, .. } => {
                if !target.is_empty() {
                    out.push((target.clone(), *span));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_writes_into(then_events, out);
                collect_writes_into(else_events, out);
            }
            FlowEvent::Loop { body, .. } => collect_writes_into(body, out),
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_writes_into(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_writes_into(body, out);
                collect_writes_into(catch_events, out);
                collect_writes_into(finally_events, out);
            }
            _ => {}
        }
    }
}

fn callee_matches(
    callee: &str,
    name: Option<&str>,
    attribute: Option<&Vec<String>>,
    regex: Option<&Regex>,
) -> bool {
    if let Some(re) = regex {
        return re.is_match(callee);
    }
    // Normalise the callee text for attribute / name matching ONLY.
    // Adapters preserve the literal source span text for the engine's
    // resolver / call-graph (resolution depends on textual identity);
    // the matcher applies a small set of equivalences that the rule
    // schema considers metadata rather than the callee path:
    //
    //   1. Drop `()` so `Runtime.getRuntime().exec` matches rules
    //      written as `attribute: [Runtime, getRuntime, exec]`.
    //   2. Drop balanced `{...}` blocks (Solidity 0.6+ call options
    //      `{value: amt, gas: g}`) so `to.call{value: amount}` matches
    //      rules keyed on `[address, call]` / `name: call`.
    //   3. Drop a leading `new ` so chained-construction shapes
    //      `new BinaryFormatter().Deserialize` match attribute rules
    //      written as `[BinaryFormatter, Deserialize]`. This belongs
    //      in the matcher (not the kit's fact-emitter) because the
    //      engine's resolver / alias_map depends on the literal
    //      `new T(args)` source text — stripping at fact-emission
    //      time breaks Java mega_flow's chained constructor → method
    //      resolution.
    let normalized = normalize_callee_for_matching(callee);
    if let Some(attr) = attribute {
        let joined_dot = attr.join(".");
        let joined_colon = attr.join("::");
        let joined_arrow = attr.join("->");
        let joined_backslash = attr.join("\\");
        let mixed_colon_dot = attr
            .split_last()
            .and_then(|(last, prefix)| (!prefix.is_empty()).then(|| format!("{}.{last}", prefix.join("::"))));
        let mixed_backslash_colon = attr.split_last().and_then(|(last, prefix)| {
            (!prefix.is_empty()).then(|| format!("{}::{last}", prefix.join("\\")))
        });
        if normalized == joined_dot
            || normalized == joined_colon
            || normalized == joined_arrow
            || normalized == joined_backslash
            || mixed_colon_dot.as_ref().is_some_and(|mixed| normalized == *mixed)
            || mixed_backslash_colon
                .as_ref()
                .is_some_and(|mixed| normalized == *mixed)
            || normalized == format!("{joined_dot}.new")
            || normalized == format!("{joined_colon}.new")
            || normalized == format!("{joined_arrow}->new")
            || normalized == format!("{joined_backslash}::__construct")
            || normalized == attr.join(":")
            || normalized.ends_with(&format!(".{joined_dot}"))
            || normalized.ends_with(&format!("/{joined_dot}"))
            || normalized.ends_with(&format!("::{joined_colon}"))
            || normalized.ends_with(&format!("->{joined_arrow}"))
            || normalized.ends_with(&format!("\\{joined_backslash}"))
            || normalized.ends_with(&format!(":{}", attr.join(":")))
        {
            return true;
        }
        // Method-chain fallback. Some adapters (Rust, Swift, Kotlin)
        // emit a whole builder chain as ONE Call event — e.g.
        // `Command::new("sh").arg("-c").arg(cmd).output`. The rule
        // targets the chain head `Command::new`, which won't match
        // any suffix of the chain. Accept it only when the emitted
        // callee starts with that head call or with an import-path
        // prefix whose final segment is that head call; a callback
        // argument like `callbacks.add(Command::new("sh"))` must not
        // match a `[Command, new]` rule.
        let inner_dot = format!("{joined_dot}(");
        let inner_colon = format!("{joined_colon}(");
        let inner_backslash = format!("{joined_backslash}(");
        if starts_with_chain_head(&normalized, &inner_dot)
            || starts_with_chain_head(&normalized, &inner_colon)
            || starts_with_chain_head(&normalized, &inner_backslash)
        {
            return true;
        }
        return false;
    }
    if let Some(n) = name {
        if normalized == n {
            return true;
        }
        for suffix in [".new", "->new", "::__construct"] {
            if normalized.strip_suffix(suffix) == Some(n) {
                return true;
            }
        }
        if let Some(tail) = normalized.rsplit('.').next() {
            if tail == n {
                return true;
            }
        }
        if let Some(tail) = normalized.rsplit("->").next() {
            if tail == n {
                return true;
            }
        }
        if let Some(tail) = normalized.rsplit("::").next() {
            if tail == n {
                return true;
            }
        }
        if let Some(tail) = normalized.rsplit('\\').next() {
            if tail == n {
                return true;
            }
        }
        if let Some(tail) = normalized.rsplit(':').next() {
            if tail == n {
                return true;
            }
        }
        return false;
    }
    false
}

fn starts_with_chain_head(normalized: &str, head_call: &str) -> bool {
    if normalized.starts_with(head_call) {
        return true;
    }
    let Some(idx) = normalized.find(head_call) else {
        return false;
    };
    if !matches!(normalized.as_bytes().get(idx.saturating_sub(1)), Some(b'/')) {
        return false;
    }
    idx < normalized.find('(').unwrap_or(normalized.len())
}

fn compile_constraint_regexes(rule_id: &str, constraints: &[ConstraintKind]) -> Option<Vec<Option<Regex>>> {
    let mut compiled = Vec::with_capacity(constraints.len());
    for constraint in constraints {
        let regex = match constraint {
            ConstraintKind::ArgMatchesRegex { arg_matches_regex } => Some(compile_constraint_regex(
                rule_id,
                "constraints.arg_matches_regex",
                &arg_matches_regex.regex,
            )?),
            ConstraintKind::ArgNotMatchesRegex {
                arg_not_matches_regex,
            } => Some(compile_constraint_regex(
                rule_id,
                "constraints.arg_not_matches_regex",
                &arg_not_matches_regex.regex,
            )?),
            ConstraintKind::AnyArgMatchesRegex {
                any_arg_matches_regex,
            } => Some(compile_constraint_regex(
                rule_id,
                "constraints.any_arg_matches_regex",
                any_arg_matches_regex,
            )?),
            ConstraintKind::ReceiverTypeIn { .. }
            | ConstraintKind::SecondArgEquals { .. }
            | ConstraintKind::ArgEquals { .. }
            | ConstraintKind::KeywordArgEquals { .. }
            | ConstraintKind::ArgTainted { .. }
            | ConstraintKind::ReceiverTainted { .. }
            | ConstraintKind::AnyArgTainted { .. }
            | ConstraintKind::FormatArgIndex { .. }
            | ConstraintKind::Namespace { .. }
            | ConstraintKind::TopLevel { .. }
            | ConstraintKind::ArgCount { .. }
            | ConstraintKind::MinArgs { .. }
            | ConstraintKind::MaxArgs { .. }
            | ConstraintKind::SameReceiverCallCountAtLeast { .. }
            | ConstraintKind::ArgLt { .. }
            | ConstraintKind::ArgLe { .. }
            | ConstraintKind::ArgGt { .. }
            | ConstraintKind::ArgGe { .. }
            | ConstraintKind::RequiresRuntimeType { .. }
            | ConstraintKind::EnclosingDecoratorIn { .. }
            | ConstraintKind::MustAlias { .. }
            | ConstraintKind::RequiresState { .. } => None,
        };
        compiled.push(regex);
    }
    Some(compiled)
}

fn compile_constraint_regex(rule_id: &str, field: &str, pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(error) => {
            tracing::warn!(
                rule_id = %rule_id,
                field = %field,
                regex = %pattern,
                %error,
                "invalid rule constraint regex; rule disabled for this analysis run"
            );
            record_runtime_disabled_rule(
                rule_id,
                format!("invalid constraint regex on `{field}` `{pattern}`: {error}"),
            );
            None
        }
    }
}

struct ConstraintEval<'a, 't> {
    rule_id: &'a str,
    callee: &'a str,
    args: &'a [CallArg],
    receiver_types: &'a [String],
    span: Span,
    call_origin: Option<CallFactOrigin>,
    constraints: &'a [ConstraintKind],
    constraint_regexes: &'a [Option<Regex>],
    receiver_call_count: Option<u32>,
    assignment_texts: Option<&'a AHashMap<String, String>>,
    mode: ConstraintMode,
    taint_view: Option<&'a InterTaintView<'t>>,
    /// Decorator names on the enclosing decl, for `EnclosingDecoratorIn`.
    enclosing_decorators: Option<&'a [String]>,
    /// Intra-procedural rename chain (`y = x` → `y → x`) for `MustAlias`.
    alias_chains: Option<&'a AHashMap<String, String>>,
    /// CFG-aware narrowings for `RequiresRuntimeType`.
    runtime_types: Option<&'a [RuntimeTypeNarrowing]>,
    /// Ordered lifecycle transitions for `RequiresState`.
    lifecycle_transitions: Option<&'a [(Span, String, String)]>,
}

fn constraints_pass(ctx: ConstraintEval<'_, '_>) -> bool {
    let can_cache_taint_verdict = ctx.call_origin == Some(CallFactOrigin::RealCall);
    if let Some(view) = ctx.taint_view.filter(|_| can_cache_taint_verdict) {
        if let Some(verdict) = view.cached_verdict(ctx.rule_id, ctx.span) {
            return verdict;
        }
    }
    let verdict = constraints_pass_uncached(&ctx);
    if let Some(view) = ctx.taint_view.filter(|_| can_cache_taint_verdict) {
        view.store_verdict(ctx.rule_id, ctx.span, verdict);
    }
    verdict
}

/// Dispatch table for the 14 `ConstraintKind` variants, evaluated
/// in declaration order. The match is exhaustive — adding a new
/// `ConstraintKind` requires a matching arm here, and the
/// compiler enforces coverage.
///
/// ## Arms (in dispatch order)
///
/// | Arm                          | Predicate                                          |
/// |------------------------------|----------------------------------------------------|
/// | `ReceiverTypeIn`             | callee's receiver type matches a semantic type     |
/// | `Namespace`                  | callee's qualified prefix matches the namespace    |
/// | `FormatArgIndex`             | the format-string arg slot matches expected index  |
/// | `TopLevel`                   | enclosing decl is at module top level              |
/// | `ArgCount`                   | exact arg count match                              |
/// | `MinArgs` / `MaxArgs`        | min / max arg-count gate                           |
/// | `SecondArgEquals`            | `arg[1]` equals literal                            |
/// | `ArgEquals`                  | `arg[index]` equals literal (or one of a list)     |
/// | `KeywordArgEquals`           | named arg equals literal                           |
/// | `ArgTainted`                 | `arg[index/kw]` is tainted (RealCall/NestedRecv)   |
/// | `ReceiverTainted`            | call receiver is tainted (RealCall/NestedRecv)     |
/// | `AnyArgTainted`              | any syntactic arg is tainted (RealCall/NestedRecv) |
/// | `ArgMatchesRegex`            | `arg[index/kw]` matches regex                      |
/// | `ArgNotMatchesRegex`         | inverse of `ArgMatchesRegex`                       |
/// | `AnyArgMatchesRegex`         | any arg matches regex                              |
/// | `SameReceiverCallCountAtLeast` | same receiver has ≥N calls in this scope        |
///
/// Each arm short-circuits to `false` on first failure; constraints
/// are conjunctive (all must pass for the rule to fire).
fn constraints_pass_uncached(ctx: &ConstraintEval<'_, '_>) -> bool {
    for (constraint_index, c) in ctx.constraints.iter().enumerate() {
        match c {
            ConstraintKind::ReceiverTypeIn { receiver_type_in } => {
                if !receiver_type_matches_any(ctx.receiver_types, receiver_type_in) {
                    return false;
                }
            }
            ConstraintKind::Namespace { namespace } => {
                if !callee_in_namespace(ctx.callee, namespace) {
                    return false;
                }
            }
            ConstraintKind::FormatArgIndex { format_arg_index } => {
                let idx = *format_arg_index as usize;
                let Some(arg) = ctx.args.get(idx) else {
                    return false;
                };
                if !format_arg_is_dynamic_or_dangerous_literal(arg.value_text.trim()) {
                    return false;
                }
            }
            ConstraintKind::TopLevel { top_level } => {
                if *top_level && has_receiver_or_namespace(ctx.callee) {
                    return false;
                }
                if !*top_level && !has_receiver_or_namespace(ctx.callee) {
                    return false;
                }
            }
            ConstraintKind::ArgCount { arg_count } => {
                if ctx.args.len() != *arg_count as usize {
                    return false;
                }
            }
            ConstraintKind::MinArgs { min_args } => {
                if ctx.args.len() < *min_args as usize {
                    return false;
                }
            }
            ConstraintKind::MaxArgs { max_args } => {
                if ctx.args.len() > *max_args as usize {
                    return false;
                }
            }
            ConstraintKind::SecondArgEquals { second_arg_equals } => {
                if ctx.args.get(1).map(|a| a.value_text.trim()) != Some(second_arg_equals.as_str()) {
                    return false;
                }
            }
            ConstraintKind::ArgEquals { arg_equals } => {
                let idx = arg_equals.index as usize;
                if ctx.args.get(idx).map(|a| a.value_text.trim()) != Some(arg_equals.value.as_str()) {
                    return false;
                }
            }
            ConstraintKind::KeywordArgEquals { keyword_arg_equals } => {
                let found = ctx
                    .args
                    .iter()
                    .any(|a| keyword_arg_matches(a, &keyword_arg_equals.name, &keyword_arg_equals.value));
                if !found {
                    return false;
                }
            }
            ConstraintKind::ArgTainted { arg_tainted } => {
                if ctx.mode.ignore_arg_tainted() {
                    continue;
                }
                let allow_synthetic_write = ctx.call_origin == Some(CallFactOrigin::SyntheticWrite);
                if !matches!(
                    ctx.call_origin,
                    Some(
                        CallFactOrigin::RealCall
                            | CallFactOrigin::NestedReceiverCall
                            | CallFactOrigin::SyntheticWrite
                    )
                ) {
                    return false;
                }
                let Some(view) = ctx.taint_view else {
                    return false;
                };
                if !view.arg_is_tainted(ctx.span, ctx.args, arg_tainted, allow_synthetic_write) {
                    return false;
                }
            }
            ConstraintKind::ReceiverTainted { receiver_tainted } => {
                if ctx.mode.ignore_arg_tainted() {
                    continue;
                }
                if !*receiver_tainted {
                    return false;
                }
                if !matches!(
                    ctx.call_origin,
                    Some(CallFactOrigin::RealCall | CallFactOrigin::NestedReceiverCall)
                ) {
                    return false;
                }
                let Some(view) = ctx.taint_view else {
                    return false;
                };
                if !view.receiver_is_tainted(ctx.span) {
                    return false;
                }
            }
            ConstraintKind::AnyArgTainted { any_arg_tainted } => {
                if ctx.mode.ignore_arg_tainted() {
                    continue;
                }
                if !*any_arg_tainted {
                    return false;
                }
                let allow_synthetic_write = ctx.call_origin == Some(CallFactOrigin::SyntheticWrite);
                if !matches!(
                    ctx.call_origin,
                    Some(
                        CallFactOrigin::RealCall
                            | CallFactOrigin::NestedReceiverCall
                            | CallFactOrigin::SyntheticWrite
                    )
                ) {
                    return false;
                }
                let Some(view) = ctx.taint_view else {
                    return false;
                };
                if !view.any_arg_is_tainted(ctx.span, ctx.args, allow_synthetic_write) {
                    return false;
                }
            }
            ConstraintKind::ArgMatchesRegex { arg_matches_regex } => {
                let idx = arg_matches_regex.index as usize;
                let Some(arg) = ctx.args.get(idx) else {
                    return false;
                };
                let Some(Some(re)) = ctx.constraint_regexes.get(constraint_index) else {
                    return false;
                };
                let candidates = arg_regex_texts(arg, ctx.assignment_texts, 4, true);
                if !candidates.iter().any(|value| re.is_match(value.trim())) {
                    return false;
                }
            }
            ConstraintKind::ArgNotMatchesRegex {
                arg_not_matches_regex,
            } => {
                let idx = arg_not_matches_regex.index as usize;
                let Some(arg) = ctx.args.get(idx) else {
                    return false;
                };
                let Some(Some(re)) = ctx.constraint_regexes.get(constraint_index) else {
                    return false;
                };
                let candidates = arg_regex_texts(arg, ctx.assignment_texts, 4, true);
                if candidates.iter().any(|value| re.is_match(value.trim())) {
                    return false;
                }
            }
            ConstraintKind::AnyArgMatchesRegex { .. } => {
                let Some(Some(re)) = ctx.constraint_regexes.get(constraint_index) else {
                    return false;
                };
                let matched = ctx.args.iter().any(|arg| {
                    let candidates = arg_regex_texts(arg, ctx.assignment_texts, 4, true);
                    candidates.iter().any(|value| re.is_match(value.trim()))
                });
                if !matched {
                    return false;
                }
            }
            ConstraintKind::SameReceiverCallCountAtLeast {
                same_receiver_call_count_at_least,
            } => {
                if ctx.receiver_call_count.unwrap_or(0) < *same_receiver_call_count_at_least {
                    return false;
                }
            }
            // Integer-comparison arms (P3 — constants tracking).
            //
            // Each one parses an integer literal from the call-site arg text
            // and compares against the rule's threshold. Non-literal args
            // (variables, expressions, function results) cause the constraint
            // to FAIL conservatively — we never approximate an unknown int.
            ConstraintKind::ArgLt { arg_lt } => {
                if !arg_int_compare(ctx.args, arg_lt.index, |literal| literal < arg_lt.value) {
                    return false;
                }
            }
            ConstraintKind::ArgLe { arg_le } => {
                if !arg_int_compare(ctx.args, arg_le.index, |literal| literal <= arg_le.value) {
                    return false;
                }
            }
            ConstraintKind::ArgGt { arg_gt } => {
                if !arg_int_compare(ctx.args, arg_gt.index, |literal| literal > arg_gt.value) {
                    return false;
                }
            }
            ConstraintKind::ArgGe { arg_ge } => {
                if !arg_int_compare(ctx.args, arg_ge.index, |literal| literal >= arg_ge.value) {
                    return false;
                }
            }
            // P1: arg must be narrowed by a guarding type test.
            ConstraintKind::RequiresRuntimeType {
                requires_runtime_type,
            } => {
                let Some(arg) = ctx.args.get(requires_runtime_type.index as usize) else {
                    return false;
                };
                let trimmed = arg.value_text.trim();
                if !is_simple_ident(trimmed) {
                    return false;
                }
                let Some(narrowings) = ctx.runtime_types else {
                    return false;
                };
                let observed = runtime_type_at(narrowings, trimmed, ctx.span.start);
                if observed.as_deref() != Some(requires_runtime_type.type_name.as_str()) {
                    return false;
                }
            }
            ConstraintKind::EnclosingDecoratorIn {
                enclosing_decorator_in,
            } => {
                if enclosing_decorator_in.is_empty() {
                    return false;
                }
                let Some(decorators) = ctx.enclosing_decorators else {
                    return false;
                };
                let any_match = decorators
                    .iter()
                    .any(|attached| enclosing_decorator_in.iter().any(|want| want == attached));
                if !any_match {
                    return false;
                }
            }
            // P5: source and sink args must share a must-alias root.
            ConstraintKind::MustAlias { must_alias } => {
                let Some(src_arg) = ctx.args.get(must_alias.source_arg as usize) else {
                    return false;
                };
                let Some(sink_arg) = ctx.args.get(must_alias.sink_arg as usize) else {
                    return false;
                };
                let src_n = src_arg.value_text.trim();
                let sink_n = sink_arg.value_text.trim();
                if !is_simple_ident(src_n) || !is_simple_ident(sink_n) {
                    return false;
                }
                if src_n != sink_n {
                    let Some(chains) = ctx.alias_chains else {
                        return false;
                    };
                    let src_root = chains.get(src_n).map(String::as_str).unwrap_or(src_n);
                    let sink_root = chains.get(sink_n).map(String::as_str).unwrap_or(sink_n);
                    if src_root != sink_root {
                        return false;
                    }
                }
            }
            // P6: binding must be in `expected` state at this call.
            ConstraintKind::RequiresState { requires_state } => {
                let Some(transitions) = ctx.lifecycle_transitions else {
                    return false;
                };
                let observed = lifecycle_state_at(transitions, &requires_state.name, ctx.span.start);
                if observed.as_deref() != Some(requires_state.expected.as_str()) {
                    return false;
                }
            }
        }
    }
    true
}

/// Parse the call-site arg at `index` as a 64-bit integer literal and
/// run `predicate` on it. Returns false when the arg is missing, isn't
/// a literal int, or fails the predicate.
///
/// Conservative on parse failure: an unknown / variable / expression arg
/// makes the rule NOT fire (we never speculate about unknown integers).
fn arg_int_compare(args: &[CallArg], index: u32, predicate: impl Fn(i64) -> bool) -> bool {
    let Some(arg) = args.get(index as usize) else {
        return false;
    };
    let Some(literal) = parse_int_literal(arg.value_text.trim()) else {
        return false;
    };
    predicate(literal)
}

/// Parse a single integer literal from raw call-site text.
///
/// Accepts decimal (`1024`, `-5`), hex (`0xFF`, `0Xff`), octal (`0o777`,
/// `0O777`), binary (`0b1010`, `0B1010`), and underscore-separated
/// (`1_000_000`) forms. Returns None for non-literal expressions —
/// `2048 + 0` is intentionally rejected; only single literals are
/// recognised so the constraint stays conservative.
fn parse_int_literal(raw: &str) -> Option<i64> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    // Strip an optional leading sign.
    let (negative, body) = match text.as_bytes().first().copied() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    // Underscore separators are common in Java/Rust/Python literals.
    let body_clean: String = body.chars().filter(|c| *c != '_').collect();
    let body_str = body_clean.as_str();
    let parsed = if let Some(rest) = body_str
        .strip_prefix("0x")
        .or_else(|| body_str.strip_prefix("0X"))
    {
        i64::from_str_radix(rest, 16).ok()?
    } else if let Some(rest) = body_str
        .strip_prefix("0o")
        .or_else(|| body_str.strip_prefix("0O"))
    {
        i64::from_str_radix(rest, 8).ok()?
    } else if let Some(rest) = body_str
        .strip_prefix("0b")
        .or_else(|| body_str.strip_prefix("0B"))
    {
        i64::from_str_radix(rest, 2).ok()?
    } else {
        body_str.parse::<i64>().ok()?
    };
    Some(if negative { -parsed } else { parsed })
}

/// True when call argument `arg` carries the keyword `name` bound to
/// literal `value`. Handles four common keyword shapes
/// (`name: value`, `name => value`, `name=value`, `name = value`)
/// across Python / Ruby / Hash-style / JS object-literal call sites.
fn keyword_arg_matches(arg: &CallArg, name: &str, value: &str) -> bool {
    let trimmed = arg.value_text.trim();
    if arg.name.as_deref() == Some(name) && trimmed == value {
        return true;
    }

    let forms = [
        format!("{name}:"),
        format!("{name} =>"),
        format!("{name}="),
        format!("{name} ="),
    ];
    // Prefix-form: `name: value` / `name=value` directly at the start
    // of the arg text.
    forms.iter().any(|prefix| {
        let Some(rest) = trimmed.strip_prefix(prefix) else {
            return false;
        };
        rest.trim().trim_end_matches(',').trim() == value
    }) || forms.iter().any(|prefix| {
        // Inner-position form: a hash-/object-literal arg that
        // contains the keyword somewhere inside (`{ ..., name: value, ... }`).
        let Some(pos) = trimmed.find(prefix) else {
            return false;
        };
        let rest = trimmed[pos + prefix.len()..].trim();
        rest == value
            || rest.strip_prefix(value).is_some_and(|tail| {
                tail.trim_start()
                    .chars()
                    .next()
                    .is_some_and(|ch| matches!(ch, ',' | '}' | ')'))
            })
    })
}

/// Resolve an `arg_tainted` spec to a concrete arg index. Positional
/// specs are bounds-checked; keyword specs scan the args for any
/// arg whose name OR value-text shape matches.
fn resolve_arg_tainted_index(args: &[CallArg], spec: &ArgTaintedSpec) -> Option<usize> {
    if let Some(index) = spec.index {
        let index = index as usize;
        return (index < args.len()).then_some(index);
    }
    let keyword = spec.kw.as_deref()?;
    args.iter()
        .enumerate()
        .find_map(|(idx, arg)| keyword_arg_name_matches(arg, keyword).then_some(idx))
}

/// True when `arg` is the keyword arg `name` (regardless of value).
/// Companion to `keyword_arg_matches` for callers that only care
/// whether the keyword is present.
fn keyword_arg_name_matches(arg: &CallArg, name: &str) -> bool {
    let trimmed = arg.value_text.trim();
    if arg.name.as_deref() == Some(name) {
        return true;
    }

    let forms = [
        format!("{name}:"),
        format!("{name} =>"),
        format!("{name}="),
        format!("{name} ="),
    ];
    forms.iter().any(|prefix| trimmed.strip_prefix(prefix).is_some())
        || forms.iter().any(|prefix| trimmed.contains(prefix))
}

/// True when the callee text carries any qualifier separator —
/// `obj.method`, `Mod::fn`, `obj->method`, `Mod:fn`. Used by
/// `top_level` constraint to reject non-top-level calls.
fn has_receiver_or_namespace(callee: &str) -> bool {
    callee.contains('.') || callee.contains("::") || callee.contains("->") || callee.contains(':')
}

/// Final identifier in a receiver path, with any trailing
/// non-identifier punctuation (parentheses, brackets) stripped.
fn receiver_path_tail(receiver: &str) -> &str {
    receiver
        .rsplit(['.', ':', '\\'])
        .next()
        .unwrap_or(receiver)
        .trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
}

/// True when `callee` lives inside `namespace` (exact or
/// `namespace.x` / `namespace::x` / `namespace->x` / `namespace:x`).
/// Used by the `Namespace` constraint.
fn callee_in_namespace(callee: &str, namespace: &str) -> bool {
    callee == namespace
        || callee.strip_prefix(namespace).is_some_and(|rest| {
            rest.starts_with('.') || rest.starts_with("::") || rest.starts_with("->") || rest.starts_with(':')
        })
}

/// True when a format-string argument is "dangerous" — either dynamic
/// (not a literal at all) or a literal containing the `%n` directive.
/// Used by `FormatArgIndex` to gate rules that flag user-controlled
/// format strings.
fn format_arg_is_dynamic_or_dangerous_literal(value: &str) -> bool {
    match unquote_literal(value) {
        Some(literal) => literal.contains("%n"),
        None => true,
    }
}

/// Strip matching surrounding quotes (`"`/`'`/`` ` ``) and return the
/// inner string. Returns `None` when the input isn't quoted on both
/// sides with the same character.
fn unquote_literal(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let first = bytes[0];
    let last = *bytes.last()?;
    if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') || (first == b'`' && last == b'`')
    {
        Some(&trimmed[1..trimmed.len() - 1])
    } else {
        None
    }
}

/// Gather every `DeclKind::Constructor` name in the workspace into a
/// set. The matcher uses this to recognise constructor calls written
/// without `new` (e.g. `MyClass(x)` in Python / Ruby) when applying
/// `kind: new` rules.
fn collect_constructor_names(global: &bonsai_index::GlobalIndex) -> AHashSet<String> {
    let mut names = AHashSet::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if matches!(decl.kind, DeclKind::Constructor) {
                names.insert(decl.name.clone());
            }
        }
    }
    names
}

/// True when the callee's tail (after `.` / `::` qualification)
/// names a known constructor. Lets `kind: new` rules fire on the
/// `MyClass(x)` form even though the AST didn't tag it as a
/// constructor call.
fn constructor_name_matches(callee: &str, constructor_names: &AHashSet<String>) -> bool {
    let normalized = callee
        .trim()
        .strip_prefix("new ")
        .unwrap_or_else(|| callee.trim())
        .replace("()", "");
    let tail = normalized.rsplit('.').next().unwrap_or(&normalized);
    let tail = tail.rsplit("::").next().unwrap_or(tail);
    constructor_names.contains(tail)
}

/// Resolve a span to `(file_path, line, column)` for renderer output.
/// Uses the cached span map so repeated lookups within one file are
/// O(1) after the first lookup builds the line offset table.
fn resolve_span(ws: &Workspace, file: FileId, span: Span) -> (String, u32, u32) {
    let path = ws
        .vfs()
        .path(file)
        .map(|file_path| file_path.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Ok(snapshot) = ws.vfs().snapshot(file) {
        let span_map = bonsai_common::cached_span_map(file, snapshot.version, snapshot.text.as_ref());
        let line_col = span_map.line_col(span.start);
        return (path, line_col.line, line_col.column);
    }
    (path, 0, 0)
}

/// Infer chain-entry parameters as synthetic sources.
///
/// Every non-trivial function parameter is a candidate taint source:
/// in real code, the value came from *somewhere* upstream. For
/// framework-less handlers (Dart `shelf` routes, Elixir Phoenix
/// controllers, Obj-C IBActions, Erlang gen_server callbacks, CLI
/// dispatchers, rules-pack-blind controllers) there is no concrete
/// rule to point at, but the parameter IS where untrusted data lives.
///
/// This pass walks every workspace decl, filters to those that look
/// like externally-facing entry points (zero in-workspace callers OR
/// decorated with a framework handler annotation), and emits a
/// synthetic [`RuleMatch`] with `rule_id = "entry-point.<kind>"` for
/// each non-trivial param. The flow builder consumes these like any
/// other source, so chains anchor at the entry and propagate through
/// the existing interprocedural taint pass.
///
/// Design properties:
///
/// - **Safe by default.** Only entry points with zero in-workspace
///   callers OR with a decorator/annotation on a known-framework
///   table produce synthetic sources. A utility function called from
///   ten places won't generate spurious taint.
/// - **Trust defaults to `local`.** Findings from inferred sources
///   render with a "inferred entry point" chip; users can opt out via
///   `--no-inferred-sources`.
/// - **Extensible.** Decorator table is data-driven (lookup name
///   against rulepack's enumerated framework decorators). Adding
///   Phoenix 2.0 / Vapor 5 is a rulepack change, not engine code.
/// - Adapter-declared receiver parameters are skipped — they carry no
///   user data and must be identified from parsed declaration metadata,
///   not from parameter-name conventions.
#[must_use]
pub fn infer_entry_point_sources(ws: &Workspace) -> Vec<RuleMatch> {
    let db = ws.db();
    let global = db.global_index();
    // Build a set of "has in-workspace callers" to detect leaf
    // functions that look like entry points (unreferenced public
    // decls).
    let mut callees_seen: ahash::AHashSet<bonsai_common::SymbolId> = ahash::AHashSet::default();
    for file in global.all_files() {
        // Build the caller's per-file alias map once per file —
        // shared across every decl in that file.
        let alias_map = file_alias_map(ws, file);
        let export_aliases = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().module_export_aliases)
            .unwrap_or(&[]);
        for decl in global.decls_in(file) {
            collect_callee_symbols(
                ws,
                &decl.flow_events,
                &global,
                decl,
                &alias_map,
                export_aliases,
                &mut callees_seen,
            );
        }
    }

    // G3 cross-method field-taint: build a per-class set of
    // qualified field writes sourced from that method's params
    // (`this.cmd = token` / `self.cmd = x`). Every sibling method
    // of the class inherits those fields as synthetic sources so
    // `constructor(t) { this.cmd = t }` + `run() { sink(this.cmd) }`
    // produces a finding without the interprocedural pass needing
    // to model object-state between method invocations on the same
    // receiver. Keyed on the class decl's symbol — derived purely
    // from tree-sitter-emitted DeclKind / parent / FlowEvent facts.
    let class_field_writes = collect_class_field_taints(&global);

    let mut out = Vec::new();
    for file in global.all_files() {
        let Some(adapter) = db.adapter_for(file) else {
            continue;
        };
        let language = adapter.language_id().as_str().to_string();
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let has_callers = callees_seen.contains(&decl.symbol);
            let decorator_kind = detect_framework_decorator(&decl.name, ws, file, decl.name_span);
            // Entry-point heuristic:
            //   - has a framework decorator → definitely entry
            //   - OR has no in-workspace caller AND is top-level / public
            //     (kind Function, not Method) → candidate entry
            let mut entry_kind: Option<EntryKind> = None;
            if let Some(k) = decorator_kind {
                entry_kind = Some(k);
            } else if !has_callers
                && matches!(decl.kind, DeclKind::Function | DeclKind::Method)
                && !is_synthetic_anonymous_callable(decl)
            {
                entry_kind = Some(EntryKind::Unreferenced);
            }

            if let Some(ek) = entry_kind {
                for (idx, param) in decl.params.iter().enumerate() {
                    if decl.receiver_param_index == Some(idx) {
                        continue;
                    }
                    let (file_path, line, col) = resolve_span(ws, file, decl.name_span);
                    out.push(RuleMatch {
                        rule_id: format!("entry-point.{}.param_{idx}", ek.rule_slug()),
                        language: language.clone(),
                        file: file_path,
                        line,
                        column: col,
                        span: decl.name_span,
                        match_text: param.clone(),
                        enclosing_fn: Some(decl.name.clone()),
                    });
                }
            }

            // G3 cross-method: if this method's class has any field
            // writes sourced from a param (recorded in
            // class_field_writes), emit a synthetic source for the
            // qualified field name inside this method. Class membership
            // must come from adapter-emitted `Decl.parent`; the matcher
            // does not recover ownership from source-span containment.
            let class_symbol = decl.parent;
            if let Some(cs) = class_symbol {
                if let Some(fields) = class_field_writes.get(&cs) {
                    // Sort the field set deterministically — the
                    // underlying `AHashSet` gives a different
                    // iteration order per run, which would make
                    // export.taint_graph.entry_points.params
                    // non-deterministic.
                    let mut sorted: Vec<&String> = fields.iter().collect();
                    sorted.sort();
                    for field_name in sorted {
                        if !flow_reads_token(&decl.flow_events, field_name) {
                            continue;
                        }
                        let (file_path, line, col) = resolve_span(ws, file, decl.name_span);
                        out.push(RuleMatch {
                            rule_id: "entry-point.class_field.inherited".to_string(),
                            language: language.clone(),
                            file: file_path,
                            line,
                            column: col,
                            span: decl.name_span,
                            match_text: field_name.clone(),
                            enclosing_fn: Some(decl.name.clone()),
                        });
                    }
                }
            }
        }
    }
    out
}

fn flow_reads_token(events: &[FlowEvent], token: &str) -> bool {
    for event in events {
        match event {
            FlowEvent::Call { receiver, args, .. } => {
                if receiver.as_deref() == Some(token)
                    || args
                        .iter()
                        .any(|arg| arg.place.as_deref() == Some(token) || arg.value_text.trim() == token)
                {
                    return true;
                }
            }
            FlowEvent::Assign {
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                if source_name.as_deref() == Some(token)
                    || source_names.iter().any(|name| name == token)
                    || source_call_args.iter().any(|arg| arg.trim() == token)
                {
                    return true;
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                if value_text.as_deref() == Some(token) || value_name.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Throw { value_name, .. } => {
                if value_name.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Yield { value_text, .. } => {
                if value_text.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if flow_reads_token(then_events, token) || flow_reads_token(else_events, token) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if flow_reads_token(body, token) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if flow_reads_token(body, token)
                    || flow_reads_token(catch_events, token)
                    || flow_reads_token(finally_events, token)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Scan every class's methods for `Assign { target: qualified_field_name,
/// source: this-method's param }` writes. Returns a map
/// `class_symbol → set of qualified field names` so sibling methods
/// can inherit field taint (G3 cross-method field-taint).
///
/// Class→method relationship is semantic: adapters populate
/// `Decl.parent` from AST ownership before the matcher runs. The
/// matcher does not infer membership from source-span containment,
/// because nested/local functions can live inside the same spans but
/// are not class methods.
fn collect_class_field_taints(
    global: &bonsai_index::GlobalIndex,
) -> ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> {
    let mut out: ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> =
        ahash::AHashMap::default();
    for file in global.all_files() {
        let decls = global.decls_in(file);
        for decl in decls.iter() {
            if !matches!(
                decl.kind,
                DeclKind::Method | DeclKind::Constructor | DeclKind::Function
            ) {
                continue;
            }
            let class_symbol = decl.parent;
            let Some(class_symbol) = class_symbol else {
                continue;
            };
            let entry = out.entry(class_symbol).or_default();
            entry.extend(
                decl.receiver_field_writes
                    .iter()
                    .map(|write| write.target.clone()),
            );
            collect_receiver_field_writes_from_events(&decl.flow_events, &decl.params, entry);
        }
    }
    out
}

fn collect_receiver_field_writes_from_events(
    events: &[FlowEvent],
    params: &[String],
    out: &mut ahash::AHashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                ..
            } => {
                if receiver_field_target(target)
                    && (source_name
                        .as_deref()
                        .is_some_and(|name| param_name_matches(params, name))
                        || source_names.iter().any(|name| param_name_matches(params, name)))
                {
                    out.insert(target.clone());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_receiver_field_writes_from_events(then_events, params, out);
                collect_receiver_field_writes_from_events(else_events, params, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_receiver_field_writes_from_events(body, params, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_receiver_field_writes_from_events(body, params, out);
                collect_receiver_field_writes_from_events(catch_events, params, out);
                collect_receiver_field_writes_from_events(finally_events, params, out);
            }
            _ => {}
        }
    }
}

/// True when `target` looks like a write to a receiver field —
/// `this.x`, `self.x`, `$this->x`, `@x`, or any qualified target with
/// `.` / `->`. Used by class-field-taint inheritance to decide which
/// assignments establish a class-level taint binding.
fn receiver_field_target(target: &str) -> bool {
    let target = target.trim();
    target.starts_with("this.")
        || target.starts_with("self.")
        || target.starts_with("$this->")
        || target.starts_with('@')
        || target.starts_with("this->")
        || target.contains('.')
        || target.contains("->")
}

/// True when `name` matches one of the formal parameters of the
/// enclosing method. Sigil-tolerant (Perl `$x`, Rust `&x`, C `*x`)
/// because adapters surface params in their declared form but
/// flow-event source names may include the prefix.
fn param_name_matches(params: &[String], name: &str) -> bool {
    let normalized = normalize_param_name(name);
    params
        .iter()
        .any(|param| normalize_param_name(param) == normalized)
}

fn is_synthetic_anonymous_callable(decl: &bonsai_lang_api::Decl) -> bool {
    decl.name.starts_with("<lambda@") && decl.name.ends_with('>')
}

/// Strip leading sigils (`$` / `&` / `*`) from a parameter name so
/// `$x` and `x` compare equal across languages.
fn normalize_param_name(name: &str) -> &str {
    name.trim()
        .trim_start_matches(bonsai_common::ALL_NAME_PUNCTUATION)
}

/// What kind of entry point we inferred. Drives the finding's
/// rule-id slug + rendering chip so users see *why* we treated the
/// function as a source.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EntryKind {
    Unreferenced,
    Decorator,
}

impl EntryKind {
    fn rule_slug(self) -> &'static str {
        match self {
            Self::Unreferenced => "unreferenced_entry",
            Self::Decorator => "decorator_handler",
        }
    }
}

/// Inspect the decl's span for any parsed decorator / annotation ref
/// immediately attached to the declaration. Exact framework names
/// belong in the rulepack or language adapters; this inference layer
/// only uses the structural fact that the parser found a decorator.
fn detect_framework_decorator(
    _decl_name: &str,
    ws: &Workspace,
    file: FileId,
    decl_span: Span,
) -> Option<EntryKind> {
    let idx = ws.db().decl_index(file)?;
    for r in &idx.refs {
        if r.kind != RefKind::Decorator {
            continue;
        }
        // Decorator refs span the whole decorator; they must sit
        // shortly before the decl's name_span.
        if r.span.end > decl_span.start {
            continue;
        }
        if decl_span.start.saturating_sub(r.span.end) > 512 {
            // Too far before the decl — unrelated decorator.
            continue;
        }
        if !decorator_is_attached_to_decl(ws, file, r.span, decl_span) {
            continue;
        }
        return Some(EntryKind::Decorator);
    }
    None
}

fn decorator_is_attached_to_decl(
    ws: &Workspace,
    file: FileId,
    decorator_span: Span,
    decl_span: Span,
) -> bool {
    let Ok(snapshot) = ws.vfs().snapshot(file) else {
        return true;
    };
    let text = snapshot.text.as_bytes();
    let start = decorator_span.end as usize;
    let end = decl_span.start as usize;
    if start >= end || end > text.len() {
        return false;
    }
    let gap = &text[start..end];
    !gap.iter().any(|b| {
        matches!(*b, b'{' | b'}' | b';') || b.is_ascii_control() && *b != b'\n' && *b != b'\r' && *b != b'\t'
    })
}

/// Walk a function's flow events collecting every callee that
/// resolves to a workspace-local symbol. Populates the "has callers"
/// map used by [`infer_entry_point_sources`] to identify
/// unreferenced public functions.
///
/// Resolution goes through `bonsai_resolve::resolve_callable_with_context`,
/// not bare `find_by_name`, so cross-TU name collisions
/// (`static fn error()` in two files; helper methods on different
/// classes that share a method name) don't cross-pollute the
/// "has callers" set. The caller decl supplies file + module +
/// alias-map context so `Decl.visibility` and `Decl.module_path`
/// narrow candidates per
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
fn collect_callee_symbols(
    ws: &Workspace,
    events: &[FlowEvent],
    global: &bonsai_index::GlobalIndex,
    caller: &bonsai_lang_api::Decl,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    export_aliases: &[&'static str],
    out: &mut ahash::AHashSet<bonsai_common::SymbolId>,
) {
    let resolve =
        |name: &str, receiver_types: &[String], out: &mut ahash::AHashSet<bonsai_common::SymbolId>| {
            if name.trim().is_empty() {
                return;
            }
            // Build a resolve context for this caller. Pass alias_map
            // through so the resolver can rewrite imported aliases
            // (`require("child_process") as cp; cp.exec(...)`) before
            // candidate lookup.
            let ahash_alias: ahash::AHashMap<String, AliasTarget> =
                alias_map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            let path_lookup = |file| {
                ws.vfs()
                    .path(file)
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned())
            };
            let ctx = bonsai_resolve::ResolveContext::new(caller.span.file, &caller.module_path)
                .with_alias_map(&ahash_alias)
                .with_file_path_lookup(&path_lookup);
            for func in bonsai_resolve::resolve_callable_with_context(global, name, &ctx) {
                out.insert(bonsai_common::SymbolId::new(func.raw()));
            }
            let tail = name.rsplit(&['.', ':', '\\'][..]).next().unwrap_or(name);
            for receiver_type in receiver_types {
                for receiver_class in bonsai_resolve::resolve_class(global, receiver_type, &ctx) {
                    let mut seen = ahash::AHashSet::default();
                    let mut candidates = Vec::new();
                    bonsai_resolve::collect_method_candidates_for_class(
                        global,
                        receiver_class,
                        tail,
                        &ctx,
                        &mut seen,
                        &mut candidates,
                    );
                    for func in candidates {
                        out.insert(bonsai_common::SymbolId::new(func.raw()));
                    }
                }
            }
            // Tail-name fallback for chains like `obj.method` where the
            // resolver couldn't infer the receiver type. The same
            // visibility/module narrowing applies because the caller
            // context is unchanged.
            if let Some(tail) = name.rsplit(&['.', ':'][..]).next() {
                if !tail.is_empty() && tail != name {
                    for func in bonsai_resolve::resolve_callable_with_context(global, tail, &ctx) {
                        out.insert(bonsai_common::SymbolId::new(func.raw()));
                    }
                }
            }
        };
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver_types, ..
            } => {
                resolve(name.as_str(), receiver_types, out);
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => {
                // Address-taken / locally aliased callables are still
                // referenced even when the call site invokes the alias
                // (`joiner = joiner_impl; joiner(...)`). Treating these
                // as unreferenced entrypoints creates component-only
                // findings disconnected from the real caller.
                //
                // Do not scan `source_names` here. Adapters also use
                // that field for object-literal keys and expression
                // operands; GraphQL resolver maps like
                // `{ Query: { bookings: (...) => dispatch(args) } }`
                // surface `bookings` there even though no workspace
                // caller invokes the resolver. Marking it as called
                // suppresses the inferred entry-point source that the
                // security wrapper needs.
                if let Some(name) = source_name.as_deref() {
                    resolve(name, &[], out);
                }
                if let Some(name) = source_call.as_deref() {
                    resolve(name, &[], out);
                }
                if assignment_exports_callable_names(target, export_aliases) {
                    for name in source_names {
                        resolve(name, &[], out);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_callee_symbols(ws, then_events, global, caller, alias_map, export_aliases, out);
                collect_callee_symbols(ws, else_events, global, caller, alias_map, export_aliases, out);
            }
            FlowEvent::Loop { body, .. } => {
                collect_callee_symbols(ws, body, global, caller, alias_map, export_aliases, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_callee_symbols(ws, body, global, caller, alias_map, export_aliases, out);
                collect_callee_symbols(ws, catch_events, global, caller, alias_map, export_aliases, out);
                collect_callee_symbols(ws, finally_events, global, caller, alias_map, export_aliases, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_callee_symbols(ws, body, global, caller, alias_map, export_aliases, out);
            }
            _ => {}
        }
    }
}

/// True when `target` names an export point under any of the
/// receiver-aliases the caller's adapter declared via
/// `LanguageCapabilities::module_export_aliases`. JS/TS supply
/// `["exports", "module.exports"]`; languages without an export-by-
/// assignment convention pass `&[]` and this returns false.
///
/// Used to identify assignments that PUBLISH a callable into the
/// workspace's caller graph — the `source_names` on these counts as
/// "callee referenced somewhere" so the leaf-detection heuristic
/// doesn't treat the exported function as an unreferenced entry
/// point.
fn assignment_exports_callable_names(target: &str, export_aliases: &[&'static str]) -> bool {
    let target = target.trim();
    export_aliases
        .iter()
        .any(|alias| target == *alias || target.starts_with(&format!("{alias}.")))
}

#[cfg(test)]
mod tests;
