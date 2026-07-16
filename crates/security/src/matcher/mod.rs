//! Match a rule against the workspace's browse facts.
//!
//! The matcher is **purely fact-level**: it never walks the tracer, never
//! builds chains, and never calls the resolver directly. Call-chain
//! enumeration and taint filtering are the job of `bonsai_inspect` via
//! [`crate::compile`]. The matcher just tells callers *which facts* in the
//! workspace look like a source / sink / sanitizer.

use crate::rule::{ArgTaintedSpec, ConstraintKind, MatchKind, Rule, RuleTarget};
use ahash::{AHashMap, AHashSet};
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    AliasTarget, CallArg, CallKind, Decl, DeclIndex, DeclKind, FlowEvent, ImportSpec, ModulePath, RefKind,
    TypeAliasBinding,
};
use bonsai_taint::{TaintedCall, TaintedCallKind};
use bonsai_workspace::{decl_decorator_names, Workspace};
use regex::Regex;
use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, OnceLock,
    },
    time::Instant,
};

const LOCAL_IMPORT_PACKAGE_PREFIX: &str = "__bonsai_local_import_pkg__";
const WORKSPACE_IMPORT_PACKAGE_PREFIX: &str = "__bonsai_workspace_import_pkg__";
const FILE_USES_REQ_FILES_MARKER: &str = "__bonsai_file_uses_req_files__";
const MATCHER_FILE_FACT_CACHE_CAP: usize = 65_536;

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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
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
#[derive(Clone, Debug, serde::Serialize)]
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

fn innermost_decl_for_span(decls: &[Decl], span: Span) -> Option<&Decl> {
    decls
        .iter()
        .filter(|decl| {
            let body = decl.body_span.unwrap_or(decl.span);
            span.start >= body.start && span.start < body.end
        })
        .min_by_key(|decl| {
            let body = decl.body_span.unwrap_or(decl.span);
            body.end.saturating_sub(body.start)
        })
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
        MatchRunConfig {
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: None,
            factory: &empty_factory_returns(),
            dedup_file_matches: false,
            retention: FactRetention::Transient,
        },
    )
}

/// Batch matcher over a caller-filtered file set. Security production
/// profile paths use this to avoid matching files that will be dropped
/// by path filters anyway.
pub(crate) fn match_rules_against_facts_with_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        MatchRunConfig {
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: Some(files),
            factory: &empty_factory_returns(),
            dedup_file_matches: false,
            retention: FactRetention::Transient,
        },
    )
}

pub(crate) fn match_rules_against_facts_for_taint_support_with_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        MatchRunConfig {
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: Some(files),
            factory: &empty_factory_returns(),
            dedup_file_matches: false,
            retention: FactRetention::Transient,
        },
    )
}

pub(crate) fn match_rules_against_facts_for_inventory_with_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        MatchRunConfig {
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: Some(files),
            factory: &empty_factory_returns(),
            dedup_file_matches: true,
            retention: FactRetention::Transient,
        },
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
        MatchRunConfig {
            mode: ConstraintMode::Strict,
            taint_view: Some(taint_view),
            scan_files: None,
            factory: &empty_factory_returns(),
            dedup_file_matches: false,
            retention: FactRetention::Transient,
        },
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
    factory: &FactoryReturns,
    // Run-scoped memo for the workspace-wide receiver→base-type map. This
    // function is called once per sink candidate; `workspace_receiver_base_map`
    // scans every decl in the workspace, so rebuilding it per candidate is a
    // candidates×workspace blowup. The caller owns a `OnceLock` shared across
    // all candidates (and parallel source groups) so the scan happens at most
    // once per analysis run — and only if some rule actually needs it.
    receiver_base_map_cell: &OnceLock<AHashMap<String, Vec<String>>>,
) -> bool {
    let Some(prepared) = PreparedRule::new(rule) else {
        return false;
    };
    if let Some(verdict) = exact_rule_match_passes_constraints_at_expected_hit(
        ws,
        &prepared,
        expected,
        taint_view,
        factory,
        receiver_base_map_cell,
    ) {
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
    factory: &FactoryReturns,
    receiver_base_map_cell: &OnceLock<AHashMap<String, Vec<String>>>,
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
            ws,
            prepared,
            expected,
            taint_view,
            factory,
            receiver_base_map_cell,
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
    factory: &FactoryReturns,
    receiver_base_map_cell: &OnceLock<AHashMap<String, Vec<String>>>,
) -> bool {
    let file = expected.span.file;
    let global = ws.db().global_index();
    let file_packages =
        file_package_set_with_workspace_context(ws, file, prepared.needs_workspace_package_context());
    let bundle = decl_match_facts_for(ws, file, factory);
    let empty_receiver_base_map = AHashMap::new();
    // Initialise the workspace scan lazily and exactly once across every
    // candidate that reaches this path (see the cell's owner). Candidates
    // whose rule doesn't consult receiver types skip the scan entirely.
    let receiver_base_map: &AHashMap<String, Vec<String>> = if prepared_rule_needs_receiver_base_map(prepared)
    {
        receiver_base_map_cell.get_or_init(|| workspace_receiver_base_map(ws, FactRetention::Cached))
    } else {
        &empty_receiver_base_map
    };
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
        for call in facts
            .calls
            .iter()
            .filter(|call| call.span == expected.span || spans_overlap(call.span, expected.span))
        {
            let receiver_types = expanded_receiver_types(&call.receiver_types, receiver_base_map);
            let Some(matched_callee) = callee_or_alias_matches(
                &call.callee,
                &receiver_types,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
                &facts.alias_map,
            ) else {
                continue;
            };
            if !prepared.call_context_allows(
                &call.callee,
                &receiver_types,
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
                receiver_types: &receiver_types,
                span: call.span,
                call_origin: Some(call.origin),
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count,
                assignment_texts: Some(&facts.assignment_map),
                ast_arg_values: None,
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
    let file_index = global.file_index(file);
    let nested_ast_values = file_index
        .map(|index| NestedAstValueIndex::new(&index.defs))
        .unwrap_or_default();
    let assignment_values = file_index
        .map(|index| AssignmentValueIndex::new(&index.assignment_values))
        .unwrap_or_default();
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let file_packages =
        file_package_set_with_workspace_context(ws, file, prepared.needs_workspace_package_context());
    let alias_map = file_alias_map(ws, file);

    for decl in global.decls_in(file) {
        if expected
            .enclosing_fn
            .as_ref()
            .is_some_and(|name| name != &decl.name)
        {
            continue;
        }
        for mut write in collect_writes(&decl.flow_events) {
            if write.span != expected.span {
                continue;
            }
            write.extend_with_assignment_value(&assignment_values, source_text.as_deref());
            write.extend_with_nested_ast_values(&nested_ast_values);
            if !callee_matches(
                &write.target,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
            ) {
                continue;
            }
            if !prepared.call_context_allows(&write.target, &[], &alias_map, file_packages.as_ref()) {
                continue;
            }
            let args = [write.argument.clone()];
            let ast_arg_values = [write.ast_values];
            if constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &write.target,
                args: &args,
                receiver_types: &[],
                span: write.span,
                call_origin: Some(CallFactOrigin::SyntheticWrite),
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count: None,
                assignment_texts: None,
                ast_arg_values: Some(&ast_arg_values),
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

    let Some(idx) = file_index else {
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
        if constraints_pass(ConstraintEval {
            rule_id: &prepared.rule.id,
            callee: &r.name,
            args: &[],
            receiver_types: &[],
            span: r.span,
            call_origin: Some(CallFactOrigin::SyntheticWrite),
            constraints: &prepared.rule.constraints.0,
            constraint_regexes: &prepared.constraint_regexes,
            receiver_call_count: None,
            assignment_texts: None,
            ast_arg_values: None,
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
pub(crate) fn match_rules_against_facts_for_taint_with_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    factory: &Arc<FactoryReturns>,
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        MatchRunConfig {
            mode: ConstraintMode::TaintEndpoint,
            taint_view: None,
            scan_files: Some(files),
            factory,
            dedup_file_matches: false,
            retention: FactRetention::Transient,
        },
    )
}

/// Sink-inventory matcher: ignores `arg_tainted` constraints (the
/// inventory lists every potential sink site, regardless of whether
/// the current workspace has data flowing into it). All other
/// constraints still apply.
pub(crate) fn match_rules_against_facts_for_sink_inventory_with_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        MatchRunConfig {
            mode: ConstraintMode::SinkInventory,
            taint_view: None,
            scan_files: Some(files),
            factory: &empty_factory_returns(),
            dedup_file_matches: true,
            retention: FactRetention::Transient,
        },
    )
}

fn match_rules_against_facts_with_progress_and_mode<F>(
    ws: &Workspace,
    rules: &[&Rule],
    on_file_done: &mut F,
    config: MatchRunConfig<'_, '_>,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    let MatchRunConfig {
        mode,
        taint_view,
        scan_files,
        factory,
        dedup_file_matches,
        retention,
    } = config;
    let db = ws.db();
    let files: Vec<_> = scan_files
        .map(|files| files.to_vec())
        .unwrap_or_else(|| db.vfs().all_files());
    let total = files.len();
    let prepared: Vec<PreparedRule<'_>> = rules.iter().filter_map(|rule| PreparedRule::new(rule)).collect();
    if prepared.is_empty() {
        for _ in 0..total {
            on_file_done();
        }
        return Vec::new();
    }
    let prepared_by_language = build_prepared_rule_batches(&prepared, factory);
    let receiver_base_map = workspace_receiver_base_map_if_needed(ws, &prepared, mode, retention);
    let global_file_indexes = (!receiver_base_map.is_empty()).then(|| ws.db().global_index());
    let debug_security_phase = bonsai_diagnostics::debug::is_enabled("security-phase");
    let constructor_fallback_languages: AHashSet<&str> = prepared
        .iter()
        .filter(|r| {
            r.rule.match_spec.kind == MatchKind::New
                && language_needs_bare_constructor_fallback(&r.rule.language)
        })
        .map(|r| r.rule.language.as_str())
        .collect();
    let needs_constructor_names = !constructor_fallback_languages.is_empty();
    let constructor_started = (debug_security_phase && needs_constructor_names).then(Instant::now);
    let constructor_files = if needs_constructor_names {
        files
            .iter()
            .copied()
            .filter(|file| {
                ws.db().adapter_for(*file).is_some_and(|adapter| {
                    constructor_fallback_languages.contains(adapter.language_id().as_str())
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let constructor_names = if needs_constructor_names {
        collect_constructor_names_for_files(ws, &constructor_files)
    } else {
        AHashSet::new()
    };
    if let Some(started) = constructor_started {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher constructor prepass: {:.3}s files={} names={}",
            started.elapsed().as_secs_f64(),
            constructor_files.len(),
            constructor_names.len()
        );
    }
    // Each `scan_file_rules` writes only to its own per-file Vec —
    // no shared state across files — so file-level work is
    // embarrassingly parallel. `par_iter` distributes files across
    // rayon's pool; per-thread match Vecs are flat-mapped at the
    // join. Match collection order is non-deterministic across
    // runs, but downstream callers already invoke `sort_matches` on
    // the returned Vec before emission to keep finding ids stable.
    let workers = matcher_worker_count(files.len());
    if workers <= 1 || files.len() <= 1 {
        return files
            .iter()
            .flat_map(|&file| {
                let mut file_out: Vec<RuleMatch> = Vec::new();
                if let Some(adapter) = ws.db().adapter_for(file) {
                    let language = adapter.language_id();
                    if let Some(file_rules) = prepared_by_language.get(language.as_str()) {
                        if let Ok(snapshot) = ws.db().vfs().snapshot(file) {
                            let Some(file_rules) = file_rules.filtered_for_text(
                                ws,
                                file,
                                snapshot.text.as_ref(),
                                mode,
                                retention,
                            ) else {
                                on_file_done();
                                return file_out;
                            };
                            match retention {
                                FactRetention::Cached => {
                                    let Some(file_index) = ws.db().decl_index(file) else {
                                        on_file_done();
                                        return file_out;
                                    };
                                    let ctx = FileScanContext {
                                        ws,
                                        file,
                                        file_index: file_index.as_ref(),
                                        constructor_names: &constructor_names,
                                        mode,
                                        taint_view,
                                        retention,
                                        receiver_base_map: &receiver_base_map,
                                    };
                                    scan_file_rules(&ctx, &file_rules, &mut file_out);
                                }
                                FactRetention::Transient => {
                                    let borrowed_index = global_file_indexes
                                        .as_ref()
                                        .and_then(|global| global.decl_index_in(file));
                                    let owned_index;
                                    let file_index = if let Some(index) = borrowed_index {
                                        index
                                    } else {
                                        owned_index = ws.db().decl_index_uncached(file);
                                        let Some(index) = owned_index.as_ref() else {
                                            on_file_done();
                                            return file_out;
                                        };
                                        index
                                    };
                                    let ctx = FileScanContext {
                                        ws,
                                        file,
                                        file_index,
                                        constructor_names: &constructor_names,
                                        mode,
                                        taint_view,
                                        retention,
                                        receiver_base_map: &receiver_base_map,
                                    };
                                    scan_file_rules(&ctx, &file_rules, &mut file_out);
                                }
                            }
                            if dedup_file_matches {
                                dedup_inventory_matches_in_place(&mut file_out);
                            }
                        } else {
                            on_file_done();
                            return file_out;
                        }
                    }
                }
                on_file_done();
                file_out
            })
            .collect();
    }
    let run_parallel_scan = |pool: Option<&rayon::ThreadPool>| {
        let (tick_tx, tick_rx) = mpsc::channel();
        let parsed_files = Arc::new(AtomicUsize::new(0));
        let text_skipped_files = Arc::new(AtomicUsize::new(0));
        let parsed_files_worker = parsed_files.clone();
        let text_skipped_files_worker = text_skipped_files.clone();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let scan = || {
                    use rayon::prelude::*;
                    files
                        .par_iter()
                        .flat_map_iter(|&file| {
                            let mut file_out: Vec<RuleMatch> = Vec::new();
                            if let Some(adapter) = ws.db().adapter_for(file) {
                                let language = adapter.language_id();
                                if let Some(file_rules) = prepared_by_language.get(language.as_str()) {
                                    if let Ok(snapshot) = ws.db().vfs().snapshot(file) {
                                        let Some(file_rules) = file_rules.filtered_for_text(
                                            ws,
                                            file,
                                            snapshot.text.as_ref(),
                                            mode,
                                            retention,
                                        ) else {
                                            text_skipped_files_worker.fetch_add(1, Ordering::Relaxed);
                                            let _ = tick_tx.send(());
                                            return file_out;
                                        };
                                        parsed_files_worker.fetch_add(1, Ordering::Relaxed);
                                        match retention {
                                            FactRetention::Cached => {
                                                let Some(file_index) = ws.db().decl_index(file) else {
                                                    let _ = tick_tx.send(());
                                                    return file_out;
                                                };
                                                let ctx = FileScanContext {
                                                    ws,
                                                    file,
                                                    file_index: file_index.as_ref(),
                                                    constructor_names: &constructor_names,
                                                    mode,
                                                    taint_view,
                                                    retention,
                                                    receiver_base_map: &receiver_base_map,
                                                };
                                                scan_file_rules(&ctx, &file_rules, &mut file_out);
                                            }
                                            FactRetention::Transient => {
                                                let borrowed_index = global_file_indexes
                                                    .as_ref()
                                                    .and_then(|global| global.decl_index_in(file));
                                                let owned_index;
                                                let file_index = if let Some(index) = borrowed_index {
                                                    index
                                                } else {
                                                    owned_index = ws.db().decl_index_uncached(file);
                                                    let Some(index) = owned_index.as_ref() else {
                                                        let _ = tick_tx.send(());
                                                        return file_out;
                                                    };
                                                    index
                                                };
                                                let ctx = FileScanContext {
                                                    ws,
                                                    file,
                                                    file_index,
                                                    constructor_names: &constructor_names,
                                                    mode,
                                                    taint_view,
                                                    retention,
                                                    receiver_base_map: &receiver_base_map,
                                                };
                                                scan_file_rules(&ctx, &file_rules, &mut file_out);
                                            }
                                        }
                                        if dedup_file_matches {
                                            dedup_inventory_matches_in_place(&mut file_out);
                                        }
                                    } else {
                                        let _ = tick_tx.send(());
                                        return file_out;
                                    }
                                }
                            }
                            let _ = tick_tx.send(());
                            file_out
                        })
                        .collect::<Vec<_>>()
                };
                match pool {
                    Some(pool) => pool.install(scan),
                    None => scan(),
                }
            });
            let mut completed = 0usize;
            while completed < total {
                match tick_rx.recv() {
                    Ok(()) => {
                        completed += 1;
                        if debug_security_phase && completed % 5_000 == 0 {
                            bonsai_diagnostics::debug_log!(
                                "security-phase",
                                "matcher scan progress: {completed}/{total}"
                            );
                        }
                        on_file_done();
                    }
                    Err(_) => break,
                }
            }
            match worker.join() {
                Ok(out) => {
                    if debug_security_phase {
                        bonsai_diagnostics::debug_log!(
                            "security-phase",
                            "matcher scan stats: files={} parsed={} text_skipped={} matches={}",
                            total,
                            parsed_files.load(Ordering::Relaxed),
                            text_skipped_files.load(Ordering::Relaxed),
                            out.len()
                        );
                    }
                    out
                }
                Err(panic) => std::panic::resume_unwind(panic),
            }
        })
    };
    match rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .stack_size(matcher_worker_stack_bytes())
        .build()
    {
        Ok(pool) => run_parallel_scan(Some(&pool)),
        Err(_) => run_parallel_scan(None),
    }
}

fn language_needs_bare_constructor_fallback(language: &str) -> bool {
    !matches!(language, "java" | "c" | "csharp" | "go" | "rust")
}

fn matcher_worker_count(_file_count: usize) -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    if let Some(requested) = std::env::var("BONSAI_SECURITY_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
    {
        return requested.clamp(1, available);
    }
    if let Some(requested) = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
    {
        return requested.clamp(1, available);
    }
    available
}

fn dedup_inventory_matches_in_place(matches: &mut Vec<RuleMatch>) {
    type InventoryDedupKey = (String, String, u32, u32, String, Option<String>);

    let mut seen: AHashMap<InventoryDedupKey, usize> = AHashMap::new();
    let mut deduped: Vec<RuleMatch> = Vec::with_capacity(matches.len());
    for m in matches.drain(..) {
        let key = (
            m.language.clone(),
            m.file.clone(),
            m.line,
            m.column,
            m.rule_id.clone(),
            m.enclosing_fn.clone(),
        );
        if let Some(&idx) = seen.get(&key) {
            if m.match_text.len() > deduped[idx].match_text.len() {
                deduped[idx] = m;
            }
            continue;
        }
        seen.insert(key, deduped.len());
        deduped.push(m);
    }
    *matches = deduped;
}

fn matcher_worker_stack_bytes() -> usize {
    std::env::var("BONSAI_SECURITY_STACK_BYTES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|bytes| *bytes >= 1024 * 1024)
        .unwrap_or(16 * 1024 * 1024)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConstraintMode {
    Strict,
    SinkInventory,
    TaintEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FactRetention {
    Cached,
    Transient,
}

struct FileScanContext<'a, 'taint> {
    ws: &'a Workspace,
    file: FileId,
    file_index: &'a DeclIndex,
    constructor_names: &'a AHashSet<String>,
    mode: ConstraintMode,
    taint_view: Option<&'a InterTaintView<'taint>>,
    retention: FactRetention,
    receiver_base_map: &'a AHashMap<String, Vec<String>>,
}

struct MatchRunConfig<'a, 'taint> {
    mode: ConstraintMode,
    taint_view: Option<&'a InterTaintView<'taint>>,
    scan_files: Option<&'a [FileId]>,
    factory: &'a Arc<FactoryReturns>,
    dedup_file_matches: bool,
    retention: FactRetention,
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

fn workspace_receiver_base_map_if_needed(
    ws: &Workspace,
    rules: &[PreparedRule<'_>],
    mode: ConstraintMode,
    retention: FactRetention,
) -> AHashMap<String, Vec<String>> {
    if matches!(mode, ConstraintMode::SinkInventory) {
        return AHashMap::new();
    }
    if !rules.iter().any(prepared_rule_needs_receiver_base_map) {
        return AHashMap::new();
    }
    workspace_receiver_base_map(ws, retention)
}

fn workspace_receiver_base_map(ws: &Workspace, _retention: FactRetention) -> AHashMap<String, Vec<String>> {
    let mut out: AHashMap<String, Vec<String>> = AHashMap::new();
    let global = ws.db().global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface | DeclKind::Enum
            ) || decl.bases.is_empty()
            {
                continue;
            }
            for key in receiver_base_keys(&decl.name, decl.qualified_name.as_deref()) {
                let entry = out.entry(key).or_default();
                for base in &decl.bases {
                    push_unique_string(entry, normalize_type_name_for_match(base));
                }
            }
        }
    }
    out
}

fn prepared_rule_needs_receiver_base_map(rule: &PreparedRule<'_>) -> bool {
    if matches!(rule.rule.kind, crate::rule::RuleKind::Source) {
        return false;
    }
    rule.attribute.as_ref().is_some_and(|attr| attr.len() >= 2)
        || rule.rule.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                ConstraintKind::ReceiverTypeIn { .. } | ConstraintKind::ReceiverTypeNotIn { .. }
            )
        })
}

fn receiver_base_keys(name: &str, qualified_name: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    push_unique_string(&mut out, normalize_type_name_for_match(name));
    if let Some(qualified_name) = qualified_name {
        push_unique_string(&mut out, normalize_type_name_for_match(qualified_name));
    }
    out
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
    text_anchor_groups: Vec<Vec<String>>,
    package_text_anchors: Vec<String>,
    call_text_anchor: Option<String>,
    base_name_in: &'a [String],
    base_name_not_in: &'a [String],
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
        let text_anchor_groups = text_anchor_groups_for_rule(rule, target);
        let package_text_anchors = package_text_anchors_for_rule(rule, target, &package_signals);
        let call_text_anchor = call_text_anchor_for_rule(rule, target);
        Some(Self {
            rule,
            name: target.name.as_deref(),
            attribute: target.attribute.as_ref(),
            regex,
            text_anchor_groups,
            package_text_anchors,
            call_text_anchor,
            base_name_in: target.base_name_in.as_slice(),
            base_name_not_in: target.base_name_not_in.as_slice(),
            requires_call_package_signal,
            constraint_regexes,
            package_signals,
        })
    }

    fn base_name_allows(&self, text: &str) -> bool {
        if self.base_name_in.is_empty() && self.base_name_not_in.is_empty() {
            return true;
        }
        let Some(base) = match_base_name(text) else {
            return self.base_name_in.is_empty();
        };
        if !self.base_name_in.is_empty() && !self.base_name_in.iter().any(|want| want == base) {
            return false;
        }
        !self.base_name_not_in.iter().any(|blocked| blocked == base)
    }

    #[cfg(test)]
    fn text_possible_in(&self, text: &str, file_packages: Option<&AHashSet<String>>) -> bool {
        self.text_possible_in_mode(text, file_packages, ConstraintMode::Strict)
    }

    fn text_possible_in_mode(
        &self,
        text: &str,
        file_packages: Option<&AHashSet<String>>,
        mode: ConstraintMode,
    ) -> bool {
        if self.rule.id == "java.source.main_args" && !java_main_args_signature_possible(text) {
            return false;
        }
        let target_possible = self
            .text_anchor_groups
            .iter()
            .all(|group| group.is_empty() || group.iter().any(|anchor| text.contains(anchor)));
        if !target_possible {
            return false;
        }
        if !special_regex_text_possible(self.rule, text) {
            return false;
        }
        if matches!(mode, ConstraintMode::SinkInventory) && self.rule.language == "java" {
            if let Some(anchor) = self.call_text_anchor.as_deref() {
                if !call_text_anchor_possible_in(text, anchor, &self.rule.language) {
                    return false;
                }
            }
        }
        self.package_text_anchors.is_empty()
            || self
                .package_text_anchors
                .iter()
                .any(|anchor| text.contains(anchor))
            || file_packages.is_some_and(|packages| self.package_evidence_allows_text_anchor_skip(packages))
    }

    fn package_evidence_allows_text_anchor_skip(&self, file_packages: &AHashSet<String>) -> bool {
        self.package_signals.iter().any(|signal| {
            file_packages.contains(*signal)
                || file_packages.contains(&workspace_import_package_marker(signal))
                || file_packages_have_local_import_package(file_packages, signal)
        })
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
        if self.request_object_source_allows_without_package(callee) {
            return true;
        }
        if self.express_response_sink_allows_without_package(callee) {
            return true;
        }
        if self.express_fileupload_mv_allows_without_package(callee, file_packages) {
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
        let workspace_level_package_evidence_allowed = self.workspace_level_package_evidence_allowed();
        let allowed = self.package_signals.iter().any(|signal| {
            (file_level_package_evidence_allowed && file_packages.contains(*signal))
                || (workspace_level_package_evidence_allowed
                    && file_packages.contains(&workspace_import_package_marker(signal)))
                || candidates
                    .iter()
                    .any(|candidate| local_import_package_allows(file_packages, candidate, signal))
                || candidates
                    .iter()
                    .any(|candidate| crate::pkg::import_matches_package(candidate, signal))
                // WS1 FQN-no-import: a Go-style path package (`os/exec`,
                // `net/http`) binds its last segment as the call qualifier
                // (`exec.Command`, `http.Get`), which the prefix matcher
                // above misses. Credit a call CANDIDATE that equals that
                // last segment — the fully-qualified call is itself the
                // package evidence, no in-file import required.
                || candidates
                    .iter()
                    .any(|candidate| crate::pkg::call_candidate_matches_package_tail(candidate, signal))
        });
        allowed
    }

    fn request_object_source_allows_without_package(&self, callee: &str) -> bool {
        if self.rule.kind != crate::rule::RuleKind::Source || self.rule.language != "javascript" {
            return false;
        }
        let target = match self.rule.match_spec.kind {
            MatchKind::Call | MatchKind::New | MatchKind::Missing => self.rule.match_spec.callee.as_ref(),
            MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
                self.rule.match_spec.target.as_ref()
            }
        };
        let Some(target) = target else {
            return false;
        };
        let is_express_signal = self
            .package_signals
            .iter()
            .any(|signal| matches!(*signal, "express" | "@nestjs/platform-express"));
        if !is_express_signal {
            return false;
        }
        let target_is_req_member = target
            .attribute
            .as_ref()
            .is_some_and(|attr| attr.first().is_some_and(|head| head == "req"))
            || target.base_name_in.iter().any(|base| base == "req")
            || target
                .regex
                .as_deref()
                .is_some_and(|regex| regex.starts_with("^req\\."));
        target_is_req_member && callee.starts_with("req.")
    }

    fn express_response_sink_allows_without_package(&self, callee: &str) -> bool {
        if self.rule.kind != crate::rule::RuleKind::Sink || self.rule.language != "javascript" {
            return false;
        }
        let target = match self.rule.match_spec.kind {
            MatchKind::Call | MatchKind::New | MatchKind::Missing => self.rule.match_spec.callee.as_ref(),
            MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
                self.rule.match_spec.target.as_ref()
            }
        };
        let Some(target) = target else {
            return false;
        };
        let is_express_signal = self.package_signals.contains(&"express");
        if !is_express_signal {
            return false;
        }
        let target_is_res_member = target
            .attribute
            .as_ref()
            .is_some_and(|attr| attr.first().is_some_and(|head| head == "res"))
            || target
                .regex
                .as_deref()
                .is_some_and(|regex| regex.starts_with("^res\\."));
        target_is_res_member && callee.starts_with("res.")
    }

    fn express_fileupload_mv_allows_without_package(
        &self,
        callee: &str,
        file_packages: &AHashSet<String>,
    ) -> bool {
        if self.rule.kind != crate::rule::RuleKind::Sink || self.rule.language != "javascript" {
            return false;
        }
        if self.rule.id != "javascript.upload.express_fileupload_mv_any_file" {
            return false;
        }
        self.package_signals.contains(&"express-fileupload")
            && callee.rsplit_once('.').is_some_and(|(_, tail)| tail == "mv")
            && file_packages.contains(FILE_USES_REQ_FILES_MARKER)
    }

    fn file_level_package_evidence_allowed(&self) -> bool {
        if self.rule.match_spec.kind == MatchKind::Param {
            return true;
        }
        match self.rule.kind {
            crate::rule::RuleKind::Source => true,
            crate::rule::RuleKind::Sanitizer => false,
            // Typing rules never participate in the finding/gate path —
            // they feed factory-return resolution via build_factory_returns.
            crate::rule::RuleKind::Typing => false,
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
                // A receiver-agnostic call regex (`^\w+\.process$`) is too
                // blunt to anchor "package in use" on file-level import
                // evidence alone — any `x.process(...)` in a file that
                // happens to import the package would qualify. BUT when the
                // rule also carries a `receiver_type_in` constraint, that
                // constraint (enforced separately in the matcher) supplies
                // the missing precision: the call only matches if the
                // receiver resolves to one of the named types. So file/
                // workspace package presence is sound evidence here, and the
                // rule's own example (typed receiver + in-file import) can
                // fire instead of being silently gated out.
                let has_receiver_type_constraint = self
                    .rule
                    .constraints
                    .iter()
                    .any(|constraint| matches!(constraint, ConstraintKind::ReceiverTypeIn { .. }));
                !receiver_agnostic_call_regex || has_receiver_type_constraint
            }
        }
    }

    fn workspace_level_package_evidence_allowed(&self) -> bool {
        matches!(self.rule.kind, crate::rule::RuleKind::Sink) && self.file_level_package_evidence_allowed()
    }

    fn needs_workspace_package_context(&self) -> bool {
        self.requires_call_package_signal && self.workspace_level_package_evidence_allowed()
    }
}

fn text_anchor_groups_for_rule(rule: &Rule, target: &RuleTarget) -> Vec<Vec<String>> {
    let mut groups = Vec::new();
    groups.extend(text_anchor_groups_for_target(target, rule.match_spec.kind));
    if rule.id == "java.source.main_args" {
        groups.push(vec!["static".to_string()]);
    }
    let mut class_group = Vec::new();
    for class_name in &target.in_class {
        push_text_anchor(&mut class_group, class_name);
    }
    if !class_group.is_empty() {
        groups.push(class_group);
    }
    let mut method_group = Vec::new();
    for method_name in &target.in_method {
        push_text_anchor(&mut method_group, method_name);
    }
    for method_prefix in &target.in_method_prefix {
        push_text_anchor(&mut method_group, method_prefix);
    }
    if !method_group.is_empty() {
        groups.push(method_group);
    }
    let mut decorator_group = Vec::new();
    for constraint in &rule.constraints.0 {
        if let ConstraintKind::EnclosingDecoratorIn {
            enclosing_decorator_in,
        } = constraint
        {
            for decorator in enclosing_decorator_in {
                push_text_anchor(&mut decorator_group, annotation_tail(decorator));
            }
        }
    }
    if !decorator_group.is_empty() {
        groups.push(decorator_group);
    }
    groups
}

fn package_text_anchors_for_rule(rule: &Rule, _target: &RuleTarget, package_signals: &[&str]) -> Vec<String> {
    if package_signals.is_empty() || !rule_requires_call_package_signal(rule) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for signal in package_signals {
        push_text_anchor(&mut out, signal);
    }
    out
}

fn call_text_anchor_for_rule(rule: &Rule, target: &RuleTarget) -> Option<String> {
    if rule.match_spec.kind != MatchKind::Call {
        return None;
    }
    if let Some(name) = target.name.as_deref() {
        return call_text_anchor_token(name);
    }
    if let Some(attribute) = target.attribute.as_ref().and_then(|parts| parts.last()) {
        return call_text_anchor_token(attribute);
    }
    target
        .regex
        .as_deref()
        .and_then(regex_terminal_call_key)
        .and_then(|key| call_text_anchor_token(&key))
}

fn call_text_anchor_token(value: &str) -> Option<String> {
    let token = text_anchor_name_tail(value.trim().trim_start_matches('@'));
    (token.len() >= 2
        && token
            .chars()
            .all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()))
    .then(|| token.to_string())
}

fn call_text_anchor_possible_in(text: &str, anchor: &str, language: &str) -> bool {
    let mut search_from = 0usize;
    while let Some(relative) = text[search_from..].find(anchor) {
        let start = search_from + relative;
        let end = start + anchor.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|ch| !is_call_identifier_char(ch));
        if before_ok {
            if call_anchor_followed_by_call_paren(text, end) {
                return true;
            }
            if matches!(language, "ruby" | "php") && call_anchor_followed_by_command_style_call(text, end) {
                return true;
            }
        }
        search_from = end;
        if search_from >= text.len() {
            break;
        }
    }
    false
}

fn call_anchor_followed_by_call_paren(text: &str, mut pos: usize) -> bool {
    pos = skip_ascii_whitespace(text, pos);
    if text[pos..].starts_with('(') {
        return true;
    }
    if !text[pos..].starts_with('<') {
        return false;
    }
    let mut depth = 0usize;
    let mut seen_gt = false;
    for (offset, ch) in text[pos..].char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    pos += offset + ch.len_utf8();
                    seen_gt = true;
                    break;
                }
            }
            _ => {}
        }
    }
    if !seen_gt {
        return false;
    }
    pos = skip_ascii_whitespace(text, pos);
    text[pos..].starts_with('(')
}

fn call_anchor_followed_by_command_style_call(text: &str, mut pos: usize) -> bool {
    let Some(next) = text[pos..].chars().next() else {
        return true;
    };
    if matches!(next, '\n' | '\r' | ';' | ')' | ']' | '}' | ':' | '?' | '|') {
        return true;
    }
    if !next.is_ascii_whitespace() {
        return false;
    }
    pos = skip_ascii_whitespace(text, pos);
    text[pos..]
        .chars()
        .next()
        .is_some_and(|ch| !matches!(ch, '\n' | '\r' | ';') && !matches!(ch, ')' | ']' | '}'))
}

fn skip_ascii_whitespace(text: &str, mut pos: usize) -> usize {
    while let Some(ch) = text[pos..].chars().next() {
        if !ch.is_ascii_whitespace() {
            break;
        }
        pos += ch.len_utf8();
        if pos >= text.len() {
            break;
        }
    }
    pos
}

fn is_call_identifier_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

fn text_anchor_groups_for_target(target: &RuleTarget, match_kind: MatchKind) -> Vec<Vec<String>> {
    let mut groups = Vec::new();
    if let Some(name) = target.name.as_deref() {
        let mut out = Vec::new();
        push_text_anchor(&mut out, text_anchor_name_tail(name));
        if !out.is_empty() {
            groups.push(out);
        }
    }
    if let Some(attribute) = target.attribute.as_ref() {
        if attribute.first().is_some_and(|head| head == "System") && attribute.len() == 2 {
            let mut out = Vec::new();
            push_text_anchor(&mut out, &attribute.join("."));
            if !out.is_empty() {
                groups.push(out);
            }
        } else {
            for (idx, part) in attribute.iter().enumerate() {
                if attribute.len() == 2 && idx == 0 && looks_like_type_anchor(part) {
                    continue;
                }
                let mut out = Vec::new();
                push_text_anchor(&mut out, part);
                if idx > 0 && part.len() < 3 {
                    push_exact_text_anchor(&mut out, &format!(".{part}"));
                    push_exact_text_anchor(&mut out, &format!("::{part}"));
                    push_exact_text_anchor(&mut out, &format!("->{part}"));
                }
                if !out.is_empty() {
                    groups.push(out);
                }
            }
        }
    }
    if let Some(annotation) = target.annotation.as_deref() {
        let mut out = Vec::new();
        push_text_anchor(&mut out, annotation_tail(annotation));
        if !out.is_empty() {
            groups.push(out);
        }
    }
    if let Some(regex) = target.regex.as_deref() {
        let mut out = Vec::new();
        for token in regex_literal_anchor_tokens(regex) {
            push_text_anchor(&mut out, &token);
        }
        if matches!(match_kind, MatchKind::Call | MatchKind::New) {
            if let Some(key) = regex_terminal_call_key(regex) {
                push_text_anchor(&mut out, &key);
            }
        }
        if out.is_empty() {
            if let Some(prefix) = regex_prefix_literal_anchor_token(regex) {
                push_text_anchor(&mut out, &prefix);
            }
        }
        for token in regex_required_literal_anchor_tokens(regex) {
            push_exact_text_anchor(&mut out, &token);
        }
        if !out.is_empty() {
            groups.push(out);
        }
    }
    groups
}

fn push_text_anchor(out: &mut Vec<String>, value: &str) {
    let value = value.trim().trim_start_matches('@');
    if value.len() > 4 && value.starts_with("__") && value.ends_with("__") {
        return;
    }
    if value.len() >= 3 && !out.iter().any(|existing| existing == value) {
        out.push(value.to_string());
    }
}

fn push_exact_text_anchor(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && !out.iter().any(|existing| existing == value) {
        out.push(value.to_string());
    }
}

fn text_anchor_name_tail(value: &str) -> &str {
    value
        .rsplit(['.', ':', '/', '\\'])
        .next()
        .filter(|tail| !tail.is_empty())
        .unwrap_or(value)
}

fn looks_like_type_anchor(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
}

fn regex_literal_anchor_tokens(pattern: &str) -> Vec<String> {
    if pattern.contains(")?") || pattern.contains('|') {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut token = String::new();
    let mut escaped = false;
    let mut char_class_depth = 0usize;
    let chars: Vec<char> = pattern.chars().collect();
    for (idx, ch) in chars.iter().copied().enumerate() {
        if escaped {
            if char_class_depth > 0 {
                escaped = false;
                continue;
            }
            if ch == 'Q' {
                token.clear();
            } else if ch == 'E' || matches!(ch, '.' | '/' | ':' | '-') {
                flush_regex_anchor_token(&mut out, &mut token);
            } else if ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() {
                token.push(ch);
            } else {
                flush_regex_anchor_token(&mut out, &mut token);
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '[' {
            flush_regex_anchor_token(&mut out, &mut token);
            char_class_depth = char_class_depth.saturating_add(1);
            continue;
        }
        if ch == ']' && char_class_depth > 0 {
            char_class_depth -= 1;
            continue;
        }
        if char_class_depth > 0 {
            continue;
        }
        if ch == '$' {
            let next_is_identifier = chars
                .get(idx + 1)
                .is_some_and(|next| *next == '_' || *next == '$' || next.is_ascii_alphanumeric());
            if !next_is_identifier {
                flush_regex_anchor_token(&mut out, &mut token);
                continue;
            }
        }
        if ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() {
            token.push(ch);
        } else {
            flush_regex_anchor_token(&mut out, &mut token);
        }
    }
    flush_regex_anchor_token(&mut out, &mut token);
    out
}

fn regex_prefix_literal_anchor_token(pattern: &str) -> Option<String> {
    let mut rest = pattern.trim();
    for prefix in ["(?i)", "(?-i)", "(?is)", "(?si)", "(?s)", "(?m)"] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
            break;
        }
    }
    rest = rest.strip_prefix('^').unwrap_or(rest);
    let mut token = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            if ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() {
                token.push(ch);
                escaped = false;
                continue;
            }
            break;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }
        break;
    }
    let token = token.trim_matches('_');
    (token.len() >= 3).then(|| token.to_string())
}

fn regex_required_literal_anchor_tokens(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    if pattern.contains(r"::|__\$\{") {
        push_exact_text_anchor(&mut out, "::");
        push_exact_text_anchor(&mut out, "__${");
    }
    out
}

fn special_regex_text_possible(rule: &Rule, text: &str) -> bool {
    let Some(pattern) = rule_target_regex_text(rule) else {
        return true;
    };
    if pattern.contains("!doctype|html|body|script")
        && pattern.contains("textarea|button|br|hr")
        && pattern.contains("&lt;")
    {
        return raw_html_literal_possible_in(text);
    }
    true
}

fn raw_html_literal_possible_in(text: &str) -> bool {
    if contains_ascii_case_insensitive(text, "&lt;") {
        return true;
    }
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while let Some(relative) = text[idx..].find('<') {
        idx += relative + 1;
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if html_tag_name_follows(&text[idx..]) {
            return true;
        }
    }
    false
}

fn html_tag_name_follows(text: &str) -> bool {
    const TAGS: &[&str] = &[
        "!doctype", "html", "body", "script", "div", "span", "p", "a", "img", "svg", "iframe", "h1", "h2",
        "h3", "h4", "h5", "h6", "ul", "ol", "li", "table", "form", "input", "textarea", "button", "br", "hr",
    ];
    TAGS.iter().any(|tag| {
        let Some(rest) = strip_ascii_prefix_case_insensitive(text, tag) else {
            return false;
        };
        rest.chars().next().is_none_or(|ch| !is_call_identifier_char(ch))
    })
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn strip_ascii_prefix_case_insensitive<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &text[prefix.len()..])
}

fn flush_regex_anchor_token(out: &mut Vec<String>, token: &mut String) {
    let value = token.trim_matches('_');
    let looks_like_regex_noise = matches!(
        value,
        "A" | "Z" | "Za" | "az" | "d" | "s" | "w" | "b" | "i" | "m" | "u"
    );
    if value.len() >= 3
        && !looks_like_regex_noise
        && value.chars().any(|ch| ch.is_ascii_lowercase())
        && !out.iter().any(|existing| existing == value)
    {
        out.push(value.to_string());
    }
    token.clear();
}

fn java_main_args_signature_possible(text: &str) -> bool {
    let mut search_from = 0usize;
    while let Some(relative) = text[search_from..].find("main") {
        let idx = search_from + relative;
        let before_start = floor_char_boundary(text, idx.saturating_sub(512));
        let after_end = floor_char_boundary(text, (idx + 512).min(text.len()));
        let before = &text[before_start..idx];
        let after = &text[idx..after_end];
        if before.contains("static") && before.contains("void") && after.contains("args") {
            return true;
        }
        search_from = idx.saturating_add("main".len());
        if search_from >= text.len() {
            break;
        }
    }
    false
}

fn floor_char_boundary(text: &str, mut idx: usize) -> usize {
    idx = idx.min(text.len());
    while idx > 0 && !text.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
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

fn local_import_package_marker(module: &str, package: &str) -> String {
    format!("{LOCAL_IMPORT_PACKAGE_PREFIX}:{module}:{package}")
}

fn workspace_import_package_marker(package: &str) -> String {
    format!("{WORKSPACE_IMPORT_PACKAGE_PREFIX}:{package}")
}

fn local_import_package_allows(file_packages: &AHashSet<String>, candidate: &str, signal: &str) -> bool {
    file_packages.contains(&local_import_package_marker(candidate, signal))
        || split_call_head_tail(candidate)
            .is_some_and(|(head, _)| file_packages.contains(&local_import_package_marker(head, signal)))
}

fn file_packages_have_local_import_package(file_packages: &AHashSet<String>, signal: &str) -> bool {
    let suffix = format!(":{signal}");
    file_packages
        .iter()
        .any(|package| package.starts_with(LOCAL_IMPORT_PACKAGE_PREFIX) && package.ends_with(&suffix))
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

#[allow(clippy::struct_field_names)] // Rule buckets intentionally carry the matched rule kind in each field name.
struct PreparedRuleBatch<'p, 'rule> {
    call_rules: Vec<&'p PreparedRule<'rule>>,
    call_wildcard_rules: Vec<&'p PreparedRule<'rule>>,
    call_keyed_rules: AHashMap<String, Vec<&'p PreparedRule<'rule>>>,
    read_rules: Vec<&'p PreparedRule<'rule>>,
    write_rules: Vec<&'p PreparedRule<'rule>>,
    param_rules: Vec<&'p PreparedRule<'rule>>,
    return_rules: Vec<&'p PreparedRule<'rule>>,
    missing_rules: Vec<&'p PreparedRule<'rule>>,
    /// Rulepack factory-return map for this run (shared across batches;
    /// empty/0-fingerprint unless the pack ships `returns_type` rules).
    factory: Arc<FactoryReturns>,
    include_workspace_package_context: bool,
    has_package_text_anchors: bool,
}

impl<'p, 'rule> PreparedRuleBatch<'p, 'rule> {
    fn new(rules: &[&'p PreparedRule<'rule>], factory: Arc<FactoryReturns>) -> Self {
        let mut out = Self {
            call_rules: Vec::new(),
            call_wildcard_rules: Vec::new(),
            call_keyed_rules: AHashMap::new(),
            read_rules: Vec::new(),
            write_rules: Vec::new(),
            param_rules: Vec::new(),
            return_rules: Vec::new(),
            missing_rules: Vec::new(),
            factory,
            include_workspace_package_context: rules
                .iter()
                .any(|rule| rule.needs_workspace_package_context()),
            has_package_text_anchors: rules.iter().any(|rule| !rule.package_text_anchors.is_empty()),
        };
        for &rule in rules {
            match rule.rule.match_spec.kind {
                MatchKind::Call | MatchKind::New => {
                    out.call_rules.push(rule);
                    insert_call_rule_index(&mut out.call_keyed_rules, &mut out.call_wildcard_rules, rule);
                }
                MatchKind::Read => out.read_rules.push(rule),
                MatchKind::Write => out.write_rules.push(rule),
                MatchKind::Param => out.param_rules.push(rule),
                MatchKind::Return => out.return_rules.push(rule),
                MatchKind::Missing => out.missing_rules.push(rule),
            }
        }
        out
    }

    fn filtered_for_text(
        &self,
        ws: &Workspace,
        file: FileId,
        text: &str,
        mode: ConstraintMode,
        retention: FactRetention,
    ) -> Option<Self> {
        let include_workspace_package_context = self.include_workspace_package_context
            && (!matches!(mode, ConstraintMode::SinkInventory)
                || workspace_manifest_package_context_allowed(ws, file));
        let file_packages = self.has_package_text_anchors.then(|| {
            file_package_set_with_workspace_context_and_retention(
                ws,
                file,
                include_workspace_package_context,
                retention,
            )
        });
        let mut rules = Vec::new();
        for &rule in self
            .call_rules
            .iter()
            .chain(self.read_rules.iter())
            .chain(self.write_rules.iter())
            .chain(self.param_rules.iter())
            .chain(self.return_rules.iter())
        {
            if rule.text_possible_in_mode(text, file_packages.as_deref(), mode) {
                rules.push(rule);
            }
        }
        // `kind: missing` rules look for an absent target, so the
        // target's own text anchor is expected not to exist. Keep them
        // in the exact syntax pass; package/context constraints still
        // run inside the matcher. There are very few such rules, and
        // none in the default Java taint path.
        rules.extend(self.missing_rules.iter().copied());
        (!rules.is_empty()).then(|| Self::new(&rules, self.factory.clone()))
    }
}

fn build_prepared_rule_batches<'p, 'rule>(
    prepared: &'p [PreparedRule<'rule>],
    factory: &Arc<FactoryReturns>,
) -> AHashMap<String, PreparedRuleBatch<'p, 'rule>> {
    let mut by_language: AHashMap<String, Vec<&'p PreparedRule<'rule>>> = AHashMap::new();
    for rule in prepared {
        by_language
            .entry(rule.rule.language.clone())
            .or_default()
            .push(rule);
    }
    by_language
        .into_iter()
        .map(|(language, rules)| (language, PreparedRuleBatch::new(&rules, factory.clone())))
        .collect()
}

fn insert_call_rule_index<'p, 'rule>(
    keyed_rules: &mut AHashMap<String, Vec<&'p PreparedRule<'rule>>>,
    wildcard_rules: &mut Vec<&'p PreparedRule<'rule>>,
    rule: &'p PreparedRule<'rule>,
) {
    if rule.regex.is_some() {
        let keys = prepared_regex_call_keys(rule);
        if keys.is_empty() {
            wildcard_rules.push(rule);
        } else {
            for key in keys {
                insert_call_rule_key(keyed_rules, &key, rule);
            }
        }
        return;
    }
    let mut inserted = false;
    if let Some(name) = rule.name {
        insert_call_rule_key(keyed_rules, name, rule);
        inserted = true;
    }
    if let Some(attribute) = rule.attribute {
        for part in attribute {
            insert_call_rule_key(keyed_rules, part, rule);
            inserted = true;
        }
    }
    if !inserted {
        wildcard_rules.push(rule);
    }
}

fn prepared_regex_call_keys(rule: &PreparedRule<'_>) -> Vec<String> {
    let Some(pattern) = rule_target_regex_text(rule.rule) else {
        return Vec::new();
    };
    regex_terminal_call_key(pattern).into_iter().collect()
}

fn rule_target_regex_text(rule: &Rule) -> Option<&str> {
    let target = match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
            rule.match_spec.target.as_ref()
        }
    }?;
    target.regex.as_deref()
}

fn regex_terminal_call_key(pattern: &str) -> Option<String> {
    let trimmed = pattern.trim();
    let trimmed = trimmed
        .strip_prefix("(?i)")
        .or_else(|| trimmed.strip_prefix("(?-i)"))
        .unwrap_or(trimmed);
    if trimmed.contains("_?") {
        return None;
    }
    let trimmed = trimmed.strip_suffix('$').unwrap_or(trimmed);
    let mut end = trimmed.len();
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    let bytes = trimmed.as_bytes();
    while end > 0 {
        let b = bytes[end - 1];
        if b == b'_' || b == b'$' || b.is_ascii_alphanumeric() {
            end -= 1;
            continue;
        }
        break;
    }
    let key = trimmed
        .get(end..)?
        .trim()
        .trim_start_matches(bonsai_common::IDENTIFIER_SIGILS);
    if key.len() < 3 {
        return None;
    }
    if key.starts_with('_') {
        return None;
    }
    if !key
        .chars()
        .all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    if matches!(
        key,
        "A" | "Z" | "Za" | "az" | "d" | "s" | "w" | "b" | "i" | "m" | "u"
    ) {
        return None;
    }
    Some(key.to_string())
}

fn scan_file_rules(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    out: &mut Vec<RuleMatch>,
) {
    if !rules.call_rules.is_empty() {
        scan_calls_batch(ctx, rules, out);
    }
    if !rules.read_rules.is_empty() {
        scan_refs_batch(
            ctx,
            &rules.read_rules,
            RefKind::Read,
            rules.include_workspace_package_context,
            out,
        );
        scan_flow_reads_batch(
            ctx.ws,
            ctx.file,
            ctx.file_index,
            &rules.read_rules,
            rules.include_workspace_package_context,
            ctx.retention,
            out,
        );
    }
    if !rules.write_rules.is_empty() {
        scan_writes_batch(
            ctx,
            &rules.write_rules,
            rules.include_workspace_package_context,
            out,
        );
        scan_ref_writes_batch(
            ctx,
            &rules.write_rules,
            rules.include_workspace_package_context,
            out,
        );
    }
    if !rules.param_rules.is_empty() {
        scan_params_batch(
            ctx.ws,
            ctx.file,
            ctx.file_index,
            &rules.param_rules,
            rules.include_workspace_package_context,
            ctx.retention,
            out,
        );
    }
    if !rules.return_rules.is_empty() {
        scan_returns_batch(ctx.ws, ctx.file, ctx.file_index, &rules.return_rules, out);
    }
    if !rules.missing_rules.is_empty() {
        scan_missing_batch(
            ctx,
            &rules.missing_rules,
            rules.include_workspace_package_context,
            out,
        );
    }
}

fn scan_returns_batch(
    ws: &Workspace,
    file: FileId,
    file_index: &DeclIndex,
    rules: &[&PreparedRule<'_>],
    out: &mut Vec<RuleMatch>,
) {
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    for decl in &file_index.defs {
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

fn scan_params_batch(
    ws: &Workspace,
    file: FileId,
    file_index: &DeclIndex,
    rules: &[&PreparedRule<'_>],
    include_workspace_package_context: bool,
    retention: FactRetention,
    out: &mut Vec<RuleMatch>,
) {
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
    );
    let alias_map = file_alias_map_with_retention(ws, file, retention);
    for decl in &file_index.defs {
        let decl_decorators = decl_decorator_names(ws, file, file_index, decl.span, decl.name_span);
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
                if !decl_target_context_allows(file_index, Some(decl), target, Some(idx)) {
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
                if !prepared.base_name_allows(param) {
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
                    .or_else(|| first_param_read_site(ws, file, file_index, decl, param))
                    .unwrap_or_else(|| {
                        let (file_path, line, col) = resolve_span(ws, file, decl.name_span);
                        (file_path, line, col, decl.name_span)
                    });
                if !constraints_pass(ConstraintEval {
                    rule_id: &prepared.rule.id,
                    callee: param,
                    args: &[],
                    receiver_types: &[],
                    span,
                    call_origin: None,
                    constraints: &prepared.rule.constraints.0,
                    constraint_regexes: &prepared.constraint_regexes,
                    receiver_call_count: None,
                    assignment_texts: None,
                    ast_arg_values: None,
                    mode: ConstraintMode::Strict,
                    taint_view: None,
                    enclosing_decorators: Some(decl_decorators.as_slice()),
                    alias_chains: None,
                    runtime_types: None,
                    lifecycle_transitions: None,
                }) {
                    continue;
                }
                out.push(RuleMatch {
                    rule_id: prepared.rule.id.clone(),
                    language: prepared.rule.language.clone(),
                    file: file_path,
                    line,
                    column: col,
                    span,
                    match_text: param.to_string(),
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
    let body_start = upper_bounds
        .into_iter()
        .filter(|bound| *bound > decl.span.start)
        .map(|bound| bound.min(decl.span.end) as usize)
        .filter(|bound| *bound <= text.len() && *bound > start)
        .min()?;
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
        .map(|event| match event {
            FlowEvent::Call { span, .. }
            | FlowEvent::Assign { span, .. }
            | FlowEvent::AggregateAssign { span, .. }
            | FlowEvent::Return { span, .. }
            | FlowEvent::Throw { span, .. }
            | FlowEvent::Break { span, .. }
            | FlowEvent::Continue { span, .. }
            | FlowEvent::Yield { span, .. }
            | FlowEvent::Await { span, .. }
            | FlowEvent::Lifecycle { span, .. } => span.start,
            FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } => [
                Some(span.start),
                first_flow_event_start(then_events),
                first_flow_event_start(else_events),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(span.start),
            FlowEvent::Loop { span, body, .. }
            | FlowEvent::Defer { span, body }
            | FlowEvent::Using { span, body, .. } => [Some(span.start), first_flow_event_start(body)]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(span.start),
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                ..
            } => [
                Some(span.start),
                first_flow_event_start(body),
                first_flow_event_start(catch_events),
                first_flow_event_start(finally_events),
            ]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(span.start),
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
    file_index: &DeclIndex,
    decl: &bonsai_lang_api::Decl,
    param: &str,
) -> Option<(String, u32, u32, Span)> {
    let body = decl.body_span.unwrap_or(decl.span);
    let min_start = body.start.max(decl.name_span.end);
    let read = file_index
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
    file_index: &DeclIndex,
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
        && target.in_method_prefix.is_empty()
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
    let method_name_allowed = target.in_method.is_empty() && target.in_method_prefix.is_empty()
        || target.in_method.iter().any(|want| want == &decl.name)
        || target
            .in_method_prefix
            .iter()
            .any(|prefix| decl.name.starts_with(prefix));
    if !method_name_allowed {
        return false;
    }
    if let Some(idx) = param_index {
        if !target.param_index_in.is_empty() && !target.param_index_in.contains(&(idx as u32)) {
            return false;
        }
    }
    if target.in_class.is_empty() {
        return true;
    }

    let enclosing_class = decl
        .parent
        .and_then(|sym| local_decl_by_symbol(file_index, sym))
        .filter(|p| {
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

fn local_decl_by_symbol(file_index: &DeclIndex, symbol: SymbolId) -> Option<&Decl> {
    file_index.defs.iter().find(|decl| decl.symbol == symbol)
}

#[derive(Clone)]
struct LocalEnclosingEntry {
    start: u64,
    end: u64,
    name: String,
}

fn local_enclosing_entries(file_index: &DeclIndex) -> Vec<LocalEnclosingEntry> {
    let mut entries: Vec<LocalEnclosingEntry> = file_index
        .defs
        .iter()
        .map(|decl| {
            let body = decl.body_span.unwrap_or(decl.span);
            LocalEnclosingEntry {
                start: body.start,
                end: body.end,
                name: decl.name.clone(),
            }
        })
        .collect();
    entries.sort_unstable_by_key(|entry| entry.start);
    entries
}

fn local_enclosing_name(entries: &[LocalEnclosingEntry], pos: u64) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let partition = entries.partition_point(|entry| entry.start <= pos);
    if partition == 0 {
        return None;
    }
    let entry = &entries[partition - 1];
    (pos < entry.end).then(|| entry.name.clone())
}

fn scan_calls_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let constructor_names = ctx.constructor_names;
    let mode = ctx.mode;
    let taint_view = ctx.taint_view;
    let retention = ctx.retention;
    let receiver_base_map = ctx.receiver_base_map;
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        rules.include_workspace_package_context,
        retention,
    );
    let import_aliases = file_alias_map_with_retention(ws, file, retention);
    let bundle = decl_match_facts_for_retention(ws, file, Some(file_index), &rules.factory, retention);
    let mut decl_call_keys: AHashSet<(String, u64)> = AHashSet::new();

    for decl in &file_index.defs {
        let fn_name = decl.name.clone();
        let Some(facts) = bundle.by_decl_span.get(&decl.span).cloned() else {
            continue;
        };
        for call in &facts.calls {
            decl_call_keys.insert((call.callee.clone(), call.span.start));
            let receiver_types = expanded_receiver_types(&call.receiver_types, receiver_base_map);
            let mut candidate_rules = Vec::new();
            push_call_candidate_rules(&mut candidate_rules, rules, &call.callee, &facts.alias_map);
            for prepared in candidate_rules {
                if !decl_target_context_allows(
                    file_index,
                    Some(decl),
                    prepared.rule.match_spec.callee.as_ref(),
                    None,
                ) {
                    continue;
                }
                let Some(matched_callee) = callee_or_alias_matches(
                    &call.callee,
                    &receiver_types,
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
                if !base_receiver_type_allows(
                    prepared,
                    Some(decl),
                    &matched_callee,
                    &facts.factory_type_aliases,
                ) {
                    continue;
                }
                if !prepared.call_context_allows(
                    &call.callee,
                    &receiver_types,
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
                    receiver_types: &receiver_types,
                    span: call.span,
                    call_origin: Some(call.origin),
                    constraints: &prepared.rule.constraints.0,
                    constraint_regexes: &prepared.constraint_regexes,
                    receiver_call_count,
                    assignment_texts: Some(&facts.assignment_map),
                    ast_arg_values: None,
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

    let enclosing_entries = local_enclosing_entries(file_index);
    for r in &file_index.refs {
        if r.kind != RefKind::Call || decl_call_keys.contains(&(r.name.clone(), r.span.start)) {
            continue;
        }
        let enclosing_fn = local_enclosing_name(&enclosing_entries, r.span.start);
        let mut candidate_rules = Vec::new();
        push_call_candidate_rules(&mut candidate_rules, rules, &r.name, &import_aliases);
        for prepared in candidate_rules {
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
                ast_arg_values: None,
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

fn insert_call_rule_key<'r, 'rule>(
    keyed_rules: &mut AHashMap<String, Vec<&'r PreparedRule<'rule>>>,
    key: &str,
    rule: &'r PreparedRule<'rule>,
) {
    let key = key.trim();
    if key.is_empty() {
        return;
    }
    let bucket = keyed_rules.entry(key.to_string()).or_default();
    push_unique_prepared_rule(bucket, rule);
}

fn push_unique_prepared_rule<'r, 'rule>(
    out: &mut Vec<&'r PreparedRule<'rule>>,
    rule: &'r PreparedRule<'rule>,
) {
    if !out.iter().any(|existing| std::ptr::eq(*existing, rule)) {
        out.push(rule);
    }
}

fn push_call_candidate_rules<'batch, 'p, 'rule>(
    out: &mut Vec<&'p PreparedRule<'rule>>,
    rules: &'batch PreparedRuleBatch<'p, 'rule>,
    callee: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) {
    for &rule in &rules.call_wildcard_rules {
        push_unique_prepared_rule(out, rule);
    }
    for key in call_candidate_keys(callee, alias_map) {
        if let Some(bucket) = rules.call_keyed_rules.get(&key) {
            for &rule in bucket {
                push_unique_prepared_rule(out, rule);
            }
        }
    }
}

fn call_candidate_keys(
    callee: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Vec<String> {
    let mut out = Vec::new();
    collect_call_candidate_keys(callee, &mut out);
    if !alias_map.is_empty() {
        if let Some(bare) = callee.split(&['.', ':'][..]).next() {
            if let Some(target) = alias_map.get(bare) {
                let tail = &callee[bare.len()..];
                let expanded = match target {
                    AliasTarget::Member { module, member } => format!("{module}.{member}{tail}"),
                    AliasTarget::Namespace { module } => format!("{module}{tail}"),
                    AliasTarget::Type { type_name } => format!("{type_name}{tail}"),
                };
                collect_call_candidate_keys(&expanded, &mut out);
            }
        }
    }
    out
}

fn collect_call_candidate_keys(callee: &str, out: &mut Vec<String>) {
    let normalized = normalize_callee_for_matching(callee);
    push_unique_call_key(out, &normalized);
    for sep in [".", "::", "->", "\\", ":", "/"] {
        if let Some(tail) = normalized.rsplit(sep).next() {
            push_unique_call_key(out, tail);
        }
    }
    for token in normalized.split(|ch: char| !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())) {
        push_unique_call_key(out, token);
    }
}

fn push_unique_call_key(out: &mut Vec<String>, key: &str) {
    let key = key.trim().trim_start_matches(bonsai_common::IDENTIFIER_SIGILS);
    if key.is_empty() || out.iter().any(|existing| existing == key) {
        return;
    }
    out.push(key.to_string());
}

/// Fire each Missing rule on every function-shaped decl in `file`
/// where the expected callee is absent. Cross-procedural reach is
/// opt-in via `match.search_depth`.
fn scan_missing_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    include_workspace_package_context: bool,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let mode = ctx.mode;
    let taint_view = ctx.taint_view;
    let retention = ctx.retention;
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
    );
    let import_aliases = file_alias_map_with_retention(ws, file, retention);
    // Missing-call rules don't use factory-return typing.
    let empty_factory = empty_factory_returns();
    let bundle =
        decl_match_facts_for_retention(ws, file, Some(file_index), empty_factory.as_ref(), retention);

    for decl in &file_index.defs {
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
                ast_arg_values: None,
                mode,
                taint_view,
                enclosing_decorators: Some(facts.decl_decorators.as_slice()),
                alias_chains: Some(&facts.alias_chains),
                runtime_types: Some(&facts.runtime_types),
                lifecycle_transitions: Some(&facts.lifecycle_transitions),
            }) {
                continue;
            }

            // Does any call inside this declaration (or, when
            // `search_depth > 0`, any resolved callee reachable within the
            // rule-declared depth) match the expected target? Cross-procedure
            // traversal only runs when the rule opts in.
            let target_present = facts.calls.iter().any(|call| {
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
            }) || missing_target_in_reachable_callees(
                ws,
                file,
                decl,
                prepared,
                &import_aliases,
                retention,
            );
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

/// Walk the entry declaration's resolved callees up to the rule's exact
/// `search_depth`, looking for the expected target. Used by the Missing
/// walker only when the rule opts into cross-procedural reach.
fn missing_target_in_reachable_callees(
    ws: &Workspace,
    file: FileId,
    entry: &bonsai_lang_api::Decl,
    prepared: &PreparedRule<'_>,
    import_aliases: &std::collections::HashMap<String, AliasTarget>,
    retention: FactRetention,
) -> bool {
    if prepared.rule.match_spec.kind != MatchKind::Missing {
        return false;
    }
    let max_depth = prepared.rule.match_spec.search_depth;
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
            let callee_file_packages = file_package_set_with_workspace_context_and_retention(
                ws,
                callee_file,
                prepared.needs_workspace_package_context(),
                retention,
            );
            let empty_factory = empty_factory_returns();
            let callee_bundle =
                decl_match_facts_for_retention(ws, callee_file, None, empty_factory.as_ref(), retention);
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
                    let mut callee_alias = file_alias_map_with_retention(ws, callee_file, retention);
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
    let file_packages =
        file_package_set_with_workspace_context(ws, file, prepared.needs_workspace_package_context());
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

fn file_alias_map_with_retention(
    ws: &Workspace,
    file: FileId,
    retention: FactRetention,
) -> std::collections::HashMap<String, AliasTarget> {
    match retention {
        FactRetention::Cached => file_alias_map(ws, file),
        FactRetention::Transient => transient_import_index(ws, file)
            .map(|imports| bonsai_lang_api::kit::alias_map_from_imports(&imports))
            .unwrap_or_default(),
    }
}

fn transient_import_index(ws: &Workspace, file: FileId) -> Option<bonsai_lang_api::ImportIndex> {
    if let Some(index) = java_textual_import_index(ws, file) {
        return Some(index);
    }
    ws.db().import_index_uncached(file)
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
type FilePackageSetMap = AHashMap<(FileId, u64, u64, u64, bool), Arc<AHashSet<String>>>;
static FILE_PACKAGE_SET_CACHE: std::sync::LazyLock<parking_lot::RwLock<FilePackageSetMap>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));

type WorkspaceImportPackageContextMap = AHashMap<(u64, String, u64), Arc<WorkspaceImportPackageContext>>;
static WORKSPACE_IMPORT_PACKAGE_CONTEXT_CACHE: std::sync::LazyLock<
    parking_lot::RwLock<WorkspaceImportPackageContextMap>,
> = std::sync::LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));

#[derive(Clone, Default)]
struct WorkspaceImportPackageContext {
    packages: AHashSet<String>,
    fingerprint: u64,
}

/// Build the set of canonical package names imported by `file`.
/// Pre-enumerates every prefix shape an import target could match
/// against the rule's signal needles (exact, `.h`-stripped, and
/// progressive `/`, `.`, `:`, `\`-separated prefixes) so the
/// match-time gate can do `set.contains(rule_signal)` in O(1).
fn file_package_set_with_workspace_context(
    ws: &Workspace,
    file: FileId,
    include_workspace_context: bool,
) -> Arc<AHashSet<String>> {
    file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        include_workspace_context,
        FactRetention::Cached,
    )
}

fn file_package_set_with_workspace_context_and_retention(
    ws: &Workspace,
    file: FileId,
    include_workspace_context: bool,
    retention: FactRetention,
) -> Arc<AHashSet<String>> {
    let workspace_imports = if include_workspace_context {
        workspace_import_package_context(ws, file)
    } else {
        Arc::new(WorkspaceImportPackageContext::default())
    };
    let workspace_packages =
        if include_workspace_context && workspace_manifest_package_context_allowed(ws, file) {
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
    let manifest_fingerprint = workspace_packages
        .as_ref()
        .map(|packages| packages.fingerprint)
        .unwrap_or(0);
    let workspace_package_fingerprint = manifest_fingerprint ^ workspace_imports.fingerprint;
    let (version, text_hash) = ws.db().vfs().snapshot(file).map_or((0, 0), |snapshot| {
        (
            snapshot.version,
            package_cache_content_hash(snapshot.text.as_bytes()),
        )
    });
    let key = (
        file,
        version,
        text_hash,
        workspace_package_fingerprint,
        include_workspace_context,
    );
    if retention == FactRetention::Transient {
        return build_file_package_set(
            ws,
            file,
            workspace_imports.as_ref(),
            workspace_packages,
            retention,
        );
    }
    // Drop the read guard at the `;` before any potential write
    // upgrade — parking_lot RwLocks are non-reentrant.
    let cached = FILE_PACKAGE_SET_CACHE.read().get(&key).cloned();
    if let Some(hit) = cached {
        return hit;
    }
    let out = build_file_package_set(
        ws,
        file,
        workspace_imports.as_ref(),
        workspace_packages,
        retention,
    );
    let mut write = FILE_PACKAGE_SET_CACHE.write();
    if write.len() >= MATCHER_FILE_FACT_CACHE_CAP {
        write.clear();
    }
    write.entry(key).or_insert_with(|| out.clone()).clone()
}

fn build_file_package_set(
    ws: &Workspace,
    file: FileId,
    workspace_imports: &WorkspaceImportPackageContext,
    workspace_packages: Option<crate::deps::WorkspaceDependencyPackages>,
    retention: FactRetention,
) -> Arc<AHashSet<String>> {
    let mut out: AHashSet<String> = AHashSet::new();
    let imports = match retention {
        FactRetention::Cached => ws.db().import_index(file).map(|imports| (*imports).clone()),
        FactRetention::Transient => transient_import_index(ws, file),
    };
    if let Some(imports) = imports {
        insert_file_import_packages(ws, file, &imports, retention, &mut out);
    }
    if let Ok(snapshot) = ws.db().vfs().snapshot(file) {
        let text = snapshot.text.as_ref();
        if text.contains("req.files") {
            out.insert(FILE_USES_REQ_FILES_MARKER.to_string());
            insert_import_target_prefixes(&mut out, "express-fileupload");
        }
        if js_like_routed_controller_request_context(ws, file, text) {
            insert_import_target_prefixes(&mut out, "express");
        }
    }
    out.extend(
        workspace_imports
            .packages
            .iter()
            .map(|package| workspace_import_package_marker(package)),
    );
    if let Some(workspace_packages) = workspace_packages {
        out.extend(workspace_packages.packages.iter().cloned());
    }
    Arc::new(out)
}

fn js_like_routed_controller_request_context(ws: &Workspace, file: FileId, text: &str) -> bool {
    if ws.db().adapter_for(file).is_none_or(|adapter| {
        !matches!(
            adapter.language_id().as_str(),
            "javascript" | "typescript" | "tsx"
        )
    }) {
        return false;
    }
    if !file_path_has_route_controller_segment(ws, file) {
        return false;
    }
    (text.contains("req.") || text.contains("res."))
        && (text.contains("(req, res")
            || text.contains("(req,res")
            || text.contains("(request, response")
            || text.contains("(request,response"))
}

fn file_path_has_route_controller_segment(ws: &Workspace, file: FileId) -> bool {
    let Ok(path) = ws.vfs().path(file) else {
        return false;
    };
    path.components().any(|component| {
        let segment = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            segment.as_str(),
            "controller" | "controllers" | "route" | "routes" | "router" | "routers"
        ) || segment.contains(".controller.")
            || segment.contains(".route.")
            || segment.contains(".router.")
    })
}

fn workspace_import_package_context(ws: &Workspace, file: FileId) -> Arc<WorkspaceImportPackageContext> {
    let Some(adapter) = ws.db().adapter_for(file) else {
        return Arc::new(WorkspaceImportPackageContext::default());
    };
    let language = adapter.language_id();
    let key = (
        ws.db().vfs().instance_id(),
        language.as_str().to_string(),
        ws.db().vfs().revision(),
    );
    let cached = WORKSPACE_IMPORT_PACKAGE_CONTEXT_CACHE.read().get(&key).cloned();
    if let Some(hit) = cached {
        return hit;
    }
    // Single-flight the expensive workspace-wide scan. Source/sink
    // matching runs files in parallel; without this second check under
    // the write lock, every worker that misses the read cache can scan
    // the whole language corpus independently on large repos.
    let mut write = WORKSPACE_IMPORT_PACKAGE_CONTEXT_CACHE.write();
    if let Some(hit) = write.get(&key).cloned() {
        return hit;
    }
    let mut context = WorkspaceImportPackageContext::default();
    for candidate_file in ws.db().vfs().all_files() {
        if ws
            .db()
            .adapter_for(candidate_file)
            .is_none_or(|candidate_adapter| candidate_adapter.language_id() != language)
        {
            continue;
        }
        if let Ok(snapshot) = ws.db().vfs().snapshot(candidate_file) {
            context.fingerprint = context
                .fingerprint
                .wrapping_mul(16_777_619)
                .wrapping_add(u64::from(candidate_file.raw()))
                .wrapping_add(snapshot.version)
                .wrapping_add(package_cache_content_hash(snapshot.text.as_bytes()));
            insert_textual_workspace_import_prefixes(
                &mut context.packages,
                language.as_str(),
                snapshot.text.as_ref(),
            );
        }
    }
    let context = Arc::new(context);
    if write.len() >= MATCHER_FILE_FACT_CACHE_CAP {
        write.clear();
    }
    write.entry(key).or_insert_with(|| context.clone()).clone()
}

fn insert_textual_workspace_import_prefixes(out: &mut AHashSet<String>, language: &str, text: &str) {
    match language {
        "python" => insert_python_textual_imports(out, text),
        "javascript" | "typescript" | "tsx" => insert_js_like_textual_imports(out, text),
        "go" => insert_go_textual_imports(out, text),
        "rust" => insert_rust_textual_imports(out, text),
        "c" | "cpp" | "objective-c" | "objc" => insert_c_like_textual_includes(out, text),
        "ruby" => insert_ruby_textual_imports(out, text),
        "php" => insert_php_textual_imports(out, text),
        "csharp" => insert_csharp_textual_imports(out, text),
        "java" | "kotlin" | "scala" | "swift" | "dart" => insert_dotted_textual_imports(out, text),
        _ => insert_generic_textual_imports(out, text),
    }
}

fn java_textual_import_index(ws: &Workspace, file: FileId) -> Option<bonsai_lang_api::ImportIndex> {
    let adapter = ws.db().adapter_for(file)?;
    if adapter.language_id().as_str() != "java" {
        return None;
    }
    let snapshot = ws.db().vfs().snapshot(file).ok()?;
    let mut imports = Vec::new();
    let mut offset = 0u64;
    for raw_line in snapshot.text.lines() {
        let trimmed = raw_line.trim_start();
        let leading_ws = raw_line.len().saturating_sub(trimmed.len()) as u64;
        let line_start = offset.saturating_add(leading_ws);
        offset = offset.saturating_add(raw_line.len() as u64).saturating_add(1);
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("import ") else {
            continue;
        };
        let mut rest = rest.trim();
        let is_static = rest.starts_with("static ");
        if is_static {
            rest = rest.trim_start_matches("static ").trim_start();
        }
        let mut module = rest
            .trim_end_matches(';')
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim();
        if module.is_empty() {
            continue;
        }
        let is_wildcard = module.ends_with(".*");
        if is_wildcard {
            module = module.trim_end_matches(".*");
        }
        let (module, original_name) = if is_static && !is_wildcard {
            module
                .rsplit_once('.')
                .map(|(owner, member)| (owner, Some(member.to_string())))
                .unwrap_or((module, None))
        } else {
            (module, None)
        };
        imports.push(ImportSpec {
            span: Span::new(file, line_start, line_start.saturating_add(trimmed.len() as u64)),
            module: module.to_string(),
            alias: None,
            is_wildcard,
            original_name,
            scope: bonsai_lang_api::ImportScope::Module,
        });
    }
    Some(bonsai_lang_api::ImportIndex { file, imports })
}

fn insert_python_textual_imports(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        if line.starts_with('#') {
            continue;
        }
        let line = strip_inline_comment(line, '#').trim();
        if let Some(rest) = line.strip_prefix("import ") {
            for item in rest.split(',') {
                let module = item.split_whitespace().next().unwrap_or_default();
                insert_workspace_import_module(out, module);
            }
        } else if let Some(rest) = line.strip_prefix("from ") {
            let module = rest.split_whitespace().next().unwrap_or_default();
            insert_workspace_import_module(out, module);
        }
    }
}

fn insert_js_like_textual_imports(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        if line.starts_with("//") || line.starts_with('*') {
            continue;
        }
        let relevant = line.contains("import")
            || line.contains("from ")
            || line.contains("require(")
            || line.contains("require.resolve(")
            || line.contains("export ");
        if !relevant {
            continue;
        }
        for module in quoted_segments(line) {
            insert_workspace_import_module(out, module);
        }
    }
}

fn insert_go_textual_imports(out: &mut AHashSet<String>, text: &str) {
    let mut in_import_block = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with("//") {
            continue;
        }
        if line.starts_with("import (") {
            in_import_block = true;
            continue;
        }
        if in_import_block && line.starts_with(')') {
            in_import_block = false;
            continue;
        }
        if in_import_block || line.starts_with("import ") {
            for module in quoted_segments(line) {
                insert_workspace_import_module(out, module);
            }
        }
    }
}

fn insert_rust_textual_imports(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        if line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("use ") {
            let module = rest
                .trim()
                .trim_end_matches(';')
                .split_whitespace()
                .next()
                .unwrap_or_default();
            insert_workspace_import_module(out, module);
        } else if let Some(rest) = line.strip_prefix("extern crate ") {
            let module = rest
                .trim()
                .trim_end_matches(';')
                .split_whitespace()
                .next()
                .unwrap_or_default();
            insert_workspace_import_module(out, module);
        }
    }
}

fn insert_c_like_textual_includes(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        let Some(rest) = line.strip_prefix("#include") else {
            continue;
        };
        let rest = rest.trim_start();
        if let Some(module) =
            bracketed_segment(rest, '<', '>').or_else(|| quoted_segments(rest).into_iter().next())
        {
            insert_workspace_import_module(out, module);
        }
    }
}

fn insert_ruby_textual_imports(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        if line.starts_with('#') || line.starts_with("require_relative") {
            continue;
        }
        if line.starts_with("require ") || line.starts_with("load ") || line.starts_with("autoload ") {
            for module in quoted_segments(line) {
                insert_workspace_import_module(out, module);
            }
        }
    }
}

fn insert_php_textual_imports(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        if line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("use ") {
            let module = rest
                .trim()
                .trim_end_matches(';')
                .split_whitespace()
                .next()
                .unwrap_or_default();
            insert_workspace_import_module(out, module);
        } else if line.starts_with("require")
            || line.starts_with("include")
            || line.starts_with("require_once")
            || line.starts_with("include_once")
        {
            for module in quoted_segments(line) {
                insert_workspace_import_module(out, module);
            }
        }
    }
}

fn insert_csharp_textual_imports(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        if line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("using ") {
            let module = rest
                .trim()
                .trim_end_matches(';')
                .trim_start_matches("static ")
                .split('=')
                .next_back()
                .unwrap_or_default()
                .trim();
            insert_workspace_import_module(out, module);
        }
    }
}

fn insert_dotted_textual_imports(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        if line.starts_with("//") || line.starts_with('*') {
            continue;
        }
        let Some(rest) = line.strip_prefix("import ") else {
            continue;
        };
        let module = rest
            .trim()
            .trim_end_matches(';')
            .trim_start_matches("static ")
            .trim_end_matches(".*")
            .split_whitespace()
            .next()
            .unwrap_or_default();
        insert_workspace_import_module(out, module);
    }
}

fn insert_generic_textual_imports(out: &mut AHashSet<String>, text: &str) {
    for line in text.lines().map(str::trim_start) {
        if line.starts_with('#') {
            if line.starts_with("#include") {
                insert_c_like_textual_includes(out, line);
            }
            continue;
        }
        if line.starts_with("//") {
            continue;
        }
        if line.starts_with("import ") {
            insert_dotted_textual_imports(out, line);
            insert_python_textual_imports(out, line);
        } else if line.starts_with("from ") {
            insert_python_textual_imports(out, line);
        } else if line.starts_with("use ") {
            insert_rust_textual_imports(out, line);
        } else if line.contains("require(") || line.starts_with("require ") {
            insert_js_like_textual_imports(out, line);
            insert_ruby_textual_imports(out, line);
        }
    }
}

fn insert_workspace_import_module(out: &mut AHashSet<String>, module: &str) {
    let mut module = module
        .trim()
        .trim_matches(|c| matches!(c, '\'' | '"' | '`' | '<' | '>' | '(' | ')' | ';' | ','));
    if let Some(stripped) = module.strip_prefix("node:") {
        module = stripped;
    }
    if module.is_empty()
        || module.starts_with('.')
        || module.starts_with('/')
        || module.starts_with('@')
        || module.contains("${")
    {
        return;
    }
    module = module
        .trim_end_matches("::*")
        .trim_end_matches(".*")
        .trim_end_matches("::*")
        .trim_end_matches("/*");
    insert_import_target_prefixes(out, module);
    if let Some(stripped) = module
        .strip_suffix(".h")
        .or_else(|| module.strip_suffix(".hpp"))
        .or_else(|| module.strip_suffix(".hxx"))
    {
        insert_import_target_prefixes(out, stripped);
    }
}

fn quoted_segments(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        match quote {
            Some(open) if ch == open => {
                if let Some(segment) = line.get(start..idx) {
                    out.push(segment);
                }
                quote = None;
            }
            Some(_) => {}
            None if matches!(ch, '\'' | '"' | '`') => {
                quote = Some(ch);
                start = idx + ch.len_utf8();
            }
            None => {}
        }
    }
    out
}

fn bracketed_segment(line: &str, open: char, close: char) -> Option<&str> {
    let start = line.find(open)? + open.len_utf8();
    let end = line[start..].find(close)? + start;
    line.get(start..end)
}

fn strip_inline_comment(line: &str, marker: char) -> &str {
    line.find(marker).and_then(|idx| line.get(..idx)).unwrap_or(line)
}

fn insert_file_import_packages(
    ws: &Workspace,
    file: FileId,
    imports: &bonsai_lang_api::ImportIndex,
    retention: FactRetention,
    out: &mut AHashSet<String>,
) {
    for spec in &imports.imports {
        insert_import_target_prefixes(out, &spec.module);
        if let Some(stripped) = spec
            .module
            .strip_suffix(".h")
            .or_else(|| spec.module.strip_suffix(".hpp"))
            .or_else(|| spec.module.strip_suffix(".hxx"))
        {
            insert_import_target_prefixes(out, stripped);
        }
        if let Some(imported_file) = resolve_relative_import_file(ws, file, &spec.module) {
            for package in direct_package_imports_for_file(ws, imported_file, retention) {
                insert_local_import_package_markers(out, spec, &package);
            }
        }
    }
}

fn direct_package_imports_for_file(
    ws: &Workspace,
    file: FileId,
    retention: FactRetention,
) -> AHashSet<String> {
    let mut out = AHashSet::new();
    let imports = match retention {
        FactRetention::Cached => ws.db().import_index(file).map(|imports| (*imports).clone()),
        FactRetention::Transient => transient_import_index(ws, file),
    };
    let Some(imports) = imports else { return out };
    for spec in &imports.imports {
        if spec.module.starts_with('.') {
            continue;
        }
        insert_import_target_prefixes(&mut out, &spec.module);
    }
    out
}

fn insert_local_import_package_markers(out: &mut AHashSet<String>, spec: &ImportSpec, package: &str) {
    out.insert(local_import_package_marker(&spec.module, package));
    if let Some(alias) = &spec.alias {
        out.insert(local_import_package_marker(alias, package));
    }
    if let Some(original_name) = &spec.original_name {
        out.insert(local_import_package_marker(original_name, package));
    }
    if let Some(stem) = spec
        .module
        .rsplit('/')
        .next()
        .and_then(|name| name.split('.').next())
        .filter(|stem| !stem.is_empty())
    {
        out.insert(local_import_package_marker(stem, package));
    }
}

fn resolve_relative_import_file(ws: &Workspace, importer: FileId, module: &str) -> Option<FileId> {
    if !module.starts_with('.') {
        return None;
    }
    let importer_path = ws.vfs().path(importer).ok()?;
    let base_dir = importer_path.parent()?;
    let raw = normalize_path(&base_dir.join(module));
    relative_import_candidates(&raw)
        .into_iter()
        .find_map(|candidate| ws.vfs().lookup(&candidate))
}

fn normalize_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            _ => out.push(component.as_os_str()),
        }
    }
    out
}

fn relative_import_candidates(raw: &std::path::Path) -> Vec<std::path::PathBuf> {
    const EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
    let mut out = Vec::new();
    out.push(raw.to_path_buf());

    let raw_ext = raw.extension().and_then(|ext| ext.to_str());
    let has_known_code_ext = raw_ext.is_some_and(|ext| EXTENSIONS.contains(&ext));
    if raw_ext.is_none() {
        for ext in EXTENSIONS {
            out.push(raw.with_extension(ext));
        }
        for ext in EXTENSIONS {
            out.push(raw.join(format!("index.{ext}")));
        }
    } else if !has_known_code_ext {
        // TypeScript projects often import dotted basenames without the
        // final source extension, e.g. `../user/user.model` resolves to
        // `../user/user.model.ts`. `Path::extension()` sees `.model`,
        // so the extensionless branch above would otherwise never try
        // the real file.
        for ext in EXTENSIONS {
            let mut appended = raw.as_os_str().to_os_string();
            appended.push(format!(".{ext}"));
            out.push(std::path::PathBuf::from(appended));
        }
    }
    out
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
    /// `local → ReturnType` aliases synthesized from rulepack-declared
    /// factory returns (`returns_type`). Empty unless the pack ships
    /// such rules. Consulted by `base_receiver_type_allows` so a sink
    /// keyed on `receiver_type_in` resolves on a factory-typed local.
    factory_type_aliases: Vec<TypeAliasBinding>,
}

/// Bundle of per-decl facts for one file, keyed by `decl.span` (the
/// stable identifier for a decl within a file).
#[derive(Default)]
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
// Note: `decl_decorator_names` consults `ws` only for source text
// needed to attach file-level decorator refs to declaration spans.
// The workspace handle leaves no state in the cached bundle other
// than what's derived from adapter facts + content_hash, so two
// workspaces with byte-identical files produce byte-identical bundles.
/// Rulepack-declared factory-method return types. A rule with
/// `returns_type: Cursor` whose structured callee names a method
/// (`name: cursor` or `attribute: [Connection, cursor]`) declares that
/// a call to that method yields a `Cursor`. The matcher uses this to
/// type a local assigned from a factory chain
/// (`c = engine.connect().cursor()` → `c: Cursor`) so a
/// `receiver_type_in: [Cursor]` sink on `c.execute(...)` resolves —
/// without the engine owning any method-name list (the names come from
/// the rulepack, mirroring `taint_receiver_from_args`).
#[derive(Debug, Clone)]
struct FactoryReturnSpec {
    method: String,
    receiver_path: Vec<String>,
    type_name: String,
}

#[derive(Debug, Default)]
pub(crate) struct FactoryReturns {
    /// language → factory return specs. Scoped by language so a Python
    /// `cursor → Cursor` rule can never type a `.cursor()` call in a
    /// JS/Ruby/etc. file. Specs with an empty receiver path preserve the
    /// original method-name-only behavior; specs from
    /// `attribute: [Receiver, method]` require the assignment RHS callee
    /// to end in that receiver path before typing the local.
    by_language: AHashMap<String, Vec<FactoryReturnSpec>>,
    /// `0` when empty, so the decl-facts cache key is byte-identical to a
    /// no-factory run — the feature is dormant unless the pack ships
    /// `returns_type` rules.
    fingerprint: u64,
}

impl FactoryReturns {
    fn is_empty(&self) -> bool {
        self.by_language.is_empty()
    }
    fn specs_for(&self, language: &str) -> Option<&[FactoryReturnSpec]> {
        self.by_language.get(language).map(Vec::as_slice)
    }
}

static EMPTY_FACTORY_RETURNS: std::sync::LazyLock<Arc<FactoryReturns>> =
    std::sync::LazyLock::new(|| Arc::new(FactoryReturns::default()));

/// Shared empty map for the non-taint match paths (sink inventory,
/// source enumeration, tests). Cloning the `Arc` is O(1) and keeps the
/// cache key fingerprint at 0.
pub(crate) fn empty_factory_returns() -> Arc<FactoryReturns> {
    EMPTY_FACTORY_RETURNS.clone()
}

/// Build the factory-return map from every rule that declares
/// `returns_type`. The factory method is read from the rule's
/// structured callee (`name`, or the last `attribute` segment);
/// `regex`-only callees are skipped (no clean method name to key on).
pub(crate) fn build_factory_returns(rules: &[&Rule]) -> Arc<FactoryReturns> {
    let mut by_language: AHashMap<String, Vec<FactoryReturnSpec>> = AHashMap::new();
    for rule in rules {
        let Some(ty) = rule.returns_type.as_deref() else {
            continue;
        };
        if ty.is_empty() {
            continue;
        }
        let Some(target) = rule_primary_target(rule) else {
            continue;
        };
        let (method, receiver_path) = if let Some(name) = target.name.as_deref() {
            (name, Vec::new())
        } else if let Some(attr) = target.attribute.as_deref() {
            let Some(method) = attr.last().map(String::as_str) else {
                continue;
            };
            let receiver_path = attr[..attr.len().saturating_sub(1)]
                .iter()
                .flat_map(|part| factory_path_segments(part))
                .collect();
            (method, receiver_path)
        } else {
            continue;
        };
        if method.is_empty() {
            continue;
        }
        by_language
            .entry(rule.language.clone())
            .or_default()
            .push(FactoryReturnSpec {
                method: method.to_string(),
                receiver_path,
                type_name: ty.to_string(),
            });
    }
    if by_language.is_empty() {
        return empty_factory_returns();
    }
    // Deterministic fingerprint over sorted (language, receiver, method, type)
    // triples so the decl-facts cache never serves a bundle built for a
    // different pack.
    let mut langs: Vec<&String> = by_language.keys().collect();
    langs.sort();
    let mut fingerprint_input = String::new();
    for lang in langs {
        fingerprint_input.push_str(lang);
        fingerprint_input.push('\u{1}');
        let mut specs: Vec<&FactoryReturnSpec> = by_language[lang].iter().collect();
        specs.sort_by(|a, b| {
            (&a.receiver_path, &a.method, &a.type_name).cmp(&(&b.receiver_path, &b.method, &b.type_name))
        });
        for spec in specs {
            fingerprint_input.push_str(&spec.receiver_path.join("."));
            fingerprint_input.push('\0');
            fingerprint_input.push_str(&spec.method);
            fingerprint_input.push('\0');
            fingerprint_input.push_str(&spec.type_name);
            fingerprint_input.push('\n');
        }
    }
    let fingerprint = bonsai_hash::fnv1a_bytes64(fingerprint_input.as_bytes());
    Arc::new(FactoryReturns {
        by_language,
        fingerprint,
    })
}

/// Extract the method name of the OUTERMOST call in an assignment RHS:
/// `engine.connect().cursor()` → `cursor`, `make_cursor()` →
/// `make_cursor`. Returns `None` when the RHS is not a call expression.
fn final_call_callee(rhs: &str) -> Option<&str> {
    let rhs = rhs.trim();
    if !rhs.ends_with(')') {
        return None;
    }
    // Find the `(` that opens the final argument list by scanning back
    // with paren depth so nested calls don't confuse the split.
    let bytes = rhs.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    for (i, &b) in bytes.iter().enumerate().rev() {
        match b {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    Some(rhs[..open?].trim_end())
}

fn final_call_method(rhs: &str) -> Option<&str> {
    let callee = final_call_callee(rhs)?;
    // The method is the last identifier segment after a `.` / `::` / `->`.
    let start = callee.rfind(['.', ':', '>']).map_or(0, |p| p + 1);
    let method = callee[start..].trim();
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    {
        return None;
    }
    Some(method)
}

fn factory_path_segments(text: &str) -> Vec<String> {
    text.split(['.', ':', '>', '\\'])
        .filter_map(|part| {
            let trimmed = part.trim();
            (!trimmed.is_empty() && trimmed != "-").then(|| trimmed.to_string())
        })
        .collect()
}

fn factory_spec_matches_rhs(rhs: &str, spec: &FactoryReturnSpec) -> bool {
    let Some(method) = final_call_method(rhs) else {
        return false;
    };
    if method != spec.method {
        return false;
    }
    if spec.receiver_path.is_empty() {
        return true;
    }
    let Some(callee) = final_call_callee(rhs) else {
        return false;
    };
    let segments = factory_path_segments(callee);
    let needed = spec.receiver_path.len() + 1;
    if segments.len() < needed {
        return false;
    }
    let start = segments.len() - needed;
    segments[start..segments.len() - 1] == spec.receiver_path
}

/// Synthesize `local → ReturnType` aliases for assignments whose RHS is
/// a factory call named in the rulepack map. Empty (no allocation) when
/// the pack ships no `returns_type` rules.
fn synth_factory_type_aliases(
    assignment_map: &AHashMap<String, String>,
    factory: &FactoryReturns,
    language: &str,
) -> Vec<TypeAliasBinding> {
    let Some(specs) = factory.specs_for(language) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, rhs) in assignment_map {
        for spec in specs {
            if !factory_spec_matches_rhs(rhs, spec) {
                continue;
            }
            out.push(TypeAliasBinding {
                name: name.clone(),
                type_name: spec.type_name.clone(),
            });
        }
    }
    out
}

type FileDeclFactsMap = AHashMap<(FileId, u64, u64, u64), Arc<FileDeclFactsBundle>>;
static DECL_FACTS_CACHE: std::sync::LazyLock<parking_lot::RwLock<FileDeclFactsMap>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));

/// Return the per-decl matcher fact bundle for `file`. Builds the
/// bundle on miss; cached on `(file, version, text_hash, factory_fp)`
/// so source edits — and a change of factory-return map — naturally
/// invalidate. `factory_fp` is 0 when the pack ships no `returns_type`
/// rules, keeping the key (and behavior) identical to a no-factory run.
fn decl_match_facts_for(ws: &Workspace, file: FileId, factory: &FactoryReturns) -> Arc<FileDeclFactsBundle> {
    decl_match_facts_for_retention(ws, file, None, factory, FactRetention::Cached)
}

fn decl_match_facts_for_retention(
    ws: &Workspace,
    file: FileId,
    file_index: Option<&DeclIndex>,
    factory: &FactoryReturns,
    retention: FactRetention,
) -> Arc<FileDeclFactsBundle> {
    let (version, text_hash) = ws.db().vfs().snapshot(file).map_or((0, 0), |snap| {
        (snap.version, package_cache_content_hash(snap.text.as_bytes()))
    });
    let key = (file, version, text_hash, factory.fingerprint);
    if retention == FactRetention::Transient {
        return file_index
            .map(|index| build_decl_match_facts_bundle(ws, file, index, factory, retention))
            .unwrap_or_else(|| {
                ws.db()
                    .decl_index_uncached(file)
                    .map(|index| build_decl_match_facts_bundle(ws, file, &index, factory, retention))
                    .unwrap_or_default()
            });
    }
    let cached = DECL_FACTS_CACHE.read().get(&key).cloned();
    if let Some(hit) = cached {
        return hit;
    }
    let bundle = file_index
        .map(|index| build_decl_match_facts_bundle(ws, file, index, factory, retention))
        .or_else(|| {
            ws.db()
                .decl_index(file)
                .map(|index| build_decl_match_facts_bundle(ws, file, index.as_ref(), factory, retention))
        })
        .unwrap_or_default();
    let mut write = DECL_FACTS_CACHE.write();
    if write.len() >= MATCHER_FILE_FACT_CACHE_CAP {
        write.clear();
    }
    write.entry(key).or_insert_with(|| bundle.clone()).clone()
}

fn build_decl_match_facts_bundle(
    ws: &Workspace,
    file: FileId,
    file_index: &DeclIndex,
    factory: &FactoryReturns,
    retention: FactRetention,
) -> Arc<FileDeclFactsBundle> {
    let import_aliases = file_alias_map_with_retention(ws, file, retention);
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    // File language scopes factory-return typing (a Python `cursor`
    // factory must not type `.cursor()` in a JS file). Skipped entirely
    // when the pack ships no `returns_type` rules.
    let file_language = (!factory.is_empty())
        .then(|| {
            ws.db()
                .adapter_for(file)
                .map(|a| a.language_id().as_str().to_string())
        })
        .flatten();
    let module_type_aliases: Vec<TypeAliasBinding> = file_index
        .defs
        .iter()
        .filter(|decl| decl.name == "__module__")
        .flat_map(|decl| decl.type_aliases.iter().cloned())
        .collect();
    let assignment_values = AssignmentValueIndex::new(&file_index.assignment_values);
    let mut by_decl_span: AHashMap<Span, Arc<DeclMatchFacts>> = AHashMap::new();
    for decl in &file_index.defs {
        let mut alias_map = import_aliases.clone();
        extend_alias_map_with_declared_types(&mut alias_map, &module_type_aliases);
        extend_alias_map_with_declared_types(&mut alias_map, &decl.type_aliases);
        bonsai_lang_api::extend_alias_map_with_flow_events(&mut alias_map, &decl.flow_events);
        let assignment_map =
            collect_assignment_texts(&decl.flow_events, &assignment_values, source_text.as_deref());
        let factory_type_aliases = file_language
            .as_deref()
            .map(|lang| synth_factory_type_aliases(&assignment_map, factory, lang))
            .unwrap_or_default();
        let mut calls = collect_calls(&decl.flow_events);
        enrich_call_fact_receiver_types(&mut calls, &module_type_aliases);
        enrich_call_fact_receiver_types(&mut calls, &decl.type_aliases);
        if !factory_type_aliases.is_empty() {
            // Factory-typed locals participate in receiver-type matching
            // and the package gate's receiver-type candidate chase.
            enrich_call_fact_receiver_types(&mut calls, &factory_type_aliases);
            extend_alias_map_with_declared_types(&mut alias_map, &factory_type_aliases);
        }
        let receiver_counts = receiver_method_call_counts(&calls);
        let decl_decorators = decl_decorator_names(ws, file, file_index, decl.span, decl.name_span);
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
                factory_type_aliases,
            }),
        );
    }
    Arc::new(FileDeclFactsBundle { by_decl_span })
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
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    want_kind: RefKind,
    include_workspace_package_context: bool,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let retention = ctx.retention;
    let decls = file_index.defs.as_slice();
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
    );
    let alias_map = file_alias_map_with_retention(ws, file, retention);
    for r in &file_index.refs {
        if r.kind != want_kind {
            continue;
        }
        let enclosing_decl = innermost_decl_for_span(decls, r.span);
        for prepared in rules {
            if !decl_target_context_allows(
                file_index,
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
            if !base_receiver_type_allows(prepared, enclosing_decl, &r.name, &[]) {
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
    file_index: &DeclIndex,
    rules: &[&PreparedRule<'_>],
    include_workspace_package_context: bool,
    retention: FactRetention,
    out: &mut Vec<RuleMatch>,
) {
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
    );
    let alias_map = file_alias_map_with_retention(ws, file, retention);
    for decl in &file_index.defs {
        let mut reads = Vec::new();
        collect_flow_read_sites(&decl.flow_events, &mut reads);
        for (span, tokens) in reads {
            for prepared in rules {
                if !decl_target_context_allows(
                    file_index,
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
                if !base_receiver_type_allows(prepared, Some(decl), &match_text, &[]) {
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
        if prepared.base_name_allows(&joined) && tokens_contain_attribute(tokens, &joined) {
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

fn tokens_contain_attribute(tokens: &[String], joined: &str) -> bool {
    tokens.iter().any(|token| {
        token == joined
            || token
                .strip_prefix(joined)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
    })
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
    factory_aliases: &[TypeAliasBinding],
) -> bool {
    let Some(target) = rule_primary_target(prepared.rule) else {
        return true;
    };
    if target.receiver_type_in.is_empty() {
        return true;
    }
    let Some(base) = match_base_name(match_text) else {
        return false;
    };
    // Rulepack-declared factory-return types stand in for adapter
    // type-aliases the constructor heuristic can't see
    // (`c = engine.connect().cursor()` → `c: Cursor`).
    if factory_aliases
        .iter()
        .filter(|alias| alias.name == base)
        .any(|alias| receiver_type_matches_wanted(&alias.type_name, &target.receiver_type_in))
    {
        return true;
    }
    let Some(decl) = decl else {
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
    // `start`/`end` are adapter span offsets; bail rather than panic if a
    // multi-byte UTF-8 char straddles either bound.
    let Some(raw) = source.get(start..end) else {
        return span;
    };
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
                ..
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
                if let Some(receiver) = receiver {
                    let mut tokens = Vec::new();
                    tokens.extend(split_read_token(receiver));
                    if !tokens.is_empty() {
                        out.push((*span, tokens));
                    }
                }
                for arg in args {
                    let mut tokens = Vec::new();
                    tokens.extend(split_read_token(&arg.value_text));
                    if let Some(place) = &arg.place {
                        tokens.extend(split_read_token(place));
                    }
                    for source in &arg.source_names {
                        tokens.extend(split_read_token(source));
                    }
                    if !tokens.is_empty() {
                        out.push((arg.span, tokens));
                    }
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
            FlowEvent::Yield { span, value_text, .. } => {
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
/// non-identifier char so `obj.field[i]` yields `[obj, field, i]`,
/// while also preserving qualified chains such as `obj.field`.
/// Used by `flow_read_rule_match` to detect read-rule hits inside
/// argument expressions.
fn split_read_token(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    fn push_unique(out: &mut Vec<String>, part: &str) {
        let part = part.trim().trim_start_matches('$').trim_matches('.');
        if part.is_empty() || out.iter().any(|existing| existing == part) {
            return;
        }
        out.push(part.to_string());
    }
    for part in value.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' || ch == '.')) {
        if part.contains('.') {
            push_unique(&mut out, part);
        }
    }
    for part in value.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')) {
        push_unique(&mut out, part);
    }
    out
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

#[derive(Clone, Debug, Default)]
struct AssignmentValueIndex {
    value_spans: AHashMap<Span, Span>,
}

impl AssignmentValueIndex {
    fn new(facts: &[bonsai_lang_api::AssignmentValueFact]) -> Self {
        let mut value_spans = AHashMap::with_capacity(facts.len());
        for fact in facts {
            value_spans.entry(fact.assignment_span).or_insert(fact.value_span);
        }
        Self { value_spans }
    }

    fn rendering<'a>(&self, assignment_span: Span, source_text: Option<&'a str>) -> Option<&'a str> {
        let value_span = self.value_spans.get(&assignment_span)?;
        if value_span.file != assignment_span.file {
            return None;
        }
        source_text?
            .get(value_span.start as usize..value_span.end as usize)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
}

fn collect_assignment_texts(
    events: &[FlowEvent],
    assignment_values: &AssignmentValueIndex,
    source_text: Option<&str>,
) -> AHashMap<String, String> {
    let mut out = AHashMap::new();
    collect_assignment_texts_into(events, assignment_values, source_text, &mut out);
    out
}

fn collect_assignment_texts_into(
    events: &[FlowEvent],
    assignment_values: &AssignmentValueIndex,
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
                let rhs_text = assignment_values
                    .rendering(*span, source_text)
                    .map(str::to_string)
                    .or_else(|| {
                        structured_assignment_rendering(
                            source_name.as_deref(),
                            source_call.as_deref(),
                            source_call_args,
                            source_names,
                        )
                    });
                if let Some(rhs_text) = rhs_text {
                    out.insert(target.clone(), rhs_text);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assignment_texts_into(then_events, assignment_values, source_text, out);
                collect_assignment_texts_into(else_events, assignment_values, source_text, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assignment_texts_into(body, assignment_values, source_text, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assignment_texts_into(body, assignment_values, source_text, out);
                collect_assignment_texts_into(catch_events, assignment_values, source_text, out);
                collect_assignment_texts_into(finally_events, assignment_values, source_text, out);
            }
            _ => {}
        }
    }
}

/// Canonical display fallback for synthetic assignments that have no parsed
/// RHS-node fact. This composes already-structured operands; it never scans
/// an assignment statement or tokenizes source text.
fn structured_assignment_rendering(
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
) -> Option<String> {
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
            passing_mode: arg.passing_mode,
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

fn constraint_regex_texts(ctx: &ConstraintEval<'_, '_>, index: usize, arg: &CallArg) -> Vec<String> {
    let mut candidates = arg_regex_texts(arg, ctx.assignment_texts, 4, true);
    if let Some(values) = ctx.ast_arg_values.and_then(|all| all.get(index)) {
        for value in values {
            let value = value.trim();
            if !value.is_empty() && !candidates.iter().any(|candidate| candidate == value) {
                candidates.push(value.to_string());
            }
        }
    }
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
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    include_workspace_package_context: bool,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let mode = ctx.mode;
    let taint_view = ctx.taint_view;
    let retention = ctx.retention;
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
    );
    let alias_map = file_alias_map_with_retention(ws, file, retention);
    let nested_ast_values = NestedAstValueIndex::new(&file_index.defs);
    let assignment_values = AssignmentValueIndex::new(&file_index.assignment_values);
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    for decl in &file_index.defs {
        let writes = collect_writes(&decl.flow_events);
        for mut write in writes {
            write.extend_with_assignment_value(&assignment_values, source_text.as_deref());
            write.extend_with_nested_ast_values(&nested_ast_values);
            let args = [write.argument.clone()];
            let ast_arg_values = [write.ast_values];
            for prepared in rules {
                if !callee_matches(
                    &write.target,
                    prepared.name,
                    prepared.attribute,
                    prepared.regex.as_ref(),
                ) {
                    continue;
                }
                if !prepared.base_name_allows(&write.target) {
                    continue;
                }
                // Same package-signal gate the call/read scanners use —
                // a receiver-agnostic write target like
                // `^[A-Za-z_$]\w*\.headers$` would otherwise fire on
                // any file regardless of the rule's `packages` list.
                if !prepared.call_context_allows(&write.target, &[], &alias_map, file_packages.as_ref()) {
                    continue;
                }
                if !constraints_pass(ConstraintEval {
                    rule_id: &prepared.rule.id,
                    callee: &write.target,
                    args: &args,
                    receiver_types: &[],
                    span: write.span,
                    call_origin: Some(CallFactOrigin::SyntheticWrite),
                    constraints: &prepared.rule.constraints.0,
                    constraint_regexes: &prepared.constraint_regexes,
                    receiver_call_count: None,
                    assignment_texts: None,
                    ast_arg_values: Some(&ast_arg_values),
                    mode,
                    taint_view,
                    enclosing_decorators: None,
                    alias_chains: None,
                    runtime_types: None,
                    lifecycle_transitions: None,
                }) {
                    continue;
                }
                let (file_path, line, col) = resolve_span(ws, file, write.span);
                out.push(RuleMatch {
                    rule_id: prepared.rule.id.clone(),
                    language: prepared.rule.language.clone(),
                    file: file_path,
                    line,
                    column: col,
                    span: write.span,
                    match_text: write.target.clone(),
                    enclosing_fn: Some(decl.name.clone()),
                });
            }
        }
    }
}

fn scan_ref_writes_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    include_workspace_package_context: bool,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let mode = ctx.mode;
    let taint_view = ctx.taint_view;
    let retention = ctx.retention;
    let decls = file_index.defs.as_slice();
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
    );
    let alias_map = file_alias_map_with_retention(ws, file, retention);
    for r in &file_index.refs {
        if r.kind != RefKind::Write {
            continue;
        }
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
                args: &[],
                receiver_types: &[],
                span: r.span,
                call_origin: Some(CallFactOrigin::SyntheticWrite),
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count: None,
                assignment_texts: None,
                ast_arg_values: None,
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
            let enclosing_fn = innermost_decl_for_span(decls, r.span).map(|d| d.name.clone());
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
        for write in collect_writes(&decl.flow_events) {
            if callee_matches(
                &write.target,
                prepared.name,
                prepared.attribute,
                prepared.regex.as_ref(),
            ) {
                return true;
            }
        }
    }

    let Some(idx) = global.file_index(file) else {
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
    // Fold each (target, src) so target points to src's root. Detect cycles
    // by identity instead of truncating valid alias chains at an arbitrary
    // depth.
    for (target, src) in order {
        let mut root = src;
        let mut visited = AHashSet::new();
        visited.insert(root.clone());
        loop {
            match pairs.get(&root) {
                Some(next) if next != &root && visited.insert(next.clone()) => {
                    root.clone_from(next);
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
        let span = event.span();
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
        // Transitions are sorted by `span.start`, which does NOT make
        // `span.end` monotonic — a wide early span can end after the call
        // while a later narrow span ends before it. So `skip` (continue)
        // transitions that end after the call rather than `break`, or we'd
        // miss a valid later transition behind a wide earlier one. The last
        // matching transition in start order is the latest state.
        if span.end > call_span_start {
            continue;
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

fn expanded_receiver_types(
    receiver_types: &[String],
    receiver_base_map: &AHashMap<String, Vec<String>>,
) -> Vec<String> {
    if receiver_types.is_empty() || receiver_base_map.is_empty() {
        return receiver_types.to_vec();
    }
    let mut out = receiver_types.to_vec();
    let mut seen = AHashSet::new();
    for receiver_type in receiver_types {
        push_receiver_type_bases(&mut out, receiver_type, receiver_base_map, &mut seen);
    }
    out
}

fn push_receiver_type_bases(
    out: &mut Vec<String>,
    receiver_type: &str,
    receiver_base_map: &AHashMap<String, Vec<String>>,
    seen: &mut AHashSet<String>,
) {
    let key = normalize_type_name_for_match(receiver_type);
    if key.is_empty() || !seen.insert(key.clone()) {
        return;
    }
    if let Some(bases) = receiver_base_map.get(&key) {
        for base in bases {
            push_unique_string(out, base.clone());
            push_receiver_type_bases(out, base, receiver_base_map, seen);
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
        .split(['.', ':', '\\', '[', '(', '?'])
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
                            passing_mode: Default::default(),
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
            // R5: a sink in the yielded value (`yield exec(cmd)`, C#
            // `yield return Sink(x)`) only surfaces as a Yield event,
            // never a Call. Lower the yielded expression into a CallFact
            // when it is a call so sink attribution can see it.
            FlowEvent::Yield {
                span,
                value_text: Some(value_text),
                ..
            } => {
                if let Some((callee, args)) = receiver_call_with_args(value_text, *span) {
                    out.push(CallFact {
                        callee,
                        span: *span,
                        args,
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Function,
                        origin: CallFactOrigin::NestedReceiverCall,
                    });
                }
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
                passing_mode: Default::default(),
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

#[derive(Clone, Debug)]
struct WriteFact {
    target: String,
    span: Span,
    argument: CallArg,
    /// Rule-visible renderings that came from parsed expression/control-flow
    /// nodes. This is deliberately separate from `CallArg::value_text`: the
    /// matcher may compare a rule-owned regex with these facts, but it must
    /// never rediscover assignment structure by scanning a source line.
    ast_values: Vec<String>,
}

impl WriteFact {
    fn from_assign(
        target: &str,
        span: Span,
        source_name: Option<&str>,
        source_call: Option<&str>,
        source_call_args: &[String],
        source_names: &[String],
    ) -> Self {
        let mut ast_values = Vec::new();
        let mut dependencies = Vec::new();
        let push_unique = |values: &mut Vec<String>, value: &str| {
            let value = value.trim();
            if !value.is_empty() && !values.iter().any(|existing| existing == value) {
                values.push(value.to_string());
            }
        };
        if let Some(value) = source_name {
            push_unique(&mut ast_values, value);
            push_unique(&mut dependencies, value);
        }
        if let Some(value) = source_call {
            push_unique(&mut ast_values, value);
        }
        for value in source_call_args {
            push_unique(&mut ast_values, value);
            push_unique(&mut dependencies, value);
        }
        for value in source_names {
            push_unique(&mut ast_values, value);
            push_unique(&mut dependencies, value);
        }
        let value_text = source_name.unwrap_or_default().trim().to_string();
        Self {
            target: target.to_string(),
            span,
            argument: CallArg {
                passing_mode: Default::default(),
                span,
                name: None,
                place: source_name
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string),
                source_names: dependencies,
                value_text,
            },
            ast_values,
        }
    }

    fn extend_with_nested_ast_values(&mut self, index: &NestedAstValueIndex) {
        index.extend_values_within(self.span, &mut self.ast_values);
    }

    fn extend_with_assignment_value(&mut self, index: &AssignmentValueIndex, source_text: Option<&str>) {
        let Some(value) = index.rendering(self.span, source_text) else {
            return;
        };
        self.argument.value_text = value.to_string();
        if !self.ast_values.iter().any(|existing| existing == value) {
            self.ast_values.push(value.to_string());
        }
    }
}

#[derive(Clone, Debug)]
struct NestedAstValueEntry {
    span: Span,
    values: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct NestedAstValueIndex {
    entries: Vec<NestedAstValueEntry>,
}

impl NestedAstValueIndex {
    fn new(decls: &[Decl]) -> Self {
        let mut entries = decls
            .iter()
            .filter_map(|decl| {
                let mut values = Vec::new();
                collect_branch_condition_values(&decl.flow_events, &mut values);
                values.sort();
                values.dedup();
                (!values.is_empty()).then_some(NestedAstValueEntry {
                    span: decl.span,
                    values,
                })
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| (entry.span.file.raw(), entry.span.start, entry.span.end));
        Self { entries }
    }

    fn extend_values_within(&self, outer: Span, out: &mut Vec<String>) {
        let mut seen = out.iter().cloned().collect::<AHashSet<_>>();
        let start = self.entries.partition_point(|entry| {
            entry.span.file.raw() < outer.file.raw()
                || (entry.span.file == outer.file && entry.span.start <= outer.start)
        });
        for entry in self.entries[start..]
            .iter()
            .take_while(|entry| entry.span.file == outer.file && entry.span.start < outer.end)
        {
            if entry.span.end > outer.end {
                continue;
            }
            for value in &entry.values {
                if seen.insert(value.clone()) {
                    out.push(value.clone());
                }
            }
        }
    }
}

fn collect_writes(events: &[FlowEvent]) -> Vec<WriteFact> {
    let mut out = Vec::new();
    collect_writes_into(events, &mut out);
    out
}

fn collect_writes_into(events: &[FlowEvent], out: &mut Vec<WriteFact>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                span,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                if !target.is_empty() {
                    out.push(WriteFact::from_assign(
                        target,
                        *span,
                        source_name.as_deref(),
                        source_call.as_deref(),
                        source_call_args,
                        source_names,
                    ));
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

fn collect_branch_condition_values(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Branch {
                condition,
                then_events,
                else_events,
                ..
            } => {
                if let Some(value) = condition
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    out.push(value.to_string());
                }
                collect_branch_condition_values(then_events, out);
                collect_branch_condition_values(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_branch_condition_values(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_branch_condition_values(body, out);
                collect_branch_condition_values(catch_events, out);
                collect_branch_condition_values(finally_events, out);
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
            | ConstraintKind::ReceiverTypeNotIn { .. }
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
            | ConstraintKind::SinkTagIn { .. }
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
    /// Additional argument values emitted by parsed AST facts. Write rules
    /// use this for RHS operands and nested callable branch conditions;
    /// source snapshots are never scanned to reconstruct them.
    ast_arg_values: Option<&'a [Vec<String>]>,
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
/// | `ReceiverTypeNotIn`          | callee's receiver type does not match a safe type  |
/// | `Namespace`                  | callee's qualified prefix matches the namespace    |
/// | `FormatArgIndex`             | the format-string arg slot matches expected index  |
/// | `TopLevel`                   | enclosing decl is at module top level              |
/// | `ArgCount`                   | exact arg count match                              |
/// | `MinArgs` / `MaxArgs`        | min / max arg-count gate                           |
/// | `SecondArgEquals`            | `arg[1]` equals literal                            |
/// | `ArgEquals`                  | `arg[index]` equals the literal value              |
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
            ConstraintKind::ReceiverTypeNotIn { receiver_type_not_in } => {
                if receiver_type_matches_any(ctx.receiver_types, receiver_type_not_in) {
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
                let candidates = constraint_regex_texts(ctx, idx, arg);
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
                let candidates = constraint_regex_texts(ctx, idx, arg);
                if candidates.iter().any(|value| re.is_match(value.trim())) {
                    return false;
                }
            }
            ConstraintKind::AnyArgMatchesRegex { .. } => {
                let Some(Some(re)) = ctx.constraint_regexes.get(constraint_index) else {
                    return false;
                };
                let matched = ctx.args.iter().enumerate().any(|(index, arg)| {
                    let candidates = constraint_regex_texts(ctx, index, arg);
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
            // Source/sink compatibility is a path-level predicate. Source
            // matching has no sink yet, so retain the candidate here and let
            // taint attribution evaluate this declarative constraint once a
            // proven terminal sink is available.
            ConstraintKind::SinkTagIn { sink_tag_in } => {
                if sink_tag_in.is_empty() {
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
            // `index` resolves the binding from the call's actual
            // argument (general — `free(q)` then `strcpy(q, ..)` flags a
            // UAF of `q`); `name` keeps the legacy literal binding.
            ConstraintKind::RequiresState { requires_state } => {
                let Some(transitions) = ctx.lifecycle_transitions else {
                    return false;
                };
                let binding: Option<&str> = match (&requires_state.name, requires_state.index) {
                    (Some(name), _) => Some(name.as_str()),
                    (None, Some(index)) => ctx
                        .args
                        .get(index as usize)
                        .map(|arg| arg.value_text.trim())
                        .filter(|value| is_simple_ident(value)),
                    (None, None) => None,
                };
                let Some(binding) = binding else {
                    return false;
                };
                let observed = lifecycle_state_at(transitions, binding, ctx.span.start);
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

fn collect_constructor_names_for_files(ws: &Workspace, files: &[FileId]) -> AHashSet<String> {
    let collect_for_file = |file: FileId| -> Vec<String> {
        let Some(index) = ws.db().decl_index_uncached(file) else {
            return Vec::new();
        };
        index
            .defs
            .iter()
            .filter(|decl| matches!(decl.kind, DeclKind::Constructor))
            .map(|decl| decl.name.clone())
            .collect()
    };
    let workers = matcher_worker_count(files.len());
    if workers > 1 && files.len() > 1 {
        let collect = || {
            use rayon::prelude::*;
            let names = files
                .par_iter()
                .flat_map_iter(|&file| collect_for_file(file))
                .collect::<Vec<_>>();
            names.into_iter().collect::<AHashSet<_>>()
        };
        if let Ok(pool) = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .stack_size(matcher_worker_stack_bytes())
            .build()
        {
            return pool.install(collect);
        }
        return collect();
    }
    let mut names = AHashSet::new();
    for &file in files {
        names.extend(collect_for_file(file));
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
/// Security batch scans can touch tens of thousands of files once; do
/// not retain those span maps in the shared browse cache.
fn resolve_span(ws: &Workspace, file: FileId, span: Span) -> (String, u32, u32) {
    let path = ws
        .vfs()
        .path(file)
        .map(|file_path| file_path.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Ok(snapshot) = ws.vfs().snapshot(file) {
        let span_map = bonsai_common::SpanMap::new(snapshot.text.as_ref());
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
    let files = ws.db().global_index().all_files().collect::<Vec<_>>();
    infer_entry_point_sources_for_files_with_progress(ws, &files, || {})
}

pub(crate) fn infer_entry_point_sources_for_files_with_progress<F>(
    ws: &Workspace,
    scan_files: &[FileId],
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    let db = ws.db();
    let global = db.global_index();
    let mut files = scan_files.to_vec();
    files.sort_by_key(|file| file.raw());
    files.dedup();
    if files.is_empty() {
        return Vec::new();
    }
    // Build a set of "has in-workspace callers" to detect leaf functions
    // that look like entry points (unreferenced public decls). This uses
    // the same scoped resolved-callgraph primitive as trace/taint instead
    // of resolving every call name directly from the matcher. On large
    // copied package trees, direct global lookup turns inferred-source
    // generation into the dominant runtime; the callgraph builder keeps
    // resolution local/module/receiver scoped and parallel.
    let infer_debug = bonsai_diagnostics::debug::is_enabled("security-phase");
    let started = infer_debug.then(Instant::now);
    let callees_seen = collect_called_symbols_for_files(ws, &files);
    log_inferred_subphase(
        infer_debug,
        "called-symbol collection",
        started,
        format_args!("symbols={}", callees_seen.len()),
    );

    // G3 cross-method field-taint: build a per-class set of
    // receiver-field writes sourced from that method's params
    // (`this.cmd = token` / `self.cmd = x`). Every sibling method
    // of the class inherits those fields as synthetic sources so
    // `constructor(t) { this.cmd = t }` + `run() { sink(this.cmd) }`
    // produces a finding without the interprocedural pass needing
    // to model object-state between method invocations on the same
    // receiver. Keyed on the class decl's symbol — derived purely
    // from tree-sitter-emitted DeclKind / parent / FlowEvent facts.
    let started = infer_debug.then(Instant::now);
    let class_field_writes = collect_class_field_taints_for_files(&global, &files);
    log_inferred_subphase(
        infer_debug,
        "class-field taint collection",
        started,
        format_args!("classes={}", class_field_writes.len()),
    );

    let mut out = Vec::new();
    let started = infer_debug.then(Instant::now);
    let mut scanned_decls = 0usize;
    for file in files {
        let Some(adapter) = db.adapter_for(file) else {
            on_file_done();
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
            scanned_decls = scanned_decls.saturating_add(1);
            let has_callers = callees_seen.contains(&decl.symbol);
            let decorator_kind = detect_framework_decorator(ws, file, decl.span, decl.name_span);
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

            // G3 cross-method: if this method's class has any receiver-field
            // writes sourced from a param (recorded in
            // class_field_writes), emit a synthetic source for the
            // receiver-field name inside this method. Class membership
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
                        let Some(read_span) = flow_read_token_span(&decl.flow_events, field_name) else {
                            continue;
                        };
                        let (file_path, line, col) = resolve_span(ws, file, read_span);
                        out.push(RuleMatch {
                            rule_id: "entry-point.class_field.inherited".to_string(),
                            language: language.clone(),
                            file: file_path,
                            line,
                            column: col,
                            span: read_span,
                            match_text: field_name.clone(),
                            enclosing_fn: Some(decl.name.clone()),
                        });
                    }
                }
            }
        }
        on_file_done();
    }
    log_inferred_subphase(
        infer_debug,
        "source emission",
        started,
        format_args!("decls={scanned_decls} matches={}", out.len()),
    );
    out
}

fn collect_called_symbols_for_files(ws: &Workspace, files: &[FileId]) -> ahash::AHashSet<SymbolId> {
    let db = ws.db();
    let global = db.global_index();
    let infer_debug = bonsai_diagnostics::debug::is_enabled("security-phase");
    let started = infer_debug.then(Instant::now);
    let call_graph = bonsai_callgraph::ResolvedCallGraph::build_with_file_info_and_super_tokens_for_files(
        global.as_ref(),
        |file| bonsai_resolve::semantic_import_binding_map_for_file(&db.imports_for(file)),
        |file| {
            bonsai_lang_api::alias_map_from_import_specs(&db.imports_for(file))
                .into_iter()
                .collect()
        },
        |file| {
            db.vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        },
        |file| {
            db.adapter_for(file)
                .map(|adapter| adapter.capabilities().module_export_aliases)
                .unwrap_or(&[])
        },
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
        |file| {
            db.adapter_for(file)
                .map(|adapter| adapter.capabilities().effective_super_receiver_tokens())
                .unwrap_or(&[])
        },
        |file| {
            db.adapter_for(file)
                .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax)
        },
        files,
    );
    log_inferred_subphase(
        infer_debug,
        "resolved callgraph",
        started,
        format_args!("edges={}", call_graph.inner().edges.len()),
    );
    let mut out: ahash::AHashSet<SymbolId> = call_graph
        .inner()
        .edges
        .iter()
        .map(|edge| SymbolId::new(edge.to.raw()))
        .collect();
    let before_assignment_refs = out.len();
    let started = infer_debug.then(Instant::now);
    collect_assignment_referenced_callable_symbols(ws, files, global.as_ref(), &mut out);
    log_inferred_subphase(
        infer_debug,
        "assignment callable references",
        started,
        format_args!(
            "symbols={} added={}",
            out.len(),
            out.len().saturating_sub(before_assignment_refs)
        ),
    );
    out
}

fn log_inferred_subphase(
    enabled: bool,
    label: &str,
    started: Option<Instant>,
    args: std::fmt::Arguments<'_>,
) {
    if !enabled {
        return;
    }
    let Some(started) = started else {
        return;
    };
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "inferred {label}: {:.3}s {args}",
        started.elapsed().as_secs_f64()
    );
}

fn flow_read_token_span(events: &[FlowEvent], token: &str) -> Option<Span> {
    for event in events {
        match event {
            FlowEvent::Call {
                span, receiver, args, ..
            } => {
                if receiver.as_deref() == Some(token)
                    || args
                        .iter()
                        .any(|arg| arg.place.as_deref() == Some(token) || arg.value_text.trim() == token)
                {
                    return Some(*span);
                }
            }
            FlowEvent::Assign {
                span,
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                if source_name.as_deref() == Some(token)
                    || source_names.iter().any(|name| name == token)
                    || source_call_args.iter().any(|arg| arg.trim() == token)
                {
                    return Some(*span);
                }
            }
            FlowEvent::Return {
                span,
                value_text,
                value_name,
                ..
            } => {
                if value_text.as_deref() == Some(token) || value_name.as_deref() == Some(token) {
                    return Some(*span);
                }
            }
            FlowEvent::Throw { span, value_name, .. } => {
                if value_name.as_deref() == Some(token) {
                    return Some(*span);
                }
            }
            FlowEvent::Yield { span, value_text, .. } => {
                if value_text.as_deref() == Some(token) {
                    return Some(*span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(span) = flow_read_token_span(then_events, token)
                    .or_else(|| flow_read_token_span(else_events, token))
                {
                    return Some(span);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(span) = flow_read_token_span(body, token) {
                    return Some(span);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(span) = flow_read_token_span(body, token)
                    .or_else(|| flow_read_token_span(catch_events, token))
                    .or_else(|| flow_read_token_span(finally_events, token))
                {
                    return Some(span);
                }
            }
            _ => {}
        }
    }
    None
}

/// Scan every class's methods for `Assign { target: receiver_field_name,
/// source: this-method's param }` writes. Returns a map
/// `class_symbol → set of receiver-field names` so sibling methods
/// can inherit field taint (G3 cross-method field-taint).
///
/// Class→method relationship is semantic: adapters populate
/// `Decl.parent` from AST ownership before the matcher runs. The
/// matcher does not infer membership from source-span containment,
/// because nested/local functions can live inside the same spans but
/// are not class methods.
fn collect_class_field_taints_for_files(
    global: &bonsai_index::GlobalIndex,
    files: &[FileId],
) -> ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> {
    let mut out: ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> =
        ahash::AHashMap::default();
    for &file in files {
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
        }
    }
    out
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
    ws: &Workspace,
    file: FileId,
    decl_span: Span,
    decl_name_span: Span,
) -> Option<EntryKind> {
    let global = ws.db().global_index();
    let idx = global.file_index(file)?;
    (!decl_decorator_names(ws, file, idx, decl_span, decl_name_span).is_empty())
        .then_some(EntryKind::Decorator)
}

/// Walk assignment-only callable references that do not necessarily
/// produce a callgraph edge, collecting every referenced callable that
/// resolves to a workspace-local symbol.
///
/// The resolved callgraph above covers real calls, including
/// assignment-source calls. This supplement preserves the old
/// entrypoint-inference behavior for address-taken callables and
/// export assignments such as `exports.handler = handler`: these
/// functions are referenced by the workspace even if the assignment
/// itself is not an invocation.
fn collect_assignment_referenced_callable_symbols(
    ws: &Workspace,
    files: &[FileId],
    global: &bonsai_index::GlobalIndex,
    out: &mut ahash::AHashSet<SymbolId>,
) {
    let local_callable_index = AssignmentCallableReferenceIndex::build(global);
    let mut resolve_cache: AHashMap<AssignmentResolveKey, Vec<SymbolId>> = AHashMap::default();
    let mut stats = AssignmentReferenceStats::default();
    for &file in files {
        let alias_map: AHashMap<String, AliasTarget> = file_alias_map(ws, file).into_iter().collect();
        let export_aliases = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().module_export_aliases)
            .unwrap_or(&[]);
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            collect_assignment_referenced_callable_symbols_from_events(
                ws,
                &decl.flow_events,
                global,
                decl,
                &alias_map,
                export_aliases,
                &local_callable_index,
                &mut resolve_cache,
                &mut stats,
                out,
            );
        }
    }
    if bonsai_diagnostics::debug::is_enabled("security-phase") {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "inferred assignment refs detail: seen={} fast_hits={} skipped_simple={} skipped_qualified={} cache_hits={} fallback_resolves={} fallback_symbols={}",
            stats.seen,
            stats.fast_hits,
            stats.skipped_simple,
            stats.skipped_qualified,
            stats.cache_hits,
            stats.fallback_resolves,
            stats.fallback_symbols,
        );
        if !stats.fallback_names.is_empty() {
            let mut names = stats
                .fallback_names
                .iter()
                .map(|(name, count)| (name.as_str(), *count))
                .collect::<Vec<_>>();
            names.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            let rendered = names
                .into_iter()
                .take(12)
                .map(|(name, count)| format!("{name}:{count}"))
                .collect::<Vec<_>>()
                .join(", ");
            bonsai_diagnostics::debug_log!(
                "security-phase",
                "inferred assignment fallback names: {rendered}"
            );
        }
    }
}

#[derive(Default)]
struct AssignmentReferenceStats {
    seen: usize,
    fast_hits: usize,
    skipped_simple: usize,
    cache_hits: usize,
    fallback_resolves: usize,
    fallback_symbols: usize,
    skipped_qualified: usize,
    fallback_names: AHashMap<String, usize>,
}

#[derive(Default)]
struct AssignmentCallableReferenceIndex {
    by_file: AHashMap<(String, FileId), Option<SymbolId>>,
    by_module: AHashSet<(String, ModulePath)>,
}

impl AssignmentCallableReferenceIndex {
    fn build(global: &bonsai_index::GlobalIndex) -> Self {
        let mut index = Self::default();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if !matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    continue;
                }
                for name in assignment_callable_reference_names(decl) {
                    index.insert(file, &decl.module_path, name, decl.symbol);
                }
            }
        }
        index
    }

    fn insert(&mut self, file: FileId, module: &ModulePath, name: String, symbol: SymbolId) {
        if !module.is_empty() {
            self.by_module.insert((name.clone(), module.clone()));
        }
        let key = (name, file);
        if let Some(slot) = self.by_file.get_mut(&key) {
            if slot.is_some_and(|existing| existing != symbol) {
                *slot = None;
            }
        } else {
            self.by_file.insert(key, Some(symbol));
        }
    }

    fn unique_in_file(&self, name: &str, file: FileId) -> Option<SymbolId> {
        self.by_file
            .get(&(name.to_string(), file))
            .and_then(|symbol| *symbol)
    }

    fn contains_in_file(&self, name: &str, file: FileId) -> bool {
        self.by_file.contains_key(&(name.to_string(), file))
    }

    fn contains_in_module(&self, name: &str, module: &ModulePath) -> bool {
        !module.is_empty() && self.by_module.contains(&(name.to_string(), module.clone()))
    }
}

fn assignment_callable_reference_names(decl: &Decl) -> Vec<String> {
    let mut names = Vec::new();
    push_unique_assignment_callable_name(&mut names, decl.name.clone());
    if let Some(qualified) = decl.qualified_name.as_ref() {
        push_unique_assignment_callable_name(&mut names, qualified.clone());
        if let Some(tail) = assignment_reference_tail(qualified) {
            push_unique_assignment_callable_name(&mut names, tail.to_string());
        }
    }
    names
}

fn push_unique_assignment_callable_name(out: &mut Vec<String>, name: String) {
    if !name.is_empty() && !out.iter().any(|existing| existing == &name) {
        out.push(name);
    }
}

fn assignment_reference_tail(name: &str) -> Option<&str> {
    name.rsplit(['.', ':', '\\'])
        .next()
        .filter(|tail| !tail.is_empty())
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct AssignmentResolveKey {
    name: String,
    caller_file: FileId,
    caller_module: ModulePath,
}

impl AssignmentResolveKey {
    fn new(name: &str, caller: &Decl) -> Self {
        Self {
            name: name.to_string(),
            caller_file: caller.span.file,
            caller_module: caller.module_path.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)] // Recursive matcher collector carries workspace, resolver, cache, stats, and output context.
fn collect_assignment_referenced_callable_symbols_from_events(
    ws: &Workspace,
    events: &[FlowEvent],
    global: &bonsai_index::GlobalIndex,
    caller: &bonsai_lang_api::Decl,
    alias_map: &AHashMap<String, AliasTarget>,
    export_aliases: &[&'static str],
    local_callable_index: &AssignmentCallableReferenceIndex,
    resolve_cache: &mut AHashMap<AssignmentResolveKey, Vec<SymbolId>>,
    stats: &mut AssignmentReferenceStats,
    out: &mut ahash::AHashSet<SymbolId>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
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
                    resolve_assignment_callable_reference(
                        ws,
                        global,
                        caller,
                        alias_map,
                        local_callable_index,
                        resolve_cache,
                        stats,
                        name,
                        out,
                    );
                }
                if assignment_exports_callable_names(target, export_aliases) {
                    for name in source_names {
                        resolve_assignment_callable_reference(
                            ws,
                            global,
                            caller,
                            alias_map,
                            local_callable_index,
                            resolve_cache,
                            stats,
                            name,
                            out,
                        );
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assignment_referenced_callable_symbols_from_events(
                    ws,
                    then_events,
                    global,
                    caller,
                    alias_map,
                    export_aliases,
                    local_callable_index,
                    resolve_cache,
                    stats,
                    out,
                );
                collect_assignment_referenced_callable_symbols_from_events(
                    ws,
                    else_events,
                    global,
                    caller,
                    alias_map,
                    export_aliases,
                    local_callable_index,
                    resolve_cache,
                    stats,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } => {
                collect_assignment_referenced_callable_symbols_from_events(
                    ws,
                    body,
                    global,
                    caller,
                    alias_map,
                    export_aliases,
                    local_callable_index,
                    resolve_cache,
                    stats,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assignment_referenced_callable_symbols_from_events(
                    ws,
                    body,
                    global,
                    caller,
                    alias_map,
                    export_aliases,
                    local_callable_index,
                    resolve_cache,
                    stats,
                    out,
                );
                collect_assignment_referenced_callable_symbols_from_events(
                    ws,
                    catch_events,
                    global,
                    caller,
                    alias_map,
                    export_aliases,
                    local_callable_index,
                    resolve_cache,
                    stats,
                    out,
                );
                collect_assignment_referenced_callable_symbols_from_events(
                    ws,
                    finally_events,
                    global,
                    caller,
                    alias_map,
                    export_aliases,
                    local_callable_index,
                    resolve_cache,
                    stats,
                    out,
                );
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assignment_referenced_callable_symbols_from_events(
                    ws,
                    body,
                    global,
                    caller,
                    alias_map,
                    export_aliases,
                    local_callable_index,
                    resolve_cache,
                    stats,
                    out,
                );
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)] // Mirrors the recursive collector context.
fn resolve_assignment_callable_reference(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    caller: &bonsai_lang_api::Decl,
    alias_map: &AHashMap<String, AliasTarget>,
    local_callable_index: &AssignmentCallableReferenceIndex,
    resolve_cache: &mut AHashMap<AssignmentResolveKey, Vec<SymbolId>>,
    stats: &mut AssignmentReferenceStats,
    name: &str,
    out: &mut ahash::AHashSet<SymbolId>,
) {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return;
    }
    stats.seen = stats.seen.saturating_add(1);
    let local_name = trimmed.trim_start_matches(bonsai_common::REFERENCE_SIGILS);
    if fast_assignment_local_reference_name(local_name) {
        if let Some(symbol) = local_callable_index.unique_in_file(local_name, caller.span.file) {
            out.insert(symbol);
            stats.fast_hits = stats.fast_hits.saturating_add(1);
            return;
        }
        if !assignment_reference_needs_resolver(ws, caller, alias_map, local_callable_index, local_name) {
            stats.skipped_simple = stats.skipped_simple.saturating_add(1);
            return;
        }
    }
    if assignment_reference_is_unresolved_member_read(local_name, alias_map) {
        stats.skipped_qualified = stats.skipped_qualified.saturating_add(1);
        return;
    }

    let key = AssignmentResolveKey::new(trimmed, caller);
    if let Some(cached) = resolve_cache.get(&key) {
        out.extend(cached.iter().copied());
        stats.cache_hits = stats.cache_hits.saturating_add(1);
        return;
    }
    stats.fallback_resolves = stats.fallback_resolves.saturating_add(1);
    *stats.fallback_names.entry(trimmed.to_string()).or_insert(0) += 1;

    let path_lookup = |file| {
        ws.vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    };
    let ctx = bonsai_resolve::ResolveContext::new(caller.span.file, &caller.module_path)
        .with_alias_map(alias_map)
        .with_file_path_lookup(&path_lookup);
    let mut resolved = Vec::new();
    for func in bonsai_resolve::resolve_callable_with_context(global, trimmed, &ctx) {
        push_unique_assignment_symbol(&mut resolved, SymbolId::new(func.raw()));
    }
    stats.fallback_symbols = stats.fallback_symbols.saturating_add(resolved.len());
    out.extend(resolved.iter().copied());
    resolve_cache.insert(key, resolved);
}

fn fast_assignment_local_reference_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && !trimmed.contains('.')
        && !trimmed.contains("::")
        && !trimmed.contains(':')
        && !trimmed.contains('\\')
        && !trimmed.contains('(')
        && !trimmed.contains(')')
        && !trimmed.chars().any(char::is_whitespace)
}

fn assignment_reference_is_unresolved_member_read(
    name: &str,
    alias_map: &AHashMap<String, AliasTarget>,
) -> bool {
    let Some((head, _tail)) = assignment_reference_head_tail(name) else {
        return false;
    };
    let head = head.trim().trim_start_matches(bonsai_common::REFERENCE_SIGILS);
    if head.is_empty() {
        return false;
    }
    if alias_map.contains_key(head) {
        return false;
    }
    if head.starts_with("require(") || head.starts_with("import(") {
        return true;
    }
    if matches!(head, "this" | "self" | "$this" | "super") {
        return true;
    }
    head.chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
}

fn assignment_reference_head_tail(name: &str) -> Option<(&str, &str)> {
    name.rsplit_once("::")
        .or_else(|| name.rsplit_once('.'))
        .or_else(|| name.rsplit_once(':'))
        .or_else(|| name.rsplit_once('\\'))
}

fn assignment_reference_needs_resolver(
    ws: &Workspace,
    caller: &bonsai_lang_api::Decl,
    alias_map: &AHashMap<String, AliasTarget>,
    local_callable_index: &AssignmentCallableReferenceIndex,
    name: &str,
) -> bool {
    if local_callable_index.contains_in_file(name, caller.span.file)
        || local_callable_index.contains_in_module(name, &caller.module_path)
        || alias_map.contains_key(name)
        || alias_map
            .keys()
            .any(|key| key.starts_with(bonsai_lang_api::WILDCARD_IMPORT_ALIAS_PREFIX))
    {
        return true;
    }
    caller_allows_same_directory_unqualified_lookup(ws, caller.span.file)
}

fn caller_allows_same_directory_unqualified_lookup(ws: &Workspace, file: FileId) -> bool {
    let Ok(path) = ws.vfs().path(file) else {
        return true;
    };
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or_default(),
        "c" | "h"
            | "cc"
            | "cpp"
            | "cxx"
            | "hpp"
            | "hh"
            | "hxx"
            | "m"
            | "mm"
            | "kt"
            | "kts"
            | "swift"
            | "pl"
            | "pm"
    )
}

fn push_unique_assignment_symbol(out: &mut Vec<SymbolId>, symbol: SymbolId) {
    if !out.contains(&symbol) {
        out.push(symbol);
    }
}

fn collect_callee_symbols(
    ws: &Workspace,
    events: &[FlowEvent],
    global: &bonsai_index::GlobalIndex,
    caller: &bonsai_lang_api::Decl,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    export_aliases: &[&'static str],
    out: &mut ahash::AHashSet<SymbolId>,
) {
    let resolve = |name: &str, receiver_types: &[String], out: &mut ahash::AHashSet<SymbolId>| {
        if name.trim().is_empty() {
            return;
        }
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
            out.insert(SymbolId::new(func.raw()));
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
                    out.insert(SymbolId::new(func.raw()));
                }
            }
        }
        if let Some(tail) = name.rsplit(&['.', ':'][..]).next() {
            if !tail.is_empty() && tail != name {
                for func in bonsai_resolve::resolve_callable_with_context(global, tail, &ctx) {
                    out.insert(SymbolId::new(func.raw()));
                }
            }
        }
    };
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver_types, ..
            } => resolve(name.as_str(), receiver_types, out),
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => {
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
