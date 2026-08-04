//! Match a rule against the workspace's browse facts.
//!
//! The matcher is **purely fact-level**: it never walks the tracer, never
//! builds chains, and never calls the resolver directly. Call-chain
//! enumeration and taint filtering are the job of `bonsai_inspect` via
//! [`crate::compile`]. The matcher just tells callers *which facts* in the
//! workspace look like a source / sink / sanitizer.

use crate::rule::{
    ArgTaintedSpec, ConstraintKind, MatchKind, MatchOrigin, ReceiverOriginCallbackParamReachesCallSpec, Rule,
    RuleTarget,
};
use ahash::{AHashMap, AHashSet};
use bonsai_common::{qualified_names_match, FileId, Span, SymbolId};
use bonsai_hash::Hasher as StableHasher;
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{
    AliasTarget, AssignmentValueIndex, CallArg, CallKind, CallTextPrefilter, CompilerAssignmentAlias,
    CompilerSyntaxHeader, Decl, DeclIndex, DeclKind, FlowEvent, ImportSpec, ModulePath, RefKind,
    TypeAliasBinding,
};
use bonsai_taint::{TaintedCall, TaintedCallKind};
use bonsai_workspace::{decl_decorator_names, Workspace};
use lru::LruCache;
use regex::Regex;
use std::{
    cell::RefCell,
    hash::Hash,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, OnceLock,
    },
    time::Instant,
};

const LOCAL_IMPORT_PACKAGE_PREFIX: &str = "__bonsai_local_import_pkg__";
const WORKSPACE_IMPORT_PACKAGE_PREFIX: &str = "__bonsai_workspace_import_pkg__";
const COMPONENT_IMPORT_PACKAGE_PREFIX: &str = "__bonsai_component_import_pkg__";
static ENDPOINT_FALLBACK_DEBUG_SAMPLES: AtomicUsize = AtomicUsize::new(0);

/// Process-wide derived matcher facts share a fixed fraction of the effective
/// host/container budget. Leave explicit headroom for allocator fragmentation
/// and the semantic graph that follows: dropping an `Arc` at the phase
/// boundary does not guarantee that every allocator page is returned to the
/// operating system immediately. Retention can change recomputation and wall
/// time, never which files or facts are analyzed.
fn broad_matcher_fact_cache_total_budget_bytes() -> u64 {
    broad_matcher_fact_cache_total_budget_bytes_for_limit(bonsai_common::effective_memory_limit_bytes())
}

fn broad_matcher_fact_cache_total_budget_bytes_for_limit(limit: Option<u64>) -> u64 {
    const DEFAULT_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;
    limit
        .map(|limit| (limit / 24).clamp(1, MAX_BUDGET_BYTES))
        .unwrap_or(DEFAULT_BUDGET_BYTES)
}

fn matcher_fact_cache_budget_share(numerator: u64, denominator: u64) -> u64 {
    broad_matcher_fact_cache_total_budget_bytes()
        .saturating_mul(numerator)
        .checked_div(denominator)
        .unwrap_or(0)
        .max(1)
}

fn point_matcher_fact_cache_budget_share(numerator: u64, denominator: u64) -> u64 {
    const DEFAULT_BUDGET_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
    bonsai_common::effective_memory_limit_bytes()
        // Point constraint re-checks coexist with the complete semantic graph.
        // Keep only a small hot set after broad matcher ownership ends.
        .map(|limit| (limit / 64).clamp(1, MAX_BUDGET_BYTES))
        .unwrap_or(DEFAULT_BUDGET_BYTES)
        .saturating_mul(numerator)
        .checked_div(denominator)
        .unwrap_or(0)
        .max(1)
}

type MatcherFactCell<V> = Arc<OnceLock<Arc<V>>>;

struct MatcherFactFlight<V> {
    cell: MatcherFactCell<V>,
    retention_generation: u64,
}

struct MatcherFactEntry<V> {
    value: Arc<V>,
    estimated_bytes: u64,
}

struct MatcherFactCacheState<K, V> {
    entries: LruCache<K, MatcherFactEntry<V>>,
    in_flight: AHashMap<K, MatcherFactFlight<V>>,
    estimated_bytes: u64,
    retained_budget_bytes: u64,
    retention_generation: u64,
}

impl<K, V> MatcherFactCacheState<K, V>
where
    K: Eq + Hash,
{
    fn new(retained_budget_bytes: u64) -> Self {
        Self {
            entries: LruCache::unbounded(),
            in_flight: AHashMap::new(),
            estimated_bytes: 0,
            retained_budget_bytes,
            retention_generation: 0,
        }
    }
}

/// Byte-weighted LRU with per-key single-flight construction.
///
/// Oversize values are returned normally but not retained. Eviction therefore
/// changes only whether exact derived facts must be rebuilt on a later pass.
struct MatcherFactCache<K, V> {
    maximum_budget_bytes: u64,
    retain_oversized_singleton: bool,
    state: parking_lot::Mutex<MatcherFactCacheState<K, V>>,
}

impl<K, V> MatcherFactCache<K, V>
where
    K: Clone + Eq + Hash,
{
    fn new(budget_bytes: u64) -> Self {
        Self::new_with_oversized_singleton(budget_bytes, false)
    }

    fn new_with_oversized_singleton(budget_bytes: u64, retain_oversized_singleton: bool) -> Self {
        let budget_bytes = budget_bytes.max(1);
        Self {
            maximum_budget_bytes: budget_bytes,
            retain_oversized_singleton,
            state: parking_lot::Mutex::new(MatcherFactCacheState::new(budget_bytes)),
        }
    }

    fn get_or_insert_with(
        &self,
        key: K,
        build: impl FnOnce() -> Arc<V>,
        estimate: impl FnOnce(&V) -> u64,
    ) -> Arc<V> {
        let (cell, flight_generation) = {
            let mut state = self.state.lock();
            if let Some(entry) = state.entries.get(&key) {
                return Arc::clone(&entry.value);
            }
            if let Some(flight) = state.in_flight.get(&key) {
                (Arc::clone(&flight.cell), flight.retention_generation)
            } else {
                let cell = Arc::new(OnceLock::new());
                let retention_generation = state.retention_generation;
                state.in_flight.insert(
                    key.clone(),
                    MatcherFactFlight {
                        cell: Arc::clone(&cell),
                        retention_generation,
                    },
                );
                (cell, retention_generation)
            }
        };
        let value = cell.get_or_init(build).clone();

        let mut state = self.state.lock();
        let owns_in_flight_slot = state
            .in_flight
            .get(&key)
            .is_some_and(|candidate| Arc::ptr_eq(&candidate.cell, &cell));
        if owns_in_flight_slot {
            state.in_flight.remove(&key);
            let estimated_bytes = estimate(value.as_ref()).max(1);
            if flight_generation == state.retention_generation
                && (estimated_bytes <= state.retained_budget_bytes || self.retain_oversized_singleton)
            {
                state.estimated_bytes = state.estimated_bytes.saturating_add(estimated_bytes);
                if let Some((_replaced_key, replaced)) = state.entries.push(
                    key,
                    MatcherFactEntry {
                        value: Arc::clone(&value),
                        estimated_bytes,
                    },
                ) {
                    state.estimated_bytes = state.estimated_bytes.saturating_sub(replaced.estimated_bytes);
                }
                while state.estimated_bytes > state.retained_budget_bytes
                    && (!self.retain_oversized_singleton || state.entries.len() > 1)
                {
                    let Some((_evicted_key, evicted)) = state.entries.pop_lru() else {
                        break;
                    };
                    state.estimated_bytes = state.estimated_bytes.saturating_sub(evicted.estimated_bytes);
                }
            }
        }
        value
    }

    fn set_retained_budget(&self, retained_budget_bytes: u64) {
        let mut state = self.state.lock();
        state.retained_budget_bytes = retained_budget_bytes.max(1).min(self.maximum_budget_bytes);
        while state.estimated_bytes > state.retained_budget_bytes
            && (!self.retain_oversized_singleton || state.entries.len() > 1)
        {
            let Some((_evicted_key, evicted)) = state.entries.pop_lru() else {
                break;
            };
            state.estimated_bytes = state.estimated_bytes.saturating_sub(evicted.estimated_bytes);
        }
    }

    /// Release completed hot entries without disturbing an exact construction
    /// already in flight. Broad matcher passes call this at their ownership
    /// boundary before the semantic graph is opened. A later constraint
    /// re-check simply rebuilds the same derived fact.
    fn clear_retained(&self) {
        let mut state = self.state.lock();
        state.entries.clear();
        state.estimated_bytes = 0;
        state.retention_generation = state
            .retention_generation
            .checked_add(1)
            .expect("matcher cache retention generation exhausted");
    }
}

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
    /// Typed provenance used by analysis policy. Generated rule ids remain
    /// stable display identities and are never parsed to recover this value.
    #[serde(skip)]
    pub origin: MatchOrigin,
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

type CalleeCallsView<'a> = std::borrow::Cow<'a, [CallFact]>;

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

/// Match rules with rulepack-compiled factory return types available to
/// receiver typing. Validation and inventory paths use this so they observe
/// the same external-library type facts as taint analysis.
pub(crate) fn match_rules_against_facts_with_factory(
    ws: &Workspace,
    rules: &[&Rule],
    factory: &Arc<FactoryReturns>,
) -> Vec<RuleMatch> {
    let mut on_file_done = || {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        MatchRunConfig {
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: None,
            factory,
            dedup_file_matches: false,
            retention: FactRetention::Transient,
            global_headers: None,
        },
    )
}

pub(crate) fn match_rule_against_facts_with_factory(
    ws: &Workspace,
    rule: &Rule,
    factory: &Arc<FactoryReturns>,
) -> Vec<RuleMatch> {
    match_rules_against_facts_with_factory(ws, &[rule], factory)
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
            global_headers: None,
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
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: Some(files),
            factory,
            dedup_file_matches: false,
            retention: FactRetention::Transient,
            global_headers: None,
        },
    )
}

pub(crate) fn match_rules_against_facts_for_taint_support_with_progress_on_files<F>(
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
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: Some(files),
            factory,
            dedup_file_matches: false,
            retention: FactRetention::Transient,
            global_headers: None,
        },
    )
}

pub(crate) fn match_rules_against_facts_for_inventory_with_progress_on_files<F>(
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
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: Some(files),
            factory,
            dedup_file_matches: true,
            retention: FactRetention::Transient,
            global_headers: None,
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
    global_headers: &Arc<GlobalIndex>,
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
            global_headers: Some(global_headers),
        },
    )
}

/// Shared compiler state for one source-specific endpoint recheck.
///
/// The receiver ancestry memo is run-scoped because rebuilding it for each
/// sink candidate would turn endpoint checks into a candidates×workspace
/// scan. It remains lazy and is initialized only when a rule needs ancestry.
pub(crate) struct RuleConstraintTaintContext<'a> {
    pub endpoint_identity_proven: bool,
    pub factory: &'a FactoryReturns,
    pub global_headers: &'a Arc<GlobalIndex>,
    pub receiver_base_map_cell: &'a OnceLock<AHashMap<String, Vec<String>>>,
}

/// Re-evaluate `rule` against the workspace with taint context, and return
/// whether the specific `expected` hit (rule id + span) still passes.
pub(crate) fn rule_match_passes_constraints_with_taint_view(
    ws: &Workspace,
    rule: &Rule,
    expected: &RuleMatch,
    taint_view: &InterTaintView<'_>,
    context: &RuleConstraintTaintContext<'_>,
) -> bool {
    if rule.language != expected.language || rule.id != expected.rule_id {
        return false;
    }
    // `expected` is an exact endpoint produced by the initial
    // `TaintEndpoint` matcher pass, which has already proved every static
    // syntax/package constraint for this workspace snapshot. Re-evaluate only
    // the source-specific taint predicates here. Positional predicates on an
    // identity-proven call are fully represented by `TaintedCall`; keyword or
    // ambiguous overlapping-span cases fall through to the exact AST path.
    if let Some(verdict) = endpoint_taint_constraints_pass_without_syntax(
        rule,
        expected,
        taint_view,
        context.endpoint_identity_proven,
    ) {
        return verdict;
    }
    if bonsai_diagnostics::debug::is_enabled("security-phase")
        && ENDPOINT_FALLBACK_DEBUG_SAMPLES.fetch_add(1, Ordering::Relaxed) < 16
    {
        let call = taint_view.calls.first().copied();
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "endpoint proof fallback · rule {} · expected {} {:?} · call {} {:?} · identity {} · calls {}",
            rule.id,
            expected.match_text,
            expected.span,
            call.map(|call| call.name.as_str()).unwrap_or(""),
            call.map(|call| call.call_span),
            context.endpoint_identity_proven,
            taint_view.calls.len()
        );
    }
    let Some(prepared) = PreparedRule::new(rule) else {
        return false;
    };
    if let Some(verdict) = exact_rule_match_passes_constraints_at_expected_hit(
        ws,
        &prepared,
        expected,
        taint_view,
        context.factory,
        context.global_headers,
        context.receiver_base_map_cell,
    ) {
        return verdict;
    }
    match_rule_against_facts_with_taint_view(ws, rule, taint_view, context.global_headers)
        .into_iter()
        .any(|hit| hit.rule_id == expected.rule_id && hit.span == expected.span)
}

fn endpoint_taint_constraints_pass_without_syntax(
    rule: &Rule,
    expected: &RuleMatch,
    taint_view: &InterTaintView<'_>,
    endpoint_identity_proven: bool,
) -> Option<bool> {
    let [call] = taint_view.calls.as_slice() else {
        return None;
    };
    if !endpoint_identity_proven || !spans_overlap(call.call_span, expected.span) {
        return None;
    }

    for constraint in &rule.constraints.0 {
        match constraint {
            ConstraintKind::ArgTainted { arg_tainted } => {
                let index = usize::try_from(arg_tainted.index?).ok()?;
                if !matches!(call.kind, TaintedCallKind::Call | TaintedCallKind::Write)
                    || !call.tainted_args.iter().any(|arg| arg.index == index)
                {
                    return Some(false);
                }
            }
            ConstraintKind::ReceiverTainted { receiver_tainted } => {
                if !*receiver_tainted || call.kind != TaintedCallKind::Call || call.tainted_receiver.is_none()
                {
                    return Some(false);
                }
            }
            ConstraintKind::AnyArgTainted { any_arg_tainted } => {
                if !*any_arg_tainted
                    || !matches!(call.kind, TaintedCallKind::Call | TaintedCallKind::Write)
                    || call.tainted_args.is_empty()
                {
                    return Some(false);
                }
            }
            ConstraintKind::ReceiverOriginCallbackParamReachesCall { .. } => return None,
            _ => {}
        }
    }
    Some(true)
}

fn exact_rule_match_passes_constraints_at_expected_hit(
    ws: &Workspace,
    prepared: &PreparedRule<'_>,
    expected: &RuleMatch,
    taint_view: &InterTaintView<'_>,
    factory: &FactoryReturns,
    global_headers: &Arc<GlobalIndex>,
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
            global_headers,
            receiver_base_map_cell,
        )),
        MatchKind::Write => Some(write_rule_match_passes_constraints_at_expected_hit(
            ws,
            prepared,
            expected,
            taint_view,
            global_headers,
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
    global_headers: &Arc<GlobalIndex>,
    receiver_base_map_cell: &OnceLock<AHashMap<String, Vec<String>>>,
) -> bool {
    let file = expected.span.file;
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        prepared.needs_workspace_package_context(),
        FactRetention::Transient,
    );
    let Some(file_index) = ws
        .db()
        .decl_index_remapped_to_headers(global_headers.as_ref(), file)
    else {
        return false;
    };
    let bundle = decl_match_facts_for_retention(
        ws,
        file,
        Some(&file_index),
        factory,
        FactRetention::Transient,
        None,
    );
    let empty_receiver_base_map = AHashMap::new();
    // Initialise the workspace scan lazily and exactly once across every
    // candidate that reaches this path (see the cell's owner). Candidates
    // whose rule doesn't consult receiver types skip the scan entirely.
    let receiver_base_map: &AHashMap<String, Vec<String>> = if prepared_rule_needs_receiver_base_map(prepared)
    {
        receiver_base_map_cell.get_or_init(|| workspace_receiver_base_map(global_headers.as_ref()))
    } else {
        &empty_receiver_base_map
    };
    let constructor_names = if prepared.rule.match_spec.kind == MatchKind::New {
        collect_constructor_names(global_headers.as_ref())
    } else {
        AHashSet::new()
    };

    for decl in &file_index.defs {
        let Some(facts) = bundle.by_decl_span.get(&decl.span) else {
            continue;
        };
        if expected
            .enclosing_fn
            .as_ref()
            .is_some_and(|name| name != &facts.decl_name)
        {
            continue;
        }
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
                enclosing_modifiers: None,
                alias_chains: Some(&facts.alias_chains),
                runtime_types: Some(&facts.runtime_types),
                lifecycle_transitions: Some(&facts.lifecycle_transitions),
                structural_context: Some(StructuralConstraintContext {
                    current_decl: decl,
                    file_decls: &file_index.defs,
                    assignment_values: &file_index.assignment_values,
                    call_argument_values: &file_index.call_argument_values,
                }),
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
    global_headers: &Arc<GlobalIndex>,
) -> bool {
    let file = expected.span.file;
    let Some(file_index) = ws
        .db()
        .decl_index_remapped_to_headers(global_headers.as_ref(), file)
    else {
        return false;
    };
    let nested_ast_values = NestedAstValueIndex::new(&file_index.defs);
    let assignment_values = AssignmentValueIndex::new(&file_index.assignment_values);
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        prepared.needs_workspace_package_context(),
        FactRetention::Transient,
    );
    let alias_map = file_alias_map_with_retention(ws, file, FactRetention::Transient);

    for decl in &file_index.defs {
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
                enclosing_modifiers: None,
                alias_chains: None,
                runtime_types: None,
                lifecycle_transitions: None,
                structural_context: Some(StructuralConstraintContext {
                    current_decl: decl,
                    file_decls: &file_index.defs,
                    assignment_values: &file_index.assignment_values,
                    call_argument_values: &file_index.call_argument_values,
                }),
            }) {
                return true;
            }
        }
    }

    for r in &file_index.refs {
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
            enclosing_modifiers: None,
            alias_chains: None,
            runtime_types: None,
            lifecycle_transitions: None,
            structural_context: None,
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
    let global = streaming_global_headers(ws);
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
        let Some(file_index) = db.decl_index_remapped_to_headers(global.as_ref(), file) else {
            continue;
        };
        match rule.match_spec.kind {
            MatchKind::Call | MatchKind::New => {
                if matching_call_has_arg_index(
                    ws,
                    file,
                    &file_index,
                    &prepared,
                    &constructor_names,
                    wanted_index,
                ) {
                    return true;
                }
            }
            MatchKind::Write => {
                if wanted_index == 0 && matching_write_exists(&file_index, &prepared) {
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
            global_headers: None,
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
            mode: ConstraintMode::Inventory,
            taint_view: None,
            scan_files: Some(files),
            factory,
            dedup_file_matches: true,
            retention: FactRetention::Transient,
            global_headers: None,
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
        global_headers,
    } = config;
    if taint_view.is_none() {
        prepare_matcher_fact_caches_for_broad_scan();
    }
    let debug_security_phase = bonsai_diagnostics::debug::is_enabled("security-phase");
    let matcher_started = debug_security_phase.then(Instant::now);
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
    let dependency_context = if taint_view.is_none() {
        db.workspace_root().map(|root| {
            let lock = crate::deps::workspace_dependency_package_scan_lock(&root);
            (root, lock)
        })
    } else {
        None
    };
    let _dependency_context_guard = dependency_context.as_ref().map(|(_, lock)| lock.lock());
    let _dependency_package_snapshot = dependency_context.as_ref().map(|(root, _)| {
        crate::deps::workspace_dependency_package_context_for_scan(root, db.vfs().instance_id())
    });
    let prepared_by_language = build_prepared_rule_batches(&prepared, factory);
    // Follow the compiler planning order: reject impossible source files from
    // cheap raw anchors before opening import/syntax headers or lowering any
    // body. This is candidate planning only; every surviving rule still goes
    // through exact adapter IR and matcher constraints below.
    use rayon::prelude::*;
    let raw_scan_files = files
        .par_iter()
        .copied()
        .filter(|file| {
            let Some(adapter) = ws.db().adapter_for(*file) else {
                return false;
            };
            let Some(file_rules) = prepared_by_language.get(adapter.language_id().as_str()) else {
                return false;
            };
            let Ok(snapshot) = ws.db().vfs().snapshot(*file) else {
                return false;
            };
            file_rules.syntax_target_possible_in_text(
                snapshot.text.as_ref(),
                mode,
                adapter.capabilities().call_text_prefilter,
            )
        })
        .collect::<Vec<_>>();
    // Package/context gates consume exact file-local import facts. Receiver
    // inheritance is the only ordinary endpoint constraint that needs the
    // workspace declaration table; source rules and untyped API rules keep
    // their stable file/span identity until semantic attribution. Building
    // global headers unconditionally made a cold no-finding scan lower every
    // function body before syntax-target planning.
    let imports_started = debug_security_phase.then(Instant::now);
    let prewarmed_import_contexts =
        prewarm_language_import_package_contexts(ws, &raw_scan_files, &prepared_by_language, retention);
    if let Some(started) = imports_started {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher import/package prewarm: {:.3}s languages={}",
            started.elapsed().as_secs_f64(),
            prewarmed_import_contexts.len()
        );
    }
    let headers_started = debug_security_phase.then(Instant::now);
    // Caller-supplied semantic headers are already resident and authoritative.
    // Ordinary endpoint/inventory scans defer any new workspace ancestry table
    // until exact call headers contain a receiver/method pair whose verdict can
    // actually change through a base type.
    let needs_receiver_ancestry = prepared.iter().any(prepared_rule_needs_receiver_base_map);
    let mut global_file_indexes = global_headers.cloned();
    let mut inventory_receiver_ancestry: Option<Arc<bonsai_index::ReceiverAncestry>> = None;
    if let Some(started) = headers_started {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher symbol projection: {:.3}s declarations={} receiver_types={}",
            started.elapsed().as_secs_f64(),
            global_file_indexes.as_ref().map_or(0, |headers| headers.len()),
            inventory_receiver_ancestry
                .as_ref()
                .map_or(0, |ancestry| ancestry.len())
        );
    }
    let mut receiver_base_map = global_file_indexes
        .as_ref()
        .map_or_else(AHashMap::new, |headers| {
            workspace_receiver_base_map_if_needed(&prepared, mode, headers.as_ref())
        });
    let needs_constructor_names = prepared
        .iter()
        .any(|rule| rule.rule.match_spec.kind == MatchKind::New);
    let constructor_started = (debug_security_phase && needs_constructor_names).then(Instant::now);
    let constructor_files = if needs_constructor_names {
        files
            .iter()
            .copied()
            .filter(|file| {
                ws.db()
                    .adapter_for(*file)
                    .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax)
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let constructor_names = if needs_constructor_names {
        global_file_indexes.as_ref().map_or_else(
            || collect_constructor_names_in_compiler_files(ws, &constructor_files),
            |headers| collect_constructor_names_in_files(headers.as_ref(), &constructor_files),
        )
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
    // Apply exact import/package and syntax-header constraints to raw-anchor
    // survivors. Retain only rule references for the body phase below. This
    // is the compiler's header/body boundary: scheduling changes, but every
    // rule and file keeps the same semantics.
    let package_filter_started = debug_security_phase.then(Instant::now);
    let build_scan_plan = |candidate_files: &[FileId],
                           receiver_base_map: &AHashMap<String, Vec<String>>,
                           inventory_receiver_ancestry: Option<&Arc<bonsai_index::ReceiverAncestry>>,
                           receiver_ancestry_complete: bool| {
        use rayon::prelude::*;
        candidate_files
            .par_iter()
            .map(|&file| {
                let adapter = ws.db().adapter_for(file)?;
                let language = adapter.language_id();
                let file_rules = prepared_by_language.get(language.as_str())?;
                let snapshot = ws.db().vfs().snapshot(file).ok()?;
                let import_contexts = prewarmed_import_contexts.get(language.as_str());
                let prewarmed_compiler_imports = import_contexts
                    .and_then(|contexts| contexts.imports_by_file.get(&file))
                    .map(Arc::as_ref);
                let compiler_imports_owned = prewarmed_compiler_imports
                    .is_none()
                    .then(|| ws.db().compiler_import_index_uncached(file))
                    .flatten();
                let compiler_imports = prewarmed_compiler_imports.or(compiler_imports_owned.as_ref());
                let rules = file_rules.filtered_rule_refs_for_text(FileRuleFilterContext {
                    ws,
                    file,
                    text: snapshot.text.as_ref(),
                    mode,
                    retention,
                    prewarmed_import_contexts: import_contexts,
                    compiler_imports,
                });
                // Import/package filtering is monotone: the syntax header can
                // only reject more rules, never restore one. Do not hash,
                // decompress, decode, and integrity-check a compiler syntax
                // payload when no rule survived the cheaper exact header.
                if rules.is_empty() {
                    return Some((file, rules, None));
                }
                let Some(mut syntax) = ws.db().compiler_syntax_header_uncached(file) else {
                    return Some((file, rules, None));
                };
                if let Some(ancestry) = inventory_receiver_ancestry.as_ref() {
                    ancestry.apply_to_syntax_header(&mut syntax);
                }
                if inventory_receiver_ancestry.is_none() {
                    enrich_compiler_syntax_header_receiver_types(&mut syntax, receiver_base_map);
                }
                let (filtered_rules, deferred) = file_rules.filtered_rule_refs_for_syntax_header(
                    rules.clone(),
                    &syntax,
                    compiler_imports,
                    &constructor_names,
                    language.as_str(),
                    receiver_ancestry_complete,
                );
                let deferred_plan = deferred.then(|| {
                    (
                        rules,
                        syntax,
                        compiler_imports.cloned(),
                        language.as_str().to_string(),
                    )
                });
                Some((file, filtered_rules, deferred_plan))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    };
    let ancestry_already_complete =
        !needs_receiver_ancestry || global_file_indexes.is_some() || inventory_receiver_ancestry.is_some();
    let initial_plan = build_scan_plan(
        &raw_scan_files,
        &receiver_base_map,
        inventory_receiver_ancestry.as_ref(),
        ancestry_already_complete,
    );
    let mut deferred_plans = Vec::new();
    let mut scan_plan = Vec::new();
    for (file, rules, deferred) in initial_plan {
        if let Some(deferred) = deferred {
            deferred_plans.push((file, deferred));
        } else if !rules.is_empty() {
            scan_plan.push((file, rules));
        }
    }
    if !deferred_plans.is_empty() {
        let ancestry_started = debug_security_phase.then(Instant::now);
        if matches!(mode, ConstraintMode::Inventory) {
            inventory_receiver_ancestry = Some(ws.compiler_receiver_ancestry());
        } else if global_file_indexes.is_none() {
            global_file_indexes = Some(matcher_global_headers(ws, retention));
            receiver_base_map = global_file_indexes
                .as_ref()
                .map_or_else(AHashMap::new, |headers| {
                    workspace_receiver_base_map_if_needed(&prepared, mode, headers.as_ref())
                });
        }
        let deferred_file_count = deferred_plans.len();
        use rayon::prelude::*;
        let completed_deferred = deferred_plans
            .into_par_iter()
            .filter_map(|(file, (rules, mut syntax, compiler_imports, language))| {
                if let Some(ancestry) = inventory_receiver_ancestry.as_ref() {
                    ancestry.apply_to_syntax_header(&mut syntax);
                } else {
                    enrich_compiler_syntax_header_receiver_types(&mut syntax, &receiver_base_map);
                }
                let file_rules = prepared_by_language.get(&language)?;
                let (rules, _) = file_rules.filtered_rule_refs_for_syntax_header(
                    rules,
                    &syntax,
                    compiler_imports.as_ref(),
                    &constructor_names,
                    &language,
                    true,
                );
                (!rules.is_empty()).then_some((file, rules))
            })
            .collect::<Vec<_>>();
        scan_plan.extend(completed_deferred);
        scan_plan.sort_unstable_by_key(|(file, _)| file.raw());
        if let Some(started) = ancestry_started {
            bonsai_diagnostics::debug_log!(
                "security-phase",
                "matcher deferred receiver ancestry: {:.3}s files={} declarations={} receiver_types={}",
                started.elapsed().as_secs_f64(),
                deferred_file_count,
                global_file_indexes.as_ref().map_or(0, |headers| headers.len()),
                inventory_receiver_ancestry
                    .as_ref()
                    .map_or(0, |ancestry| ancestry.len())
            );
        }
    }
    if let Some(started) = package_filter_started {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher header/package filter: {:.3}s raw_candidates={} body_candidates={}",
            started.elapsed().as_secs_f64(),
            raw_scan_files.len(),
            scan_plan.len()
        );
    }
    let compiler_session_started = debug_security_phase.then(Instant::now);
    let body_files = scan_plan.iter().map(|(file, _)| *file).collect::<Vec<_>>();
    prepare_compiler_object_session_for_body_scan(ws, &body_files, &prepared_by_language, retention);
    if let Some(started) = compiler_session_started {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher body compiler-object session: {:.3}s files={}",
            started.elapsed().as_secs_f64(),
            body_files.len()
        );
    }
    let target_prefilter_skipped = total.saturating_sub(scan_plan.len());
    for _ in 0..target_prefilter_skipped {
        on_file_done();
    }
    // Each `scan_file_rules` writes only to its own per-file Vec. Size one
    // continuous work-stealing pool against the largest actual compiler units
    // that could overlap. This retains the weighted memory proof without
    // serial batch barriers that strand workers behind one large file. Match
    // collection order is non-deterministic across runs, but downstream
    // callers sort before emission to keep finding ids stable.
    let workers = matcher_worker_count();
    let source_bytes = scan_plan
        .iter()
        .map(|(file, _)| {
            ws.db()
                .vfs()
                .snapshot(*file)
                .map_or(0, |snapshot| snapshot.text.len() as u64)
        })
        .collect::<Vec<_>>();
    let parallel_width = bonsai_common::syntax_worker_count_for_sources(&source_bytes, workers);
    if debug_security_phase {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher schedule: files={} candidates={} max_parallel={}",
            files.len(),
            scan_plan.len(),
            parallel_width
        );
    }
    let scan_planned_file = |file: FileId, rule_refs: &[&PreparedRule<'_>]| {
        let _syntax_release = TransientSyntaxRelease::new(ws, file, retention);
        let mut file_out: Vec<RuleMatch> = Vec::new();
        let Some(adapter) = ws.db().adapter_for(file) else {
            return (file_out, false);
        };
        let language = adapter.language_id();
        let file_rules = PreparedRuleBatch::new(rule_refs, factory.clone());
        let Some(compiler_object) = ws.db().compiler_file_object_uncached(file) else {
            return (file_out, false);
        };
        let file_imports = compiler_object.imports;
        let Some(file_index) = compiler_object.declarations else {
            return (file_out, true);
        };
        let mut file_index = match global_file_indexes.as_ref() {
            Some(headers) => ws.db().remap_decl_index_to_headers(headers.as_ref(), file_index),
            None => file_index,
        };
        if let Some(ancestry) = inventory_receiver_ancestry.as_ref() {
            ancestry.apply_to_decl_index(&mut file_index);
        }
        let ctx = FileScanContext {
            ws,
            file,
            file_index: &file_index,
            file_imports: file_imports.as_ref(),
            import_package_contexts: prewarmed_import_contexts.get(language.as_str()),
            constructor_names: &constructor_names,
            mode,
            taint_view,
            retention,
            receiver_base_map: &receiver_base_map,
        };
        scan_file_rules(&ctx, &file_rules, &mut file_out);
        if dedup_file_matches {
            dedup_inventory_matches_in_place(&mut file_out);
        }
        (file_out, true)
    };
    if parallel_width <= 1 || scan_plan.len() <= 1 {
        return scan_plan
            .iter()
            .flat_map(|(file, rule_refs)| {
                let (file_out, _) = scan_planned_file(*file, rule_refs);
                on_file_done();
                file_out
            })
            .collect();
    }
    let run_parallel_scan = |pool: Option<&rayon::ThreadPool>| {
        let scan_total = scan_plan.len();
        let (tick_tx, tick_rx) = mpsc::channel();
        let parsed_files = Arc::new(AtomicUsize::new(0));
        let text_skipped_files = Arc::new(AtomicUsize::new(target_prefilter_skipped));
        let parsed_files_worker = parsed_files.clone();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                let scan = || {
                    use rayon::prelude::*;
                    scan_plan
                        .par_iter()
                        .flat_map_iter(|(file, rule_refs)| {
                            let (file_out, parsed) = scan_planned_file(*file, rule_refs);
                            if parsed {
                                parsed_files_worker.fetch_add(1, Ordering::Relaxed);
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
            while completed < scan_total {
                match tick_rx.recv() {
                    Ok(()) => {
                        completed += 1;
                        if debug_security_phase && completed % 5_000 == 0 {
                            bonsai_diagnostics::debug_log!(
                                "security-phase",
                                "matcher candidate scan progress: {completed}/{}",
                                scan_total
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
                        if let Some(started) = matcher_started {
                            bonsai_diagnostics::debug_log!(
                                "security-phase",
                                "matcher total: {:.3}s",
                                started.elapsed().as_secs_f64()
                            );
                        }
                    }
                    out
                }
                Err(panic) => std::panic::resume_unwind(panic),
            }
        })
    };
    match rayon::ThreadPoolBuilder::new()
        .num_threads(parallel_width)
        .stack_size(matcher_worker_stack_bytes())
        .build()
    {
        Ok(pool) => run_parallel_scan(Some(&pool)),
        Err(_) => run_parallel_scan(None),
    }
}

fn matcher_worker_count() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    // Source-size-weighted batches apply the live memory budget after rule
    // preparation, when the matcher knows the actual compiler-unit sizes and
    // resident linkage footprint.
    std::env::var("BONSAI_SECURITY_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .or_else(|| {
            std::env::var("RAYON_NUM_THREADS")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        })
        .map(|requested| requested.max(1))
        .unwrap_or(available)
        .min(available)
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
    Inventory,
    TaintEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FactRetention {
    Cached,
    Transient,
}

/// File-scan guard that gives broad security passes compiler-phase syntax
/// ownership. Lowered match facts survive the scan; the concrete Tree-sitter
/// tree is evicted on every exit path and will be rebuilt exactly if a later
/// query needs it.
struct TransientSyntaxRelease<'a> {
    ws: &'a Workspace,
    file: FileId,
    enabled: bool,
}

impl<'a> TransientSyntaxRelease<'a> {
    fn new(ws: &'a Workspace, file: FileId, retention: FactRetention) -> Self {
        Self {
            ws,
            file,
            enabled: retention == FactRetention::Transient,
        }
    }
}

impl Drop for TransientSyntaxRelease<'_> {
    fn drop(&mut self) {
        if self.enabled {
            self.ws.db().release_syntax(self.file);
        }
    }
}

fn matcher_global_headers(ws: &Workspace, retention: FactRetention) -> Arc<bonsai_index::GlobalIndex> {
    if retention == FactRetention::Cached {
        return ws.db().global_index();
    }
    streaming_global_headers(ws)
}

/// Return the compact workspace declaration/type symbol table.
///
/// Rule matching needs stable symbols, receiver ancestry, and cross-file
/// declarations, but not call/return linkage. Loading the independent header
/// payload keeps a broad inventory from deserializing the much larger IDG
/// stitch table before it streams exact compiler-object bodies.
fn streaming_global_headers(ws: &Workspace) -> Arc<bonsai_index::GlobalIndex> {
    ws.compiler_header_index()
}

struct FileScanContext<'a, 'taint> {
    ws: &'a Workspace,
    file: FileId,
    file_index: &'a DeclIndex,
    file_imports: Option<&'a bonsai_lang_api::ImportIndex>,
    import_package_contexts: Option<&'a Arc<LanguageImportPackageContexts>>,
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
    /// Borrow an analysis run's already-materialized compiler symbol table.
    /// Source groups execute on Rayon; recursively building this table while
    /// a worker owns its cache write lock can otherwise deadlock through
    /// work-stealing. The immutable compiler headers are the authoritative
    /// identity projection for both the planner and endpoint rechecks.
    global_headers: Option<&'a Arc<GlobalIndex>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)] // deliberate `*Call` suffix — describes call-site origin
enum CallFactOrigin {
    RealCall,
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
    rules: &[PreparedRule<'_>],
    mode: ConstraintMode,
    global: &bonsai_index::GlobalIndex,
) -> AHashMap<String, Vec<String>> {
    if matches!(mode, ConstraintMode::Inventory) {
        return AHashMap::new();
    }
    if !rules.iter().any(prepared_rule_needs_receiver_base_map) {
        return AHashMap::new();
    }
    workspace_receiver_base_map(global)
}

fn workspace_receiver_base_map(global: &bonsai_index::GlobalIndex) -> AHashMap<String, Vec<String>> {
    let mut out: AHashMap<String, Vec<String>> = AHashMap::new();
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

/// Return whether adding compiler-proven base types could change the verdict
/// for this concrete call/rule pair.
///
/// Receiver ancestry cannot repair a missing method name, a regex target, or
/// an untyped receiver. Deferring the workspace declaration table until this
/// predicate succeeds keeps the header pass exact while avoiding a complete
/// project lowering for files whose syntax already proves every rule absent.
fn receiver_ancestry_can_change_call_match(
    rule: &PreparedRule<'_>,
    call: &bonsai_lang_api::CompilerCallHeader,
    direct_match: bool,
) -> bool {
    if call.receiver_types.is_empty() {
        return false;
    }
    let has_receiver_type_constraint = rule.rule.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            ConstraintKind::ReceiverTypeIn { .. } | ConstraintKind::ReceiverTypeNotIn { .. }
        )
    });
    if direct_match && has_receiver_type_constraint {
        return true;
    }
    if direct_match || rule.regex.is_some() {
        return false;
    }
    let Some(attribute) = rule.attribute.filter(|attribute| attribute.len() >= 2) else {
        return false;
    };
    let Some(method) = attribute.last() else {
        return false;
    };
    callee_tail_matches(&normalize_callee_for_matching(&call.name), method)
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
        matches!(self, Self::Inventory | Self::TaintEndpoint)
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
        self.text_possible_in_mode(
            text,
            file_packages,
            ConstraintMode::Strict,
            CallTextPrefilter::Disabled,
        )
    }

    fn text_possible_in_mode(
        &self,
        text: &str,
        file_packages: Option<&AHashSet<String>>,
        mode: ConstraintMode,
        call_text_prefilter: CallTextPrefilter,
    ) -> bool {
        if !self.syntax_target_possible_in_mode(text, mode, call_text_prefilter) {
            return false;
        }
        self.package_text_anchors.is_empty()
            || self
                .package_text_anchors
                .iter()
                .any(|anchor| text.contains(anchor))
            || file_packages.is_some_and(|packages| self.package_evidence_allows_text_anchor_skip(packages))
    }

    /// Cheap, import-independent proof that this file can still contain the
    /// rule's syntax target.
    ///
    /// Package evidence may allow a package text anchor to be absent, so that
    /// gate remains in [`Self::text_possible_in_mode`] after imports are
    /// available. Target/call anchors cannot be created by imports; checking
    /// them against the VFS snapshot before decoding a compiler object is
    /// therefore lossless.
    fn syntax_target_possible_in_mode(
        &self,
        text: &str,
        mode: ConstraintMode,
        call_text_prefilter: CallTextPrefilter,
    ) -> bool {
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
        if matches!(mode, ConstraintMode::Inventory) && call_text_prefilter != CallTextPrefilter::Disabled {
            if let Some(anchor) = self.call_text_anchor.as_deref() {
                if !call_text_anchor_possible_in(text, anchor, call_text_prefilter) {
                    return false;
                }
            }
        }
        true
    }

    fn package_evidence_allows_text_anchor_skip(&self, file_packages: &AHashSet<String>) -> bool {
        self.package_signals.iter().any(|signal| {
            file_packages.contains(*signal)
                || file_packages.contains(&workspace_import_package_marker(signal))
                || (self.component_level_package_evidence_allowed()
                    && file_packages.contains(&component_import_package_marker(signal)))
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
                .trim_matches(bonsai_common::is_name_punctuation)
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
            if let Some(head) = call_head(&stripped) {
                if let Some(target) = alias_map.get(head) {
                    push_target(&mut candidates, target);
                }
            }
            if let Some(target) = alias_map.get(receiver_path_tail(receiver_type)) {
                push_target(&mut candidates, target);
            }
        }
        if let Some(target) = alias_map.get(callee) {
            push_target(&mut candidates, target);
        }
        if let Some(head) = call_head(callee) {
            if let Some(target) = alias_map.get(head) {
                push_target(&mut candidates, target);
            }
        }
        let file_level_package_evidence_allowed = self.file_level_package_evidence_allowed();
        let component_level_package_evidence_allowed = self.component_level_package_evidence_allowed();
        let workspace_level_package_evidence_allowed = self.workspace_level_package_evidence_allowed();
        let allowed = self.package_signals.iter().any(|signal| {
            (file_level_package_evidence_allowed
                && package_set_contains_import(
                    file_packages,
                    signal,
                    None,
                    &self.rule.package_matching,
                ))
                || (component_level_package_evidence_allowed
                    && package_set_contains_import(
                        file_packages,
                        signal,
                        Some(COMPONENT_IMPORT_PACKAGE_PREFIX),
                        &self.rule.package_matching,
                    ))
                || (workspace_level_package_evidence_allowed
                    && package_set_contains_import(
                        file_packages,
                        signal,
                        Some(WORKSPACE_IMPORT_PACKAGE_PREFIX),
                        &self.rule.package_matching,
                    ))
                || candidates
                    .iter()
                    .any(|candidate| local_import_package_allows(file_packages, candidate, signal))
                || candidates
                    .iter()
                    .any(|candidate| {
                        crate::pkg::import_matches_package(
                            candidate,
                            signal,
                            &self.rule.package_matching,
                        )
                    })
                // Some adapter-declared package paths bind their final
                // component as the local call qualifier. The exact binding
                // and separators come from rulepack language metadata.
                || candidates
                    .iter()
                    .any(|candidate| {
                        crate::pkg::call_candidate_matches_package_tail(
                            candidate,
                            signal,
                            &self.rule.package_matching,
                        )
                    })
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
            // Typing rules never participate in the finding/gate path —
            // they feed factory-return resolution via build_factory_returns.
            crate::rule::RuleKind::Typing => false,
            crate::rule::RuleKind::Sink => {
                if allows_file_package_evidence(self.rule) {
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
                // rule also carries a receiver-identity constraint, that
                // constraint (enforced separately against the same call)
                // supplies the missing precision. A `receiver_type_in`
                // constraint binds the receiver to a compiler-emitted type;
                // `receiver_tainted` binds it to the proven source dataflow.
                // File/workspace package presence is sound supporting
                // evidence in either case, and cannot enable an arbitrary
                // same-named call by itself.
                let has_receiver_type_constraint = self
                    .rule
                    .constraints
                    .iter()
                    .any(|constraint| matches!(constraint, ConstraintKind::ReceiverTypeIn { .. }));
                let has_receiver_taint_constraint = self.rule.constraints.iter().any(|constraint| {
                    matches!(
                        constraint,
                        ConstraintKind::ReceiverTainted {
                            receiver_tainted: true
                        }
                    )
                });
                !receiver_agnostic_call_regex || has_receiver_type_constraint || has_receiver_taint_constraint
            }
        }
    }

    fn workspace_level_package_evidence_allowed(&self) -> bool {
        // Generic source shapes such as `request.headers` must stay tied to
        // the current file's imports/aliases. A sibling file importing the
        // package proves only that the dependency exists somewhere in the
        // workspace; it does not prove that this value is framework input.
        // Sink rules may use workspace evidence when their target shape and
        // constraints make file-level package evidence safe.
        matches!(self.rule.kind, crate::rule::RuleKind::Sink) && self.file_level_package_evidence_allowed()
    }

    fn component_level_package_evidence_allowed(&self) -> bool {
        if self.rule.kind != crate::rule::RuleKind::Source || self.rule.frameworks.is_empty() {
            return false;
        }
        let target = match self.rule.match_spec.kind {
            MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
                self.rule.match_spec.target.as_ref()
            }
            MatchKind::Call | MatchKind::New | MatchKind::Missing => None,
        };
        // A connected importer proves which framework owns a split-out route
        // module, but only admit that evidence for an exact structured
        // attribute read. Regex/name-only source shapes remain file-local:
        // component package presence is not precise enough for them.
        target.is_some_and(|target| {
            target.regex.is_none()
                && target.name.is_none()
                && target
                    .attribute
                    .as_ref()
                    .is_some_and(|attribute| attribute.len() >= 2)
        })
    }

    fn needs_workspace_package_context(&self) -> bool {
        self.requires_call_package_signal
            && (self.component_level_package_evidence_allowed()
                || self.workspace_level_package_evidence_allowed())
    }
}

fn text_anchor_groups_for_rule(rule: &Rule, target: &RuleTarget) -> Vec<Vec<String>> {
    let mut groups = Vec::new();
    groups.extend(text_anchor_groups_for_target(target, rule.match_spec.kind));
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
    let mut modifier_group = Vec::new();
    for constraint in &rule.constraints.0 {
        if let ConstraintKind::EnclosingModifierIn {
            enclosing_modifier_in,
        } = constraint
        {
            for modifier in enclosing_modifier_in {
                push_text_anchor(&mut modifier_group, modifier);
            }
        }
    }
    if !modifier_group.is_empty() {
        groups.push(modifier_group);
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

fn call_text_anchor_possible_in(text: &str, anchor: &str, syntax: CallTextPrefilter) -> bool {
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
            if syntax == CallTextPrefilter::ParenthesizedOrCommand
                && call_anchor_followed_by_command_style_call(text, end)
            {
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
        for token in regex_required_hir_anchor_tokens(regex) {
            push_text_anchor(&mut out, &token);
        }
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

/// Return a conservative OR-group of literal tokens required by every regex
/// match.
///
/// This walks `regex-syntax` HIR instead of interpreting pattern text. A
/// concatenation may choose any one mandatory child; an alternation is usable
/// only when every branch has a required literal, in which case the branch
/// literals form one OR-group. Optional repetitions, classes, and look-around
/// contribute no evidence. Empty output means "cannot prove a prefilter," so
/// exact matcher evaluation remains the fallback.
fn regex_required_hir_anchor_tokens(pattern: &str) -> Vec<String> {
    let Ok(hir) = regex_syntax::Parser::new().parse(pattern) else {
        return Vec::new();
    };
    required_hir_anchor_group(&hir)
}

fn required_hir_anchor_group(hir: &regex_syntax::hir::Hir) -> Vec<String> {
    use regex_syntax::hir::HirKind;

    match hir.kind() {
        HirKind::Literal(literal) => strongest_literal_token(&literal.0).into_iter().collect(),
        HirKind::Capture(capture) => required_hir_anchor_group(&capture.sub),
        HirKind::Repetition(repetition) if repetition.min > 0 => required_hir_anchor_group(&repetition.sub),
        HirKind::Concat(parts) => parts.iter().fold(Vec::new(), |strongest, part| {
            stronger_anchor_group(strongest, required_hir_anchor_group(part))
        }),
        HirKind::Alternation(branches) => {
            let mut alternatives = Vec::new();
            for branch in branches {
                let required = required_hir_anchor_group(branch);
                if required.is_empty() {
                    return Vec::new();
                }
                for token in required {
                    if !alternatives.contains(&token) {
                        alternatives.push(token);
                    }
                }
            }
            alternatives.sort();
            alternatives
        }
        HirKind::Empty | HirKind::Class(_) | HirKind::Look(_) | HirKind::Repetition(_) => Vec::new(),
    }
}

fn strongest_literal_token(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.split(|ch: char| !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()))
        .filter(|token| token.len() >= 3)
        .max_by_key(|token| token.len())
        .map(str::to_string)
}

fn stronger_anchor_group(current: Vec<String>, candidate: Vec<String>) -> Vec<String> {
    if current.is_empty() {
        return candidate;
    }
    if candidate.is_empty() {
        return current;
    }
    let current_min = current.iter().map(String::len).min().unwrap_or_default();
    let candidate_min = candidate.iter().map(String::len).min().unwrap_or_default();
    if candidate_min > current_min || (candidate_min == current_min && candidate.len() < current.len()) {
        candidate
    } else {
        current
    }
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
    bonsai_common::short_qualified_tail(value)
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

fn allows_file_package_evidence(rule: &Rule) -> bool {
    rule.kind == crate::rule::RuleKind::Sink
        && rule
            .analysis_semantics
            .as_ref()
            .and_then(|semantics| semantics.allow_file_package_evidence)
            .unwrap_or(false)
}

fn skips_call_package_gate(rule: &Rule) -> bool {
    rule.kind == crate::rule::RuleKind::Sink
        && rule
            .analysis_semantics
            .as_ref()
            .and_then(|semantics| semantics.skip_call_package_gate)
            .unwrap_or(false)
}

fn call_head(callee: &str) -> Option<&str> {
    let trimmed = callee.trim();
    if trimmed.is_empty() {
        return None;
    }
    let segments = bonsai_common::qualified_name_segments(trimmed);
    (segments.len() > 1).then(|| segments[0])
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
    let value = value
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    value
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(value)
        .trim()
}

fn annotation_tail(value: &str) -> &str {
    bonsai_common::short_qualified_tail(value)
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

fn component_import_package_marker(package: &str) -> String {
    format!("{COMPONENT_IMPORT_PACKAGE_PREFIX}:{package}")
}

fn package_set_contains_import(
    file_packages: &AHashSet<String>,
    signal: &str,
    scope_prefix: Option<&str>,
    semantics: &crate::loader::PackageMatchSemantics,
) -> bool {
    file_packages.iter().any(|candidate| {
        let candidate = if let Some(prefix) = scope_prefix {
            let Some(candidate) = candidate
                .strip_prefix(prefix)
                .and_then(|candidate| candidate.strip_prefix(':'))
            else {
                return false;
            };
            candidate
        } else {
            if candidate.starts_with(LOCAL_IMPORT_PACKAGE_PREFIX)
                || candidate.starts_with(WORKSPACE_IMPORT_PACKAGE_PREFIX)
                || candidate.starts_with(COMPONENT_IMPORT_PACKAGE_PREFIX)
            {
                return false;
            }
            candidate.as_str()
        };
        crate::pkg::import_matches_package(candidate, signal, semantics)
    })
}

fn local_import_package_allows(file_packages: &AHashSet<String>, candidate: &str, signal: &str) -> bool {
    file_packages.contains(&local_import_package_marker(candidate, signal))
        || call_head(candidate)
            .is_some_and(|head| file_packages.contains(&local_import_package_marker(head, signal)))
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
    workspace_package_signals: Vec<String>,
}

struct FileRuleFilterContext<'a> {
    ws: &'a Workspace,
    file: FileId,
    text: &'a str,
    mode: ConstraintMode,
    retention: FactRetention,
    prewarmed_import_contexts: Option<&'a Arc<LanguageImportPackageContexts>>,
    compiler_imports: Option<&'a bonsai_lang_api::ImportIndex>,
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
            workspace_package_signals: {
                let mut signals = rules
                    .iter()
                    .filter(|rule| rule.needs_workspace_package_context())
                    .flat_map(|rule| rule.package_signals.iter().copied())
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                signals.sort();
                signals.dedup();
                signals
            },
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

    fn filtered_rule_refs_for_text(
        &self,
        context: FileRuleFilterContext<'_>,
    ) -> Vec<&'p PreparedRule<'rule>> {
        let FileRuleFilterContext {
            ws,
            file,
            text,
            mode,
            retention,
            prewarmed_import_contexts,
            compiler_imports,
        } = context;
        let include_workspace_package_context = self.include_workspace_package_context
            && (!matches!(mode, ConstraintMode::Inventory)
                || workspace_manifest_package_context_allowed(ws, file));
        let file_packages = self.has_package_text_anchors.then(|| {
            file_package_set_with_prewarmed_workspace_context_and_retention(
                ws,
                file,
                include_workspace_package_context,
                retention,
                prewarmed_import_contexts,
                compiler_imports,
            )
        });
        let call_text_prefilter = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().call_text_prefilter)
            .unwrap_or_default();
        let mut rules = Vec::new();
        for &rule in self
            .call_rules
            .iter()
            .chain(self.read_rules.iter())
            .chain(self.write_rules.iter())
            .chain(self.param_rules.iter())
            .chain(self.return_rules.iter())
        {
            if rule.text_possible_in_mode(text, file_packages.as_deref(), mode, call_text_prefilter) {
                rules.push(rule);
            }
        }
        // `kind: missing` rules look for an absent target, so the
        // target's own text anchor is expected not to exist. Keep them
        // in the exact syntax pass; package/context constraints still
        // run inside the matcher. There are very few such rules, and
        // none in the default Java taint path.
        rules.extend(self.missing_rules.iter().copied());
        rules
    }

    /// Narrow call/new rules with exact adapter-emitted call targets before
    /// decoding declaration and flow bodies. Non-call rules remain untouched.
    ///
    /// The projection deliberately over-approximates declaration scope by
    /// combining file-local aliases. That can retain extra bodies, but it
    /// cannot suppress a match that the full matcher would emit.
    fn filtered_rule_refs_for_syntax_header(
        &self,
        rules: Vec<&'p PreparedRule<'rule>>,
        syntax: &CompilerSyntaxHeader,
        compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
        constructor_names: &AHashSet<String>,
        language: &str,
        receiver_ancestry_complete: bool,
    ) -> (Vec<&'p PreparedRule<'rule>>, bool) {
        if rules
            .iter()
            .all(|rule| !matches!(rule.rule.match_spec.kind, MatchKind::Call | MatchKind::New))
        {
            return (rules, false);
        }
        let mut alias_map = compiler_imports
            .map(bonsai_lang_api::alias_map_from_imports)
            .unwrap_or_default();
        extend_alias_map_with_declared_types(&mut alias_map, &syntax.type_aliases);
        extend_alias_map_with_compiler_assignment_aliases(&mut alias_map, &syntax.assignment_aliases);
        if let Some(specs) = self.factory.specs_for(language) {
            let mut factory_aliases = Vec::new();
            for assignment in &syntax.factory_assignments {
                let expanded = expand_callee_alias(&assignment.call_name, &alias_map);
                for spec in specs {
                    if !factory_spec_matches_call(
                        &assignment.call_name,
                        assignment.call_receiver.as_deref(),
                        spec,
                    ) && !expanded
                        .as_deref()
                        .is_some_and(|expanded| factory_spec_matches_call(expanded, None, spec))
                    {
                        continue;
                    }
                    let binding = TypeAliasBinding {
                        name: assignment.target.clone(),
                        type_name: spec.type_name.clone(),
                    };
                    if !factory_aliases.contains(&binding) {
                        factory_aliases.push(binding);
                    }
                }
            }
            extend_alias_map_with_declared_types(&mut alias_map, &factory_aliases);
        }
        let mut retained = Vec::new();
        let mut receiver_ancestry_deferred = false;
        for prepared in rules {
            if !matches!(prepared.rule.match_spec.kind, MatchKind::Call | MatchKind::New) {
                retained.push(prepared);
                continue;
            }
            let mut rule_matches = false;
            for call in &syntax.calls {
                let matched_callee = callee_or_alias_matches(
                    &call.name,
                    &call.receiver_types,
                    prepared.name,
                    prepared.attribute,
                    prepared.regex.as_ref(),
                    &alias_map,
                );
                let direct_match = matched_callee.as_ref().is_some_and(|matched_callee| {
                    prepared.base_name_allows(matched_callee)
                        && (prepared.rule.match_spec.kind != MatchKind::New
                            || call.call_kind == CallKind::Constructor
                            || constructor_name_matches(&call.name, constructor_names))
                });
                if !receiver_ancestry_complete
                    && receiver_ancestry_can_change_call_match(prepared, call, direct_match)
                {
                    receiver_ancestry_deferred = true;
                }
                rule_matches |= direct_match;
            }
            if rule_matches {
                retained.push(prepared);
            }
        }
        (retained, receiver_ancestry_deferred)
    }

    /// Return whether any rule in this language batch can match the raw file
    /// text before imports or full adapter IR are decoded.
    fn syntax_target_possible_in_text(
        &self,
        text: &str,
        mode: ConstraintMode,
        call_text_prefilter: CallTextPrefilter,
    ) -> bool {
        !self.missing_rules.is_empty()
            || self
                .call_rules
                .iter()
                .chain(self.read_rules.iter())
                .chain(self.write_rules.iter())
                .chain(self.param_rules.iter())
                .chain(self.return_rules.iter())
                .any(|rule| rule.syntax_target_possible_in_mode(text, mode, call_text_prefilter))
    }
}

/// Extend compiler import/type aliases through adapter-proven assignment
/// aliases to an unbounded fixed point. Header planning uses a file-wide
/// over-approximation; the full body matcher retains declaration scope.
fn extend_alias_map_with_compiler_assignment_aliases(
    alias_map: &mut std::collections::HashMap<String, AliasTarget>,
    assignments: &[CompilerAssignmentAlias],
) {
    if alias_map.is_empty() || assignments.is_empty() {
        return;
    }
    let mut dependents: AHashMap<&str, Vec<&str>> = AHashMap::new();
    for assignment in assignments {
        dependents
            .entry(assignment.source.as_str())
            .or_default()
            .push(assignment.target.as_str());
    }
    let mut pending = std::collections::VecDeque::new();
    let mut queued = AHashSet::new();
    for source in alias_map.keys() {
        if queued.insert(source.clone()) {
            pending.push_back(source.clone());
        }
    }
    while let Some(source) = pending.pop_front() {
        let Some(resolved) = alias_map.get(&source).cloned() else {
            continue;
        };
        let Some(targets) = dependents.get(source.as_str()) else {
            continue;
        };
        for target in targets {
            if alias_map.contains_key(*target) {
                continue;
            }
            alias_map.insert((*target).to_string(), resolved.clone());
            if queued.insert((*target).to_string()) {
                pending.push_back((*target).to_string());
            }
        }
    }
}

/// Mirror full-body receiver typing on a compact compiler header.
///
/// Both the receiver identity and declared types are adapter facts. The
/// file-wide lookup is conservative across declaration scopes, so it may keep
/// an extra body but cannot reject an exact match.
fn enrich_compiler_syntax_header_receiver_types(
    syntax: &mut CompilerSyntaxHeader,
    receiver_base_map: &AHashMap<String, Vec<String>>,
) {
    for call in &mut syntax.calls {
        let receiver = call
            .receiver
            .as_deref()
            .or_else(|| call_receiver_text(&call.name));
        let receiver_root = receiver.and_then(receiver_root_name);
        let mut direct_types = call.receiver_types.clone();
        for alias in &syntax.type_aliases {
            if receiver.is_some_and(|receiver| alias.name == receiver)
                || receiver_root.as_deref() == Some(alias.name.as_str())
            {
                push_unique_string(&mut direct_types, alias.type_name.clone());
            }
        }
        call.receiver_types = expanded_receiver_types(&direct_types, receiver_base_map);
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

/// Materialize one scoped compiler-object generation for files that survived
/// raw, import/package, and exact syntax-target planning.
///
/// Cold header planning deliberately streams and releases compiler IR: most
/// raw candidates never reach a sink body. The scoped session is therefore
/// created only for body survivors, is content-addressed and disk-backed, and
/// is never published under the analyzed workspace. Failure is an
/// optimization miss only; the body scan falls back to canonical Tree-sitter
/// lowering with identical coverage.
fn prepare_compiler_object_session_for_body_scan<'p, 'rule>(
    ws: &Workspace,
    files: &[FileId],
    prepared_by_language: &AHashMap<String, PreparedRuleBatch<'p, 'rule>>,
    retention: FactRetention,
) {
    if retention != FactRetention::Transient || files.len() <= 1 {
        return;
    }
    let compiler_files = files
        .iter()
        .copied()
        .filter(|file| {
            ws.db()
                .adapter_for(*file)
                .is_some_and(|adapter| prepared_by_language.contains_key(adapter.language_id().as_str()))
        })
        .collect::<Vec<_>>();
    if let Err(error) = ws.db().ensure_compiler_object_session(&compiler_files) {
        bonsai_diagnostics::debug_log!(
            "compiler-object",
            "scoped compiler-object session unavailable; exact streaming fallback remains active: {error}"
        );
    }
}

/// Complete language-wide import projections on the coordinating thread
/// before file matching enters its Rayon pool.
///
/// [`language_import_package_contexts`] is a single-flight cache. Letting a
/// matcher worker own that initializer would make its compiler-object batches
/// compete with other matcher workers that are blocked on the same flight.
/// Prewarming here preserves exact whole-language evidence while ensuring the
/// file-level workers only perform completed-cache reads.
fn prewarm_language_import_package_contexts<'p, 'rule>(
    ws: &Workspace,
    files: &[FileId],
    prepared_by_language: &AHashMap<String, PreparedRuleBatch<'p, 'rule>>,
    retention: FactRetention,
) -> AHashMap<String, Arc<LanguageImportPackageContexts>> {
    let mut scheduled_languages = AHashSet::new();
    let mut contexts = AHashMap::new();
    for &file in files {
        let Some(adapter) = ws.db().adapter_for(file) else {
            continue;
        };
        let language = adapter.language_id();
        let language_name = language.as_str();
        let Some(batch) = prepared_by_language.get(language_name) else {
            continue;
        };
        if !batch.include_workspace_package_context || !scheduled_languages.insert(language_name.to_string())
        {
            continue;
        }
        contexts.insert(
            language_name.to_string(),
            project_language_import_package_contexts(
                language_import_package_contexts(ws, file, retention).as_ref(),
                Some(batch.workspace_package_signals.as_slice()),
            ),
        );
    }
    contexts
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
        let declared = attribute.join(".");
        let mut canonical_keys = Vec::new();
        collect_call_candidate_keys(&declared, &mut canonical_keys);
        for key in canonical_keys {
            insert_call_rule_key(keyed_rules, &key, rule);
            inserted = true;
        }
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
        .trim_start_matches(bonsai_common::is_name_punctuation);
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
            ctx,
            &rules.read_rules,
            rules.include_workspace_package_context,
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
            ctx,
            &rules.param_rules,
            rules.include_workspace_package_context,
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
    let assignment_values = AssignmentValueIndex::new(&file_index.assignment_values);
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
                let span = canonical_flow_read_match_span(ws, file, span, &match_text, &assignment_values);
                let (file_path, line, col) = resolve_span(ws, file, span);
                out.push(RuleMatch {
                    origin: MatchOrigin::Rulepack,
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
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    include_workspace_package_context: bool,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let retention = ctx.retention;
    let file_packages = file_package_set_with_prewarmed_workspace_context_and_retention(
        ctx.ws,
        ctx.file,
        include_workspace_package_context,
        ctx.retention,
        ctx.import_package_contexts,
        ctx.file_imports,
    );
    let alias_map = file_alias_map_with_compiler_imports(ws, file, retention, ctx.file_imports);
    for decl in &file_index.defs {
        let decl_decorators = decl_decorator_names(ws, file, file_index, decl.span, decl.name_span);
        let decl_modifiers = if rules.iter().any(|prepared| {
            prepared
                .rule
                .constraints
                .iter()
                .any(|constraint| matches!(constraint, ConstraintKind::EnclosingModifierIn { .. }))
        }) {
            decl_modifier_names(ws, file, decl)
        } else {
            Vec::new()
        };
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
                } else if target.is_some_and(param_target_is_context_only) {
                    true
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
                // A `kind: param` rule binds the declaration, not one
                // arbitrary later read. `Decl.name_span` is the adapter's
                // grammar-derived declaration anchor and remains before the
                // body for ordering/clean-overwrite analysis. The binding
                // itself is carried in `match_text` and `Decl.params`.
                let span = decl.name_span;
                let (file_path, line, col) = resolve_span(ws, file, span);
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
                    enclosing_modifiers: Some(decl_modifiers.as_slice()),
                    alias_chains: None,
                    runtime_types: None,
                    lifecycle_transitions: None,
                    structural_context: None,
                }) {
                    continue;
                }
                out.push(RuleMatch {
                    origin: MatchOrigin::Rulepack,
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
        && (param_index.is_none() || target.param_type_in.is_empty())
        && target.param_count_in.is_empty()
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
        if !target.param_type_in.is_empty() {
            let Some(param_name) = decl.params.get(idx) else {
                return false;
            };
            let type_allowed = decl
                .type_aliases
                .iter()
                .filter(|binding| &binding.name == param_name)
                .any(|binding| {
                    target
                        .param_type_in
                        .iter()
                        .any(|want| semantic_type_names_match(&binding.type_name, want))
                });
            if !type_allowed {
                return false;
            }
        }
    }
    if !target.param_count_in.is_empty()
        && !target
            .param_count_in
            .contains(&u32::try_from(decl.params.len()).unwrap_or(u32::MAX))
    {
        return false;
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

fn param_target_is_context_only(target: &RuleTarget) -> bool {
    target.name.is_none() && target.attribute.is_none() && target.regex.is_none()
}

fn semantic_type_names_match(actual: &str, expected: &str) -> bool {
    actual == expected
        || bonsai_common::short_qualified_tail(actual) == bonsai_common::short_qualified_tail(expected)
}

fn decl_modifier_names(ws: &Workspace, file: FileId, decl: &Decl) -> Vec<String> {
    let Ok(parsed) = ws.db().parse(file) else {
        return Vec::new();
    };
    let Ok(snapshot) = ws.vfs().snapshot(file) else {
        return Vec::new();
    };
    let root = parsed.tree.root_node();
    let start = decl.span.start as usize;
    let end = decl.span.end as usize;
    let Some(decl_node) = root.named_descendant_for_byte_range(start, end) else {
        return Vec::new();
    };
    let mut modifiers = Vec::new();
    let mut pending = vec![(decl_node, false)];
    while let Some((node, inside_modifier)) = pending.pop() {
        let inside_modifier = inside_modifier || node.kind().contains("modifier");
        if node.child_count() == 0 {
            if inside_modifier && node.start_byte() < decl.name_span.start as usize {
                if let Some(text) = snapshot.text.get(node.start_byte()..node.end_byte()) {
                    let text = text.trim();
                    if !text.is_empty() && !modifiers.iter().any(|existing| existing == text) {
                        modifiers.push(text.to_string());
                    }
                }
            }
            continue;
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        pending.extend(children.into_iter().rev().map(|child| (child, inside_modifier)));
    }
    modifiers
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
    let file_packages = file_package_set_with_prewarmed_workspace_context_and_retention(
        ws,
        file,
        rules.include_workspace_package_context,
        retention,
        ctx.import_package_contexts,
        ctx.file_imports,
    );
    let import_aliases = file_alias_map_with_compiler_imports(ws, file, retention, ctx.file_imports);
    let bundle = decl_match_facts_for_retention(
        ws,
        file,
        Some(file_index),
        &rules.factory,
        retention,
        ctx.file_imports,
    );
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
                    &receiver_types,
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
                    enclosing_modifiers: None,
                    alias_chains: Some(&facts.alias_chains),
                    runtime_types: Some(&facts.runtime_types),
                    lifecycle_transitions: Some(&facts.lifecycle_transitions),
                    structural_context: Some(StructuralConstraintContext {
                        current_decl: decl,
                        file_decls: &file_index.defs,
                        assignment_values: &file_index.assignment_values,
                        call_argument_values: &file_index.call_argument_values,
                    }),
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
                    origin: MatchOrigin::Rulepack,
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
            if !base_receiver_type_allows(prepared, None, &matched_callee, &[], &[]) {
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
                enclosing_modifiers: None,
                alias_chains: None,
                runtime_types: None,
                lifecycle_transitions: None,
                structural_context: None,
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
                origin: MatchOrigin::Rulepack,
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
    if let Some(expanded) = expand_callee_alias(callee, alias_map) {
        collect_call_candidate_keys(&expanded, &mut out);
    }
    out
}

/// Expand the first compiler alias in a callee while preserving its remaining
/// member path. This is the canonical import/type rewrite shared by matcher
/// candidate lookup and rulepack factory-return typing.
fn expand_callee_alias(
    callee: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Option<String> {
    let segments = bonsai_common::qualified_name_segments(callee);
    let bare = normalize_leading_call_punctuation(segments.first().copied()?);
    let target = alias_map.get(bare)?;
    let tail = segments.iter().skip(1).copied().collect::<Vec<_>>().join(".");
    let tail = if tail.is_empty() {
        String::new()
    } else {
        format!(".{tail}")
    };
    Some(match target {
        AliasTarget::Member { module, member } => format!("{module}.{member}{tail}"),
        AliasTarget::Namespace { module } => format!("{module}{tail}"),
        AliasTarget::Type { type_name } => format!("{type_name}{tail}"),
    })
}

/// Match a structured compiler call against rule-owned syntax after applying
/// the canonical import/type alias map. Guard analyses use this instead of
/// duplicating language-specific import spelling rules.
pub(crate) fn rule_target_matches_call_with_aliases(
    callee: &str,
    receiver_types: &[String],
    target: &RuleTarget,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> bool {
    rule_target_matches_call(callee, receiver_types, target)
        || expand_callee_alias(callee, alias_map)
            .as_deref()
            .is_some_and(|expanded| rule_target_matches_call(expanded, receiver_types, target))
}

fn collect_call_candidate_keys(callee: &str, out: &mut Vec<String>) {
    let normalized = normalize_callee_for_matching(callee);
    push_unique_call_key(out, &normalized);
    for segment in bonsai_common::qualified_name_segments(&normalized) {
        push_unique_call_key(out, segment);
    }
    for token in normalized.split(|ch: char| !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())) {
        push_unique_call_key(out, token);
    }
}

fn push_unique_call_key(out: &mut Vec<String>, key: &str) {
    let key = normalize_leading_call_punctuation(key);
    if key.is_empty() || out.iter().any(|existing| existing == key) {
        return;
    }
    out.push(key.to_string());
}

/// Remove a source sigil from an identifier-shaped compiler call while
/// preserving an adapter-classified symbolic operator as its exact identity.
///
/// The distinction is structural: punctuation followed by a name is a sigil;
/// a non-empty call made entirely of punctuation is an operator. No language
/// spelling or provider API is known here.
fn normalize_leading_call_punctuation(value: &str) -> &str {
    let value = value.trim();
    let stripped = value.trim_start_matches(bonsai_common::is_name_punctuation);
    if stripped.is_empty() {
        value
    } else {
        stripped
    }
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
    let file_packages = file_package_set_with_prewarmed_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
        ctx.import_package_contexts,
        ctx.file_imports,
    );
    let import_aliases = file_alias_map_with_compiler_imports(ws, file, retention, ctx.file_imports);
    // Missing-call rules don't use factory-return typing.
    let empty_factory = empty_factory_returns();
    let bundle = decl_match_facts_for_retention(
        ws,
        file,
        Some(file_index),
        empty_factory.as_ref(),
        retention,
        ctx.file_imports,
    );

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
                enclosing_modifiers: None,
                alias_chains: Some(&facts.alias_chains),
                runtime_types: Some(&facts.runtime_types),
                lifecycle_transitions: Some(&facts.lifecycle_transitions),
                structural_context: Some(StructuralConstraintContext {
                    current_decl: decl,
                    file_decls: &file_index.defs,
                    assignment_values: &file_index.assignment_values,
                    call_argument_values: &file_index.call_argument_values,
                }),
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
                ctx.import_package_contexts,
            );
            if target_present {
                continue;
            }

            let (file_path, line, col) = resolve_span(ws, file, target_span);
            out.push(RuleMatch {
                origin: MatchOrigin::Rulepack,
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
    import_package_contexts: Option<&Arc<LanguageImportPackageContexts>>,
) -> bool {
    if prepared.rule.match_spec.kind != MatchKind::Missing {
        return false;
    }
    let max_depth = prepared.rule.match_spec.search_depth;
    if max_depth == 0 {
        return false;
    }
    let global = streaming_global_headers(ws);
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
            let Some(callee_header) = global.decl_of(*symbol) else {
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
            let callee_file = global.declaring_file(callee_header.symbol).unwrap_or(file);
            let Some(callee_file_index) = ws
                .db()
                .decl_index_remapped_to_headers(global.as_ref(), callee_file)
            else {
                continue;
            };
            let Some(callee_decl) = callee_file_index.defs.iter().find(|decl| decl.symbol == *symbol) else {
                continue;
            };
            let callee_file_packages = file_package_set_with_prewarmed_workspace_context_and_retention(
                ws,
                callee_file,
                prepared.needs_workspace_package_context(),
                retention,
                import_package_contexts,
                None,
            );
            let empty_factory = empty_factory_returns();
            let callee_bundle = decl_match_facts_for_retention(
                ws,
                callee_file,
                Some(&callee_file_index),
                empty_factory.as_ref(),
                retention,
                None,
            );
            // Bundle covers every decl in the file; index by
            // span. Fallback: if the cache layer didn't
            // materialise this decl (rare — adapters that emit
            // a decl with no flow_events skip it), fall through
            // to the prior inline shape.
            let callee_facts = callee_bundle.by_decl_span.get(&callee_decl.span).cloned();
            let callee_alias_owned;
            let (calls_view, callee_alias_ref): (
                CalleeCallsView<'_>,
                &std::collections::HashMap<String, AliasTarget>,
            ) = if let Some(facts) = &callee_facts {
                (
                    std::borrow::Cow::Borrowed(facts.calls.as_slice()),
                    &facts.alias_map,
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
                callee_alias_owned = callee_alias;
                (std::borrow::Cow::Owned(calls), &callee_alias_owned)
            };
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
    file_index: &DeclIndex,
    prepared: &PreparedRule<'_>,
    constructor_names: &AHashSet<String>,
    wanted_index: usize,
) -> bool {
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        prepared.needs_workspace_package_context(),
        FactRetention::Transient,
    );
    let import_aliases = file_alias_map_with_retention(ws, file, FactRetention::Transient);
    for decl in &file_index.defs {
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
    file_alias_map_with_compiler_imports(ws, file, retention, None)
}

fn file_alias_map_with_compiler_imports(
    ws: &Workspace,
    file: FileId,
    retention: FactRetention,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> std::collections::HashMap<String, AliasTarget> {
    if let Some(imports) = compiler_imports {
        return bonsai_lang_api::kit::alias_map_from_imports(imports);
    }
    match retention {
        FactRetention::Cached => file_alias_map(ws, file),
        FactRetention::Transient => transient_import_index(ws, file)
            .map(|imports| bonsai_lang_api::kit::alias_map_from_imports(&imports))
            .unwrap_or_default(),
    }
}

fn transient_import_index(ws: &Workspace, file: FileId) -> Option<bonsai_lang_api::ImportIndex> {
    ws.db().import_index_uncached(file)
}

// Process-level shared cache keyed on VFS identity, file identity, content,
// and workspace context. Earlier this was a
// `thread_local!` which meant rayon work-stealing across the 4
// matcher passes (sources / sinks / sanitizers / pattern_sinks)
// rebuilt the same file's package set on every worker that hadn't
// seen it. The shared cache hits ~100% across all passes once a
// file has been visited once.
//
// Cross-workspace correctness requires the VFS instance because local-import
// resolution and manifest context can differ even when a source file has the
// same numeric FileId and byte content in two workspaces.
type FilePackageSetKey = (u64, FileId, u64, u64, u64, bool);
static FILE_PACKAGE_SET_CACHE: std::sync::LazyLock<MatcherFactCache<FilePackageSetKey, AHashSet<String>>> =
    std::sync::LazyLock::new(|| MatcherFactCache::new(matcher_fact_cache_budget_share(3, 32)));

type WorkspaceImportPackageContextKey = (u64, String, u64);
static LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE: std::sync::LazyLock<
    MatcherFactCache<WorkspaceImportPackageContextKey, LanguageImportPackageContexts>,
> = std::sync::LazyLock::new(|| {
    // The exact import symbol table is required throughout a matcher phase.
    // Retain one context even when it exceeds the hot-cache share so repeated
    // broad passes do not recompile a single-language workspace. Multi-language
    // phases also hold their coordinator-built contexts directly while active.
    MatcherFactCache::new_with_oversized_singleton(matcher_fact_cache_budget_share(1, 16), true)
});

#[derive(Clone, Default)]
struct WorkspaceImportPackageContext {
    packages: AHashSet<String>,
    fingerprint: u64,
}

#[derive(Default)]
struct LanguageImportPackageContexts {
    workspace: Arc<WorkspaceImportPackageContext>,
    by_file: AHashMap<FileId, Arc<WorkspaceImportPackageContext>>,
    /// Exact adapter import IR retained from the language prewarm. Imports
    /// are the compiler's lightweight header facts; keeping them lets package
    /// constraints reject files before full declaration/flow objects are
    /// decoded and also avoids reparsing relative-import targets.
    imports_by_file: AHashMap<FileId, Arc<bonsai_lang_api::ImportIndex>>,
}

struct ImportComponents {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl ImportComponents {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            rank: vec![0; len],
        }
    }

    fn root(&mut self, mut index: usize) -> usize {
        let mut root = index;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        while self.parent[index] != index {
            let parent = self.parent[index];
            self.parent[index] = root;
            index = parent;
        }
        root
    }

    fn union(&mut self, left: usize, right: usize) {
        let mut left_root = self.root(left);
        let mut right_root = self.root(right);
        if left_root == right_root {
            return;
        }
        if self.rank[left_root] < self.rank[right_root] {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root;
        if self.rank[left_root] == self.rank[right_root] {
            self.rank[left_root] = self.rank[left_root].saturating_add(1);
        }
    }
}

fn estimated_string_set_bytes(values: &AHashSet<String>) -> u64 {
    values.iter().fold(1024_u64, |total, value| {
        total
            .saturating_add(64)
            .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
    })
}

fn estimated_workspace_import_context_bytes(context: &WorkspaceImportPackageContext) -> u64 {
    estimated_string_set_bytes(&context.packages).saturating_add(64)
}

fn estimated_language_import_context_bytes(contexts: &LanguageImportPackageContexts) -> u64 {
    let mut seen = AHashSet::new();
    let workspace_identity = Arc::as_ptr(&contexts.workspace) as usize;
    seen.insert(workspace_identity);
    let package_bytes = contexts.by_file.values().fold(
        estimated_workspace_import_context_bytes(&contexts.workspace),
        |total, context| {
            let total = total.saturating_add(32);
            let identity = Arc::as_ptr(context) as usize;
            if seen.insert(identity) {
                total.saturating_add(estimated_workspace_import_context_bytes(context))
            } else {
                total
            }
        },
    );
    contexts
        .imports_by_file
        .values()
        .fold(package_bytes, |total, imports| {
            imports
                .imports
                .iter()
                .fold(total.saturating_add(64), |total, spec| {
                    total
                        .saturating_add(96)
                        .saturating_add(u64::try_from(spec.module.len()).unwrap_or(u64::MAX))
                        .saturating_add(
                            spec.alias
                                .as_ref()
                                .and_then(|value| u64::try_from(value.len()).ok())
                                .unwrap_or_default(),
                        )
                        .saturating_add(
                            spec.original_name
                                .as_ref()
                                .and_then(|value| u64::try_from(value.len()).ok())
                                .unwrap_or_default(),
                        )
                })
        })
}

/// Build the set of canonical package names imported by `file`. Broad scans
/// receive a rulepack-demanded language projection; isolated checks fall back
/// to an exhaustive projection of the same compiler import table.
fn file_package_set_with_workspace_context_and_retention(
    ws: &Workspace,
    file: FileId,
    include_workspace_context: bool,
    retention: FactRetention,
) -> Arc<AHashSet<String>> {
    file_package_set_with_prewarmed_workspace_context_and_retention(
        ws,
        file,
        include_workspace_context,
        retention,
        None,
        None,
    )
}

fn file_package_set_with_prewarmed_workspace_context_and_retention(
    ws: &Workspace,
    file: FileId,
    include_workspace_context: bool,
    retention: FactRetention,
    prewarmed_import_contexts: Option<&Arc<LanguageImportPackageContexts>>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> Arc<AHashSet<String>> {
    let language_imports = if include_workspace_context {
        prewarmed_import_contexts.cloned().unwrap_or_else(|| {
            project_language_import_package_contexts(
                language_import_package_contexts(ws, file, retention).as_ref(),
                None,
            )
        })
    } else {
        Arc::new(LanguageImportPackageContexts::default())
    };
    let prewarmed_file_imports = prewarmed_import_contexts
        .and_then(|contexts| contexts.imports_by_file.get(&file))
        .map(Arc::as_ref);
    let workspace_imports = Arc::clone(&language_imports.workspace);
    let component_imports = language_imports
        .by_file
        .get(&file)
        .cloned()
        .unwrap_or_else(|| Arc::new(WorkspaceImportPackageContext::default()));
    let workspace_packages =
        if include_workspace_context && workspace_manifest_package_context_allowed(ws, file) {
            ws.db().workspace_root().map(|root| {
                let language = ws
                    .db()
                    .adapter_for(file)
                    .map(|adapter| adapter.language_id().as_str())
                    .unwrap_or("");
                crate::deps::workspace_dependency_packages_for_language_in_workspace(
                    &root,
                    language,
                    ws.db().vfs().instance_id(),
                )
            })
        } else {
            None
        };
    let manifest_fingerprint = workspace_packages
        .as_ref()
        .map(|packages| packages.fingerprint)
        .unwrap_or(0);
    let import_fingerprint =
        combined_workspace_package_fingerprint(workspace_imports.fingerprint, component_imports.fingerprint);
    let workspace_package_fingerprint =
        combined_workspace_package_fingerprint(manifest_fingerprint, import_fingerprint);
    let (version, text_hash) = ws.db().vfs().snapshot(file).map_or((0, 0), |snapshot| {
        (
            snapshot.version,
            package_cache_content_hash(snapshot.text.as_bytes()),
        )
    });
    let key = (
        ws.db().vfs().instance_id(),
        file,
        version,
        text_hash,
        workspace_package_fingerprint,
        include_workspace_context,
    );
    FILE_PACKAGE_SET_CACHE.get_or_insert_with(
        key,
        || {
            build_file_package_set(
                ws,
                file,
                FilePackageSetInputs {
                    workspace_imports: workspace_imports.as_ref(),
                    component_imports: component_imports.as_ref(),
                    workspace_packages,
                    retention,
                    compiler_imports: compiler_imports.or(prewarmed_file_imports),
                    prewarmed_imports: prewarmed_import_contexts.map(|contexts| &contexts.imports_by_file),
                },
            )
        },
        estimated_string_set_bytes,
    )
}

struct FilePackageSetInputs<'a> {
    workspace_imports: &'a WorkspaceImportPackageContext,
    component_imports: &'a WorkspaceImportPackageContext,
    workspace_packages: Option<crate::deps::WorkspaceDependencyPackages>,
    retention: FactRetention,
    compiler_imports: Option<&'a bonsai_lang_api::ImportIndex>,
    prewarmed_imports: Option<&'a AHashMap<FileId, Arc<bonsai_lang_api::ImportIndex>>>,
}

fn build_file_package_set(
    ws: &Workspace,
    file: FileId,
    inputs: FilePackageSetInputs<'_>,
) -> Arc<AHashSet<String>> {
    let mut out: AHashSet<String> = AHashSet::new();
    if let Some(imports) = inputs.compiler_imports {
        insert_file_import_packages(
            ws,
            file,
            imports,
            inputs.retention,
            inputs.prewarmed_imports,
            &mut out,
        );
    } else {
        let imports = match inputs.retention {
            FactRetention::Cached => ws.db().import_index(file).map(|imports| (*imports).clone()),
            FactRetention::Transient => transient_import_index(ws, file),
        };
        if let Some(imports) = imports {
            insert_file_import_packages(
                ws,
                file,
                &imports,
                inputs.retention,
                inputs.prewarmed_imports,
                &mut out,
            );
        }
    }
    out.extend(
        inputs
            .workspace_imports
            .packages
            .iter()
            .map(|package| workspace_import_package_marker(package)),
    );
    out.extend(
        inputs
            .component_imports
            .packages
            .iter()
            .map(|package| component_import_package_marker(package)),
    );
    if let Some(workspace_packages) = inputs.workspace_packages {
        out.extend(workspace_packages.packages.iter().cloned());
    }
    Arc::new(out)
}

fn language_import_package_contexts(
    ws: &Workspace,
    file: FileId,
    retention: FactRetention,
) -> Arc<LanguageImportPackageContexts> {
    let Some(adapter) = ws.db().adapter_for(file) else {
        return Arc::new(LanguageImportPackageContexts::default());
    };
    let language = adapter.language_id();
    let key = (
        ws.db().vfs().instance_id(),
        language.as_str().to_string(),
        ws.db().vfs().revision(),
    );
    LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE.get_or_insert_with(
        key,
        || build_language_import_package_contexts(ws, language, retention),
        estimated_language_import_context_bytes,
    )
}

/// Project the compiler's canonical raw import targets onto exactly the
/// package symbols demanded by the active rule batch. `None` preserves the
/// exhaustive legacy projection for isolated point checks; broad scans always
/// provide the rulepack-derived signal set.
fn project_language_import_package_contexts(
    base: &LanguageImportPackageContexts,
    demanded_signals: Option<&[String]>,
) -> Arc<LanguageImportPackageContexts> {
    let demanded = demanded_signals.map(|signals| signals.iter().cloned().collect::<AHashSet<_>>());
    let projection_fingerprint = import_package_projection_fingerprint(demanded_signals);
    let workspace = project_workspace_import_package_context(
        base.workspace.as_ref(),
        demanded.as_ref(),
        projection_fingerprint,
    );
    let mut projected_by_identity = AHashMap::new();
    let by_file = base
        .by_file
        .iter()
        .map(|(&file, context)| {
            let identity = Arc::as_ptr(context) as usize;
            let projected = projected_by_identity
                .entry(identity)
                .or_insert_with(|| {
                    project_workspace_import_package_context(
                        context.as_ref(),
                        demanded.as_ref(),
                        projection_fingerprint,
                    )
                })
                .clone();
            (file, projected)
        })
        .collect();
    Arc::new(LanguageImportPackageContexts {
        workspace,
        by_file,
        imports_by_file: base.imports_by_file.clone(),
    })
}

fn project_workspace_import_package_context(
    base: &WorkspaceImportPackageContext,
    demanded_signals: Option<&AHashSet<String>>,
    projection_fingerprint: u64,
) -> Arc<WorkspaceImportPackageContext> {
    let mut packages = AHashSet::new();
    for module in &base.packages {
        if let Some(demanded_signals) = demanded_signals {
            insert_demanded_import_target_prefixes(&mut packages, module, demanded_signals);
        } else {
            insert_import_target_prefixes(&mut packages, module);
        }
    }
    Arc::new(WorkspaceImportPackageContext {
        packages,
        fingerprint: combined_workspace_package_fingerprint(base.fingerprint, projection_fingerprint),
    })
}

fn import_package_projection_fingerprint(demanded_signals: Option<&[String]>) -> u64 {
    let mut hasher = StableHasher::new();
    hasher.absorb(b"bonsai-import-package-projection-v1");
    hasher.absorb_separator();
    match demanded_signals {
        Some(signals) => {
            hasher.absorb(&(signals.len() as u64).to_le_bytes());
            for signal in signals {
                hasher.absorb(&(signal.len() as u64).to_le_bytes());
                hasher.absorb(signal.as_bytes());
            }
        }
        None => hasher.absorb(b"exhaustive"),
    }
    hasher.finish()
}

/// Derive workspace-wide and connected-component package evidence from one
/// deterministic compiler-object pass. A transient broad scan must not parse
/// the same language once per projection: imports are small enough to retain
/// for this construction, while full per-file compiler objects remain
/// streamed and are released by the database after each memory-aware batch.
fn build_language_import_package_contexts(
    ws: &Workspace,
    language: bonsai_lang_api::LanguageId,
    retention: FactRetention,
) -> Arc<LanguageImportPackageContexts> {
    let mut files: Vec<FileId> = ws
        .db()
        .vfs()
        .all_files()
        .into_iter()
        .filter(|candidate_file| {
            ws.db()
                .adapter_for(*candidate_file)
                .is_some_and(|candidate_adapter| candidate_adapter.language_id() == language)
        })
        .collect();
    files.sort_unstable_by_key(|candidate_file| candidate_file.raw());
    let file_indices: AHashMap<FileId, usize> = files
        .iter()
        .copied()
        .enumerate()
        .map(|(index, candidate_file)| (candidate_file, index))
        .collect();
    let imports_by_file: AHashMap<FileId, bonsai_lang_api::ImportIndex> = match retention {
        FactRetention::Cached => files
            .iter()
            .filter_map(|candidate_file| {
                ws.db()
                    .import_index(*candidate_file)
                    .map(|imports| (*candidate_file, (*imports).clone()))
            })
            .collect(),
        FactRetention::Transient => files
            .iter()
            .filter_map(|candidate_file| {
                ws.db()
                    .import_index_uncached(*candidate_file)
                    .map(|imports| (*candidate_file, imports))
            })
            .collect(),
    };
    let mut components = ImportComponents::new(files.len());
    for importer in files.iter().copied() {
        let Some(imports) = imports_by_file.get(&importer) else {
            continue;
        };
        let importer_index = file_indices[&importer];
        for spec in &imports.imports {
            let Some(imported) = resolve_relative_import_file(ws, importer, &spec.module) else {
                continue;
            };
            let Some(&imported_index) = file_indices.get(&imported) else {
                continue;
            };
            components.union(importer_index, imported_index);
        }
    }

    let mut workspace = WorkspaceImportPackageContext::default();
    let mut component_packages: AHashMap<usize, AHashSet<String>> = AHashMap::new();
    let mut component_fingerprints: AHashMap<usize, u64> = AHashMap::new();
    for (index, candidate_file) in files.iter().copied().enumerate() {
        let root = components.root(index);
        if let Ok(snapshot) = ws.db().vfs().snapshot(candidate_file) {
            workspace.fingerprint = workspace
                .fingerprint
                .wrapping_mul(16_777_619)
                .wrapping_add(u64::from(candidate_file.raw()))
                .wrapping_add(snapshot.version)
                .wrapping_add(package_cache_content_hash(snapshot.text.as_bytes()));
            let fingerprint = component_fingerprints.entry(root).or_default();
            *fingerprint = fingerprint
                .wrapping_mul(16_777_619)
                .wrapping_add(u64::from(candidate_file.raw()))
                .wrapping_add(snapshot.version)
                .wrapping_add(package_cache_content_hash(snapshot.text.as_bytes()));
        }
        let Some(imports) = imports_by_file.get(&candidate_file) else {
            continue;
        };
        for spec in &imports.imports {
            workspace.packages.insert(spec.module.clone());
            if resolve_relative_import_file(ws, candidate_file, &spec.module).is_some() {
                continue;
            }
            component_packages
                .entry(root)
                .or_default()
                .insert(spec.module.clone());
        }
    }

    let mut shared_by_root: AHashMap<usize, Arc<WorkspaceImportPackageContext>> = AHashMap::new();
    for (index, _) in files.iter().enumerate() {
        let root = components.root(index);
        shared_by_root.entry(root).or_insert_with(|| {
            Arc::new(WorkspaceImportPackageContext {
                packages: component_packages.remove(&root).unwrap_or_default(),
                fingerprint: component_fingerprints.get(&root).copied().unwrap_or_default(),
            })
        });
    }
    Arc::new(LanguageImportPackageContexts {
        workspace: Arc::new(workspace),
        by_file: files
            .into_iter()
            .enumerate()
            .filter_map(|(index, candidate_file)| {
                let root = components.root(index);
                shared_by_root
                    .get(&root)
                    .cloned()
                    .map(|context| (candidate_file, context))
            })
            .collect(),
        imports_by_file: imports_by_file
            .into_iter()
            .map(|(file, imports)| (file, Arc::new(imports)))
            .collect(),
    })
}

fn insert_file_import_packages(
    ws: &Workspace,
    file: FileId,
    imports: &bonsai_lang_api::ImportIndex,
    retention: FactRetention,
    prewarmed_imports: Option<&AHashMap<FileId, Arc<bonsai_lang_api::ImportIndex>>>,
    out: &mut AHashSet<String>,
) {
    for spec in &imports.imports {
        insert_import_target_prefixes(out, &spec.module);
        if let Some(imported_file) = resolve_relative_import_file(ws, file, &spec.module) {
            for package in direct_package_imports_for_file(ws, imported_file, retention, prewarmed_imports) {
                insert_local_import_package_markers(out, spec, &package);
            }
        }
    }
}

fn direct_package_imports_for_file(
    ws: &Workspace,
    file: FileId,
    retention: FactRetention,
    prewarmed_imports: Option<&AHashMap<FileId, Arc<bonsai_lang_api::ImportIndex>>>,
) -> AHashSet<String> {
    let mut out = AHashSet::new();
    let prewarmed = prewarmed_imports.and_then(|imports| imports.get(&file));
    let loaded;
    let imports = if let Some(imports) = prewarmed {
        imports.as_ref()
    } else {
        loaded = match retention {
            FactRetention::Cached => ws.db().import_index(file).map(|imports| (*imports).clone()),
            FactRetention::Transient => transient_import_index(ws, file),
        };
        let Some(imports) = loaded.as_ref() else {
            return out;
        };
        imports
    };
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
    let extensions = ws
        .db()
        .adapter_for(importer)
        .map(|adapter| adapter.capabilities().module_resolution_extensions)
        .unwrap_or(&[]);
    relative_import_candidates(&raw, extensions)
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

fn relative_import_candidates(raw: &std::path::Path, extensions: &[&str]) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    out.push(raw.to_path_buf());

    let raw_ext = raw.extension().and_then(|ext| ext.to_str());
    let has_known_code_ext = raw_ext.is_some_and(|ext| extensions.contains(&ext));
    if raw_ext.is_none() {
        for ext in extensions {
            out.push(raw.with_extension(ext));
        }
        for ext in extensions {
            out.push(raw.join(format!("index.{ext}")));
        }
    } else if !has_known_code_ext {
        // TypeScript projects often import dotted basenames without the
        // final source extension, e.g. `../user/user.model` resolves to
        // `../user/user.model.ts`. `Path::extension()` sees `.model`,
        // so the extensionless branch above would otherwise never try
        // the real file.
        for ext in extensions {
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
    let extensions = adapter.capabilities().workspace_manifest_context_extensions;
    let Ok(path) = ws.vfs().path(file) else {
        return false;
    };
    let path = path.to_string_lossy();
    std::path::Path::new(path.as_ref())
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| extensions.contains(&ext))
}

fn package_cache_content_hash(bytes: &[u8]) -> u64 {
    bonsai_hash::fnv1a_bytes64(bytes)
}

fn combined_workspace_package_fingerprint(manifest: u64, imports: u64) -> u64 {
    let mut hasher = StableHasher::new();
    hasher.absorb(b"bonsai-matcher-workspace-packages-v1");
    hasher.absorb_separator();
    hasher.absorb(&manifest.to_le_bytes());
    hasher.absorb(&imports.to_le_bytes());
    hasher.finish()
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
    decl_name: String,
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

// Process-level shared cache keyed on VFS identity, file identity, content,
// and factory-return policy. Earlier this was a
// `thread_local!` which meant rayon work-stealing across the 4
// matcher passes (sources / sinks / sanitizers / pattern_sinks)
// rebuilt the same file's per-decl bundle on every worker that
// hadn't seen it yet — expected reuse rate ~25%. The shared
// cache approaches 100% reuse across passes.
//
// The VFS identity prevents future workspace- or path-scoped compiler
// context from leaking across byte-identical files in separate workspaces.
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
        if !rule.enabled {
            continue;
        }
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
    // Deterministic, length-delimited fingerprint over sorted
    // (language, receiver, method, type) tuples so the decl-facts cache never
    // serves a bundle built for a different pack.
    let mut langs: Vec<&String> = by_language.keys().collect();
    langs.sort();
    let mut hasher = StableHasher::new();
    hasher.absorb(b"bonsai-matcher-factory-returns-v1");
    hasher.absorb_separator();
    for lang in langs {
        hasher.absorb(&(lang.len() as u64).to_le_bytes());
        hasher.absorb(lang.as_bytes());
        let mut specs: Vec<&FactoryReturnSpec> = by_language[lang].iter().collect();
        specs.sort_by(|a, b| {
            (&a.receiver_path, &a.method, &a.type_name).cmp(&(&b.receiver_path, &b.method, &b.type_name))
        });
        hasher.absorb(&(specs.len() as u64).to_le_bytes());
        for spec in specs {
            hasher.absorb(&(spec.receiver_path.len() as u64).to_le_bytes());
            for segment in &spec.receiver_path {
                hasher.absorb(&(segment.len() as u64).to_le_bytes());
                hasher.absorb(segment.as_bytes());
            }
            hasher.absorb(&(spec.method.len() as u64).to_le_bytes());
            hasher.absorb(spec.method.as_bytes());
            hasher.absorb(&(spec.type_name.len() as u64).to_le_bytes());
            hasher.absorb(spec.type_name.as_bytes());
        }
        hasher.absorb_separator();
    }
    Arc::new(FactoryReturns {
        by_language,
        fingerprint: hasher.finish(),
    })
}

fn factory_path_segments(text: &str) -> Vec<String> {
    bonsai_common::qualified_name_segments(text)
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn factory_spec_matches_call(call_name: &str, call_receiver: Option<&str>, spec: &FactoryReturnSpec) -> bool {
    if !callee_tail_matches(call_name, &spec.method) {
        return false;
    }
    if spec.receiver_path.is_empty() {
        return true;
    }
    let segments = call_receiver.map_or_else(
        || {
            let mut segments = factory_path_segments(call_name);
            segments.pop();
            segments
        },
        factory_path_segments,
    );
    if segments.len() < spec.receiver_path.len() {
        return false;
    }
    let start = segments.len() - spec.receiver_path.len();
    segments[start..] == spec.receiver_path
}

/// Synthesize `local → ReturnType` aliases for assignments whose RHS is
/// a factory call named in the rulepack map. Empty (no allocation) when
/// the pack ships no `returns_type` rules.
fn synth_factory_type_aliases(
    events: &[FlowEvent],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    factory: &FactoryReturns,
    language: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Vec<TypeAliasBinding> {
    let Some(specs) = factory.specs_for(language) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    fn walk(
        events: &[FlowEvent],
        assignment_values: &[bonsai_lang_api::AssignmentValueFact],
        specs: &[FactoryReturnSpec],
        alias_map: &std::collections::HashMap<String, AliasTarget>,
        out: &mut Vec<TypeAliasBinding>,
    ) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    span,
                    target,
                    source_call,
                    ..
                } => {
                    // Ordinary assignments have an indexed RHS expression.
                    // Syntax-bound resource aliases (`with Factory() as x`,
                    // `using (...)`) are emitted directly as exact Assign
                    // events because their grammar node is not an assignment
                    // expression. Preserve that compiler fact as the fallback
                    // factory identity instead of requiring a second textual
                    // reconstruction.
                    let indexed = bonsai_lang_api::assignment_value_fact_for_span(assignment_values, *span);
                    let call_name = indexed
                        .and_then(|fact| fact.direct_call_name.as_deref())
                        .or(source_call.as_deref());
                    let Some(call_name) = call_name else {
                        continue;
                    };
                    let call_receiver = indexed.and_then(|fact| fact.direct_call_receiver.as_deref());
                    let expanded = expand_callee_alias(call_name, alias_map);
                    for spec in specs {
                        if !factory_spec_matches_call(call_name, call_receiver, spec)
                            && !expanded
                                .as_deref()
                                .is_some_and(|expanded| factory_spec_matches_call(expanded, None, spec))
                        {
                            continue;
                        }
                        let binding = TypeAliasBinding {
                            name: target.clone(),
                            type_name: spec.type_name.clone(),
                        };
                        if !out.contains(&binding) {
                            out.push(binding);
                        }
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    walk(then_events, assignment_values, specs, alias_map, out);
                    walk(else_events, assignment_values, specs, alias_map, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => {
                    walk(body, assignment_values, specs, alias_map, out);
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(body, assignment_values, specs, alias_map, out);
                    walk(catch_events, assignment_values, specs, alias_map, out);
                    walk(finally_events, assignment_values, specs, alias_map, out);
                }
                _ => {}
            }
        }
    }
    walk(events, assignment_values, specs, alias_map, &mut out);
    out
}

type FileDeclFactsKey = (u64, FileId, u64, u64, u64);
static DECL_FACTS_CACHE: std::sync::LazyLock<MatcherFactCache<FileDeclFactsKey, FileDeclFactsBundle>> =
    std::sync::LazyLock::new(|| MatcherFactCache::new(matcher_fact_cache_budget_share(7, 8)));

fn prepare_matcher_fact_caches_for_broad_scan() {
    FILE_PACKAGE_SET_CACHE.set_retained_budget(matcher_fact_cache_budget_share(3, 32));
    LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE.set_retained_budget(matcher_fact_cache_budget_share(1, 16));
    DECL_FACTS_CACHE.set_retained_budget(matcher_fact_cache_budget_share(7, 8));
}

/// End broad matcher ownership before opening a workspace-sized semantic
/// graph. These caches contain only deterministic projections of compiler
/// facts; clearing them changes reuse, never matching or taint semantics.
pub(crate) fn release_matcher_fact_caches() {
    FILE_PACKAGE_SET_CACHE.clear_retained();
    LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE.clear_retained();
    DECL_FACTS_CACHE.clear_retained();
    FILE_PACKAGE_SET_CACHE.set_retained_budget(point_matcher_fact_cache_budget_share(3, 32));
    LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE.set_retained_budget(point_matcher_fact_cache_budget_share(1, 16));
    DECL_FACTS_CACHE.set_retained_budget(point_matcher_fact_cache_budget_share(7, 8));
}

fn estimated_decl_match_facts_bytes(source_bytes: usize) -> u64 {
    const PER_FILE_BYTES: u64 = 64 * 1024;
    const SOURCE_AMPLIFICATION: u64 = 16;
    PER_FILE_BYTES.saturating_add(
        u64::try_from(source_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(SOURCE_AMPLIFICATION),
    )
}

/// Return the per-decl matcher fact bundle for `file`. Builds the
/// bundle on miss; cached on `(vfs, file, version, text_hash, factory_fp)`
/// so source edits — and a change of factory-return map — naturally
/// invalidate. `factory_fp` is 0 when the pack ships no `returns_type`
/// rules, keeping the key (and behavior) identical to a no-factory run.
fn decl_match_facts_for_retention(
    ws: &Workspace,
    file: FileId,
    file_index: Option<&DeclIndex>,
    factory: &FactoryReturns,
    retention: FactRetention,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> Arc<FileDeclFactsBundle> {
    let (version, text_hash, source_bytes) = ws.db().vfs().snapshot(file).map_or((0, 0, 0), |snap| {
        (
            snap.version,
            package_cache_content_hash(snap.text.as_bytes()),
            snap.text.len(),
        )
    });
    let key = (
        ws.db().vfs().instance_id(),
        file,
        version,
        text_hash,
        factory.fingerprint,
    );
    DECL_FACTS_CACHE.get_or_insert_with(
        key,
        || {
            if let Some(index) = file_index {
                build_decl_match_facts_bundle(ws, file, index, factory, retention, compiler_imports)
            } else {
                match retention {
                    FactRetention::Cached => ws.db().decl_index(file).map(|index| {
                        build_decl_match_facts_bundle(
                            ws,
                            file,
                            index.as_ref(),
                            factory,
                            retention,
                            compiler_imports,
                        )
                    }),
                    FactRetention::Transient => ws.db().decl_index_uncached(file).map(|index| {
                        build_decl_match_facts_bundle(ws, file, &index, factory, retention, compiler_imports)
                    }),
                }
                .unwrap_or_default()
            }
        },
        move |_| estimated_decl_match_facts_bytes(source_bytes),
    )
}

fn build_decl_match_facts_bundle(
    ws: &Workspace,
    file: FileId,
    file_index: &DeclIndex,
    factory: &FactoryReturns,
    retention: FactRetention,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> Arc<FileDeclFactsBundle> {
    let import_aliases = file_alias_map_with_compiler_imports(ws, file, retention, compiler_imports);
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
            .map(|lang| {
                synth_factory_type_aliases(
                    &decl.flow_events,
                    &file_index.assignment_values,
                    factory,
                    lang,
                    &alias_map,
                )
            })
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
        let runtime_types = collect_runtime_type_narrowings(decl.span, &file_index.runtime_type_narrowings);
        let lifecycle_transitions = collect_lifecycle_transitions(&decl.flow_events);
        by_decl_span.insert(
            decl.span,
            Arc::new(DeclMatchFacts {
                decl_name: decl.name.clone(),
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
    for prefix in bonsai_common::qualified_name_prefixes(module) {
        out.insert(prefix.to_string());
    }
}

/// Insert only prefix symbols requested by the active rulepack projection.
/// This is the exact intersection of [`insert_import_target_prefixes`] with
/// `demanded`, but it avoids allocating and hashing every unused prefix in a
/// large compiler import table.
fn insert_demanded_import_target_prefixes(
    out: &mut AHashSet<String>,
    module: &str,
    demanded: &AHashSet<String>,
) {
    for prefix in bonsai_common::qualified_name_prefixes(module) {
        if demanded.contains(prefix) {
            out.insert(prefix.to_string());
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
fn rule_requires_call_package_signal(rule: &Rule) -> bool {
    if rule.packages.is_empty() && rule.imports.is_empty() && rule.modules.is_empty() {
        return false;
    }
    if skips_call_package_gate(rule) {
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
    let segments = bonsai_common::qualified_name_segments(callee);
    let bare = normalize_leading_call_punctuation(segments.first().copied()?);
    let target = alias_map.get(bare)?;
    let mut tail = String::new();
    for segment in segments.iter().skip(1) {
        tail.push('.');
        tail.push_str(segment);
    }
    let expanded = expand_callee_alias(callee, alias_map)?;
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
    let file_packages = file_package_set_with_prewarmed_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
        ctx.import_package_contexts,
        ctx.file_imports,
    );
    let alias_map = file_alias_map_with_compiler_imports(ws, file, retention, ctx.file_imports);
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
            if !base_receiver_type_allows(prepared, enclosing_decl, &r.name, &[], &[]) {
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
                origin: MatchOrigin::Rulepack,
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
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    include_workspace_package_context: bool,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let file_packages = file_package_set_with_prewarmed_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        ctx.retention,
        ctx.import_package_contexts,
        ctx.file_imports,
    );
    let alias_map = file_alias_map_with_compiler_imports(ws, file, ctx.retention, ctx.file_imports);
    let assignment_values = AssignmentValueIndex::new(&file_index.assignment_values);
    for decl in &file_index.defs {
        let mut reads = Vec::new();
        collect_flow_read_sites(
            &decl.flow_events,
            &file_index.assignment_values,
            &file_index.call_receivers,
            &mut reads,
        );
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
                if !base_receiver_type_allows(prepared, Some(decl), &match_text, &[], &[]) {
                    continue;
                }
                // Same package-signal gate that `scan_refs_batch`
                // applies; without it a receiver-agnostic read
                // regex would fire on any file regardless of the
                // imports it actually pulls in.
                if !prepared.call_context_allows(&match_text, &[], &alias_map, file_packages.as_ref()) {
                    continue;
                }
                let span = canonical_flow_read_match_span(ws, file, span, &match_text, &assignment_values);
                if out
                    .iter()
                    .any(|existing| existing.rule_id == prepared.rule.id && existing.span == span)
                {
                    continue;
                }
                let (file_path, line, col) = resolve_span(ws, file, span);
                out.push(RuleMatch {
                    origin: MatchOrigin::Rulepack,
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
    receiver_types: &[String],
    factory_aliases: &[TypeAliasBinding],
) -> bool {
    let Some(target) = rule_primary_target(prepared.rule) else {
        return true;
    };
    if target.receiver_type_in.is_empty() {
        return true;
    }
    if receiver_type_matches_any(receiver_types, &target.receiver_type_in) {
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
fn canonical_flow_read_match_span(
    ws: &Workspace,
    file: FileId,
    span: Span,
    match_text: &str,
    assignment_values: &AssignmentValueIndex,
) -> Span {
    let match_text = match_text.trim();
    if match_text.is_empty() || match_text.contains(',') {
        return span;
    }
    let Ok(snapshot) = ws.vfs().snapshot(file) else {
        return span;
    };
    canonical_flow_read_match_span_in_source(
        file,
        span,
        match_text,
        assignment_values,
        snapshot.text.as_ref(),
    )
}

fn canonical_flow_read_match_span_in_source(
    file: FileId,
    span: Span,
    match_text: &str,
    assignment_values: &AssignmentValueIndex,
    source: &str,
) -> Span {
    let search_span = assignment_values.value_span(span).unwrap_or(span);
    let start = search_span.start as usize;
    let end = search_span.end as usize;
    if start >= end || end > source.len() {
        return span;
    }
    // `start`/`end` are adapter span offsets; bail rather than panic if a
    // multi-byte UTF-8 char straddles either bound.
    let Some(raw) = source.get(start..end) else {
        return span;
    };
    let offset = raw.find(match_text);
    let Some(offset) = offset else {
        return span;
    };
    let match_start = search_span.start.saturating_add(offset as u64);
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

fn collect_flow_read_sites(
    events: &[FlowEvent],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    out: &mut Vec<(Span, Vec<String>)>,
) {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if let Some(receiver) = bonsai_lang_api::call_receiver_fact_for_span(call_receivers, *span) {
                    let mut names = Vec::new();
                    collect_expression_flow_read_names(&receiver.value_flow, &mut names);
                    if !names.is_empty() {
                        out.push((*span, names));
                    }
                }
                for arg in args {
                    let mut names = Vec::new();
                    if let Some(place) = &arg.place {
                        push_structured_read_name(&mut names, place);
                    }
                    for source in &arg.source_names {
                        push_structured_read_name(&mut names, source);
                    }
                    if !names.is_empty() {
                        out.push((arg.span, names));
                    }
                }
            }
            FlowEvent::Assign {
                span,
                source_name,
                source_names,
                ..
            } => {
                let mut names = Vec::new();
                if let Some(source_name) = source_name {
                    push_structured_read_name(&mut names, source_name);
                }
                for name in source_names {
                    push_structured_read_name(&mut names, name);
                }
                if let Some(fact) = bonsai_lang_api::assignment_value_fact_for_span(assignment_values, *span)
                {
                    collect_expression_flow_read_names(&fact.value_flow, &mut names);
                }
                if !names.is_empty() {
                    out.push((*span, names));
                }
            }
            FlowEvent::AggregateAssign { span, value_flow, .. }
            | FlowEvent::Return { span, value_flow, .. }
            | FlowEvent::Yield { span, value_flow, .. } => {
                let mut names = Vec::new();
                collect_expression_flow_read_names(value_flow, &mut names);
                if !names.is_empty() {
                    out.push((*span, names));
                }
            }
            FlowEvent::Throw { span, value_name, .. } | FlowEvent::Await { span, value_name } => {
                if let Some(value_name) = value_name {
                    let mut names = Vec::new();
                    push_structured_read_name(&mut names, value_name);
                    if !names.is_empty() {
                        out.push((*span, names));
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_flow_read_sites(then_events, assignment_values, call_receivers, out);
                collect_flow_read_sites(else_events, assignment_values, call_receivers, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_flow_read_sites(body, assignment_values, call_receivers, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_flow_read_sites(body, assignment_values, call_receivers, out);
                collect_flow_read_sites(catch_events, assignment_values, call_receivers, out);
                collect_flow_read_sites(finally_events, assignment_values, call_receivers, out);
            }
            _ => {}
        }
    }
}

fn collect_expression_flow_read_names(flow: &bonsai_lang_api::ExpressionFlow, out: &mut Vec<String>) {
    if let Some(projection) = &flow.projection {
        push_structured_read_name(out, &projection.canonical_place());
    } else if let Some(place) = &flow.place {
        push_structured_read_name(out, place);
    }
    for source in &flow.source_names {
        push_structured_read_name(out, source);
    }
    for field in &flow.aggregate_fields {
        collect_expression_flow_read_names(&field.value, out);
    }
    for item in &flow.tuple_items {
        collect_expression_flow_read_names(item, out);
    }
    for spread in &flow.spreads {
        collect_expression_flow_read_names(spread, out);
    }
}

/// Normalize an adapter-proven value/place name for rule matching. This never
/// receives rendered expression text: punctuation inside an expression has
/// already been interpreted by the Tree-sitter lowering layer.
fn push_structured_read_name(out: &mut Vec<String>, value: &str) {
    let value = value
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    let value = value.trim_matches('.');
    if !value.is_empty() && !out.iter().any(|existing| existing == value) {
        out.push(value.to_string());
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
                let rhs_text = source_text
                    .and_then(|source_text| assignment_values.rendering(*span, source_text))
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
/// Cycles terminate through an exact visited set; semantic depth is uncapped.
fn arg_regex_texts(
    arg: &CallArg,
    assignment_texts: Option<&AHashMap<String, String>>,
    follow_assignments: bool,
) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut seen = AHashSet::new();
    let mut current = arg.value_text.trim();
    loop {
        if current.is_empty() || !seen.insert(current.to_string()) {
            break;
        }
        candidates.push(current.to_string());
        if !follow_assignments || !is_simple_identifier(current) {
            break;
        }
        let Some(next) = assignment_texts
            .and_then(|assignments| assignments.get(current))
            .map(String::as_str)
            .map(str::trim)
            .filter(|next| !next.is_empty())
        else {
            break;
        };
        current = next;
    }
    candidates
}

fn constraint_regex_texts(ctx: &ConstraintEval<'_, '_>, index: usize, arg: &CallArg) -> Vec<String> {
    let mut candidates = arg_regex_texts(arg, ctx.assignment_texts, true);
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
    let file_packages = file_package_set_with_prewarmed_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
        ctx.import_package_contexts,
        ctx.file_imports,
    );
    let alias_map = file_alias_map_with_compiler_imports(ws, file, retention, ctx.file_imports);
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
                    enclosing_modifiers: None,
                    alias_chains: None,
                    runtime_types: None,
                    lifecycle_transitions: None,
                    structural_context: Some(StructuralConstraintContext {
                        current_decl: decl,
                        file_decls: &file_index.defs,
                        assignment_values: &file_index.assignment_values,
                        call_argument_values: &file_index.call_argument_values,
                    }),
                }) {
                    continue;
                }
                let (file_path, line, col) = resolve_span(ws, file, write.span);
                out.push(RuleMatch {
                    origin: MatchOrigin::Rulepack,
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
    let file_packages = file_package_set_with_prewarmed_workspace_context_and_retention(
        ws,
        file,
        include_workspace_package_context,
        retention,
        ctx.import_package_contexts,
        ctx.file_imports,
    );
    let alias_map = file_alias_map_with_compiler_imports(ws, file, retention, ctx.file_imports);
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
                enclosing_modifiers: None,
                alias_chains: None,
                runtime_types: None,
                lifecycle_transitions: None,
                structural_context: None,
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
                origin: MatchOrigin::Rulepack,
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

fn matching_write_exists(file_index: &DeclIndex, prepared: &PreparedRule<'_>) -> bool {
    for decl in &file_index.defs {
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

    for r in &file_index.refs {
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

/// Project file-local compiler facts into the declaration-local matcher view.
fn collect_runtime_type_narrowings(
    decl_span: Span,
    facts: &[bonsai_lang_api::RuntimeTypeNarrowingFact],
) -> Vec<RuntimeTypeNarrowing> {
    facts
        .iter()
        .filter(|fact| {
            decl_span.file == fact.branch_span.file
                && decl_span.start <= fact.branch_span.start
                && fact.branch_span.end <= decl_span.end
        })
        .map(|fact| RuntimeTypeNarrowing {
            name: fact.subject.clone(),
            type_name: fact.type_name.clone(),
            start: fact.guarded_span.start,
            end: fact.guarded_span.end,
        })
        .collect()
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
    bonsai_common::qualified_name_owner(callee.trim())
}

fn receiver_root_name(receiver: &str) -> Option<String> {
    let receiver = receiver
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    let root = receiver
        .chars()
        .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
        .collect::<String>();
    let root = root.trim();
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
/// `None` for bare unqualified names. Source punctuation has already been
/// classified by the adapter; this candidate key uses structural boundaries.
fn receiver_method_key(callee: &str) -> Option<String> {
    let callee = callee.trim();
    let receiver = bonsai_common::qualified_name_owner(callee)?.trim();
    let method = bonsai_common::short_qualified_tail(callee).trim();
    (!receiver.is_empty() && !method.is_empty()).then(|| format!("{receiver}\0{method}"))
}

fn collect_calls_into(events: &[FlowEvent], out: &mut Vec<CallFact>) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                span,
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
        .filter(|call| call.origin == CallFactOrigin::RealCall)
        .map(|call| (call.callee.clone(), call.span))
        .collect();
    calls.retain(|call| {
        if call.origin != CallFactOrigin::AssignmentSourceCall {
            return true;
        }
        !real_calls.iter().any(|(callee, span)| {
            qualified_names_match(callee, &call.callee) && spans_overlap(*span, call.span)
        })
    });
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

/// Match an adapter-emitted call against a rulepack-owned callable target.
/// This is shared by the ordinary rule matcher and structured guard proofs so
/// analysis helpers never grow their own API-name comparisons.
pub(crate) fn rule_target_matches_call(callee: &str, receiver_types: &[String], target: &RuleTarget) -> bool {
    if target.annotation.is_some()
        || !target.in_class.is_empty()
        || !target.in_method.is_empty()
        || !target.in_method_prefix.is_empty()
        || !target.param_index_in.is_empty()
        || !target.base_param_index_in.is_empty()
        || !target.decl_kind_in.is_empty()
        || !target.visibility_in.is_empty()
    {
        // This helper has call facts but no declaration context. Contextual
        // constraints must fail closed instead of being silently ignored.
        return false;
    }
    let base_name_allowed = match_base_name(callee).map_or(target.base_name_in.is_empty(), |base| {
        (target.base_name_in.is_empty() || target.base_name_in.iter().any(|wanted| wanted == base))
            && !target.base_name_not_in.iter().any(|blocked| blocked == base)
    });
    if !base_name_allowed
        || (!target.receiver_type_in.is_empty()
            && !receiver_type_matches_any(receiver_types, &target.receiver_type_in))
    {
        return false;
    }
    let regex = target
        .regex
        .as_deref()
        .and_then(|pattern| Regex::new(pattern).ok());
    callee_matches_with_receiver_types(
        callee,
        receiver_types,
        target.name.as_deref(),
        target.attribute.as_ref(),
        regex.as_ref(),
    )
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
    let normalized = normalize_type_name_for_match(actual);
    let actual = bonsai_common::qualified_name_segments(&normalized);
    (actual.len() >= expected.len()
        && actual[actual.len() - expected.len()..]
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected))
        || actual
            .last()
            .zip(expected.last())
            .is_some_and(|(actual, expected)| actual == expected)
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
        .trim_start_matches(bonsai_common::is_name_punctuation)
        .to_string();
    if let Some(stripped) = out.strip_suffix("()") {
        out = stripped.trim().to_string();
    }
    out
}

fn normalize_callee_for_matching(callee: &str) -> String {
    let mut normalized = normalize_leading_call_punctuation(callee).replace("()", "");
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
    normalized == method || bonsai_common::short_qualified_tail(normalized) == method
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
        let Some(value) = source_text.and_then(|source_text| index.rendering(self.span, source_text)) else {
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
    // Normalize only representation details of the adapter-emitted callee.
    // Source-language keywords and API spellings are never interpreted here;
    // adapters own syntax and rule targets own provider vocabulary.
    let normalized = normalize_callee_for_matching(callee);
    if let Some(attr) = attribute {
        let actual = call_match_segments(&normalized);
        // Attribute components are rulepack fields, not necessarily one CST
        // identifier each: a receiver component may itself be qualified
        // (`CryptoJS.DES`, `ERB::Util`, `Crypt::DES`). Canonicalize both
        // complete identities through the vocabulary-free qualified-name
        // helper before applying suffix/window convenience matching.
        let declared = attr.join(".");
        let declared = normalize_leading_call_punctuation(&declared);
        if bonsai_common::normalize_qualified_name(&normalized)
            == bonsai_common::normalize_qualified_name(declared)
        {
            return true;
        }
        let expected = call_match_segments(declared);
        if actual.ends_with(&expected) {
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
        if actual
            .windows(expected.len())
            .any(|candidate| candidate == expected.as_slice())
        {
            return true;
        }
        return false;
    }
    if let Some(n) = name {
        // `name` may intentionally be a complete adapter-emitted callable
        // identity (`pool.query`) rather than only its terminal segment.
        // Exact identity must win before the bare-tail convenience match.
        if normalized == n {
            return true;
        }
        return call_match_segments(&normalized)
            .last()
            .is_some_and(|tail| tail == n);
    }
    false
}

fn call_match_segments(callee: &str) -> Vec<String> {
    bonsai_common::qualified_name_segments(callee)
        .into_iter()
        .filter_map(|segment| {
            let identifier = segment.split_once('(').map_or(segment, |(head, _)| head).trim();
            let identifier = normalize_leading_call_punctuation(identifier);
            (!identifier.is_empty()).then(|| identifier.to_string())
        })
        .collect()
}

fn compile_constraint_regexes(rule_id: &str, constraints: &[ConstraintKind]) -> Option<Vec<Option<Regex>>> {
    let mut compiled = Vec::with_capacity(constraints.len());
    for constraint in constraints {
        let regex = match constraint {
            ConstraintKind::ReceiverMatchesRegex {
                receiver_matches_regex,
            } => Some(compile_constraint_regex(
                rule_id,
                "constraints.receiver_matches_regex",
                receiver_matches_regex,
            )?),
            ConstraintKind::ReceiverNotMatchesRegex {
                receiver_not_matches_regex,
            } => Some(compile_constraint_regex(
                rule_id,
                "constraints.receiver_not_matches_regex",
                receiver_not_matches_regex,
            )?),
            ConstraintKind::UnlessPriorReceiverCall {
                unless_prior_receiver_call,
            } => Some(compile_constraint_regex(
                rule_id,
                "constraints.unless_prior_receiver_call.static_string_args_regex",
                &unless_prior_receiver_call.static_string_args_regex,
            )?),
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
            | ConstraintKind::ReceiverOriginCallbackParamReachesCall { .. }
            | ConstraintKind::FormatArgIndex { .. }
            | ConstraintKind::Namespace { .. }
            | ConstraintKind::TopLevel { .. }
            | ConstraintKind::ArgCount { .. }
            | ConstraintKind::MinArgs { .. }
            | ConstraintKind::MaxArgs { .. }
            | ConstraintKind::ArgValueNotAggregate { .. }
            | ConstraintKind::ArgSequenceItemsEqual { .. }
            | ConstraintKind::SameReceiverCallCountAtLeast { .. }
            | ConstraintKind::ArgLt { .. }
            | ConstraintKind::ArgLe { .. }
            | ConstraintKind::ArgGt { .. }
            | ConstraintKind::ArgGe { .. }
            | ConstraintKind::RequiresRuntimeType { .. }
            | ConstraintKind::EnclosingDecoratorIn { .. }
            | ConstraintKind::EnclosingModifierIn { .. }
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

#[derive(Clone, Copy)]
struct StructuralConstraintContext<'a> {
    current_decl: &'a Decl,
    file_decls: &'a [Decl],
    assignment_values: &'a [bonsai_lang_api::AssignmentValueFact],
    call_argument_values: &'a [bonsai_lang_api::CallArgumentValueFact],
}

#[derive(Copy, Clone)]
struct GuaranteedPriorCall<'a> {
    span: Span,
    name: &'a str,
    receiver: Option<&'a str>,
    receiver_types: &'a [String],
    arg_count: usize,
}

fn collect_guaranteed_prior_calls<'a>(
    events: &'a [FlowEvent],
    target: Span,
    out: &mut Vec<GuaranteedPriorCall<'a>>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                args,
                ..
            } => {
                if span.end <= target.start {
                    out.push(GuaranteedPriorCall {
                        span: *span,
                        name,
                        receiver: receiver.as_deref(),
                        receiver_types,
                        arg_count: args.len(),
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if events_contain_call_match(then_events, target) {
                    collect_guaranteed_prior_calls(then_events, target, out);
                    return;
                }
                if events_contain_call_match(else_events, target) {
                    collect_guaranteed_prior_calls(else_events, target, out);
                    return;
                }
                // Calls made by only one completed branch are not guaranteed
                // after the merge, so they are deliberately not accumulated.
            }
            FlowEvent::Loop { body, .. } => {
                if events_contain_call_match(body, target) {
                    collect_guaranteed_prior_calls(body, target, out);
                    return;
                }
                // A loop may execute zero times.
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                for region in [
                    body.as_slice(),
                    catch_events.as_slice(),
                    finally_events.as_slice(),
                ] {
                    if events_contain_call_match(region, target) {
                        collect_guaranteed_prior_calls(region, target, out);
                        return;
                    }
                }
                // No call inside a completed try/catch region is assumed to
                // dominate a later site: exceptions make that unsound.
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if events_contain_call_match(body, target) {
                    collect_guaranteed_prior_calls(body, target, out);
                    return;
                }
            }
            _ => {}
        }
    }
}

fn events_contain_call_match(events: &[FlowEvent], target: Span) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Call { span, .. } => {
            *span == target
                || spans_overlap(*span, target)
                || (span.start <= target.start && target.end <= span.end)
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => events_contain_call_match(then_events, target) || events_contain_call_match(else_events, target),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            events_contain_call_match(body, target)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            events_contain_call_match(body, target)
                || events_contain_call_match(catch_events, target)
                || events_contain_call_match(finally_events, target)
        }
        _ => false,
    })
}

fn static_string_call_arguments(
    facts: &[bonsai_lang_api::CallArgumentValueFact],
    call_span: Span,
    argument_count: usize,
) -> Option<String> {
    let mut values = Vec::with_capacity(argument_count);
    for argument_index in 0..argument_count {
        let value = bonsai_lang_api::call_argument_value_fact(facts, call_span, argument_index)?
            .static_value
            .as_ref()?;
        let bonsai_lang_api::StaticScalarValue::String(value) = value else {
            return None;
        };
        values.push(value.as_str());
    }
    Some(values.join("\u{1f}"))
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
    /// Modifier tokens on the enclosing declaration, extracted from the
    /// parsed Tree-sitter node rather than inferred from source/rule names.
    enclosing_modifiers: Option<&'a [String]>,
    /// Intra-procedural rename chain (`y = x` → `y → x`) for `MustAlias`.
    alias_chains: Option<&'a AHashMap<String, String>>,
    /// CFG-aware narrowings for `RequiresRuntimeType`.
    runtime_types: Option<&'a [RuntimeTypeNarrowing]>,
    /// Ordered lifecycle transitions for `RequiresState`.
    lifecycle_transitions: Option<&'a [(Span, String, String)]>,
    /// Enclosing compiler declarations used by constraints that relate a
    /// matched factory/member write to an assigned nested callback.
    structural_context: Option<StructuralConstraintContext<'a>>,
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

/// Dispatch table for `ConstraintKind`, evaluated in declaration order.
/// The match is exhaustive: adding a variant requires a matching arm here,
/// and the compiler enforces coverage.
///
/// ## Arms (in dispatch order)
///
/// | Arm                          | Predicate                                          |
/// |------------------------------|----------------------------------------------------|
/// | `ReceiverTypeIn`             | callee's receiver type matches a semantic type     |
/// | `ReceiverMatchesRegex`        | parsed call receiver matches a rule-owned regex    |
/// | `ReceiverNotMatchesRegex`     | parsed call receiver does not match a regex        |
/// | `UnlessPriorReceiverCall`     | no guaranteed matching prior receiver call         |
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
/// | `ArgValueNotAggregate`       | parsed argument is not an aggregate/object         |
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
            ConstraintKind::ReceiverMatchesRegex { .. } => {
                let Some(receiver) = call_receiver_text(ctx.callee) else {
                    return false;
                };
                let Some(Some(re)) = ctx.constraint_regexes.get(constraint_index) else {
                    return false;
                };
                if !re.is_match(receiver) {
                    return false;
                }
            }
            ConstraintKind::ReceiverNotMatchesRegex { .. } => {
                let Some(receiver) = call_receiver_text(ctx.callee) else {
                    return false;
                };
                let Some(Some(re)) = ctx.constraint_regexes.get(constraint_index) else {
                    return false;
                };
                if re.is_match(receiver) {
                    return false;
                }
            }
            ConstraintKind::UnlessPriorReceiverCall {
                unless_prior_receiver_call,
            } => {
                let Some(receiver) = call_receiver_text(ctx.callee) else {
                    continue;
                };
                let Some(Some(re)) = ctx.constraint_regexes.get(constraint_index) else {
                    return false;
                };
                let Some(structural) = ctx.structural_context else {
                    continue;
                };
                let owner = structural
                    .file_decls
                    .iter()
                    .filter(|decl| decl.span.start <= ctx.span.start && ctx.span.end <= decl.span.end)
                    .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
                    .unwrap_or(structural.current_decl);
                let mut prior_calls = Vec::new();
                collect_guaranteed_prior_calls(&owner.flow_events, ctx.span, &mut prior_calls);
                if prior_calls.iter().any(|call| {
                    call.receiver == Some(receiver)
                        && rule_target_matches_call(
                            call.name,
                            call.receiver_types,
                            &unless_prior_receiver_call.call,
                        )
                        && static_string_call_arguments(
                            structural.call_argument_values,
                            call.span,
                            call.arg_count,
                        )
                        .is_some_and(|arguments| re.is_match(&arguments))
                }) {
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
                if !format_arg_is_dynamic(arg.value_text.trim()) {
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
                    Some(CallFactOrigin::RealCall | CallFactOrigin::SyntheticWrite)
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
                if !matches!(ctx.call_origin, Some(CallFactOrigin::RealCall)) {
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
                    Some(CallFactOrigin::RealCall | CallFactOrigin::SyntheticWrite)
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
            ConstraintKind::ReceiverOriginCallbackParamReachesCall {
                receiver_origin_callback_param_reaches_call,
            } => {
                if !receiver_origin_callback_param_reaches_call_passes(
                    ctx,
                    receiver_origin_callback_param_reaches_call,
                ) {
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
            ConstraintKind::ArgValueNotAggregate {
                arg_value_not_aggregate,
            } => {
                let Some(structural) = ctx.structural_context else {
                    continue;
                };
                if bonsai_lang_api::call_argument_value_fact(
                    structural.call_argument_values,
                    ctx.span,
                    *arg_value_not_aggregate as usize,
                )
                .is_some_and(|fact| {
                    !fact.value_flow.aggregate_fields.is_empty()
                        || !fact.value_flow.tuple_items.is_empty()
                        || !fact.value_flow.spreads.is_empty()
                        || fact.exact_static_sequence_values.is_some()
                }) {
                    return false;
                }
            }
            ConstraintKind::ArgSequenceItemsEqual {
                arg_sequence_items_equal,
            } => {
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                let Some(values) = bonsai_lang_api::call_argument_value_fact(
                    structural.call_argument_values,
                    ctx.span,
                    arg_sequence_items_equal.argument_index,
                )
                .and_then(|fact| fact.exact_static_sequence_values.as_ref()) else {
                    return false;
                };
                if arg_sequence_items_equal.items.is_empty()
                    || !arg_sequence_items_equal.items.iter().all(|required| {
                        values
                            .get(required.index)
                            .and_then(Option::as_ref)
                            .is_some_and(|actual| required.accepted_values.contains(actual))
                    })
                {
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
            ConstraintKind::EnclosingModifierIn {
                enclosing_modifier_in,
            } => {
                if enclosing_modifier_in.is_empty() {
                    return false;
                }
                let Some(modifiers) = ctx.enclosing_modifiers else {
                    return false;
                };
                let any_match = modifiers.iter().any(|attached| {
                    enclosing_modifier_in
                        .iter()
                        .any(|want| want.eq_ignore_ascii_case(attached))
                });
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

fn receiver_origin_callback_param_reaches_call_passes(
    ctx: &ConstraintEval<'_, '_>,
    spec: &ReceiverOriginCallbackParamReachesCallSpec,
) -> bool {
    let Some(structural) = ctx.structural_context else {
        return false;
    };
    let Some(proof) =
        receiver_origin_callback_proof(ctx.call_origin, ctx.callee, ctx.args, ctx.span, structural, spec)
    else {
        return false;
    };

    if ctx.mode.ignore_arg_tainted() {
        return true;
    }
    let Some(taint_view) = ctx.taint_view else {
        return false;
    };
    let factory_arg = ArgTaintedSpec {
        index: Some(spec.factory_tainted_arg_index),
        kw: None,
    };
    taint_view.arg_is_tainted(proof.factory_span, &proof.factory_args, &factory_arg, false)
}

struct CallbackExtensionProof {
    factory_span: Span,
    factory_args: Vec<CallArg>,
    extension_span: Span,
    extension_target: String,
}

fn receiver_origin_callback_proof(
    call_origin: Option<CallFactOrigin>,
    callee: &str,
    args: &[CallArg],
    span: Span,
    structural: StructuralConstraintContext<'_>,
    spec: &ReceiverOriginCallbackParamReachesCallSpec,
) -> Option<CallbackExtensionProof> {
    let mut assignments = Vec::new();
    collect_assignment_events(&structural.current_decl.flow_events, &mut assignments);
    let all_calls = collect_calls(&structural.current_decl.flow_events);

    let (factory_span, factory_args, extension_assignment) = match call_origin {
        Some(CallFactOrigin::RealCall) => {
            if !rule_target_matches_call(callee, &[], &spec.receiver_factory) {
                return None;
            }
            let (factory_assignment, receiver) = assignments
                .iter()
                .filter(|assignment| {
                    assignment.span.start <= span.start
                        && span.end <= assignment.span.end
                        && assignment
                            .source_call
                            .is_some_and(|name| rule_target_matches_call(name, &[], &spec.receiver_factory))
                })
                .filter_map(|assignment| {
                    let fact = bonsai_lang_api::assignment_value_fact_for_span(
                        structural.assignment_values,
                        assignment.span,
                    )?;
                    let target = fact.target.as_deref()?;
                    (target == assignment.target).then_some((assignment, target))
                })
                .min_by_key(|(assignment, _)| assignment.span.end.saturating_sub(assignment.span.start))?;
            let extension = assignments
                .iter()
                .filter(|assignment| {
                    assignment.span.start > factory_assignment.span.end
                        && rule_target_matches_call(assignment.target, &[], &spec.receiver_member)
                        && call_receiver_text(assignment.target) == Some(receiver)
                })
                .min_by_key(|assignment| assignment.span.start)?;
            (span, args.to_vec(), extension)
        }
        Some(CallFactOrigin::SyntheticWrite) => {
            if !rule_target_matches_call(callee, &[], &spec.receiver_member) {
                return None;
            }
            let receiver = call_receiver_text(callee)?;
            let reaching_assignment = assignments
                .iter()
                .filter(|assignment| assignment.span.start < span.start && assignment.target == receiver)
                .filter(|assignment| {
                    bonsai_lang_api::assignment_value_fact_for_span(
                        structural.assignment_values,
                        assignment.span,
                    )
                    .is_none_or(|fact| fact.target.as_deref() == Some(receiver))
                })
                .max_by_key(|assignment| assignment.span.start)?;
            if !reaching_assignment
                .source_call
                .is_some_and(|name| rule_target_matches_call(name, &[], &spec.receiver_factory))
            {
                return None;
            }
            let factory_call = all_calls
                .iter()
                .filter(|call| {
                    call.origin == CallFactOrigin::RealCall
                        && reaching_assignment.span.start <= call.span.start
                        && call.span.end <= reaching_assignment.span.end
                        && rule_target_matches_call(
                            &call.callee,
                            &call.receiver_types,
                            &spec.receiver_factory,
                        )
                })
                .min_by_key(|call| call.span.end.saturating_sub(call.span.start))?;
            let extension = assignments
                .iter()
                .find(|assignment| assignment.span == span && assignment.target == callee)?;
            (factory_call.span, factory_call.args.clone(), extension)
        }
        _ => return None,
    };

    let callback = structural
        .file_decls
        .iter()
        .filter(|candidate| {
            candidate.span.start >= extension_assignment.span.start
                && candidate.span.end <= extension_assignment.span.end
                && candidate.params.get(spec.callback_param_index as usize).is_some()
        })
        .min_by_key(|candidate| candidate.span.end.saturating_sub(candidate.span.start))?;
    if !callback_param_reaches_declared_call(callback, spec) {
        return None;
    }

    Some(CallbackExtensionProof {
        factory_span,
        factory_args,
        extension_span: extension_assignment.span,
        extension_target: extension_assignment.target.to_string(),
    })
}

/// Reattribute a factory-anchored taint sink to the callback extension site
/// whose structure made that factory use dangerous.
///
/// The IDG remains anchored at the real tainted value operand (the factory
/// input); only the security terminal location changes to the compiler-proven
/// member write. This avoids inventing a value edge into the callback RHS.
pub(crate) fn callback_extension_attribution_match(
    ws: &Workspace,
    global: &GlobalIndex,
    sink: &RuleMatch,
    rule: &Rule,
) -> Option<RuleMatch> {
    if rule.match_spec.kind != MatchKind::Call {
        return None;
    }
    let spec = rule.constraints.0.iter().find_map(|constraint| {
        let ConstraintKind::ReceiverOriginCallbackParamReachesCall {
            receiver_origin_callback_param_reaches_call,
        } = constraint
        else {
            return None;
        };
        Some(receiver_origin_callback_param_reaches_call)
    })?;
    let file_index = ws.db().decl_index_remapped_to_headers(global, sink.span.file)?;
    let current_decl = file_index
        .defs
        .iter()
        .filter(|decl| decl.span.start <= sink.span.start && sink.span.end <= decl.span.end)
        .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))?;
    let factory_call = collect_calls(&current_decl.flow_events)
        .into_iter()
        .filter(|call| {
            call.origin == CallFactOrigin::RealCall
                && (call.span == sink.span || spans_overlap(call.span, sink.span))
                && rule_target_matches_call(&call.callee, &call.receiver_types, &spec.receiver_factory)
        })
        .min_by_key(|call| call.span.end.saturating_sub(call.span.start))?;
    let proof = receiver_origin_callback_proof(
        Some(CallFactOrigin::RealCall),
        &factory_call.callee,
        &factory_call.args,
        factory_call.span,
        StructuralConstraintContext {
            current_decl,
            file_decls: &file_index.defs,
            assignment_values: &file_index.assignment_values,
            call_argument_values: &file_index.call_argument_values,
        },
        spec,
    )?;
    let (file, line, column) = resolve_span(ws, proof.extension_span.file, proof.extension_span);
    let mut attributed = sink.clone();
    attributed.file = file;
    attributed.line = line;
    attributed.column = column;
    attributed.span = proof.extension_span;
    attributed.match_text = proof.extension_target;
    Some(attributed)
}

struct AssignmentEventRef<'a> {
    span: Span,
    target: &'a str,
    source_call: Option<&'a str>,
}

fn collect_assignment_events<'a>(events: &'a [FlowEvent], out: &mut Vec<AssignmentEventRef<'a>>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                ..
            } => out.push(AssignmentEventRef {
                span: *span,
                target,
                source_call: source_call.as_deref(),
            }),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assignment_events(then_events, out);
                collect_assignment_events(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assignment_events(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assignment_events(body, out);
                collect_assignment_events(catch_events, out);
                collect_assignment_events(finally_events, out);
            }
            _ => {}
        }
    }
}

fn callback_param_reaches_declared_call(
    callback: &Decl,
    spec: &ReceiverOriginCallbackParamReachesCallSpec,
) -> bool {
    let Some(parameter) = callback.params.get(spec.callback_param_index as usize) else {
        return false;
    };
    let mut tainted = AHashSet::from_iter([parameter.clone()]);
    callback_events_reach_declared_call(&callback.flow_events, spec, &mut tainted)
}

fn callback_events_reach_declared_call(
    events: &[FlowEvent],
    spec: &ReceiverOriginCallbackParamReachesCallSpec,
    tainted: &mut AHashSet<String>,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver_types,
                args,
                ..
            } => {
                if rule_target_matches_call(name, receiver_types, &spec.callback_call)
                    && args
                        .get(spec.callback_call_arg_index as usize)
                        .is_some_and(|arg| call_arg_depends_on_tainted_place(arg, tainted))
                {
                    return true;
                }
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                ..
            } => {
                let value_is_tainted = source_name
                    .iter()
                    .chain(source_names)
                    .any(|source| place_depends_on_tainted_place(source, tainted));
                overwrite_callback_place(tainted, target, value_is_tainted);
            }
            FlowEvent::AggregateAssign {
                target, value_flow, ..
            } => {
                let value_is_tainted = expression_flow_depends_on_tainted_place(value_flow, tainted);
                overwrite_callback_place(tainted, target, value_is_tainted);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let mut then_tainted = tainted.clone();
                let mut else_tainted = tainted.clone();
                if callback_events_reach_declared_call(then_events, spec, &mut then_tainted)
                    || callback_events_reach_declared_call(else_events, spec, &mut else_tainted)
                {
                    return true;
                }
                tainted.extend(then_tainted);
                tainted.extend(else_tainted);
            }
            FlowEvent::Loop { body, .. } => {
                let entry = tainted.clone();
                let mut fixed_point = entry.clone();
                loop {
                    let mut next = fixed_point.clone();
                    if callback_events_reach_declared_call(body, spec, &mut next) {
                        return true;
                    }
                    next.extend(entry.iter().cloned());
                    if next == fixed_point {
                        break;
                    }
                    fixed_point = next;
                }
                tainted.extend(fixed_point);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                let mut body_tainted = tainted.clone();
                let mut catch_tainted = tainted.clone();
                if callback_events_reach_declared_call(body, spec, &mut body_tainted)
                    || callback_events_reach_declared_call(catch_events, spec, &mut catch_tainted)
                {
                    return true;
                }
                tainted.extend(body_tainted);
                tainted.extend(catch_tainted);
                if callback_events_reach_declared_call(finally_events, spec, tainted) {
                    return true;
                }
            }
            FlowEvent::Defer { body, .. } => {
                let mut deferred_tainted = tainted.clone();
                if callback_events_reach_declared_call(body, spec, &mut deferred_tainted) {
                    return true;
                }
            }
            FlowEvent::Using { body, .. } => {
                if callback_events_reach_declared_call(body, spec, tainted) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn call_arg_depends_on_tainted_place(arg: &CallArg, tainted: &AHashSet<String>) -> bool {
    arg.place
        .iter()
        .chain(arg.source_names.iter())
        .any(|place| place_depends_on_tainted_place(place, tainted))
}

fn expression_flow_depends_on_tainted_place(
    flow: &bonsai_lang_api::ExpressionFlow,
    tainted: &AHashSet<String>,
) -> bool {
    flow.place
        .iter()
        .chain(flow.source_names.iter())
        .any(|place| place_depends_on_tainted_place(place, tainted))
        || flow
            .aggregate_fields
            .iter()
            .any(|field| expression_flow_depends_on_tainted_place(&field.value, tainted))
        || flow
            .tuple_items
            .iter()
            .chain(flow.spreads.iter())
            .any(|item| expression_flow_depends_on_tainted_place(item, tainted))
}

fn place_depends_on_tainted_place(place: &str, tainted: &AHashSet<String>) -> bool {
    let place = place
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    !place.is_empty()
        && tainted.iter().any(|candidate| {
            let candidate = candidate
                .trim()
                .trim_start_matches(bonsai_common::is_name_punctuation);
            place == candidate
                || place
                    .strip_prefix(candidate)
                    .is_some_and(|rest| rest.starts_with(['.', '[', ':']))
        })
}

fn overwrite_callback_place(tainted: &mut AHashSet<String>, target: &str, value_is_tainted: bool) {
    let target = target
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    if target.is_empty() {
        return;
    }
    tainted.retain(|candidate| {
        candidate != target
            && !candidate
                .strip_prefix(target)
                .is_some_and(|rest| rest.starts_with(['.', '[', ':']))
    });
    if value_is_tainted {
        tainted.insert(target.to_string());
    }
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
    bonsai_common::qualified_name_owner(callee).is_some()
}

/// Final identifier in a receiver path, with any trailing
/// non-identifier punctuation (parentheses, brackets) stripped.
fn receiver_path_tail(receiver: &str) -> &str {
    bonsai_common::short_qualified_tail(receiver)
        .trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
}

/// True when `callee` lives inside `namespace` (exact or
/// `namespace.x` / `namespace::x` / `namespace->x` / `namespace:x`).
/// Used by the `Namespace` constraint.
fn callee_in_namespace(callee: &str, namespace: &str) -> bool {
    callee == namespace
        || callee
            .strip_prefix(namespace)
            .is_some_and(bonsai_common::starts_at_qualified_name_boundary)
}

/// `FormatArgIndex` models a dynamic format operand. Static dangerous
/// directives are API/policy values and belong in a separate rule constraint.
fn format_arg_is_dynamic(value: &str) -> bool {
    unquote_literal(value).is_none()
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

fn collect_constructor_names_in_files(
    global: &bonsai_index::GlobalIndex,
    files: &[FileId],
) -> AHashSet<String> {
    let mut names = AHashSet::new();
    for &file in files {
        names.extend(
            global
                .decls_in(file)
                .iter()
                .filter(|decl| matches!(decl.kind, DeclKind::Constructor))
                .map(|decl| decl.name.clone()),
        );
    }
    names
}

fn collect_constructor_names_in_compiler_files(ws: &Workspace, files: &[FileId]) -> AHashSet<String> {
    let mut names = AHashSet::new();
    for &file in files {
        let Some(index) = ws.db().decl_index_uncached(file) else {
            continue;
        };
        names.extend(
            index
                .defs
                .iter()
                .filter(|decl| matches!(decl.kind, DeclKind::Constructor))
                .map(|decl| decl.name.clone()),
        );
    }
    names
}

/// True when the callee's tail (after `.` / `::` qualification)
/// names a known constructor. Lets `kind: new` rules fire on the
/// `MyClass(x)` form even though the AST didn't tag it as a
/// constructor call.
fn constructor_name_matches(callee: &str, constructor_names: &AHashSet<String>) -> bool {
    let normalized = callee.trim().trim_end_matches("()");
    let tail = bonsai_common::short_qualified_tail(normalized);
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
    let files = ws.db().vfs().all_files();
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
    let global = streaming_global_headers(ws);
    let mut files = scan_files.to_vec();
    files.sort_by_key(|file| file.raw());
    files.dedup();
    if files.is_empty() {
        return Vec::new();
    }
    // Build a set of "has in-workspace callers" to detect leaf functions
    // that look like entry points (unreferenced public decls). Reuse the
    // canonical resolved callgraph and filter it by caller file; cold graph
    // construction already streams exact per-file bodies, while warm queries
    // reuse the validated sidecar.
    let infer_debug = bonsai_diagnostics::debug::is_enabled("security-phase");
    let started = infer_debug.then(Instant::now);
    let (callees_seen, class_field_writes) =
        collect_entry_point_support_for_files(ws, &files, global.as_ref());
    log_inferred_subphase(
        infer_debug,
        "called-symbol and class-field collection",
        started,
        format_args!(
            "symbols={} classes={}",
            callees_seen.len(),
            class_field_writes.len()
        ),
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
        let Some(file_index) = db.decl_index_remapped_to_headers(global.as_ref(), file) else {
            on_file_done();
            continue;
        };
        for decl in &file_index.defs {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            scanned_decls = scanned_decls.saturating_add(1);
            let has_callers = callees_seen.contains(&decl.symbol);
            let decorator_kind = detect_framework_decorator(ws, file, &file_index, decl.span, decl.name_span);
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
                let source_span = inferred_parameter_source_span(decl);
                let (file_path, line, col) = resolve_span(ws, file, source_span);
                for (idx, param) in decl.params.iter().enumerate() {
                    if decl.receiver_param_index == Some(idx) {
                        continue;
                    }
                    out.push(RuleMatch {
                        origin: if matches!(ek, EntryKind::Unreferenced) {
                            MatchOrigin::InferredUnreferencedParameter
                        } else {
                            MatchOrigin::InferredFrameworkParameter
                        },
                        rule_id: format!("entry-point.{}.param_{idx}", ek.rule_slug()),
                        language: language.clone(),
                        file: file_path.clone(),
                        line,
                        column: col,
                        span: source_span,
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
                            origin: MatchOrigin::InferredClassField,
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

fn inferred_parameter_source_span(decl: &bonsai_lang_api::Decl) -> Span {
    let name_is_owned = decl.name_span.file == decl.span.file
        && decl.span.start <= decl.name_span.start
        && decl.name_span.end <= decl.span.end;
    if name_is_owned {
        decl.name_span
    } else {
        // Assigned lambdas and object-property callables obtain a useful
        // display name from their binding/property node, which is outside
        // the callable value-expression span. Anchor the inferred parameter
        // on the callable's own parsed declaration so duplicate display
        // names remain exactly attributable.
        decl.span
    }
}

fn collect_entry_point_support_for_files(
    ws: &Workspace,
    files: &[FileId],
    global: &bonsai_index::GlobalIndex,
) -> (
    ahash::AHashSet<SymbolId>,
    ahash::AHashMap<SymbolId, ahash::AHashSet<String>>,
) {
    let infer_debug = bonsai_diagnostics::debug::is_enabled("security-phase");
    let included_files: AHashSet<FileId> = files.iter().copied().collect();
    let started = infer_debug.then(Instant::now);
    let call_graph = ws.cached_resolved_call_graph();
    let mut out: ahash::AHashSet<SymbolId> = call_graph
        .inner()
        .edges
        .iter()
        .filter(|edge| {
            global
                .declaring_file(SymbolId::new(edge.from.raw()))
                .is_some_and(|file| included_files.contains(&file))
        })
        .map(|edge| SymbolId::new(edge.to.raw()))
        .collect();
    log_inferred_subphase(
        infer_debug,
        "resolved callgraph",
        started,
        format_args!(
            "edges={} called_symbols={}",
            call_graph.inner().edges.len(),
            out.len()
        ),
    );
    let before_assignment_refs = out.len();
    let started = infer_debug.then(Instant::now);
    let class_field_writes = collect_assignment_references_and_class_fields(ws, files, global, &mut out);
    log_inferred_subphase(
        infer_debug,
        "streamed body support facts",
        started,
        format_args!(
            "symbols={} added={} classes={}",
            out.len(),
            out.len().saturating_sub(before_assignment_refs),
            class_field_writes.len()
        ),
    );
    (out, class_field_writes)
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

fn is_synthetic_anonymous_callable(decl: &bonsai_lang_api::Decl) -> bool {
    decl.name.starts_with("<lambda@") && decl.name.ends_with('>')
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
    file_index: &DeclIndex,
    decl_span: Span,
    decl_name_span: Span,
) -> Option<EntryKind> {
    (!decl_decorator_names(ws, file, file_index, decl_span, decl_name_span).is_empty())
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
fn collect_assignment_references_and_class_fields(
    ws: &Workspace,
    files: &[FileId],
    global: &bonsai_index::GlobalIndex,
    out: &mut ahash::AHashSet<SymbolId>,
) -> ahash::AHashMap<SymbolId, ahash::AHashSet<String>> {
    let local_callable_index = AssignmentCallableReferenceIndex::build(global);
    let mut resolve_cache: AHashMap<AssignmentResolveKey, Vec<SymbolId>> = AHashMap::default();
    let mut stats = AssignmentReferenceStats::default();
    let mut class_field_writes: AHashMap<SymbolId, AHashSet<String>> = AHashMap::default();
    for &file in files {
        let Some(file_index) = ws.db().decl_index_remapped_to_headers(global, file) else {
            continue;
        };
        let alias_map: AHashMap<String, AliasTarget> =
            file_alias_map_with_retention(ws, file, FactRetention::Transient)
                .into_iter()
                .collect();
        let export_aliases = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().module_export_aliases)
            .unwrap_or(&[]);
        for decl in &file_index.defs {
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
            // G3 cross-method field taint is adapter-authored compiler IR:
            // class ownership comes from `Decl.parent`, and the writes come
            // from the exact Tree-sitter-lowered body. Accumulate only the
            // compact class-to-field relation while that body is resident.
            if let Some(class_symbol) = decl.parent {
                class_field_writes.entry(class_symbol).or_default().extend(
                    decl.receiver_field_writes
                        .iter()
                        .map(|write| write.target.clone()),
                );
            }
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
    class_field_writes
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
    let tail = bonsai_common::short_qualified_tail(name);
    (!tail.is_empty()).then_some(tail)
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
    let local_name = trimmed.trim_start_matches(bonsai_common::is_name_punctuation);
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
    if assignment_reference_is_unresolved_member_read(local_name, alias_map, &caller.implicit_receiver_names)
    {
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
        .with_file_path_lookup(&path_lookup)
        .with_same_directory_unqualified_calls(caller_allows_same_directory_unqualified_lookup(
            ws,
            caller.span.file,
        ));
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
        && bonsai_common::qualified_name_owner(trimmed).is_none()
        && !trimmed.contains('(')
        && !trimmed.contains(')')
        && !trimmed.chars().any(char::is_whitespace)
}

fn assignment_reference_is_unresolved_member_read(
    name: &str,
    alias_map: &AHashMap<String, AliasTarget>,
    implicit_receiver_names: &[String],
) -> bool {
    let Some((head, _tail)) = assignment_reference_head_tail(name) else {
        return false;
    };
    let head = head.trim().trim_start_matches(bonsai_common::is_name_punctuation);
    if head.is_empty() {
        return false;
    }
    if alias_map.contains_key(head) {
        return false;
    }
    if head.contains('(') {
        return true;
    }
    if implicit_receiver_names.iter().any(|declared| {
        bonsai_common::trim_leading_name_punctuation(declared.trim())
            == bonsai_common::trim_leading_name_punctuation(head)
    }) {
        return true;
    }
    head.chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
}

fn assignment_reference_head_tail(name: &str) -> Option<(&str, &str)> {
    bonsai_common::split_qualified_name_owner_tail(name)
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
    ws.db()
        .adapter_for(file)
        .is_some_and(|adapter| adapter.capabilities().same_directory_unqualified_calls)
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
            .with_file_path_lookup(&path_lookup)
            .with_same_directory_unqualified_calls(caller_allows_same_directory_unqualified_lookup(
                ws,
                caller.span.file,
            ));
        for func in bonsai_resolve::resolve_callable_with_context(global, name, &ctx) {
            out.insert(SymbolId::new(func.raw()));
        }
        let tail = bonsai_common::short_qualified_tail(name);
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
        let tail = bonsai_common::short_qualified_tail(name);
        if !tail.is_empty() && tail != name {
            for func in bonsai_resolve::resolve_callable_with_context(global, tail, &ctx) {
                out.insert(SymbolId::new(func.raw()));
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
